package sshexec

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"golang.org/x/crypto/ssh"
)

// maxHelperRequestBytes caps the JSON request read from stdin.
const maxHelperRequestBytes = 1 << 20

// HelperRequest describes one exec or key-normalization operation. Production
// exec requests use AgentFD. PrivateKeyB64 remains for import and legacy tests.
type HelperRequest struct {
	Op             string `json:"op,omitempty"` // "" | "exec" | "normalize_key"
	Passphrase     string `json:"passphrase,omitempty"`
	Host           string `json:"host"`           // address (ip/dns)
	User           string `json:"user"`           // ssh user (default "root")
	Port           int    `json:"port"`           // ssh port (default 22)
	HostKey        string `json:"hostKeyPolicy"`  // "accept-new" (default) | "strict"
	Command        string `json:"command"`        // the command line to run
	TimeoutS       int    `json:"timeoutS"`       // per-command timeout seconds; 0 uses the default
	KnownHostsPath string `json:"knownHostsPath"` // caller-owned file; TOFU appends here
	RecordPath     string `json:"recordPath"`     // asciicast file target; "" disables (tests only)
	// ReturnCast returns an in-memory recording in CastB64. It takes precedence
	// over RecordPath so the app can seal the cast without a plaintext file.
	ReturnCast bool `json:"returnCast,omitempty"`

	// AgentFD is an inherited socket connected to the app's SSH signer. A zero
	// value selects the legacy stdin-key path.
	AgentFD int `json:"agentFD,omitempty"`

	// PrivateKeyB64 carries an imported key for normalization or a key for the
	// legacy exec path.
	PrivateKeyB64 string `json:"privateKeyB64,omitempty"`
}

// HelperResponse is written to stdout. Exec output and recordings preserve the
// retained remote bytes without credential-pattern filtering.
type HelperResponse struct {
	Stdout     string `json:"stdout"` // base64 retained stdout
	Stderr     string `json:"stderr"` // base64 retained stderr
	ExitCode   int    `json:"exitCode"`
	BytesOut   int    `json:"bytesOut"`
	Truncated  bool   `json:"truncated,omitempty"`
	DurationMs int64  `json:"durationMs"`
	HostKeyFP  string `json:"hostKeyFp"`
	NewHostKey bool   `json:"newHostKey"` // a previously-unknown host was TOFU-accepted
	Recording  string `json:"recording,omitempty"`
	// CastB64 is the base64 of the in-memory asciicast (op=exec with ReturnCast).
	CastB64 string `json:"castB64,omitempty"`
	// NormalizedKeyB64 is set only for op=normalize_key: the base64 of the
	// validated, unencrypted OpenSSH PEM ready for vault storage.
	NormalizedKeyB64 string `json:"normalizedKeyB64,omitempty"`
	Error            string `json:"error,omitempty"` // set on failure; other fields best-effort
}

// staticKey supplies the stdin key to the legacy exec path.
type staticKey struct{ pem []byte }

func (s staticKey) SecretValue(string) ([]byte, error) {
	return append([]byte(nil), s.pem...), nil
}

// RunHelper reads one request and writes one response.
func RunHelper(r io.Reader, w io.Writer) error {
	var req HelperRequest
	if err := decodeHelperRequest(r, &req); err != nil {
		return writeResp(w, HelperResponse{Error: "sp-ssh: bad request: " + err.Error()})
	}

	// Imported keys arrive on stdin because they are not in the vault yet.
	if req.Op == "normalize_key" {
		key, err := base64.StdEncoding.DecodeString(req.PrivateKeyB64)
		if err != nil || len(key) == 0 {
			return writeResp(w, HelperResponse{Error: "sp-ssh: missing/invalid private key"})
		}
		defer zero(key)
		normalized, err := NormalizeKey(string(key), req.Passphrase)
		if err != nil {
			return writeResp(w, HelperResponse{Error: err.Error()})
		}
		return writeResp(w, HelperResponse{
			NormalizedKeyB64: base64.StdEncoding.EncodeToString([]byte(normalized)),
		})
	}
	if req.Op != "" && req.Op != "exec" {
		return writeResp(w, HelperResponse{Error: fmt.Sprintf("sp-ssh: unsupported operation %q", req.Op)})
	}

	// Reject out-of-range values before converting to time.Duration.
	if req.TimeoutS < 0 || req.TimeoutS > 86400 {
		req.TimeoutS = 30
	}

	// Production uses the inherited signing socket. Tests may use the stdin key.
	var ex *Executor
	var agentSig ssh.Signer
	if req.AgentFD > 0 {
		agentTimeout := time.Duration(req.TimeoutS) * time.Second
		if agentTimeout <= 0 {
			agentTimeout = defaultTimeout
		}
		signer, conn, err := agentSignerWithTimeout(req.AgentFD, agentTimeout)
		if err != nil {
			return writeResp(w, HelperResponse{Error: err.Error()})
		}
		defer func() { _ = conn.Close() }()
		agentSig = signer
		ex = New(nil, req.KnownHostsPath, time.Duration(req.TimeoutS)*time.Second)
	} else {
		key, err := base64.StdEncoding.DecodeString(req.PrivateKeyB64)
		if err != nil || len(key) == 0 {
			return writeResp(w, HelperResponse{Error: "sp-ssh: missing/invalid private key"})
		}
		defer zero(key)
		ex = New(staticKey{pem: key}, req.KnownHostsPath, time.Duration(req.TimeoutS)*time.Second)
	}
	// ReturnCast keeps the recording in memory for the app to seal. RecordPath is
	// used by direct tests.
	var castBuf *bytes.Buffer
	opts := Opts{
		Timeout:    time.Duration(req.TimeoutS) * time.Second,
		RecordPath: req.RecordPath,
		Signer:     agentSig, // nil on the legacy path; the executor resolves the key
	}
	if req.ReturnCast {
		castBuf = &bytes.Buffer{}
		opts.RecordSink = castBuf
		opts.RecordPath = ""
	}
	res, execErr := ex.Exec(context.Background(), HostRef{
		Addr:    req.Host,
		User:    req.User,
		Port:    req.Port,
		HostKey: req.HostKey,
		KeyName: "stdin", // any non-empty name routes signer() to our staticKey resolver
	}, req.Command, opts)

	resp := HelperResponse{}
	if res != nil {
		resp.Stdout = base64.StdEncoding.EncodeToString(res.Stdout)
		resp.Stderr = base64.StdEncoding.EncodeToString(res.Stderr)
		resp.ExitCode = res.ExitCode
		resp.BytesOut = res.BytesOut
		resp.Truncated = res.Truncated
		resp.DurationMs = res.Duration.Milliseconds()
		resp.HostKeyFP = res.HostKeyFP
		resp.NewHostKey = res.NewHostKey
		resp.Recording = res.Recording
		if castBuf != nil {
			resp.CastB64 = base64.StdEncoding.EncodeToString(castBuf.Bytes())
		}
	}
	if execErr != nil {
		resp.Error = execErr.Error()
	}
	return writeResp(w, resp)
}

// decodeHelperRequest accepts one bounded JSON value and clears its input
// buffer after decoding.
func decodeHelperRequest(r io.Reader, req *HelperRequest) error {
	body, err := io.ReadAll(io.LimitReader(r, maxHelperRequestBytes+1))
	if err != nil {
		return fmt.Errorf("read request: %w", err)
	}
	defer zero(body)
	if len(body) > maxHelperRequestBytes {
		return fmt.Errorf("request exceeds %d-byte limit", maxHelperRequestBytes)
	}
	if bytes.Equal(bytes.TrimSpace(body), []byte("null")) {
		return fmt.Errorf("request must be a JSON object")
	}

	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(req); err != nil {
		return err
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		if err == nil {
			return fmt.Errorf("multiple JSON values")
		}
		return fmt.Errorf("trailing data: %w", err)
	}
	return nil
}

func writeResp(w io.Writer, resp HelperResponse) error {
	b, err := json.Marshal(resp)
	if err != nil {
		return fmt.Errorf("sp-ssh: marshal response: %w", err)
	}
	frame := append(b, '\n')
	n, err := w.Write(frame)
	if err != nil {
		return err
	}
	if n != len(frame) {
		return io.ErrShortWrite
	}
	return nil
}
