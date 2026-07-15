package sshexec_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/sallyport/sallyport/internal/sshexec"
	"github.com/sallyport/sallyport/internal/sshtest"
)

// drive runs the stateless helper on a request and returns the parsed response.
func drive(t *testing.T, req sshexec.HelperRequest) sshexec.HelperResponse {
	t.Helper()
	in, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := sshexec.RunHelper(bytes.NewReader(in), &out); err != nil {
		t.Fatalf("RunHelper: %v", err)
	}
	var resp sshexec.HelperResponse
	if err := json.Unmarshal(out.Bytes(), &resp); err != nil {
		t.Fatalf("decode response %q: %v", out.String(), err)
	}
	return resp
}

func decode(t *testing.T, b64 string) string {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

// baseReq wires a request to a fresh test server with the client key authorized.
func baseReq(t *testing.T, cmd string) (sshexec.HelperRequest, *sshtest.Server) {
	t.Helper()
	srv, err := sshtest.New(func(c string) (string, string, int) {
		switch {
		case strings.HasPrefix(c, "false"):
			return "", "nope\n", 3
		default:
			return "ok: " + c + "\n", "", 0
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = srv.Close() })

	keyPEM, pub, err := sshtest.ClientKeyPEM("sp-ssh-test")
	if err != nil {
		t.Fatal(err)
	}
	srv.Authorize(pub)
	addr, port := srv.Host()

	return sshexec.HelperRequest{
		Host:           addr,
		User:           "os",
		Port:           port,
		HostKey:        "accept-new",
		Command:        cmd,
		TimeoutS:       5,
		KnownHostsPath: filepath.Join(t.TempDir(), "known_hosts"),
		PrivateKeyB64:  base64.StdEncoding.EncodeToString(keyPEM),
	}, srv
}

// TestHelper_StdinKeyHandoffRunsCommand: the key travels on stdin, the command
// runs server-side, and the output comes back — the whole point of the seam.
func TestHelper_StdinKeyHandoffRunsCommand(t *testing.T) {
	req, srv := baseReq(t, "whoami")
	resp := drive(t, req)

	if resp.Error != "" {
		t.Fatalf("unexpected error: %s", resp.Error)
	}
	if got := decode(t, resp.Stdout); got != "ok: whoami\n" {
		t.Fatalf("stdout = %q", got)
	}
	if resp.ExitCode != 0 {
		t.Fatalf("exit = %d, want 0", resp.ExitCode)
	}
	// The server authenticated with OUR client key (server-side key use).
	if srv.LastAuthorizedKey() == nil {
		t.Fatal("server never saw an authenticated key")
	}
}

// TestHelper_TOFUCapturesHostKey: a first connect under accept-new records the
// host key fingerprint and flags it new — and persists it to the caller's file.
func TestHelper_TOFUCapturesHostKey(t *testing.T) {
	req, srv := baseReq(t, "whoami")
	resp := drive(t, req)

	if !resp.NewHostKey {
		t.Fatal("first accept-new connect must report a new host key")
	}
	wantFP := ssh.FingerprintSHA256(srv.HostPublicKey())
	if resp.HostKeyFP != wantFP {
		t.Fatalf("host key fp = %q, want %q", resp.HostKeyFP, wantFP)
	}
	// The caller-owned known_hosts file now carries the pinned key.
	kh, _ := os.ReadFile(req.KnownHostsPath)
	if len(kh) == 0 {
		t.Fatal("TOFU acceptance was not persisted to the known_hosts file")
	}

	// A second connect against the SAME file is no longer "new".
	resp2 := drive(t, req)
	if resp2.NewHostKey {
		t.Fatal("second connect to a pinned host must not report a new key")
	}
}

// TestHelper_StrictRejectsUnknownHost: strict policy refuses a host it hasn't
// pinned — fail closed, no command runs.
func TestHelper_StrictRejectsUnknownHost(t *testing.T) {
	req, _ := baseReq(t, "whoami")
	req.HostKey = "strict"
	resp := drive(t, req)
	if resp.Error == "" {
		t.Fatal("strict policy must reject an unknown host")
	}
}

// TestHelper_NonZeroExitIsSuccessfulRun: a command's non-zero exit is a normal
// result (exit code surfaced), not a helper error.
func TestHelper_NonZeroExitIsSuccessfulRun(t *testing.T) {
	req, _ := baseReq(t, "false please")
	resp := drive(t, req)
	if resp.Error != "" {
		t.Fatalf("non-zero exit must not be an error, got %q", resp.Error)
	}
	if resp.ExitCode != 3 {
		t.Fatalf("exit = %d, want 3", resp.ExitCode)
	}
	if got := decode(t, resp.Stderr); got != "nope\n" {
		t.Fatalf("stderr = %q", got)
	}
}

// TestHelper_BadKeyFailsClosed: a missing/garbage key never dials.
func TestHelper_BadKeyFailsClosed(t *testing.T) {
	req, _ := baseReq(t, "whoami")
	req.PrivateKeyB64 = base64.StdEncoding.EncodeToString([]byte("not a key"))
	resp := drive(t, req)
	if resp.Error == "" {
		t.Fatal("a bad private key must fail closed")
	}
}

func TestHelper_BoundaryValidation(t *testing.T) {
	tests := []struct {
		name       string
		mutate     func(*sshexec.HelperRequest)
		wantError  bool
		wantOutput string
	}{
		{
			name: "invalid base64 key",
			mutate: func(req *sshexec.HelperRequest) {
				req.PrivateKeyB64 = "%%%"
			},
			wantError: true,
		},
		{
			name: "missing key",
			mutate: func(req *sshexec.HelperRequest) {
				req.PrivateKeyB64 = ""
			},
			wantError: true,
		},
		{
			name: "negative timeout is clamped",
			mutate: func(req *sshexec.HelperRequest) {
				req.TimeoutS = -1
			},
			wantOutput: "ok: whoami\n",
		},
		{
			name: "overflowing timeout is clamped",
			mutate: func(req *sshexec.HelperRequest) {
				req.TimeoutS = 86401
			},
			wantOutput: "ok: whoami\n",
		},
		{
			name: "explicit exec operation",
			mutate: func(req *sshexec.HelperRequest) {
				req.Op = "exec"
			},
			wantOutput: "ok: whoami\n",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, _ := baseReq(t, "whoami")
			tt.mutate(&req)
			resp := drive(t, req)
			if tt.wantError {
				if resp.Error == "" {
					t.Fatal("request unexpectedly succeeded")
				}
				return
			}
			if resp.Error != "" {
				t.Fatalf("request failed: %s", resp.Error)
			}
			if got := decode(t, resp.Stdout); got != tt.wantOutput {
				t.Fatalf("stdout = %q, want %q", got, tt.wantOutput)
			}
		})
	}
}

// TestHelper_RecordsSession: when a record path is given, an asciicast is written.
func TestHelper_RecordsSession(t *testing.T) {
	req, _ := baseReq(t, "whoami")
	req.RecordPath = filepath.Join(t.TempDir(), "session.cast")
	resp := drive(t, req)
	if resp.Recording == "" {
		t.Fatal("expected a recording path")
	}
	if _, err := os.Stat(resp.Recording); err != nil {
		t.Fatalf("recording file missing: %v", err)
	}
}

// TestHelper_ReturnCast: the caller-seals mode — the asciicast comes back
// in-memory (CastB64) and NO recording file is written anywhere, even when a
// RecordPath is (mistakenly) also supplied. The caller seals the bytes under
// the vault key; plaintext must never touch disk.
func TestHelper_ReturnCast(t *testing.T) {
	req, _ := baseReq(t, "whoami")
	req.ReturnCast = true
	req.RecordPath = filepath.Join(t.TempDir(), "must-not-exist.cast")
	resp := drive(t, req)
	if resp.Error != "" {
		t.Fatalf("exec failed: %s", resp.Error)
	}
	if resp.Recording != "" {
		t.Fatalf("no recording path expected in ReturnCast mode, got %q", resp.Recording)
	}
	if _, err := os.Stat(req.RecordPath); !os.IsNotExist(err) {
		t.Fatal("ReturnCast mode must not write a plaintext cast file")
	}
	cast, err := base64.StdEncoding.DecodeString(resp.CastB64)
	if err != nil || len(cast) == 0 {
		t.Fatalf("expected an in-memory cast, got err=%v len=%d", err, len(cast))
	}
	if !bytes.Contains(cast, []byte(`"version":2`)) && !bytes.Contains(cast, []byte(`"version": 2`)) {
		t.Fatalf("cast is not an asciicast v2 header: %.80s", cast)
	}
	if !bytes.Contains(cast, []byte("whoami")) {
		t.Fatal("cast should contain the echoed command line")
	}
}

// TestHelper_NormalizeKey: the import op — an encrypted key demands a passphrase
// (stable sentinel), decrypts with the right one into an UNENCRYPTED OpenSSH PEM,
// and rejects garbage. No SSH dial happens in this mode.
func TestHelper_NormalizeKey(t *testing.T) {
	// An ed25519 key encrypted with "pw" (generated via ssh.MarshalPrivateKeyWithPassphrase).
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKeyWithPassphrase(priv, "test", []byte("pw"))
	if err != nil {
		t.Fatal(err)
	}
	encPEM := pem.EncodeToMemory(block)

	run := func(passphrase string) sshexec.HelperResponse {
		return drive(t, sshexec.HelperRequest{
			Op:            "normalize_key",
			Passphrase:    passphrase,
			PrivateKeyB64: base64.StdEncoding.EncodeToString(encPEM),
		})
	}

	if resp := run(""); !strings.Contains(resp.Error, "passphrase-protected") {
		t.Fatalf("no passphrase: error = %q, want the passphrase-protected sentinel", resp.Error)
	}
	if resp := run("wrong"); resp.Error == "" {
		t.Fatal("wrong passphrase must fail")
	}
	resp := run("pw")
	if resp.Error != "" {
		t.Fatalf("correct passphrase: %v", resp.Error)
	}
	normalized, err := base64.StdEncoding.DecodeString(resp.NormalizedKeyB64)
	if err != nil || len(normalized) == 0 {
		t.Fatal("missing normalized key")
	}
	if !strings.HasPrefix(string(normalized), "-----BEGIN OPENSSH PRIVATE KEY-----") {
		t.Fatalf("unexpected PEM header: %q", string(normalized[:40]))
	}
	if _, err := ssh.ParsePrivateKey(normalized); err != nil {
		t.Fatalf("normalized key must parse UNENCRYPTED: %v", err)
	}
}

// TestHelper_RecordingIsRedacted: the .cast file the helper writes goes straight
// to disk — the caller never sees it — so a token echoed by the command must be
// scrubbed HERE, or it lands on disk in the clear.
func TestHelper_RecordingIsRedacted(t *testing.T) {
	secret := "ghp_" + strings.Repeat("A", 32) // a shape the DLP knows
	req, _ := baseReq(t, "echo "+secret)
	req.RecordPath = filepath.Join(t.TempDir(), "session.cast")
	resp := drive(t, req)
	if resp.Error != "" {
		t.Fatalf("exec: %v", resp.Error)
	}
	cast, err := os.ReadFile(resp.Recording)
	if err != nil {
		t.Fatalf("read recording: %v", err)
	}
	if strings.Contains(string(cast), secret) {
		t.Fatalf("the recording contains the secret verbatim:\n%s", cast)
	}
	if !strings.Contains(string(cast), "redacted") {
		t.Fatalf("expected a redaction marker in the recording:\n%s", cast)
	}
}
