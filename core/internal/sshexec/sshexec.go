// Package sshexec implements the ssh.exec helper.
package sshexec

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"golang.org/x/crypto/ssh"
)

// Host-key policy names.
const (
	hostKeyAcceptNew = "accept-new"
	hostKeyStrict    = "strict"
)

// defaultTimeout bounds a single command when the caller passes none.
const defaultTimeout = 30 * time.Second

// Errors the engine maps to structured result codes.
var (
	// ErrNoKey means neither a vault key name nor a key file was usable.
	ErrNoKey = errors.New("sshexec: no usable private key for host")
	// ErrTimeout means the command exceeded its deadline.
	ErrTimeout = errors.New("sshexec: command timed out")
)

// KeyResolver materializes a private key by vault secret name. *vault.Vault
// satisfies it via SecretValue; the returned bytes are zeroized by the executor.
type KeyResolver interface {
	SecretValue(name string) ([]byte, error)
}

// HostRef identifies a host and its authentication source.
type HostRef struct {
	Name    string // inventory name, for error/reference text only
	Addr    string // host address (ip or dns)
	User    string // ssh user (default "root")
	Port    int    // ssh port (default 22)
	HostKey string // "accept-new" (default) | "strict"
	KeyName string // vault secret name holding the private key
	KeyPath string // explicit private-key file path (alternative to KeyName)
}

// Opts are per-call knobs.
type Opts struct {
	Timeout    time.Duration // per-command timeout; 0 uses the default
	RecordPath string        // asciicast file target; "" disables (tests/dev only)
	// RecordSink writes the asciicast to memory instead of RecordPath.
	RecordSink      io.Writer
	OnHostKeyAccept func(addr, fingerprint string) // audited TOFU acceptance hook
	// Signer bypasses private-key resolution. Production supplies the app-backed
	// signer over an inherited socket.
	Signer ssh.Signer
}

// Result is the outcome of one ssh.exec. Stdout and Stderr preserve the remote
// command's retained bytes without credential-pattern filtering.
type Result struct {
	Stdout     []byte
	Stderr     []byte
	ExitCode   int
	BytesOut   int  // total drained stdout+stderr byte count before retention truncation
	Truncated  bool // true when output exceeded the bounded retention budget
	Duration   time.Duration
	Recording  string // path to the .cast file, or ""
	HostKeyFP  string // SHA256 fingerprint of the host key that authenticated the server
	NewHostKey bool   // true when this connect TOFU-accepted a previously unknown host
}

// Executor runs commands against inventory hosts.
type Executor struct {
	keys    KeyResolver
	known   *KnownHosts
	timeout time.Duration
}

// New builds an Executor. keys may be nil if every host uses an explicit KeyPath.
// knownHostsPath is the sallyport-managed host-key file.
func New(keys KeyResolver, knownHostsPath string, timeout time.Duration) *Executor {
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	return &Executor{keys: keys, known: NewKnownHosts(knownHostsPath), timeout: timeout}
}

// Exec resolves the key, dials the host under the configured host-key policy,
// runs cmd, records the session, and returns its retained output.
func (e *Executor) Exec(ctx context.Context, ref HostRef, cmd string, opts Opts) (*Result, error) {
	if ref.HostKey == "" {
		ref.HostKey = hostKeyAcceptNew
	}
	if ref.HostKey != hostKeyAcceptNew && ref.HostKey != hostKeyStrict {
		return nil, fmt.Errorf("sshexec: invalid hostkey policy %q", ref.HostKey)
	}
	user := ref.User
	if user == "" {
		user = "root"
	}
	port := ref.Port
	if port == 0 {
		port = 22
	}
	addr := ref.Addr
	if addr == "" {
		addr = ref.Name
	}
	hostID := net.JoinHostPort(addr, fmt.Sprintf("%d", port))

	// Authenticate either with the injected agent signer (the key never reaches
	// this process) or, legacy/tests, by resolving the private key at point of
	// use. The agent path is the default in production (PROTOCOL.md).
	var err error
	signer := opts.Signer
	if signer == nil {
		signer, err = e.signer(ref)
		if err != nil {
			return nil, err
		}
	}

	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = e.timeout
	}

	// Open the recording BEFORE connecting so a recording we cannot write fails
	// the call closed (the session record is part of the ssh audit trail).
	var rec *cast
	switch {
	case opts.RecordSink != nil:
		rec, err = newCastWriter(opts.RecordSink, 80, 24)
	case opts.RecordPath != "":
		rec, err = newCast(opts.RecordPath, 80, 24)
	}
	if err != nil {
		return nil, fmt.Errorf("sshexec: open recording (fail-closed): %w", err)
	}
	if rec != nil {
		if eventErr := rec.event("i", []byte(commandLine(cmd))); eventErr != nil {
			return nil, fmt.Errorf("sshexec: initialize recording (fail-closed): %w", errors.Join(eventErr, rec.close()))
		}
	}

	res := &Result{}
	if opts.RecordSink == nil {
		res.Recording = opts.RecordPath
	}
	var newKey bool
	trust := e.known.verifier(hostID, ref.HostKey)

	cfg := &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: trust.callback,
		Timeout:         timeout,
	}
	// Capture the host key that actually authenticated the server (for audit),
	// even on a match where onAccept does not fire.
	cfg.HostKeyCallback = wrapCapture(cfg.HostKeyCallback, func(k ssh.PublicKey) {
		if res.HostKeyFP == "" {
			res.HostKeyFP = ssh.FingerprintSHA256(k)
		}
	})

	start := time.Now()
	commitHostKey := func() error {
		added, fp, err := trust.commit()
		if err != nil {
			return err
		}
		if !added {
			return nil
		}
		newKey = true
		res.HostKeyFP = fp
		if opts.OnHostKeyAccept != nil {
			opts.OnHostKeyAccept(hostID, fp)
		}
		return nil
	}
	out, errRun := e.run(ctx, hostID, cfg, cmd, timeout, rec, commitHostKey)
	res.Duration = time.Since(start)
	res.NewHostKey = newKey

	var recErr error
	if rec != nil {
		recErr = rec.close()
	}
	if recErr != nil {
		recErr = fmt.Errorf("sshexec: finalize recording (fail-closed): %w", recErr)
		if errRun != nil {
			return res, errors.Join(errRun, recErr)
		}
		return res, recErr
	}
	if errRun != nil {
		return res, errRun
	}

	res.BytesOut = saturatingAddInt(out.rawStdout, out.rawStderr)
	res.Truncated = out.truncated
	res.Stdout = out.stdout.Bytes()
	res.Stderr = out.stderr.Bytes()
	res.ExitCode = out.exit
	return res, nil
}

// runResult is the internal per-run capture.
type runResult struct {
	stdout, stderr       bytes.Buffer
	rawStdout, rawStderr int
	truncated            bool
	exit                 int
}

// run performs the dial + session, honoring ctx and the per-command timeout.
func (e *Executor) run(ctx context.Context, hostID string, cfg *ssh.ClientConfig, cmd string,
	timeout time.Duration, rec *cast, afterHandshake func() error) (*runResult, error) {
	dialer := net.Dialer{Timeout: timeout}
	nc, err := dialer.DialContext(ctx, "tcp", hostID)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, fmt.Errorf("sshexec: %w during dial: %w", ErrTimeout, ctxErr)
		}
		return nil, fmt.Errorf("sshexec: dial %s: %w", hostID, err)
	}
	// Bound the handshake: NewClientConn (unlike ssh.Dial) does not honor
	// cfg.Timeout, so a hung peer would block forever. Cancellation must also
	// interrupt this synchronous phase; AfterFunc closes the transport without
	// leaving a watcher goroutine behind. Clear the deadline once secure.
	_ = nc.SetDeadline(time.Now().Add(timeout))
	stopHandshakeCancel := context.AfterFunc(ctx, func() { _ = nc.Close() })
	sc, chans, reqs, err := ssh.NewClientConn(nc, hostID, cfg)
	stopHandshakeCancel()
	if ctxErr := ctx.Err(); ctxErr != nil {
		if sc != nil {
			_ = sc.Close()
		} else {
			_ = nc.Close()
		}
		return nil, fmt.Errorf("sshexec: %w during handshake: %w", ErrTimeout, ctxErr)
	}
	if err != nil {
		_ = nc.Close()
		var netErr net.Error
		if errors.As(err, &netErr) && netErr.Timeout() {
			return nil, fmt.Errorf("sshexec: %w during handshake: %w", ErrTimeout, err)
		}
		return nil, fmt.Errorf("sshexec: handshake %s: %w", hostID, err)
	}
	// The server has proved possession of its host key and accepted the client's
	// authentication. Commit any staged TOFU key before opening a session or
	// sending the command. A concurrent different first key fails closed here.
	if afterHandshake != nil {
		if err := afterHandshake(); err != nil {
			_ = sc.Close()
			return nil, fmt.Errorf("sshexec: commit authenticated host key: %w", err)
		}
	}
	_ = nc.SetDeadline(time.Time{})
	client := ssh.NewClient(sc, chans, reqs)
	defer func() { _ = client.Close() }()

	session, err := client.NewSession()
	if err != nil {
		return nil, fmt.Errorf("sshexec: open session: %w", err)
	}
	defer func() { _ = session.Close() }()

	rr := &runResult{}
	// Share one 8 MiB retention budget across output and recording.
	cap := newOutputCap(8 << 20)
	stdoutWriter := &streamWriter{code: "o", rec: rec, dst: &rr.stdout, cap: cap}
	session.Stdout = stdoutWriter
	// Asciicast v2 has no stderr event. Keep returned streams separate but record
	// both as output events.
	stderrWriter := &streamWriter{code: "o", rec: rec, dst: &rr.stderr, cap: cap}
	session.Stderr = stderrWriter

	runErr := make(chan error, 1)
	go func() { runErr <- session.Run(cmd) }()

	deadline := time.NewTimer(timeout)
	defer deadline.Stop()

	select {
	case <-ctx.Done():
		_ = session.Signal(ssh.SIGKILL)
		_ = client.Close()
		return nil, fmt.Errorf("sshexec: %w: %w", ErrTimeout, ctx.Err())
	case <-deadline.C:
		_ = session.Signal(ssh.SIGKILL)
		_ = client.Close()
		return nil, ErrTimeout
	case err := <-runErr:
		// BytesOut counts drained bytes, including bytes discarded after the cap.
		rr.rawStdout = stdoutWriter.n
		rr.rawStderr = stderrWriter.n
		rr.truncated = cap.isTruncated()
		if captureErr := errors.Join(stdoutWriter.err, stderrWriter.err); captureErr != nil {
			return rr, fmt.Errorf("sshexec: capture output: %w", captureErr)
		}
		if err == nil {
			rr.exit = 0
			return rr, nil
		}
		var ee *ssh.ExitError
		if errors.As(err, &ee) {
			rr.exit = ee.ExitStatus()
			return rr, nil // a non-zero exit is a successful run, not an error
		}
		var em *ssh.ExitMissingError
		if errors.As(err, &em) {
			rr.exit = -1
			return rr, nil
		}
		return rr, fmt.Errorf("sshexec: run: %w", err)
	}
}

// signer resolves the private key for ref and zeroizes the raw material.
func (e *Executor) signer(ref HostRef) (ssh.Signer, error) {
	var raw []byte
	var err error
	switch {
	case ref.KeyName != "":
		if e.keys == nil {
			return nil, fmt.Errorf("%w: no key resolver configured", ErrNoKey)
		}
		raw, err = e.keys.SecretValue(ref.KeyName)
		if err != nil {
			return nil, fmt.Errorf("sshexec: resolve key %q: %w", ref.KeyName, err)
		}
	case ref.KeyPath != "":
		raw, err = readKeyFile(ref.KeyPath)
		if err != nil {
			return nil, fmt.Errorf("sshexec: read key file: %w", err)
		}
	default:
		return nil, ErrNoKey
	}
	defer zero(raw)
	if len(raw) == 0 {
		return nil, ErrNoKey
	}
	signer, err := ssh.ParsePrivateKey(raw)
	if err != nil {
		// ssh parse errors do not include key bytes.
		return nil, fmt.Errorf("sshexec: parse private key for %s: %w", refLabel(ref), err)
	}
	return signer, nil
}

// wrapCapture composes a host-key callback with a peek at the presented key.
func wrapCapture(inner ssh.HostKeyCallback, peek func(ssh.PublicKey)) ssh.HostKeyCallback {
	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		peek(key)
		return inner(hostname, remote, key)
	}
}

// zero wipes a byte slice.
func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// refLabel is a non-secret identifier for a host used in errors.
func refLabel(ref HostRef) string {
	if ref.Name != "" {
		return ref.Name
	}
	return ref.Addr
}
