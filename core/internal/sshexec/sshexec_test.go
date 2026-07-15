package sshexec_test

import (
	"bufio"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/sallyport/sallyport/internal/dlp"
	"github.com/sallyport/sallyport/internal/sshexec"
	"github.com/sallyport/sallyport/internal/sshtest"
)

// fakeKeys is an in-memory KeyResolver (stands in for the vault).
type fakeKeys map[string][]byte

func (f fakeKeys) SecretValue(name string) ([]byte, error) {
	if b, ok := f[name]; ok {
		return append([]byte(nil), b...), nil
	}
	return nil, os.ErrNotExist
}

// echoHandler returns stdout keyed off the command; a couple of commands emit a
// secret so we can prove DLP scrubs the recording and the returned output.
func echoHandler(cmd string) (string, string, int) {
	switch {
	case strings.HasPrefix(cmd, "df"):
		return "Filesystem  Size  Used Avail\n/dev/sda1   50G   10G   40G\n", "", 0
	case strings.HasPrefix(cmd, "leak-token"):
		return "here is a token: Bearer sk_live_abcdefghij1234567890\n", "", 0
	case strings.HasPrefix(cmd, "fail"):
		return "", "boom\n", 3
	default:
		return "ran: " + cmd + "\n", "", 0
	}
}

// newServerWithKey starts a server and returns it plus a vault-style key store
// with an ed25519 client key named "fleet-key" authorized on the server.
func newServerWithKey(t *testing.T) (*sshtest.Server, fakeKeys, []byte) {
	t.Helper()
	srv, err := sshtest.New(echoHandler)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = srv.Close() })
	pemBytes, pub, err := sshtest.ClientKeyPEM("fleet@test")
	if err != nil {
		t.Fatal(err)
	}
	srv.Authorize(pub)
	return srv, fakeKeys{"fleet-key": pemBytes}, pemBytes
}

func hostRef(srv *sshtest.Server, policy string) sshexec.HostRef {
	addr, port := srv.Host()
	return sshexec.HostRef{Name: "t", Addr: addr, User: "os", Port: port, HostKey: policy, KeyName: "fleet-key"}
}

func TestExec_Basic(t *testing.T) {
	srv, keys, keyPEM := newServerWithKey(t)
	e := sshexec.New(keys, filepath.Join(t.TempDir(), "known_hosts"), 5*time.Second)

	res, err := e.Exec(context.Background(), hostRef(srv, "accept-new"), "df -h /", sshexec.Opts{Redactor: dlp.Redact})
	if err != nil {
		t.Fatalf("exec: %v", err)
	}
	if res.ExitCode != 0 {
		t.Fatalf("exit = %d, want 0", res.ExitCode)
	}
	if !strings.Contains(string(res.Stdout), "Filesystem") {
		t.Fatalf("stdout missing df output: %q", res.Stdout)
	}
	if res.BytesOut == 0 {
		t.Fatal("bytesOut should be > 0")
	}
	// The private key must have been used server-side.
	if srv.LastAuthorizedKey() == nil {
		t.Fatal("server never saw an authenticated key")
	}
	// And it must never appear in the output.
	if strings.Contains(string(res.Stdout)+string(res.Stderr), string(keyPEM)) {
		t.Fatal("private key leaked into command output")
	}
}

func TestExec_NonZeroExit(t *testing.T) {
	srv, keys, _ := newServerWithKey(t)
	e := sshexec.New(keys, filepath.Join(t.TempDir(), "known_hosts"), 5*time.Second)
	res, err := e.Exec(context.Background(), hostRef(srv, "accept-new"), "fail please", sshexec.Opts{})
	if err != nil {
		t.Fatalf("a non-zero exit must not be an error: %v", err)
	}
	if res.ExitCode != 3 {
		t.Fatalf("exit = %d, want 3", res.ExitCode)
	}
	if !strings.Contains(string(res.Stderr), "boom") {
		t.Fatalf("stderr = %q", res.Stderr)
	}
}

// TestHostKey_TOFUThenStrict walks the full host-key lifecycle:
//   - accept-new records the key + fires the audit hook (NewHostKey)
//   - a second connect under strict matches silently
//   - after the host key rotates, strict FAILS (mismatch never trusted)
func TestHostKey_TOFUThenStrict(t *testing.T) {
	srv, keys, _ := newServerWithKey(t)
	kh := filepath.Join(t.TempDir(), "known_hosts")
	e := sshexec.New(keys, kh, 5*time.Second)

	var acceptedFP string
	var acceptedAddr string
	res, err := e.Exec(context.Background(), hostRef(srv, "accept-new"), "uptime", sshexec.Opts{
		OnHostKeyAccept: func(addr, fp string) { acceptedAddr = addr; acceptedFP = fp },
	})
	if err != nil {
		t.Fatalf("first connect: %v", err)
	}
	if !res.NewHostKey {
		t.Fatal("first accept-new connect should report NewHostKey")
	}
	if acceptedFP == "" || !strings.HasPrefix(acceptedFP, "SHA256:") {
		t.Fatalf("audit hook fingerprint = %q", acceptedFP)
	}
	if acceptedAddr == "" {
		t.Fatal("audit hook missing host addr")
	}
	// The fingerprint recorded must be the server's actual host key.
	if want := ssh.FingerprintSHA256(srv.HostPublicKey()); want != acceptedFP {
		t.Fatalf("recorded fp %q != server host key %q", acceptedFP, want)
	}
	// The known_hosts file now has exactly one line.
	if n := countLines(t, kh); n != 1 {
		t.Fatalf("known_hosts lines = %d, want 1", n)
	}

	// Second connect under strict must match silently (no new key).
	res2, err := e.Exec(context.Background(), hostRef(srv, "strict"), "uptime", sshexec.Opts{})
	if err != nil {
		t.Fatalf("strict match should succeed: %v", err)
	}
	if res2.NewHostKey {
		t.Fatal("strict match must not record a new key")
	}

	// Rotate the server host key → strict must now FAIL.
	if err := srv.RotateHostKey(); err != nil {
		t.Fatal(err)
	}
	if _, err := e.Exec(context.Background(), hostRef(srv, "strict"), "uptime", sshexec.Opts{}); err == nil {
		t.Fatal("strict must fail on a changed host key")
	}
	// accept-new must ALSO fail on a changed key (never silently re-trust).
	if _, err := e.Exec(context.Background(), hostRef(srv, "accept-new"), "uptime", sshexec.Opts{}); err == nil {
		t.Fatal("accept-new must fail on a changed host key")
	}
}

func TestHostKey_StrictUnknownFails(t *testing.T) {
	srv, keys, _ := newServerWithKey(t)
	e := sshexec.New(keys, filepath.Join(t.TempDir(), "known_hosts"), 5*time.Second)
	if _, err := e.Exec(context.Background(), hostRef(srv, "strict"), "uptime", sshexec.Opts{}); err == nil {
		t.Fatal("strict on an unknown host must fail closed")
	}
}

// TestRecording writes an asciicast and proves an echoed secret is redacted in
// the recording and in the returned stdout.
func TestRecording_RedactsSecret(t *testing.T) {
	srv, keys, _ := newServerWithKey(t)
	e := sshexec.New(keys, filepath.Join(t.TempDir(), "known_hosts"), 5*time.Second)

	recPath := filepath.Join(t.TempDir(), "rec", "sess", "1.cast")
	res, err := e.Exec(context.Background(), hostRef(srv, "accept-new"), "leak-token", sshexec.Opts{
		RecordPath: recPath,
		Redactor:   dlp.Redact,
	})
	if err != nil {
		t.Fatalf("exec: %v", err)
	}
	if res.Recording != recPath {
		t.Fatalf("recording path = %q, want %q", res.Recording, recPath)
	}
	if res.Redactions == 0 {
		t.Fatal("expected at least one redaction")
	}
	// Returned stdout must not contain the raw token.
	if strings.Contains(string(res.Stdout), "sk_live_abcdefghij1234567890") {
		t.Fatalf("secret leaked into returned stdout: %q", res.Stdout)
	}
	// The .cast file must exist, be valid asciicast v2, and not contain the token.
	data, err := os.ReadFile(recPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "sk_live_abcdefghij1234567890") {
		t.Fatal("secret leaked into the recording")
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) < 2 {
		t.Fatalf("recording too short: %d lines", len(lines))
	}
	if !strings.Contains(lines[0], `"version":2`) {
		t.Fatalf("bad asciicast header: %s", lines[0])
	}
	if !strings.Contains(string(data), "«redacted»") {
		t.Fatal("recording should contain the redaction marker")
	}
}

func TestExec_KeyFromExplicitPath(t *testing.T) {
	srv, _, keyPEM := newServerWithKey(t)
	keyPath := filepath.Join(t.TempDir(), "id_ed25519")
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	e := sshexec.New(nil, filepath.Join(t.TempDir(), "known_hosts"), 5*time.Second)
	addr, port := srv.Host()
	ref := sshexec.HostRef{Addr: addr, User: "os", Port: port, HostKey: "accept-new", KeyPath: keyPath}
	res, err := e.Exec(context.Background(), ref, "echo hi", sshexec.Opts{})
	if err != nil {
		t.Fatalf("exec with key file: %v", err)
	}
	if res.ExitCode != 0 {
		t.Fatalf("exit = %d", res.ExitCode)
	}
}

func TestExec_MissingKeyFailsClosed(t *testing.T) {
	srv, keys, _ := newServerWithKey(t)
	e := sshexec.New(keys, filepath.Join(t.TempDir(), "known_hosts"), 5*time.Second)
	addr, port := srv.Host()
	ref := sshexec.HostRef{Addr: addr, User: "os", Port: port, HostKey: "accept-new", KeyName: "nope"}
	if _, err := e.Exec(context.Background(), ref, "df", sshexec.Opts{}); err == nil {
		t.Fatal("missing key must fail closed")
	}
}

func countLines(t *testing.T, path string) int {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	n := 0
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if strings.TrimSpace(sc.Text()) != "" {
			n++
		}
	}
	return n
}
