package sshexec

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sallyport/sallyport/internal/sshtest"
	"golang.org/x/crypto/ssh"
	"golang.org/x/sys/unix"
)

func TestExecutorSignerFailsClosedAndZeroizesMaterial(t *testing.T) {
	keyPEM, _, err := sshtest.ClientKeyPEM("signer-test")
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name    string
		ex      *Executor
		ref     HostRef
		wantErr error
		inspect []byte
	}{
		{name: "no key reference", ex: New(nil, "", 0), ref: HostRef{}, wantErr: ErrNoKey},
		{name: "nil resolver", ex: New(nil, "", 0), ref: HostRef{KeyName: "key"}, wantErr: ErrNoKey},
		{name: "resolver error", ex: New(borrowingResolver{err: os.ErrPermission}, "", 0), ref: HostRef{KeyName: "key"}, wantErr: os.ErrPermission},
		{name: "empty key", ex: New(borrowingResolver{}, "", 0), ref: HostRef{KeyName: "key"}, wantErr: ErrNoKey},
		func() struct {
			name    string
			ex      *Executor
			ref     HostRef
			wantErr error
			inspect []byte
		} {
			raw := []byte("not-a-private-key")
			return struct {
				name    string
				ex      *Executor
				ref     HostRef
				wantErr error
				inspect []byte
			}{name: "invalid key", ex: New(borrowingResolver{raw: raw}, "", 0), ref: HostRef{Name: "safe-label", KeyName: "key"}, inspect: raw}
		}(),
		func() struct {
			name    string
			ex      *Executor
			ref     HostRef
			wantErr error
			inspect []byte
		} {
			raw := append([]byte(nil), keyPEM...)
			return struct {
				name    string
				ex      *Executor
				ref     HostRef
				wantErr error
				inspect []byte
			}{name: "valid key", ex: New(borrowingResolver{raw: raw}, "", 0), ref: HostRef{Addr: "host", KeyName: "key"}, inspect: raw}
		}(),
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			signer, err := tt.ex.signer(tt.ref)
			if tt.wantErr != nil && !errors.Is(err, tt.wantErr) {
				t.Fatalf("signer error = %v, want %v", err, tt.wantErr)
			}
			if tt.wantErr == nil && tt.name == "invalid key" && err == nil {
				t.Fatal("invalid key must fail")
			}
			if tt.name == "valid key" && (err != nil || signer == nil) {
				t.Fatalf("valid signer = (%v, %v)", signer, err)
			}
			for i, b := range tt.inspect {
				if b != 0 {
					t.Fatalf("key material byte %d was not zeroized", i)
				}
			}
		})
	}

	ex := New(nil, "", time.Second)
	if _, err := ex.signer(HostRef{KeyPath: filepath.Join(t.TempDir(), "missing")}); err == nil || !strings.Contains(err.Error(), "read key file") {
		t.Fatalf("missing key file error = %v", err)
	}
	if ex.timeout != time.Second || New(nil, "", 0).timeout != defaultTimeout {
		t.Fatal("executor timeout defaults were not applied")
	}
	if refLabel(HostRef{Name: "inventory", Addr: "addr"}) != "inventory" || refLabel(HostRef{Addr: "addr"}) != "addr" {
		t.Fatal("refLabel did not prefer the inventory name")
	}
}

func TestPrivateKeyFileReadIsBoundedAndRejectsUnsafeFilesystemObjects(t *testing.T) {
	root := t.TempDir()
	safe := filepath.Join(root, "safe-key")
	if err := os.WriteFile(safe, []byte("private-key"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, err := readKeyFile(safe); err != nil || string(got) != "private-key" {
		t.Fatalf("safe key read = %q, %v", got, err)
	}

	if err := os.Chmod(safe, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := readKeyFile(safe); err == nil {
		t.Fatal("group/world-readable private key was accepted")
	}

	victim := filepath.Join(root, "victim")
	if err := os.WriteFile(victim, []byte("victim"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victim, filepath.Join(root, "symlink")); err != nil {
		t.Fatal(err)
	}
	if _, err := readKeyFile(filepath.Join(root, "symlink")); err == nil {
		t.Fatal("symlinked private key was accepted")
	}
	if err := os.Link(victim, filepath.Join(root, "hardlink")); err != nil {
		t.Fatal(err)
	}
	if _, err := readKeyFile(victim); err == nil {
		t.Fatal("hardlinked private key was accepted")
	}

	fifo := filepath.Join(root, "fifo")
	if err := unix.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	if _, err := readKeyFile(fifo); err == nil {
		t.Fatal("FIFO private key was accepted")
	}
	if time.Since(started) > time.Second {
		t.Fatal("FIFO rejection blocked")
	}

	oversized := filepath.Join(root, "oversized")
	f, err := os.OpenFile(oversized, os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(maxPrivateKeyFileBytes + 1); err != nil {
		f.Close()
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := readKeyFile(oversized); err == nil {
		t.Fatal("oversized private key was accepted")
	}
}

func TestExecRejectsInvalidPolicyBeforeAuthentication(t *testing.T) {
	ex := New(nil, filepath.Join(t.TempDir(), "known_hosts"), time.Second)
	if _, err := ex.Exec(context.Background(), HostRef{HostKey: "off"}, "whoami", Opts{}); err == nil || !strings.Contains(err.Error(), "invalid hostkey policy") {
		t.Fatalf("invalid policy error = %v", err)
	}
}

func TestRunPreCanceledContextDoesNotDial(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := (&Executor{}).run(ctx, "127.0.0.1:1", &ssh.ClientConfig{
		User:            "test",
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}, "noop", time.Second, nil, nil)
	if !errors.Is(err, ErrTimeout) || !errors.Is(err, context.Canceled) {
		t.Fatalf("pre-canceled dial error = %v", err)
	}
}

func TestRunHandshakeHonorsDeadlineAndCancellation(t *testing.T) {
	tests := []struct {
		name    string
		cancel  bool
		timeout time.Duration
	}{
		{name: "deadline", timeout: 60 * time.Millisecond},
		{name: "cancellation", cancel: true, timeout: 5 * time.Second},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = ln.Close() }()
			accepted := make(chan net.Conn, 1)
			go func() {
				conn, err := ln.Accept()
				if err == nil {
					accepted <- conn
				}
			}()

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			result := make(chan error, 1)
			begin := time.Now()
			go func() {
				_, err := (&Executor{}).run(ctx, ln.Addr().String(), &ssh.ClientConfig{
					User:            "test",
					HostKeyCallback: ssh.InsecureIgnoreHostKey(), // peer never reaches host-key exchange
				}, "noop", tt.timeout, nil, nil)
				result <- err
			}()
			var peer net.Conn
			select {
			case peer = <-accepted:
				defer func() { _ = peer.Close() }()
			case <-time.After(time.Second):
				t.Fatal("executor never connected to stalled peer")
			}
			if tt.cancel {
				cancel()
			}
			select {
			case err := <-result:
				if err == nil {
					t.Fatal("stalled handshake unexpectedly succeeded")
				}
				if !errors.Is(err, ErrTimeout) {
					t.Fatalf("handshake error = %v, want ErrTimeout", err)
				}
				if tt.cancel && (!errors.Is(err, ErrTimeout) || !errors.Is(err, context.Canceled)) {
					t.Fatalf("cancellation error = %v", err)
				}
			case <-time.After(time.Second):
				t.Fatal("stalled handshake was not interrupted")
			}
			if elapsed := time.Since(begin); elapsed > time.Second {
				t.Fatalf("handshake termination took %s", elapsed)
			}
		})
	}
}

func TestRunSessionProtocolFailuresDoNotHang(t *testing.T) {
	tests := []struct {
		name       string
		behavior   string
		wantErr    string
		wantExit   int
		wantStdout string
	}{
		{name: "channel rejected", behavior: "reject-channel", wantErr: "open session"},
		{name: "exec rejected", behavior: "reject-exec", wantErr: "run"},
		{name: "missing exit status", behavior: "missing-exit", wantExit: -1, wantStdout: "partial"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			addr, cfg := startProtocolTestServer(t, tt.behavior)
			rr, err := (&Executor{}).run(context.Background(), addr, cfg, "noop", time.Second, nil, nil)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("run error = %v, want containing %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if rr.exit != tt.wantExit || rr.stdout.String() != tt.wantStdout {
				t.Fatalf("result exit/stdout = %d/%q", rr.exit, rr.stdout.String())
			}
		})
	}
}

func TestRunAuthenticatedHostKeyCommitFailureClosesBeforeSession(t *testing.T) {
	srv, err := sshtest.New(func(string) (string, string, int) {
		return "must not run", "", 0
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = srv.Close() })
	keyPEM, pub, err := sshtest.ClientKeyPEM("commit-failure")
	if err != nil {
		t.Fatal(err)
	}
	srv.Authorize(pub)
	signer, err := ssh.ParsePrivateKey(keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &ssh.ClientConfig{
		User:            "test",
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}
	commitErr := errors.New("concurrent first-contact key won")
	rr, err := (&Executor{}).run(context.Background(), srv.Addr(), cfg, "must-not-run",
		time.Second, nil, func() error { return commitErr })
	if rr != nil || !errors.Is(err, commitErr) || !strings.Contains(err.Error(), "commit authenticated host key") {
		t.Fatalf("commit failure result = (%v, %v)", rr, err)
	}
	if commands := srv.ExecedCommands(); len(commands) != 0 {
		t.Fatalf("commit failure opened a command session: %v", commands)
	}
}

type borrowingResolver struct {
	raw []byte
	err error
}

func (r borrowingResolver) SecretValue(string) ([]byte, error) { return r.raw, r.err }

func startProtocolTestServer(t *testing.T, behavior string) (string, *ssh.ClientConfig) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	_, hostPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	hostSigner, err := ssh.NewSignerFromKey(hostPrivate)
	if err != nil {
		t.Fatal(err)
	}
	serverCfg := &ssh.ServerConfig{NoClientAuth: true}
	serverCfg.AddHostKey(hostSigner)
	done := make(chan struct{})
	go func() {
		defer close(done)
		nc, err := ln.Accept()
		if err != nil {
			return
		}
		defer func() { _ = nc.Close() }()
		conn, chans, reqs, err := ssh.NewServerConn(nc, serverCfg)
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		go ssh.DiscardRequests(reqs)
		for nch := range chans {
			if behavior == "reject-channel" {
				_ = nch.Reject(ssh.Prohibited, "rejected for test")
				return
			}
			ch, requests, err := nch.Accept()
			if err != nil {
				return
			}
			for req := range requests {
				if req.Type != "exec" {
					_ = req.Reply(false, nil)
					continue
				}
				if behavior == "reject-exec" {
					_ = req.Reply(false, nil)
					_ = ch.Close()
					return
				}
				_ = req.Reply(true, nil)
				_, _ = io.WriteString(ch, "partial")
				_ = ch.Close()
				return
			}
		}
	}()
	t.Cleanup(func() {
		_ = ln.Close()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Errorf("protocol test server did not stop (%s)", behavior)
		}
	})
	return ln.Addr().String(), &ssh.ClientConfig{
		User:            "test",
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}
}
