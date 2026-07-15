package sshexec_test

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/sallyport/sallyport/internal/sshexec"
	"github.com/sallyport/sallyport/internal/sshtest"
)

func TestExecOutputFloodIsBoundedCountedAndFlagged(t *testing.T) {
	const capBytes = 8 << 20
	const surplus = 64 << 10
	wantBytes := capBytes + surplus
	srv, err := sshtest.New(func(string) (string, string, int) {
		return strings.Repeat("x", wantBytes), "", 0
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = srv.Close() })
	keyPEM, pub, err := sshtest.ClientKeyPEM("flood-test")
	if err != nil {
		t.Fatal(err)
	}
	srv.Authorize(pub)
	keys := fakeKeys{"fleet-key": keyPEM}
	ex := sshexec.New(keys, filepath.Join(t.TempDir(), "known_hosts"), 10*time.Second)

	res, err := ex.Exec(context.Background(), hostRef(srv, "accept-new"), "flood", sshexec.Opts{})
	if err != nil {
		t.Fatalf("flood exec: %v", err)
	}
	if got := len(res.Stdout) + len(res.Stderr); got != capBytes {
		t.Fatalf("retained output = %d, want cap %d", got, capBytes)
	}
	if res.BytesOut != wantBytes {
		t.Fatalf("BytesOut = %d, want raw count %d", res.BytesOut, wantBytes)
	}
	if !res.Truncated {
		t.Fatal("over-budget output must be explicitly flagged as truncated")
	}
}

func TestExecAppliesSafeHostAndUserDefaults(t *testing.T) {
	srv, keys, _ := newServerWithKey(t)
	addr, port := srv.Host()
	ref := sshexec.HostRef{
		Name:    addr, // Addr intentionally empty: inventory name is the fallback.
		Port:    port,
		KeyName: "fleet-key",
		// User and HostKey intentionally empty: root + accept-new defaults.
	}
	ex := sshexec.New(keys, filepath.Join(t.TempDir(), "known_hosts"), 5*time.Second)
	res, err := ex.Exec(context.Background(), ref, "defaults", sshexec.Opts{})
	if err != nil {
		t.Fatal(err)
	}
	if res.ExitCode != 0 || !res.NewHostKey {
		t.Fatalf("defaulted result exit/new = %d/%v", res.ExitCode, res.NewHostKey)
	}
}

func TestExecUnauthorizedKeyFailsBeforeCommand(t *testing.T) {
	srv, err := sshtest.New(echoHandler)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = srv.Close() })
	keyPEM, _, err := sshtest.ClientKeyPEM("unauthorized")
	if err != nil {
		t.Fatal(err)
	}
	ex := sshexec.New(fakeKeys{"fleet-key": keyPEM}, filepath.Join(t.TempDir(), "known_hosts"), 5*time.Second)
	if _, err := ex.Exec(context.Background(), hostRef(srv, "accept-new"), "must-not-run", sshexec.Opts{}); err == nil || !strings.Contains(err.Error(), "handshake") {
		t.Fatalf("unauthorized authentication error = %v", err)
	}
	if commands := srv.ExecedCommands(); len(commands) != 0 {
		t.Fatalf("unauthorized key ran commands: %v", commands)
	}
}

func TestExecRecordingFailuresAreSurfaced(t *testing.T) {
	srv, keys, _ := newServerWithKey(t)
	ex := sshexec.New(keys, filepath.Join(t.TempDir(), "known_hosts"), 5*time.Second)

	t.Run("open failure prevents remote command", func(t *testing.T) {
		parentFile := filepath.Join(t.TempDir(), "not-a-directory")
		if err := os.WriteFile(parentFile, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		before := len(srv.ExecedCommands())
		_, err := ex.Exec(context.Background(), hostRef(srv, "accept-new"), "must-not-run", sshexec.Opts{
			RecordPath: filepath.Join(parentFile, "session.cast"),
		})
		if err == nil || !strings.Contains(err.Error(), "open recording (fail-closed)") {
			t.Fatalf("recording open error = %v", err)
		}
		if after := len(srv.ExecedCommands()); after != before {
			t.Fatalf("remote command ran despite recording open failure: before=%d after=%d", before, after)
		}
	})

	t.Run("flush failure is returned", func(t *testing.T) {
		want := errors.New("record sink failed")
		res, err := ex.Exec(context.Background(), hostRef(srv, "accept-new"), "ran-once", sshexec.Opts{
			RecordSink: errorWriter{err: want},
		})
		if res == nil {
			t.Fatal("expected best-effort result metadata on recording failure")
		}
		if !errors.Is(err, want) || !strings.Contains(err.Error(), "finalize recording (fail-closed)") {
			t.Fatalf("recording flush error = %v", err)
		}
	})
}

func TestExecCancellationAndDeadlineTerminateRunningSession(t *testing.T) {
	tests := []struct {
		name       string
		cancel     bool
		timeout    time.Duration
		maxElapsed time.Duration
	}{
		{name: "context cancellation", cancel: true, timeout: 10 * time.Second, maxElapsed: 2 * time.Second},
		{name: "command deadline", timeout: 400 * time.Millisecond, maxElapsed: 2 * time.Second},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			started := make(chan struct{})
			release := make(chan struct{})
			var startOnce, releaseOnce sync.Once
			t.Cleanup(func() { releaseOnce.Do(func() { close(release) }) })
			srv, err := sshtest.New(func(string) (string, string, int) {
				startOnce.Do(func() { close(started) })
				<-release
				return "late", "", 0
			})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = srv.Close() })
			keyPEM, pub, err := sshtest.ClientKeyPEM("timeout-test")
			if err != nil {
				t.Fatal(err)
			}
			srv.Authorize(pub)
			ex := sshexec.New(fakeKeys{"fleet-key": keyPEM}, filepath.Join(t.TempDir(), "known_hosts"), 10*time.Second)

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			result := make(chan error, 1)
			begin := time.Now()
			go func() {
				_, err := ex.Exec(ctx, hostRef(srv, "accept-new"), "hang", sshexec.Opts{Timeout: tt.timeout})
				result <- err
			}()
			select {
			case <-started:
			case <-time.After(3 * time.Second):
				t.Fatal("remote command never started")
			}
			if tt.cancel {
				cancel()
			}
			select {
			case err := <-result:
				if !errors.Is(err, sshexec.ErrTimeout) {
					t.Fatalf("termination error = %v, want ErrTimeout", err)
				}
			case <-time.After(tt.maxElapsed):
				t.Fatal("Exec did not terminate after cancellation/deadline")
			}
			if elapsed := time.Since(begin); elapsed > tt.maxElapsed {
				t.Fatalf("termination took %s, max %s", elapsed, tt.maxElapsed)
			}
			releaseOnce.Do(func() { close(release) })
		})
	}
}

type errorWriter struct{ err error }

func (w errorWriter) Write([]byte) (int, error) { return 0, w.err }

var _ io.Writer = errorWriter{}
