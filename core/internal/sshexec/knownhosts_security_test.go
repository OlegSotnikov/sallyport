package sshexec

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/sys/unix"
)

func TestKnownHostsLookupHandlesCommentsMalformedAndCorruptInput(t *testing.T) {
	key := newKnownHostsTestKey(t)
	keyLine := marshalKey(key)
	path := filepath.Join(t.TempDir(), "known_hosts")
	kh := NewKnownHosts(path)

	if line, found, err := kh.lookup("host:22"); err != nil || found || line != "" {
		t.Fatalf("missing lookup = (%q, %v, %v)", line, found, err)
	}
	data := strings.Join([]string{
		"",
		"  # comment",
		"malformed",
		"other:22 " + keyLine,
		"host:22    " + keyLine + "   ",
	}, "\n")
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	line, found, err := kh.lookup("host:22")
	if err != nil || !found || line != keyLine {
		t.Fatalf("lookup = (%q, %v, %v), want (%q, true, nil)", line, found, err, keyLine)
	}

	// Scanner's bounded token size must fail closed on a corrupt gigantic line;
	// silently skipping it could let a later duplicate pin override it.
	corrupt := strings.Repeat("x", 70<<10) + "\nhost:22 " + keyLine + "\n"
	if err := os.WriteFile(path, []byte(corrupt), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := kh.lookup("host:22"); err == nil {
		t.Fatal("oversized known_hosts line must return a scanner error")
	}
}

func TestKnownHostsFilesUsePrivateModes(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "private", "known_hosts")
	kh := NewKnownHosts(path)
	if err := kh.add("host:22", marshalKey(newKnownHostsTestKey(t))); err != nil {
		t.Fatal(err)
	}
	assertMode(t, filepath.Dir(path), 0o700)
	assertMode(t, path, 0o600)

	// Reopening with O_APPEND or O_TRUNC preserves an existing broad mode; add
	// must actively repair it rather than relying on the creation argument.
	if err := os.Chmod(path, 0o666); err != nil {
		t.Fatal(err)
	}
	if err := kh.add("other:22", marshalKey(newKnownHostsTestKey(t))); err != nil {
		t.Fatal(err)
	}
	assertMode(t, path, 0o600)

	lockPath := path + ".lock"
	if err := os.WriteFile(lockPath, nil, 0o666); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(lockPath, 0o666); err != nil {
		t.Fatal(err)
	}
	unlock, err := kh.flock()
	if err != nil {
		t.Fatal(err)
	}
	assertMode(t, lockPath, 0o600)
	if err := unlock(); err != nil {
		t.Fatal(err)
	}
}

func TestKnownHostsTOFUStagesUntilAuthenticatedCommit(t *testing.T) {
	key := newKnownHostsTestKey(t)
	tests := []struct {
		name      string
		policy    string
		seed      bool
		wantCheck string
		wantAdded bool
		wantLines int
	}{
		{name: "unknown accept-new stages then commits", policy: hostKeyAcceptNew, wantAdded: true, wantLines: 1},
		{name: "known accept-new needs no commit", policy: hostKeyAcceptNew, seed: true, wantLines: 1},
		{name: "known strict needs no commit", policy: hostKeyStrict, seed: true, wantLines: 1},
		{name: "unknown strict fails during exchange", policy: hostKeyStrict, wantCheck: "unknown host key"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "known_hosts")
			kh := NewKnownHosts(path)
			if tt.seed {
				if err := kh.add("host:22", marshalKey(key)); err != nil {
					t.Fatal(err)
				}
			}
			verifier := kh.verifier("host:22", tt.policy)
			err := verifier.callback("", nil, key)
			if tt.wantCheck != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantCheck) {
					t.Fatalf("callback error = %v, want %q", err, tt.wantCheck)
				}
				if _, statErr := os.Stat(path); !os.IsNotExist(statErr) {
					t.Fatalf("rejected key exchange mutated known_hosts: %v", statErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("callback: %v", err)
			}
			if !tt.seed {
				if _, err := os.Stat(path); !os.IsNotExist(err) {
					t.Fatalf("key exchange mutated known_hosts before authentication: %v", err)
				}
			}
			added, fp, err := verifier.commit()
			if err != nil {
				t.Fatalf("commit: %v", err)
			}
			if added != tt.wantAdded {
				t.Fatalf("added = %v, want %v", added, tt.wantAdded)
			}
			if tt.wantAdded && fp != ssh.FingerprintSHA256(key) {
				t.Fatalf("fingerprint = %q, want %q", fp, ssh.FingerprintSHA256(key))
			}
			if got := nonEmptyLines(t, path); got != tt.wantLines {
				t.Fatalf("known_hosts lines = %d, want %d", got, tt.wantLines)
			}
		})
	}
}

func TestKnownHostsConcurrentAuthenticatedCommitsAreSerializedAcrossStores(t *testing.T) {
	tests := []struct {
		name           string
		keys           func(*testing.T) []ssh.PublicKey
		wantAdded      int
		wantMismatches int
	}{
		{
			name: "same key is persisted once",
			keys: func(t *testing.T) []ssh.PublicKey {
				key := newKnownHostsTestKey(t)
				keys := make([]ssh.PublicKey, 24)
				for i := range keys {
					keys[i] = key
				}
				return keys
			},
			wantAdded: 1,
		},
		{
			name: "different keys cannot both win",
			keys: func(t *testing.T) []ssh.PublicKey {
				return []ssh.PublicKey{newKnownHostsTestKey(t), newKnownHostsTestKey(t)}
			},
			wantAdded: 1, wantMismatches: 1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "known_hosts")
			keys := tt.keys(t)
			verifiers := make([]*hostKeyVerifier, len(keys))
			for i, key := range keys {
				verifiers[i] = NewKnownHosts(path).verifier("host:22", hostKeyAcceptNew)
				if err := verifiers[i].callback("", nil, key); err != nil {
					t.Fatalf("stage key %d: %v", i, err)
				}
			}
			if _, err := os.Stat(path); !os.IsNotExist(err) {
				t.Fatalf("staging mutated known_hosts: %v", err)
			}

			type outcome struct {
				added bool
				err   error
			}
			start := make(chan struct{})
			outcomes := make(chan outcome, len(verifiers))
			var wg sync.WaitGroup
			for _, verifier := range verifiers {
				wg.Add(1)
				go func() {
					defer wg.Done()
					<-start
					added, _, err := verifier.commit()
					outcomes <- outcome{added: added, err: err}
				}()
			}
			close(start)
			wg.Wait()
			close(outcomes)

			var added, mismatches int
			for outcome := range outcomes {
				switch {
				case outcome.err == nil && outcome.added:
					added++
				case outcome.err == nil:
				case strings.Contains(outcome.err.Error(), "host key mismatch"):
					mismatches++
				default:
					t.Fatalf("unexpected commit error: %v", outcome.err)
				}
			}
			if added != tt.wantAdded || mismatches != tt.wantMismatches {
				t.Fatalf("added=%d mismatches=%d, want %d/%d",
					added, mismatches, tt.wantAdded, tt.wantMismatches)
			}
			if got := nonEmptyLines(t, path); got != 1 {
				t.Fatalf("known_hosts lines = %d, want 1", got)
			}
		})
	}
}

func TestKnownHostsLockFailureAndInvalidIdentityFailClosed(t *testing.T) {
	key := newKnownHostsTestKey(t)
	t.Run("lock failure", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "known_hosts")
		kh := NewKnownHosts(path)
		if err := kh.add("host:22", marshalKey(key)); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(path+".lock", 0o700); err != nil {
			t.Fatal(err)
		}
		if err := kh.verifier("host:22", hostKeyStrict).callback("", nil, key); err == nil || !strings.Contains(err.Error(), "lock known_hosts") {
			t.Fatalf("verify with unusable lock = %v", err)
		}
	})

	for _, hostID := range []string{"", "host:22\nattacker:22", "host:22 other"} {
		t.Run("invalid identity", func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "known_hosts")
			if err := NewKnownHosts(path).verifier(hostID, hostKeyAcceptNew).callback("", nil, key); err == nil {
				t.Fatalf("identity %q must be rejected", hostID)
			}
			if _, err := os.Stat(path); !os.IsNotExist(err) {
				t.Fatalf("invalid identity created known_hosts: %v", err)
			}
		})
	}
}

func TestKnownHostsFilesystemFailuresAreReturned(t *testing.T) {
	key := newKnownHostsTestKey(t)
	t.Run("mkdir failure", func(t *testing.T) {
		parent := filepath.Join(t.TempDir(), "parent-file")
		if err := os.WriteFile(parent, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := NewKnownHosts(filepath.Join(parent, "known_hosts")).add("host:22", marshalKey(key)); err == nil {
			t.Fatal("add unexpectedly succeeded beneath a regular file")
		}
	})
	t.Run("open failure", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "known_hosts")
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := NewKnownHosts(path).add("host:22", marshalKey(key)); err == nil {
			t.Fatal("add unexpectedly opened a directory as a file")
		}
	})
	t.Run("corrupt store verify", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "known_hosts")
		if err := os.WriteFile(path, []byte(strings.Repeat("x", 70<<10)), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := NewKnownHosts(path).verifier("host:22", hostKeyAcceptNew).callback("", nil, key); err == nil || !strings.Contains(err.Error(), "read known_hosts") {
			t.Fatalf("verify corrupt store error = %v", err)
		}
	})
}

func TestKnownHostsRejectsSymlinksHardlinksFIFOsAndLinkedParent(t *testing.T) {
	keyLine := marshalKey(newKnownHostsTestKey(t))
	for _, kind := range []string{"symlink", "hardlink", "fifo"} {
		t.Run("known_hosts "+kind, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "known_hosts")
			target := filepath.Join(dir, "victim")
			if err := os.WriteFile(target, []byte("do-not-touch"), 0o644); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(target, 0o644); err != nil {
				t.Fatal(err)
			}
			makeHostileFile(t, kind, path, target)
			kh := NewKnownHosts(path)
			mustReturnErrorPromptly(t, func() error { return kh.add("host:22", keyLine) })
			mustReturnErrorPromptly(t, func() error {
				_, _, err := kh.lookup("host:22")
				return err
			})
			assertFileUnchanged(t, target, "do-not-touch", 0o644)
		})

		t.Run("lock "+kind, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "known_hosts")
			key := newKnownHostsTestKey(t)
			kh := NewKnownHosts(path)
			if err := kh.add("host:22", marshalKey(key)); err != nil {
				t.Fatal(err)
			}
			target := filepath.Join(dir, "lock-victim")
			if err := os.WriteFile(target, []byte("lock-target"), 0o644); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(target, 0o644); err != nil {
				t.Fatal(err)
			}
			makeHostileFile(t, kind, path+".lock", target)
			mustReturnErrorPromptly(t, func() error {
				return kh.verifier("host:22", hostKeyStrict).callback("", nil, key)
			})
			assertFileUnchanged(t, target, "lock-target", 0o644)
		})
	}

	t.Run("symlinked parent", func(t *testing.T) {
		dir := t.TempDir()
		realParent := filepath.Join(dir, "real")
		if err := os.Mkdir(realParent, 0o700); err != nil {
			t.Fatal(err)
		}
		linkedParent := filepath.Join(dir, "linked")
		if err := os.Symlink(realParent, linkedParent); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(linkedParent, "known_hosts")
		mustReturnErrorPromptly(t, func() error {
			return NewKnownHosts(path).add("host:22", keyLine)
		})
		if _, err := os.Stat(filepath.Join(realParent, "known_hosts")); !os.IsNotExist(err) {
			t.Fatalf("symlinked parent received a file: %v", err)
		}
	})
}

func newKnownHostsTestKey(t *testing.T) ssh.PublicKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func assertMode(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != want {
		t.Fatalf("%s mode = %#o, want %#o", path, got, want)
	}
}

func nonEmptyLines(t *testing.T, path string) int {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, line := range strings.Split(string(b), "\n") {
		if strings.TrimSpace(line) != "" {
			count++
		}
	}
	return count
}

func makeHostileFile(t *testing.T, kind, path, target string) {
	t.Helper()
	var err error
	switch kind {
	case "symlink":
		err = os.Symlink(target, path)
	case "hardlink":
		err = os.Link(target, path)
	case "fifo":
		err = unix.Mkfifo(path, 0o600)
	default:
		t.Fatalf("unknown hostile file kind %q", kind)
	}
	if err != nil {
		t.Fatal(err)
	}
}

func mustReturnErrorPromptly(t *testing.T, fn func() error) {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- fn() }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("hostile filesystem object unexpectedly succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("hostile filesystem object blocked the helper")
	}
}

func assertFileUnchanged(t *testing.T, path, want string, mode os.FileMode) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != want {
		t.Fatalf("%s changed to %q, want %q", path, b, want)
	}
	assertMode(t, path, mode)
}
