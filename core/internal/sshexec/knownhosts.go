package sshexec

import (
	"bufio"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"

	"golang.org/x/crypto/ssh"
	"golang.org/x/sys/unix"
)

// KnownHosts is a sallyport-managed host-key store (docs/02 §3.1). It persists
// one line per host to a 0600 file:
//
//	<hostID> <keytype> <base64(key.Marshal())>
//
// hostID is the "addr:port" the executor dialed, so a service on a different
// port is a distinct trust anchor. The store backs two host-key policies:
//
//   - accept-new (TOFU): an unknown host is staged on first sight, then recorded
//     only after client authentication succeeds; a changed key fails.
//   - strict: the key must already be present and match, else the connect fails.
type KnownHosts struct {
	path string
	mu   sync.Mutex
}

// NewKnownHosts returns a store backed by path (created lazily on first write).
func NewKnownHosts(path string) *KnownHosts { return &KnownHosts{path: path} }

// marshalKey renders a public key as "keytype base64(wire)".
func marshalKey(key ssh.PublicKey) string {
	return key.Type() + " " + base64.StdEncoding.EncodeToString(key.Marshal())
}

// lookup returns the stored key line for hostID (caller holds no lock; this
// reads the file fresh each time so concurrent executors see each other's TOFU
// writes). found=false when the host is unknown.
func (kh *KnownHosts) lookup(hostID string) (line string, found bool, err error) {
	f, err := openSingleLinkRegular(kh.path, unix.O_RDONLY, 0)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", false, nil
		}
		return "", false, err
	}
	defer func() {
		if closeErr := f.Close(); err == nil && closeErr != nil {
			err = closeErr
		}
	}()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		raw := strings.TrimSpace(sc.Text())
		if raw == "" || strings.HasPrefix(raw, "#") {
			continue
		}
		id, rest, ok := strings.Cut(raw, " ")
		if !ok || id != hostID {
			continue
		}
		return strings.TrimSpace(rest), true, nil
	}
	return "", false, sc.Err()
}

// add appends a host-to-key line with 0600 permissions.
func (kh *KnownHosts) add(hostID, keyLine string) error {
	if err := os.MkdirAll(filepath.Dir(kh.path), 0o700); err != nil {
		return err
	}
	f, err := openSingleLinkRegular(kh.path, unix.O_CREAT|unix.O_WRONLY|unix.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	// OpenFile does not tighten an existing file's mode. Repair it before
	// writing so an accidentally broad known_hosts file is not left tamperable.
	if err := f.Chmod(0o600); err != nil {
		return errors.Join(err, f.Close())
	}
	if _, err := fmt.Fprintf(f, "%s %s\n", hostID, keyLine); err != nil {
		return errors.Join(err, f.Close())
	}
	// Durably persist the pin before the authenticated connection may open a
	// session, so a crash cannot cause a second TOFU decision.
	if err := f.Sync(); err != nil {
		return errors.Join(err, f.Close())
	}
	return f.Close()
}

// hostKeyVerifier separates verification during key exchange from persistence
// after client authentication. An unauthenticated peer may present a key, but it
// must never be allowed to mutate the trust store merely by reaching key
// exchange.
type hostKeyVerifier struct {
	known  *KnownHosts
	hostID string
	policy string

	mu          sync.Mutex
	pendingLine string
	pendingFP   string
}

func (kh *KnownHosts) verifier(hostID, policy string) *hostKeyVerifier {
	return &hostKeyVerifier{known: kh, hostID: hostID, policy: policy}
}

// callback validates the presented key against the current store. For an
// unknown accept-new host it only stages the key in memory; commit performs the
// durable check-and-write after SSH authentication succeeds.
func (v *hostKeyVerifier) callback(_ string, _ net.Addr, key ssh.PublicKey) error {
	if v.hostID == "" || strings.ContainsAny(v.hostID, " \t\r\n") {
		return fmt.Errorf("sshexec: invalid known_hosts identity %q", v.hostID)
	}

	presented := marshalKey(key)
	fingerprint := ssh.FingerprintSHA256(key)
	unknown := false
	err := v.known.withLock(func() error {
		stored, found, err := v.known.lookup(v.hostID)
		if err != nil {
			return fmt.Errorf("sshexec: read known_hosts: %w", err)
		}
		switch {
		case found && stored == presented:
			return nil
		case found:
			return hostKeyMismatch(v.hostID, fingerprint)
		case v.policy == hostKeyStrict:
			return fmt.Errorf("sshexec: unknown host key for %s and hostkey policy is strict", v.hostID)
		default:
			unknown = true
			return nil
		}
	})
	if err != nil || !unknown {
		return err
	}

	v.mu.Lock()
	defer v.mu.Unlock()
	if v.pendingLine != "" && v.pendingLine != presented {
		return fmt.Errorf("sshexec: peer presented multiple host keys for %s", v.hostID)
	}
	v.pendingLine = presented
	v.pendingFP = fingerprint
	return nil
}

// commit atomically rechecks and persists a staged TOFU key under the
// process-wide and cross-process locks. It must be called after
// ssh.NewClientConn succeeds and before any command is opened. added is true
// only when this connection performed the durable first write.
func (v *hostKeyVerifier) commit() (added bool, fingerprint string, retErr error) {
	v.mu.Lock()
	presented := v.pendingLine
	fingerprint = v.pendingFP
	v.mu.Unlock()
	if presented == "" {
		return false, "", nil
	}

	err := v.known.withLock(func() error {
		stored, found, err := v.known.lookup(v.hostID)
		if err != nil {
			return fmt.Errorf("sshexec: read known_hosts: %w", err)
		}
		switch {
		case found && stored == presented:
			// Another authenticated connection pinned the same key first.
			return nil
		case found:
			return hostKeyMismatch(v.hostID, fingerprint)
		default:
			if err := v.known.add(v.hostID, presented); err != nil {
				return fmt.Errorf("sshexec: record known_hosts (fail-closed): %w", err)
			}
			added = true
			return nil
		}
	})
	if err != nil {
		return false, fingerprint, err
	}
	return added, fingerprint, nil
}

func hostKeyMismatch(hostID, fingerprint string) error {
	return fmt.Errorf("sshexec: host key mismatch for %s (%s); refusing possible MITM or re-provision",
		hostID, fingerprint)
}

// flock serializes TOFU checks across helper processes.
func (kh *KnownHosts) flock() (unlock func() error, err error) {
	if err := os.MkdirAll(filepath.Dir(kh.path), 0o700); err != nil {
		return func() error { return nil }, err
	}
	f, err := openSingleLinkRegular(kh.path+".lock", unix.O_CREAT|unix.O_RDWR, 0o600)
	if err != nil {
		return func() error { return nil }, err
	}
	if err := f.Chmod(0o600); err != nil {
		return func() error { return nil }, errors.Join(err, f.Close())
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		return func() error { return nil }, errors.Join(err, f.Close())
	}
	return func() error {
		unlockErr := syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		return errors.Join(unlockErr, f.Close())
	}, nil
}

// withLock serializes trust-store decisions in this process and across helper
// processes. The callback must not retain references to mutable shared state.
func (kh *KnownHosts) withLock(fn func() error) (retErr error) {
	kh.mu.Lock()
	defer kh.mu.Unlock()
	// Serialize each read/commit decision across processes too.
	unlock, err := kh.flock()
	if err != nil {
		return fmt.Errorf("sshexec: lock known_hosts (fail-closed): %w", err)
	}
	defer func() {
		if err := unlock(); err != nil {
			retErr = errors.Join(retErr, fmt.Errorf("sshexec: unlock known_hosts: %w", err))
		}
	}()
	return fn()
}
