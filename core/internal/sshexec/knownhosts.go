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
//   - accept-new (TOFU): an unknown host is recorded on first sight and its
//     acceptance is surfaced to the caller for audit; a changed key fails.
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
	// Persist the pin before connecting so a crash cannot cause a second TOFU.
	if err := f.Sync(); err != nil {
		return errors.Join(err, f.Close())
	}
	return f.Close()
}

// callback builds an ssh.HostKeyCallback enforcing the given policy for hostID.
// onAccept receives the SHA256 fingerprint of a new TOFU key.
// The store mutex serializes the check-then-write so two concurrent first
// connects to the same host cannot both record.
func (kh *KnownHosts) callback(hostID, policy string, onAccept func(fp string)) ssh.HostKeyCallback {
	return func(_ string, _ net.Addr, key ssh.PublicKey) error {
		return kh.verify(hostID, policy, key, onAccept)
	}
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

// verify implements the accept-new/strict decision for one presented key.
func (kh *KnownHosts) verify(hostID, policy string, key ssh.PublicKey, onAccept func(fp string)) (retErr error) {
	if hostID == "" || strings.ContainsAny(hostID, " \t\r\n") {
		return fmt.Errorf("sshexec: invalid known_hosts identity %q", hostID)
	}
	kh.mu.Lock()
	defer kh.mu.Unlock()
	// Serialize the check-then-write across processes too.
	unlock, err := kh.flock()
	if err != nil {
		return fmt.Errorf("sshexec: lock known_hosts (fail-closed): %w", err)
	}
	defer func() {
		if err := unlock(); err != nil {
			retErr = errors.Join(retErr, fmt.Errorf("sshexec: unlock known_hosts: %w", err))
		}
	}()

	presented := marshalKey(key)
	stored, found, err := kh.lookup(hostID)
	if err != nil {
		return fmt.Errorf("sshexec: read known_hosts: %w", err)
	}
	switch {
	case found && stored == presented:
		return nil
	case found && stored != presented:
		// A changed key is never trusted under any policy.
		return fmt.Errorf("sshexec: host key mismatch for %s (SHA256:%s); refusing possible MITM or re-provision",
			hostID, ssh.FingerprintSHA256(key))
	default: // unknown host
		if policy == hostKeyStrict {
			return fmt.Errorf("sshexec: unknown host key for %s and hostkey policy is strict", hostID)
		}
		if err := kh.add(hostID, presented); err != nil {
			return fmt.Errorf("sshexec: record known_hosts (fail-closed): %w", err)
		}
		if onAccept != nil {
			onAccept(ssh.FingerprintSHA256(key))
		}
		return nil
	}
}
