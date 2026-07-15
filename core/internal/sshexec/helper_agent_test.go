package sshexec_test

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/sallyport/sallyport/internal/sshexec"
)

// The agent-signing path end to end IN GO: the helper receives NO private key,
// only an inherited socket fd. It authenticates a real SSH session by asking the
// agent on the other end of the socket to sign — exactly what the Swift vault
// will do in production. Here the agent is x/crypto's keyring (same protocol as
// the Swift SSHAgentServer), holding the fixture key.
func TestRunHelper_AgentPathAuthenticates(t *testing.T) {
	srv, _, keyPEM := newServerWithKey(t)

	// Serve the fixture private key from a keyring over one end of a socketpair.
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		t.Fatalf("socketpair: %v", err)
	}
	serverFile := os.NewFile(uintptr(fds[0]), "agent")
	serverConn, err := net.FileConn(serverFile)
	_ = serverFile.Close()
	if err != nil {
		t.Fatalf("FileConn: %v", err)
	}
	defer func() { _ = serverConn.Close() }()

	raw, err := ssh.ParseRawPrivateKey(keyPEM)
	if err != nil {
		t.Fatalf("parse fixture key: %v", err)
	}
	if p, ok := raw.(*ed25519.PrivateKey); ok {
		raw = *p
	}
	kr := agent.NewKeyring()
	if err := kr.Add(agent.AddedKey{PrivateKey: raw}); err != nil {
		t.Fatalf("keyring add: %v", err)
	}
	go func() { _ = agent.ServeAgent(kr, serverConn) }()

	addr, port := srv.Host()
	req := map[string]any{
		"host":           addr,
		"user":           "os",
		"port":           port,
		"hostKeyPolicy":  "accept-new",
		"command":        "df -h /",
		"timeoutS":       5,
		"knownHostsPath": filepath.Join(t.TempDir(), "known_hosts"),
		"agentFD":        fds[1],
		// NOTE: no privateKeyB64 — the key never reaches the helper.
	}
	body, _ := json.Marshal(req)

	var out bytes.Buffer
	if err := sshexec.RunHelper(bytes.NewReader(body), &out); err != nil {
		t.Fatalf("RunHelper: %v", err)
	}
	var resp sshexec.HelperResponse
	if err := json.Unmarshal(out.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Error != "" {
		t.Fatalf("helper reported error: %s", resp.Error)
	}
	stdout, _ := base64.StdEncoding.DecodeString(resp.Stdout)
	if !strings.Contains(string(stdout), "Filesystem") {
		t.Fatalf("stdout missing df output: %q", stdout)
	}
	if srv.LastAuthorizedKey() == nil {
		t.Fatal("server never authenticated a key — agent signing failed")
	}
	if resp.HostKeyFP == "" {
		t.Fatal("no host-key fingerprint returned")
	}
}
