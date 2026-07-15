package sshexec

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/binary"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// agentSigner must turn an inherited socket fd into a working ssh.Signer that
// delegates signing over the ssh-agent protocol — the private key stays on the
// other end (in production, the Swift vault). Here the other end is x/crypto's
// own keyring agent, which speaks the identical wire protocol.
func TestAgentSignerDelegatesOverSocket(t *testing.T) {
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		t.Fatalf("socketpair: %v", err)
	}

	// Server end: a keyring holding one ed25519 key.
	serverFile := os.NewFile(uintptr(fds[0]), "agent-server")
	serverConn, err := net.FileConn(serverFile)
	_ = serverFile.Close()
	if err != nil {
		t.Fatalf("server FileConn: %v", err)
	}
	defer func() { _ = serverConn.Close() }()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	kr := agent.NewKeyring()
	if err := kr.Add(agent.AddedKey{PrivateKey: priv}); err != nil {
		t.Fatalf("keyring add: %v", err)
	}
	go func() { _ = agent.ServeAgent(kr, serverConn) }()

	// Client end: our helper's agentSigner.
	signer, conn, err := agentSigner(fds[1])
	if err != nil {
		t.Fatalf("agentSigner: %v", err)
	}
	defer func() { _ = conn.Close() }()

	// The signer's public key is the agent's key…
	if got := signer.PublicKey().Marshal(); len(got) == 0 {
		t.Fatal("empty public key from agent signer")
	}
	// …and a signature it produces (over the socket) verifies with that key.
	data := []byte("challenge over the agent socket")
	sig, err := signer.Sign(rand.Reader, data)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if !ed25519.Verify(pub, data, sig.Blob) {
		t.Fatal("agent-delegated signature did not verify")
	}
	if err := signer.PublicKey().Verify(data, sig); err != nil {
		t.Fatalf("ssh public key verify: %v", err)
	}
}

func TestAgentSignerForwardsRSASHA2Algorithm(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	kr := agent.NewKeyring()
	if err := kr.Add(agent.AddedKey{PrivateKey: privateKey}); err != nil {
		t.Fatal(err)
	}
	extended, ok := kr.(agent.ExtendedAgent)
	if !ok {
		t.Fatal("test keyring does not implement ExtendedAgent")
	}
	recorder := &flagRecordingAgent{ExtendedAgent: extended}
	fd, server := rawAgentSocket(t)
	done := make(chan struct{})
	go func() {
		_ = agent.ServeAgent(recorder, server)
		close(done)
	}()

	signer, conn, err := agentSigner(fd)
	if err != nil {
		t.Fatal(err)
	}
	algorithmSigner, ok := signer.(ssh.AlgorithmSigner)
	if !ok {
		t.Fatal("agent signer does not implement ssh.AlgorithmSigner")
	}
	data := []byte("rsa-sha2 challenge")
	sig, err := algorithmSigner.SignWithAlgorithm(rand.Reader, data, ssh.KeyAlgoRSASHA512)
	if err != nil {
		t.Fatal(err)
	}
	if sig.Format != ssh.KeyAlgoRSASHA512 {
		t.Fatalf("signature format = %q, want %q", sig.Format, ssh.KeyAlgoRSASHA512)
	}
	if err := signer.PublicKey().Verify(data, sig); err != nil {
		t.Fatalf("signature verification: %v", err)
	}
	if got := recorder.lastFlags(); got != agent.SignatureFlagRsaSha512 {
		t.Fatalf("agent flags = %#x, want rsa-sha2-512", got)
	}
	_ = conn.Close()
	_ = server.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("agent server did not stop")
	}
}

// A zero / invalid fd fails closed rather than panicking.
func TestAgentSignerRejectsBadFD(t *testing.T) {
	tests := []struct {
		name string
		fd   int
	}{
		{name: "negative", fd: -1},
		{name: "zero", fd: 0},
		{name: "closed", fd: 1 << 30},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, _, err := agentSigner(tt.fd); err == nil {
				t.Fatalf("expected an error for fd %d", tt.fd)
			}
		})
	}
}

func TestAgentSignerRejectsNonSocketFD(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "not-a-socket")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	fd, err := syscall.Dup(int(f.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	// agentSigner takes ownership of the descriptor, including on failure.
	if _, _, err := agentSigner(fd); err == nil || !strings.Contains(err.Error(), "not a socket") {
		t.Fatalf("agentSigner regular file error = %v", err)
	}
}

func TestAgentSignerRejectsTCPRatherThanUnixSocket(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	peerCh := make(chan net.Conn, 1)
	go func() {
		peer, err := listener.Accept()
		if err == nil {
			peerCh <- peer
		}
	}()
	client, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = client.Close() }()
	peer := <-peerCh
	defer func() { _ = peer.Close() }()
	raw, err := client.(syscall.Conn).SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	dupFD := -1
	if err := raw.Control(func(fd uintptr) {
		dupFD, err = syscall.Dup(int(fd))
	}); err != nil {
		t.Fatal(err)
	}
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := agentSigner(dupFD); err == nil || !strings.Contains(err.Error(), "not a unix socket") {
		t.Fatalf("TCP descriptor error = %v", err)
	}
}

func TestAgentSignerRequiresExactlyOneKey(t *testing.T) {
	tests := []struct {
		name string
		keys int
	}{
		{name: "empty", keys: 0},
		{name: "ambiguous", keys: 2},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fd, stop := serveTestAgent(t, tt.keys)
			defer stop()
			if _, _, err := agentSigner(fd); err == nil || !strings.Contains(err.Error(), "exactly one key") {
				t.Fatalf("agentSigner with %d keys error = %v", tt.keys, err)
			}
		})
	}
}

func TestAgentSignerBoundsMalformedFrames(t *testing.T) {
	tests := []struct {
		name  string
		reply func(net.Conn)
	}{
		{
			name: "oversized",
			reply: func(c net.Conn) {
				var frame [4]byte
				binary.BigEndian.PutUint32(frame[:], (16<<20)+1)
				_, _ = c.Write(frame[:])
			},
		},
		{
			name: "truncated",
			reply: func(c net.Conn) {
				var frame [4]byte
				binary.BigEndian.PutUint32(frame[:], 8)
				_, _ = c.Write(append(frame[:], byte(12)))
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fd, server := rawAgentSocket(t)
			go func() {
				defer func() { _ = server.Close() }()
				var size [4]byte
				if _, err := io.ReadFull(server, size[:]); err != nil {
					return
				}
				req := make([]byte, binary.BigEndian.Uint32(size[:]))
				if _, err := io.ReadFull(server, req); err != nil {
					return
				}
				tt.reply(server)
			}()
			if _, _, err := agentSignerWithTimeout(fd, time.Second); err == nil {
				t.Fatal("malformed agent response must fail")
			}
		})
	}
}

func TestAgentSignerTimesOutStalledParent(t *testing.T) {
	fd, server := rawAgentSocket(t)
	defer func() { _ = server.Close() }()
	start := time.Now()
	if _, _, err := agentSignerWithTimeout(fd, 40*time.Millisecond); err == nil {
		t.Fatal("stalled agent must time out")
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("agent timeout took %s", elapsed)
	}
}

func TestAgentSignerAppliesDefaultForNonPositiveTimeout(t *testing.T) {
	fd, stop := serveTestAgent(t, 1)
	defer stop()
	signer, conn, err := agentSignerWithTimeout(fd, 0)
	if err != nil || signer == nil {
		t.Fatalf("agentSignerWithTimeout = (%v, %v)", signer, err)
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
}

func serveTestAgent(t *testing.T, keyCount int) (int, func()) {
	t.Helper()
	fd, server := rawAgentSocket(t)
	kr := agent.NewKeyring()
	for i := 0; i < keyCount; i++ {
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		if err := kr.Add(agent.AddedKey{PrivateKey: priv}); err != nil {
			t.Fatal(err)
		}
	}
	done := make(chan struct{})
	go func() {
		_ = agent.ServeAgent(kr, server)
		close(done)
	}()
	return fd, func() {
		_ = server.Close()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("agent server did not stop")
		}
	}
}

func rawAgentSocket(t *testing.T) (int, net.Conn) {
	t.Helper()
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	serverFile := os.NewFile(uintptr(fds[0]), "test-agent-server")
	server, err := net.FileConn(serverFile)
	_ = serverFile.Close()
	if err != nil {
		_ = syscall.Close(fds[1])
		t.Fatal(err)
	}
	return fds[1], server
}

type flagRecordingAgent struct {
	agent.ExtendedAgent
	mu    sync.Mutex
	flags agent.SignatureFlags
}

func (a *flagRecordingAgent) SignWithFlags(key ssh.PublicKey, data []byte, flags agent.SignatureFlags) (*ssh.Signature, error) {
	a.mu.Lock()
	a.flags = flags
	a.mu.Unlock()
	return a.ExtendedAgent.SignWithFlags(key, data, flags)
}

func (a *flagRecordingAgent) lastFlags() agent.SignatureFlags {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.flags
}
