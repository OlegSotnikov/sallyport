// Package sshtest is an in-process SSH server for tests. It never touches a real
// host: it listens on 127.0.0.1:0, authenticates a set of authorized client
// public keys, and answers "exec" requests from a pluggable command handler. It
// also supports rotating its host key so tests can exercise the strict host-key
// mismatch path. It is deliberately not under _test.go so both the sshexec and
// engine test packages can import it.
package sshtest

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"

	"golang.org/x/crypto/ssh"
)

// CommandHandler produces the canned output for a command string.
type CommandHandler func(cmd string) (stdout, stderr string, exit int)

// Server is a running in-process SSH server.
type Server struct {
	ln      net.Listener
	handler CommandHandler

	mu          sync.Mutex
	hostSigner  ssh.Signer
	authorized  map[string]bool // authorized client key fingerprints
	lastAuthKey ssh.PublicKey   // the client key that last authenticated
	execedCmds  []string
}

// New starts a server with the given command handler. Callers Authorize client
// keys before connecting and Close when done.
func New(handler CommandHandler) (*Server, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	signer, err := newHostSigner()
	if err != nil {
		return nil, errors.Join(err, ln.Close())
	}
	s := &Server{ln: ln, handler: handler, hostSigner: signer, authorized: map[string]bool{}}
	go s.serve()
	return s, nil
}

func newHostSigner() (ssh.Signer, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return ssh.NewSignerFromKey(priv)
}

// Addr returns the host:port the server is listening on.
func (s *Server) Addr() string { return s.ln.Addr().String() }

// Host returns address and port separately for inventory wiring.
func (s *Server) Host() (addr string, port int) {
	h, p, _ := net.SplitHostPort(s.ln.Addr().String())
	portN, err := strconv.Atoi(p)
	if err != nil {
		return h, 0
	}
	return h, portN
}

// Authorize allows a client public key to authenticate.
func (s *Server) Authorize(pub ssh.PublicKey) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.authorized[ssh.FingerprintSHA256(pub)] = true
}

// HostPublicKey returns the current host key.
func (s *Server) HostPublicKey() ssh.PublicKey {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.hostSigner.PublicKey()
}

// LastAuthorizedKey returns the client key that most recently authenticated.
// Tests use it to confirm server-side key use.
func (s *Server) LastAuthorizedKey() ssh.PublicKey {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastAuthKey
}

// ExecedCommands returns the commands the server has run.
func (s *Server) ExecedCommands() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.execedCmds...)
}

// RotateHostKey swaps in a fresh host key so the next connect presents a
// different key for the same address (exercises the strict-mismatch path).
func (s *Server) RotateHostKey() error {
	signer, err := newHostSigner()
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.hostSigner = signer
	s.mu.Unlock()
	return nil
}

// Close stops the listener.
func (s *Server) Close() error { return s.ln.Close() }

func (s *Server) serve() {
	for {
		nc, err := s.ln.Accept()
		if err != nil {
			return
		}
		go s.handleConn(nc)
	}
}

func (s *Server) handleConn(nc net.Conn) {
	cfg := &ssh.ServerConfig{
		PublicKeyCallback: func(_ ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			s.mu.Lock()
			defer s.mu.Unlock()
			if s.authorized[ssh.FingerprintSHA256(key)] {
				s.lastAuthKey = key
				return &ssh.Permissions{}, nil
			}
			return nil, fmt.Errorf("unauthorized key")
		},
	}
	// Build the config with the host key current at accept time so RotateHostKey
	// affects subsequent connections.
	s.mu.Lock()
	cfg.AddHostKey(s.hostSigner)
	s.mu.Unlock()

	sconn, chans, reqs, err := ssh.NewServerConn(nc, cfg)
	if err != nil {
		_ = nc.Close()
		return
	}
	defer func() { _ = sconn.Close() }()
	go ssh.DiscardRequests(reqs)
	for nch := range chans {
		if nch.ChannelType() != "session" {
			_ = nch.Reject(ssh.UnknownChannelType, "only session")
			continue
		}
		ch, chReqs, err := nch.Accept()
		if err != nil {
			continue
		}
		go s.handleSession(ch, chReqs)
	}
}

func (s *Server) handleSession(ch ssh.Channel, reqs <-chan *ssh.Request) {
	defer func() { _ = ch.Close() }()
	for req := range reqs {
		switch req.Type {
		case "exec":
			var payload struct{ Command string }
			_ = ssh.Unmarshal(req.Payload, &payload)
			_ = req.Reply(true, nil)
			s.mu.Lock()
			s.execedCmds = append(s.execedCmds, payload.Command)
			handler := s.handler
			s.mu.Unlock()
			stdout, stderr, exit := handler(payload.Command)
			if _, err := io.WriteString(ch, stdout); err != nil {
				return
			}
			if _, err := io.WriteString(ch.Stderr(), stderr); err != nil {
				return
			}
			_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{uint32(exit)}))
			return
		case "shell":
			_ = req.Reply(false, nil)
		default:
			_ = req.Reply(false, nil)
		}
	}
}

// ClientKeyPEM generates an ed25519 client key and returns its OpenSSH PEM bytes
// plus the ssh.PublicKey (to authorize on the server). This mirrors what the
// vault would store for a fleet key.
func ClientKeyPEM(comment string) (pemBytes []byte, pub ssh.PublicKey, err error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	block, err := ssh.MarshalPrivateKey(priv, comment)
	if err != nil {
		return nil, nil, err
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		return nil, nil, err
	}
	return encodePEM(block), signer.PublicKey(), nil
}
