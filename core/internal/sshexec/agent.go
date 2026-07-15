package sshexec

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// agentSigner wraps the inherited app socket as an ssh.Signer. The app answers
// signing requests, so the private key does not enter this process.
func agentSigner(fd int) (ssh.Signer, *net.UnixConn, error) {
	return agentSignerWithTimeout(fd, defaultTimeout)
}

// agentSignerWithTimeout keeps the deadline through SSH authentication.
func agentSignerWithTimeout(fd int, timeout time.Duration) (ssh.Signer, *net.UnixConn, error) {
	if fd <= 0 {
		return nil, nil, fmt.Errorf("sp-ssh: no agent fd")
	}
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	f := os.NewFile(uintptr(fd), "sp-agent")
	if f == nil {
		return nil, nil, fmt.Errorf("sp-ssh: bad agent fd %d", fd)
	}
	// FileConn dups the descriptor; close our os.File wrapper, keep the conn.
	c, err := net.FileConn(f)
	closeErr := f.Close()
	if err != nil {
		primary := fmt.Errorf("sp-ssh: agent fd is not a socket: %w", err)
		if closeErr != nil {
			primary = errors.Join(primary, fmt.Errorf("sp-ssh: close inherited agent fd: %w", closeErr))
		}
		return nil, nil, primary
	}
	if closeErr != nil {
		return nil, nil, closeAgentOnError(c, fmt.Errorf("sp-ssh: close inherited agent fd: %w", closeErr))
	}
	conn, ok := c.(*net.UnixConn)
	if !ok {
		return nil, nil, closeAgentOnError(c, fmt.Errorf("sp-ssh: agent fd is not a unix socket"))
	}
	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return nil, nil, closeAgentOnError(conn, fmt.Errorf("sp-ssh: bound agent socket: %w", err))
	}
	client := agent.NewClient(conn)
	signers, err := client.Signers()
	if err != nil {
		return nil, nil, closeAgentOnError(conn, fmt.Errorf("sp-ssh: agent offered no signer: %w", err))
	}
	if len(signers) != 1 {
		return nil, nil, closeAgentOnError(conn, fmt.Errorf("sp-ssh: agent must hold exactly one key, got %d", len(signers)))
	}
	// Each exec exposes only its resolved key.
	return signers[0], conn, nil
}

func closeAgentOnError(c io.Closer, primary error) error {
	if err := c.Close(); err != nil {
		return errors.Join(primary, fmt.Errorf("sp-ssh: close agent socket: %w", err))
	}
	return primary
}
