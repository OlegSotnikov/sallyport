package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/sallyport/sallyport/internal/sshexec"
)

func TestMainProcessReturnsStructuredProtocolError(t *testing.T) {
	stdout, stderr, err := runMainSubprocess(t, []byte("{"), false)
	if err != nil {
		t.Fatalf("sp-ssh exited unsuccessfully: %v; stderr=%q", err, stderr)
	}
	scanner := bufio.NewScanner(bytes.NewReader(stdout))
	if !scanner.Scan() {
		t.Fatalf("sp-ssh emitted no response: stderr=%q", stderr)
	}
	var resp sshexec.HelperResponse
	if err := json.Unmarshal(scanner.Bytes(), &resp); err != nil {
		t.Fatalf("response is not JSON: %v: %q", err, scanner.Bytes())
	}
	if !strings.Contains(resp.Error, "bad request") {
		t.Fatalf("response error = %q", resp.Error)
	}
}

func TestMainProcessExitsNonZeroWhenResponsePipeIsBroken(t *testing.T) {
	_, stderr, err := runMainSubprocess(t, []byte(`{}`), true)
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) || exitErr.ExitCode() != 1 {
		t.Fatalf("exit error = %v, want status 1", err)
	}
	if !strings.Contains(string(stderr), "sp-ssh:") {
		t.Fatalf("stderr = %q, want transport failure", stderr)
	}
}

func TestMainHelperProcess(t *testing.T) {
	if os.Getenv("SP_SSH_MAIN_HELPER") != "1" {
		return
	}
	if os.Getenv("SP_SSH_CLOSE_STDOUT") == "1" {
		_ = os.Stdout.Close()
	}
	main()
}

func runMainSubprocess(t *testing.T, stdin []byte, closeStdout bool) ([]byte, []byte, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestMainHelperProcess$")
	cmd.Env = append(os.Environ(), "SP_SSH_MAIN_HELPER=1")
	if closeStdout {
		cmd.Env = append(cmd.Env, "SP_SSH_CLOSE_STDOUT=1")
	}
	cmd.Stdin = bytes.NewReader(stdin)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if ctx.Err() != nil {
		t.Fatalf("sp-ssh subprocess hung: %v", ctx.Err())
	}
	return stdout.Bytes(), stderr.Bytes(), err
}
