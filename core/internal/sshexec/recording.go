package sshexec

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

// cast writes an asciicast v2 recording (https://docs.asciinema.org/manual/asciicast/v2/):
// a JSON header line followed by [time, code, data] event lines. It is the
// session record referenced from the audit row for an ssh.exec. It does not
// rewrite command output based on credential-like patterns; callers must treat
// the recording as sensitive.
type cast struct {
	mu      sync.Mutex
	w       *bufio.Writer
	f       *os.File
	start   time.Time
	pending *castEvent
	err     error
}

type castEvent struct {
	at   float64
	code string
	data []byte
}

const maxCastEventBytes = 64 << 10

// newCast creates the recording file (parents 0700, file 0600) and writes the
// asciicast header. width/height are the assumed terminal size for playback.
func newCast(path string, width, height int) (*cast, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	// Do not use O_TRUNC here: a hardlink must be rejected by
	// openSingleLinkRegular before any existing target can be modified.
	f, err := openSingleLinkRegular(path, unix.O_CREAT|unix.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	// O_TRUNC preserves an existing file's mode. Tighten it before any session
	// data can be flushed so reusing an accidentally broad path stays private.
	if err := f.Chmod(0o600); err != nil {
		return nil, errors.Join(err, f.Close())
	}
	if err := f.Truncate(0); err != nil {
		return nil, errors.Join(err, f.Close())
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return nil, errors.Join(err, f.Close())
	}
	c, err := newCastWriter(f, width, height)
	if err != nil {
		return nil, errors.Join(err, f.Close())
	}
	c.f = f
	return c, nil
}

// newCastWriter records to an arbitrary writer. close flushes but owns no file.
func newCastWriter(w io.Writer, width, height int) (*cast, error) {
	c := &cast{w: bufio.NewWriter(w), start: time.Now()}
	header := map[string]any{
		"version":   2,
		"width":     width,
		"height":    height,
		"timestamp": c.start.Unix(),
		"env":       map[string]string{"TERM": "xterm-256color"},
	}
	if err := c.writeLine(header); err != nil {
		return nil, err
	}
	return c, nil
}

// writeLine marshals v and appends a newline.
func (c *cast) writeLine(v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	if _, err := c.w.Write(b); err != nil {
		return err
	}
	return c.w.WriteByte('\n')
}

// event appends one stream chunk. Code "o" covers stdout and stderr; code "i"
// records the command. Adjacent chunks of the same code are coalesced only up
// to maxCastEventBytes, keeping memory bounded without retaining the full
// session until close.
func (c *cast) event(code string, data []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.err != nil {
		return c.err
	}
	now := time.Since(c.start).Seconds()
	for len(data) > 0 {
		if c.pending != nil && c.pending.code != code {
			if err := c.flushPendingLocked(); err != nil {
				return err
			}
		}
		if c.pending == nil {
			c.pending = &castEvent{at: now, code: code}
		}
		take := min(maxCastEventBytes-len(c.pending.data), len(data))
		c.pending.data = append(c.pending.data, data[:take]...)
		data = data[take:]
		if len(c.pending.data) == maxCastEventBytes {
			if err := c.flushPendingLocked(); err != nil {
				return err
			}
		}
	}
	return nil
}

// flushPendingLocked writes and clears the bounded pending event. c.mu must be
// held by the caller.
func (c *cast) flushPendingLocked() error {
	if c.pending == nil {
		return c.err
	}
	event := c.pending
	c.pending = nil
	err := c.writeLine([]any{event.at, event.code, string(event.data)})
	zero(event.data)
	if c.err == nil {
		c.err = err
	}
	return err
}

// close writes the final bounded event, flushes, and closes the file when
// file-backed. All writer errors are returned to the executor.
func (c *cast) close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	err := c.flushPendingLocked()
	if c.w != nil {
		err = errors.Join(err, c.w.Flush())
	}
	if c.f != nil {
		err = errors.Join(err, c.f.Close())
	}
	return err
}

// outputCap is the shared retention budget for stdout, stderr, and recording.
// The session keeps draining after the cap and marks the result truncated.
type outputCap struct {
	mu        sync.Mutex
	remaining int64
	truncated bool
}

func newOutputCap(max int64) *outputCap { return &outputCap{remaining: max} }

// take reports how many of the next n bytes may be retained.
func (c *outputCap) take(n int) int {
	if c == nil {
		return n
	}
	if n <= 0 {
		return 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.remaining <= 0 {
		c.truncated = true
		return 0
	}
	if int64(n) > c.remaining {
		allow := int(c.remaining)
		c.remaining = 0
		c.truncated = true
		return allow
	}
	c.remaining -= int64(n)
	return n
}

func (c *outputCap) isTruncated() bool {
	if c == nil {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.truncated
}

// streamWriter tees a session stream into the recording (as an asciicast event)
// and the returned-output buffer under a shared output cap.
type streamWriter struct {
	code string
	rec  *cast
	dst  io.Writer // raw sink (bytes.Buffer)
	cap  *outputCap
	n    int
	err  error
}

func saturatingAddInt(a, b int) int {
	if b > 0 && a > math.MaxInt-b {
		return math.MaxInt
	}
	return a + b
}

func (w *streamWriter) Write(p []byte) (int, error) {
	allow := w.cap.take(len(p))
	q := p
	if allow < len(p) {
		q = p[:allow]
	}
	if w.rec != nil && len(q) > 0 {
		if err := w.rec.event(w.code, q); w.err == nil {
			w.err = err
		}
	}
	w.n = saturatingAddInt(w.n, len(p))
	if w.dst != nil && len(q) > 0 {
		n, err := w.dst.Write(q)
		if err == nil && n != len(q) {
			err = io.ErrShortWrite
		}
		if w.err == nil {
			w.err = err
		}
	}
	// Always report full consumption so the SSH session keeps draining and the
	// command completes; the surplus is simply not retained.
	return len(p), nil
}

// commandLine formats the "$ cmd" echo recorded as the first (input) event.
func commandLine(cmd string) string { return fmt.Sprintf("$ %s\r\n", cmd) }
