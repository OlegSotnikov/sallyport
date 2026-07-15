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

// Redactor masks fixed credential patterns and returns the match count.
type Redactor func([]byte) ([]byte, int)

// cast writes an asciicast v2 recording (https://docs.asciinema.org/manual/asciicast/v2/):
// a JSON header line followed by [time, code, data] event lines. It is the
// session record referenced from the audit row for an ssh.exec. Contiguous
// stream data is redacted before writing.
type cast struct {
	mu         sync.Mutex
	w          *bufio.Writer
	f          *os.File
	start      time.Time
	redactor   Redactor
	redactions int
	events     []castEvent
}

type castEvent struct {
	at   float64
	code string
	data []byte
}

const maxCastEventBytes = 64 << 10

// newCast creates the recording file (parents 0700, file 0600) and writes the
// asciicast header. width/height are the assumed terminal size for playback.
func newCast(path string, width, height int, redactor Redactor) (*cast, error) {
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
	c, err := newCastWriter(f, width, height, redactor)
	if err != nil {
		return nil, errors.Join(err, f.Close())
	}
	c.f = f
	return c, nil
}

// newCastWriter records to an arbitrary writer. close flushes but owns no file.
func newCastWriter(w io.Writer, width, height int, redactor Redactor) (*cast, error) {
	if redactor == nil {
		redactor = func(b []byte) ([]byte, int) { return b, 0 }
	}
	c := &cast{w: bufio.NewWriter(w), start: time.Now(), redactor: redactor}
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

// event buffers one stream chunk. Code "o" covers stdout and stderr; code "i"
// records the command.
func (c *cast) event(code string, data []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	// SSH transport packet boundaries are arbitrary and can split a credential
	// in the middle. Keep bounded event data until close, then redact each
	// contiguous logical stream as a whole; chunk-local regexes would otherwise
	// write both halves of a split secret to the cast in cleartext.
	now := time.Since(c.start).Seconds()
	for len(data) > 0 {
		last := len(c.events) - 1
		if last >= 0 && c.events[last].code == code && len(c.events[last].data) < maxCastEventBytes {
			available := maxCastEventBytes - len(c.events[last].data)
			take := min(available, len(data))
			c.events[last].data = append(c.events[last].data, data[:take]...)
			data = data[take:]
			continue
		}
		take := min(maxCastEventBytes, len(data))
		c.events = append(c.events, castEvent{
			at:   now,
			code: code,
			data: append([]byte(nil), data[:take]...),
		})
		data = data[take:]
	}
}

// close flushes (and closes the file, when file-backed), returning the total
// redaction count.
func (c *cast) close() (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	var err error
	for i := 0; i < len(c.events); {
		j := i + 1
		total := len(c.events[i].data)
		for j < len(c.events) && c.events[j].code == c.events[i].code {
			total += len(c.events[j].data)
			j++
		}
		raw := make([]byte, 0, total)
		for k := i; k < j; k++ {
			raw = append(raw, c.events[k].data...)
			zero(c.events[k].data)
		}
		red, n := c.redactor(raw)
		c.redactions += n
		if err == nil {
			err = c.writeRedactedRun(c.events[i:j], red, total)
		}
		zero(raw)
		i = j
	}
	c.events = nil
	if c.w != nil {
		if flushErr := c.w.Flush(); err == nil {
			err = flushErr
		}
	}
	if c.f != nil {
		if cerr := c.f.Close(); err == nil {
			err = cerr
		}
	}
	return c.redactions, err
}

// writeRedactedRun maps whole-stream redaction back onto the original event
// timestamps. Boundaries are proportional when replacements change length and
// advance past UTF-8 continuation bytes so a marker is not split across
// JSON strings. Concatenating the emitted data exactly reproduces red.
func (c *cast) writeRedactedRun(events []castEvent, red []byte, rawTotal int) error {
	start := 0
	rawSeen := 0
	for i, event := range events {
		rawSeen += len(event.data)
		end := len(red)
		if i < len(events)-1 && rawTotal > 0 {
			end = int(int64(len(red)) * int64(rawSeen) / int64(rawTotal))
			for end < len(red) && end > start && red[end]&0xc0 == 0x80 {
				end++
			}
		}
		if err := c.writeLine([]any{event.at, event.code, string(red[start:end])}); err != nil {
			return err
		}
		start = end
	}
	return nil
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
// and a raw buffer (so the executor can redact-and-return the whole output),
// under a shared output cap.
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
		w.rec.event(w.code, q)
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
