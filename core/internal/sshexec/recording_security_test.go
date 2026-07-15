package sshexec

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"math"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestCastRedactsSecretsSplitAcrossTransportChunks(t *testing.T) {
	secret := "ghp_" + strings.Repeat("A", 32)
	redactor := func(b []byte) ([]byte, int) {
		if !bytes.Contains(b, []byte(secret)) {
			return append([]byte(nil), b...), 0
		}
		return bytes.ReplaceAll(b, []byte(secret), []byte("REDACTED")), bytes.Count(b, []byte(secret))
	}
	var dst bytes.Buffer
	c, err := newCastWriter(&dst, 80, 24, redactor)
	if err != nil {
		t.Fatal(err)
	}
	c.event("o", []byte(secret[:11]))
	c.event("o", []byte(secret[11:]))
	redactions, err := c.close()
	if err != nil {
		t.Fatal(err)
	}
	if redactions != 1 {
		t.Fatalf("redactions = %d, want 1", redactions)
	}
	if strings.Contains(dst.String(), secret) || castEventData(t, dst.Bytes()) != "REDACTED" {
		t.Fatalf("split secret was not redacted: %s", dst.String())
	}
	validateCastLines(t, dst.Bytes())
}

func TestCastConcurrentEventsAreSerializedAndComplete(t *testing.T) {
	var dst bytes.Buffer
	c, err := newCastWriter(&dst, 80, 24, nil)
	if err != nil {
		t.Fatal(err)
	}
	const writers = 32
	var wg sync.WaitGroup
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c.event("o", []byte("x"))
		}()
	}
	wg.Wait()
	if _, err := c.close(); err != nil {
		t.Fatal(err)
	}
	validateCastLines(t, dst.Bytes())
	if got := strings.Count(dst.String(), "x"); got != writers+1 { // +1 from TERM=xterm-256color.
		t.Fatalf("recorded x count = %d, want %d", got, writers+1)
	}
	if got := len(bytes.Split(bytes.TrimSpace(dst.Bytes()), []byte("\n"))); got != 2 {
		t.Fatalf("cast lines = %d, want one header + one coalesced event", got)
	}
}

func TestCastCloseSurfacesWriterFailure(t *testing.T) {
	want := errors.New("disk full")
	c, err := newCastWriter(failingWriter{err: want}, 80, 24, nil)
	if err != nil {
		t.Fatal(err)
	}
	c.event("o", bytes.Repeat([]byte("x"), 8<<10))
	if _, err := c.close(); !errors.Is(err, want) {
		t.Fatalf("close error = %v, want %v", err, want)
	}
}

func TestCastFileModeIsPrivateEvenWhenReused(t *testing.T) {
	path := filepath.Join(t.TempDir(), "session.cast")
	if err := os.WriteFile(path, []byte("old"), 0o666); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o666); err != nil {
		t.Fatal(err)
	}
	c, err := newCast(path, 80, 24, nil)
	if err != nil {
		t.Fatal(err)
	}
	c.event("o", []byte("new"))
	if _, err := c.close(); err != nil {
		t.Fatal(err)
	}
	assertMode(t, path, 0o600)
}

func TestNewCastRejectsInvalidFilesystemTargets(t *testing.T) {
	parentFile := filepath.Join(t.TempDir(), "parent-file")
	if err := os.WriteFile(parentFile, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	directoryTarget := filepath.Join(t.TempDir(), "directory.cast")
	if err := os.Mkdir(directoryTarget, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{filepath.Join(parentFile, "session.cast"), directoryTarget} {
		if _, err := newCast(path, 80, 24, nil); err == nil {
			t.Fatalf("newCast(%q) unexpectedly succeeded", path)
		}
	}
}

func TestNewCastRejectsSymlinksHardlinksFIFOsAndLinkedParent(t *testing.T) {
	for _, kind := range []string{"symlink", "hardlink", "fifo"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "session.cast")
			target := filepath.Join(dir, "victim")
			if err := os.WriteFile(target, []byte("do-not-truncate"), 0o644); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(target, 0o644); err != nil {
				t.Fatal(err)
			}
			makeHostileFile(t, kind, path, target)
			mustReturnErrorPromptly(t, func() error {
				c, err := newCast(path, 80, 24, nil)
				if err != nil {
					return err
				}
				_, closeErr := c.close()
				return closeErr
			})
			assertFileUnchanged(t, target, "do-not-truncate", 0o644)
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
		path := filepath.Join(linkedParent, "session.cast")
		mustReturnErrorPromptly(t, func() error {
			_, err := newCast(path, 80, 24, nil)
			return err
		})
		if _, err := os.Stat(filepath.Join(realParent, "session.cast")); !os.IsNotExist(err) {
			t.Fatalf("symlinked parent received a recording: %v", err)
		}
	})
}

func TestOutputCapBoundariesAndSharedConcurrency(t *testing.T) {
	var nilCap *outputCap
	if nilCap.isTruncated() {
		t.Fatal("nil cap cannot be truncated")
	}
	tests := []struct {
		name      string
		max       int64
		chunks    []int
		want      []int
		truncated bool
	}{
		{name: "exact", max: 5, chunks: []int{2, 3}, want: []int{2, 3}},
		{name: "partial", max: 5, chunks: []int{3, 4}, want: []int{3, 2}, truncated: true},
		{name: "exhausted", max: 0, chunks: []int{1}, want: []int{0}, truncated: true},
		{name: "negative cap", max: -1, chunks: []int{1}, want: []int{0}, truncated: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cap := newOutputCap(tt.max)
			for i, chunk := range tt.chunks {
				if got := cap.take(chunk); got != tt.want[i] {
					t.Fatalf("take(%d) = %d, want %d", chunk, got, tt.want[i])
				}
			}
			if got := cap.isTruncated(); got != tt.truncated {
				t.Fatalf("truncated = %v, want %v", got, tt.truncated)
			}
		})
	}

	const budget = 1024
	cap := newOutputCap(budget)
	var retained atomic.Int64
	var wg sync.WaitGroup
	for i := 0; i < budget*2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			retained.Add(int64(cap.take(1)))
		}()
	}
	wg.Wait()
	if got := retained.Load(); got != budget {
		t.Fatalf("concurrent retained bytes = %d, want %d", got, budget)
	}
	if !cap.isTruncated() {
		t.Fatal("over-budget concurrent writes must mark truncation")
	}
}

func TestStreamWriterBoundsRetentionButCountsDrainedBytes(t *testing.T) {
	var dst bytes.Buffer
	w := &streamWriter{dst: &dst, cap: newOutputCap(3), n: math.MaxInt - 1}
	if n, err := w.Write([]byte("hello")); err != nil || n != 5 {
		t.Fatalf("Write = (%d, %v), want (5, nil)", n, err)
	}
	if got := dst.String(); got != "hel" {
		t.Fatalf("retained = %q, want %q", got, "hel")
	}
	if w.n != math.MaxInt {
		t.Fatalf("raw byte counter = %d, want saturation at %d", w.n, math.MaxInt)
	}

	var unlimited bytes.Buffer
	w = &streamWriter{dst: &unlimited}
	if _, err := io.WriteString(w, "all"); err != nil {
		t.Fatal(err)
	}
	if unlimited.String() != "all" {
		t.Fatalf("nil cap retained %q", unlimited.String())
	}
	if got := saturatingAddInt(math.MaxInt-2, 3); got != math.MaxInt {
		t.Fatalf("saturatingAddInt = %d", got)
	}
	w = &streamWriter{dst: shortWriter{}}
	if n, err := w.Write([]byte("drain")); err != nil || n != len("drain") {
		t.Fatalf("short sink Write = (%d, %v)", n, err)
	}
	if !errors.Is(w.err, io.ErrShortWrite) {
		t.Fatalf("deferred sink error = %v, want ErrShortWrite", w.err)
	}
}

func TestCastCoalescesHostileTinyChunksToBoundEventMetadata(t *testing.T) {
	c := &cast{start: time.Now()}
	const bytesWritten = 2*maxCastEventBytes + 17
	for i := 0; i < bytesWritten; i++ {
		c.event("o", []byte{'x'})
	}
	if len(c.events) != 3 {
		t.Fatalf("event count = %d, want 3 bounded chunks", len(c.events))
	}
	total := 0
	for _, event := range c.events {
		if len(event.data) > maxCastEventBytes {
			t.Fatalf("event retained %d bytes, cap %d", len(event.data), maxCastEventBytes)
		}
		total += len(event.data)
	}
	if total != bytesWritten {
		t.Fatalf("retained %d bytes, want %d", total, bytesWritten)
	}
}

func TestCastWriteLineRejectsUnmarshalableValues(t *testing.T) {
	c := &cast{w: bytesWriter()}
	if err := c.writeLine(make(chan int)); err == nil {
		t.Fatal("JSON-unsupported event must fail")
	}
}

func FuzzOutputCapNeverExceedsBudget(f *testing.F) {
	f.Add(uint16(0), uint16(0), uint16(0))
	f.Add(uint16(7), uint16(3), uint16(9))
	f.Fuzz(func(t *testing.T, budget, first, second uint16) {
		cap := newOutputCap(int64(budget))
		a := cap.take(int(first))
		b := cap.take(int(second))
		if a < 0 || b < 0 || a > int(first) || b > int(second) {
			t.Fatalf("invalid allowances: %d, %d", a, b)
		}
		if a+b > int(budget) {
			t.Fatalf("retained %d exceeds budget %d", a+b, budget)
		}
		wantTruncated := uint32(first)+uint32(second) > uint32(budget)
		if cap.isTruncated() != wantTruncated {
			t.Fatalf("truncated=%v, want %v", cap.isTruncated(), wantTruncated)
		}
	})
}

type failingWriter struct{ err error }

func (w failingWriter) Write([]byte) (int, error) { return 0, w.err }

func bytesWriter() *bufio.Writer { return bufio.NewWriter(io.Discard) }

func validateCastLines(t *testing.T, data []byte) {
	t.Helper()
	lines := bytes.Split(bytes.TrimSpace(data), []byte("\n"))
	if len(lines) < 2 {
		t.Fatalf("cast has %d lines, want header + event: %q", len(lines), data)
	}
	for i, line := range lines {
		var value any
		if err := json.Unmarshal(line, &value); err != nil {
			t.Fatalf("line %d is invalid JSON: %v: %q", i, err, line)
		}
	}
}

func castEventData(t *testing.T, data []byte) string {
	t.Helper()
	lines := bytes.Split(bytes.TrimSpace(data), []byte("\n"))
	var joined strings.Builder
	for _, line := range lines[1:] {
		var event []any
		if err := json.Unmarshal(line, &event); err != nil {
			t.Fatal(err)
		}
		if len(event) != 3 {
			t.Fatalf("invalid cast event: %q", line)
		}
		chunk, ok := event[2].(string)
		if !ok {
			t.Fatalf("cast event data is not a string: %q", line)
		}
		joined.WriteString(chunk)
	}
	return joined.String()
}
