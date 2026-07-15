package sshexec

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
)

func TestDecodeHelperRequestRejectsAmbiguousAndUnboundedFrames(t *testing.T) {
	tests := []struct {
		name    string
		body    string
		wantErr bool
	}{
		{name: "empty object", body: `{}`},
		{name: "explicit exec", body: `{"op":"exec"}`},
		{name: "leading whitespace", body: " \n\t{\"op\":\"exec\"}"},
		{name: "empty input", wantErr: true},
		{name: "truncated", body: `{`, wantErr: true},
		{name: "null", body: `null`, wantErr: true},
		{name: "array", body: `[]`, wantErr: true},
		{name: "unknown field", body: `{"opr":"exec"}`, wantErr: true},
		{name: "second value", body: `{} {}`, wantErr: true},
		{name: "trailing garbage", body: `{} garbage`, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var req HelperRequest
			err := decodeHelperRequest(strings.NewReader(tt.body), &req)
			if (err != nil) != tt.wantErr {
				t.Fatalf("decode error = %v, wantErr=%v", err, tt.wantErr)
			}
		})
	}

	var req HelperRequest
	oversized := bytes.Repeat([]byte(" "), maxHelperRequestBytes+1)
	if err := decodeHelperRequest(bytes.NewReader(oversized), &req); err == nil || !strings.Contains(err.Error(), "limit") {
		t.Fatalf("oversized request error = %v", err)
	}
	if err := decodeHelperRequest(errorReader{err: io.ErrUnexpectedEOF}, &req); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("reader error = %v", err)
	}
}

func TestRunHelperRejectsUnsupportedOperationAndOversize(t *testing.T) {
	tests := []struct {
		name string
		body []byte
		want string
	}{
		{name: "unsupported operation", body: []byte(`{"op":"delete_everything"}`), want: "unsupported operation"},
		{name: "unknown field", body: []byte(`{"privateKeyB64":"","typo":true}`), want: "unknown field"},
		{name: "normalize missing key", body: []byte(`{"op":"normalize_key"}`), want: "missing/invalid private key"},
		{name: "normalize invalid base64", body: []byte(`{"op":"normalize_key","privateKeyB64":"%%%"}`), want: "missing/invalid private key"},
		{name: "oversize", body: bytes.Repeat([]byte("x"), maxHelperRequestBytes+1), want: "limit"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var out bytes.Buffer
			if err := RunHelper(bytes.NewReader(tt.body), &out); err != nil {
				t.Fatalf("RunHelper transport error: %v", err)
			}
			var resp HelperResponse
			if err := json.Unmarshal(out.Bytes(), &resp); err != nil {
				t.Fatalf("response is not JSON: %v", err)
			}
			if !strings.Contains(resp.Error, tt.want) {
				t.Fatalf("response error = %q, want containing %q", resp.Error, tt.want)
			}
		})
	}
}

func TestWriteRespDetectsBrokenWriters(t *testing.T) {
	want := errors.New("pipe closed")
	tests := []struct {
		name string
		w    io.Writer
		want error
	}{
		{name: "writer error", w: failingWriter{err: want}, want: want},
		{name: "short write", w: shortWriter{}, want: io.ErrShortWrite},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := writeResp(tt.w, HelperResponse{Error: "safe"}); !errors.Is(err, tt.want) {
				t.Fatalf("writeResp error = %v, want %v", err, tt.want)
			}
		})
	}
	if err := RunHelper(strings.NewReader(`{}`), failingWriter{err: want}); !errors.Is(err, want) {
		t.Fatalf("RunHelper response write error = %v", err)
	}
}

func TestStaticKeyReturnsIndependentCopy(t *testing.T) {
	s := staticKey{pem: []byte("secret")}
	a, err := s.SecretValue("ignored")
	if err != nil {
		t.Fatal(err)
	}
	a[0] = 'X'
	if string(s.pem) != "secret" {
		t.Fatal("staticKey returned an alias to its private key storage")
	}
}

func FuzzDecodeHelperRequestNeverPanics(f *testing.F) {
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"op":"exec"}`))
	f.Add([]byte(`{} {}`))
	f.Add([]byte{0, 1, 2, 3})
	f.Fuzz(func(t *testing.T, body []byte) {
		var req HelperRequest
		err := decodeHelperRequest(bytes.NewReader(body), &req)
		if err == nil && !json.Valid(body) {
			t.Fatalf("invalid JSON decoded successfully: %q", body)
		}
	})
}

type shortWriter struct{}

func (shortWriter) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	return len(p) - 1, nil
}

type errorReader struct{ err error }

func (r errorReader) Read([]byte) (int, error) { return 0, r.err }
