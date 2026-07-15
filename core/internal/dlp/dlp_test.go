package dlp

import (
	"bytes"
	"strings"
	"testing"
)

func TestRedactsKnownSecretShapes(t *testing.T) {
	cases := []struct {
		name string
		in   string
	}{
		{"bearer", `{"auth":"Bearer sk_live_abcdef1234567890"}`},
		{"github", `token gho_ABCDEFGHIJKLMNOPQRSTUVWXYZ012345`},
		{"aws", `AKIAIOSFODNN7EXAMPLE here`},
		{"jwt", `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			out, n := Redact([]byte(c.in))
			if n == 0 {
				t.Fatalf("expected a redaction for %s", c.name)
			}
			if !bytes.Contains(out, []byte("«redacted»")) {
				t.Fatalf("no placeholder in output: %s", out)
			}
		})
	}
}

func TestPrivateKeyBlockRedacted(t *testing.T) {
	pem := "-----BEGIN RSA PRIVATE KEY-----\nMIIhidden\n-----END RSA PRIVATE KEY-----"
	out, n := Redact([]byte(pem))
	if n != 1 {
		t.Fatalf("expected 1 redaction, got %d", n)
	}
	if bytes.Contains(out, []byte("MIIhidden")) {
		t.Fatal("private key body survived redaction")
	}
}

func TestCleanTextUntouched(t *testing.T) {
	in := `{"zones":[{"id":"abc","name":"example.com"}]}`
	out, n := Redact([]byte(in))
	if n != 0 || string(out) != in {
		t.Fatalf("clean text was modified: %s (n=%d)", out, n)
	}
}

// TestRedactWithInjectedSecret proves a NON-generic injected value (matches no
// known shape) is masked literally with the credential marker, and the caller's
// buffer is never mutated in place.
func TestRedactWithInjectedSecret(t *testing.T) {
	secret := []byte("cfat_ABC123def456_not_a_known_shape")
	in := []byte(`{"echo":"cfat_ABC123def456_not_a_known_shape","other":"ok"}`)
	orig := append([]byte(nil), in...)

	// Sanity: the generic pass alone does NOT catch this token.
	if _, n := Redact(in); n != 0 {
		t.Fatalf("token unexpectedly matched a generic shape (n=%d)", n)
	}

	out, n := RedactWith(in, [][]byte{secret})
	if n != 1 {
		t.Fatalf("redaction count = %d, want 1", n)
	}
	if strings.Contains(string(out), string(secret)) {
		t.Fatalf("injected secret leaked: %s", out)
	}
	if !strings.Contains(string(out), maskCredential) {
		t.Fatalf("missing credential mask: %s", out)
	}
	if !bytes.Equal(in, orig) {
		t.Fatal("RedactWith mutated the caller's buffer in place")
	}
}

// TestRedactWithEmptySecretIsNoop guards against a zero-length secret masking
// the entire body.
func TestRedactWithEmptySecretIsNoop(t *testing.T) {
	in := []byte("plain body, no secrets here")
	out, n := RedactWith(in, [][]byte{{}, nil})
	if n != 0 {
		t.Fatalf("empty secrets must not redact anything, got %d", n)
	}
	if string(out) != string(in) {
		t.Fatalf("body changed: %s", out)
	}
}
