package dlp

import (
	"bytes"
	"strings"
	"testing"
)

func TestEverySupportedCredentialShapeIsRedacted(t *testing.T) {
	tests := []struct {
		name   string
		secret string
	}{
		{name: "bearer case insensitive", secret: "bEaReR abcdefgh.ijklmnop"},
		{name: "github personal", secret: "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ012345"},
		{name: "github oauth", secret: "gho_ABCDEFGHIJKLMNOPQRSTUVWXYZ012345"},
		{name: "github user", secret: "ghu_ABCDEFGHIJKLMNOPQRSTUVWXYZ012345"},
		{name: "github server", secret: "ghs_ABCDEFGHIJKLMNOPQRSTUVWXYZ012345"},
		{name: "github refresh", secret: "ghr_ABCDEFGHIJKLMNOPQRSTUVWXYZ012345"},
		{name: "gitlab", secret: "glpat-ABC_def-0123456789"},
		{name: "aws", secret: "AKIAIOSFODNN7EXAMPLE"},
		{name: "stripe secret live", secret: "sk_live_abcdefghijklmnop"},
		{name: "stripe restricted test", secret: "rk_test_abcdefghijklmnop"},
		{name: "stripe publishable live", secret: "pk_live_abcdefghijklmnop"},
		{name: "openai", secret: "sk-ABCDEFGHIJKLMNOPQRSTUVWXYZ012345"},
		{name: "anthropic", secret: "sk-ant-ABCDEFGHIJKLMNOPQRSTUVWXYZ012345"},
		{name: "slack", secret: "xoxb-1234567890-ABCDEFGHIJ"},
		{name: "google", secret: "AIza" + strings.Repeat("A", 35)},
		{name: "pkcs8", secret: "-----BEGIN PRIVATE KEY-----\nsecret\n-----END PRIVATE KEY-----"},
		{name: "ec pem", secret: "-----BEGIN EC PRIVATE KEY-----\nsecret\n-----END EC PRIVATE KEY-----"},
		{name: "jwt", secret: "eyJabcdefghij.eyJklmnopqrst.uvwxyzABCDEFGHIJ"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			in := []byte("prefix " + tt.secret + " suffix")
			out, n := Redact(in)
			if n != 1 {
				t.Fatalf("redaction count = %d, want 1; output=%q", n, out)
			}
			if bytes.Contains(out, []byte(tt.secret)) || !bytes.Contains(out, []byte(maskGeneric)) {
				t.Fatalf("credential survived: %q", out)
			}
		})
	}
}

func TestCredentialBoundaryNearMissesAreNotOverRedacted(t *testing.T) {
	tests := []string{
		"Bearer short",
		"ghp_too_short",
		"AKIAIOSFODNN7EXAMPL",
		"sk_live_short",
		"AIza" + strings.Repeat("A", 34),
		"eyJabcdefghij.only-two-parts",
	}
	for _, input := range tests {
		t.Run(input, func(t *testing.T) {
			out, n := Redact([]byte(input))
			if n != 0 || string(out) != input {
				t.Fatalf("near miss was redacted: n=%d output=%q", n, out)
			}
		})
	}
}

func TestSpecificCredentialWinsOverGenericPattern(t *testing.T) {
	secret := []byte("ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ012345")
	out, n := RedactWith(append([]byte(nil), secret...), [][]byte{secret})
	if n != 1 {
		t.Fatalf("redaction count = %d, want 1", n)
	}
	if string(out) != maskCredential {
		t.Fatalf("output = %q, want exact credential marker", out)
	}
}

func TestReplacementMarkersCannotReintroduceSpecificCredential(t *testing.T) {
	tests := []struct {
		name   string
		input  []byte
		secret []byte
	}{
		{name: "one byte in marker", input: []byte("dghp_00000000000000000000"), secret: []byte("d")},
		{name: "marker word", input: []byte("redacted secret"), secret: []byte("redacted")},
		{name: "binary marker boundary", input: []byte{0xbb, '0', '0'}, secret: []byte{0xbb, '0'}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out, _ := RedactWith(append([]byte(nil), tt.input...), [][]byte{tt.secret})
			if bytes.Contains(out, tt.secret) {
				t.Fatalf("specific credential survived replacement: secret=%x output=%x", tt.secret, out)
			}
		})
	}
}

func TestMalformedStaticPatternConfigurationIsRepresentableWithoutPanic(t *testing.T) {
	if compiled, ok := compilePatterns([]string{`valid`, `[`}); ok || compiled != nil {
		t.Fatal("malformed pattern configuration did not fail closed")
	}
	compiled, ok := compilePatterns([]string{`valid`, `also-valid`})
	if !ok || len(compiled) != 2 {
		t.Fatal("valid pattern configuration did not compile")
	}
}

func FuzzRedactionNeverMutatesInputOrLeaksSpecificSecret(f *testing.F) {
	f.Add([]byte("plain"), []byte("secret"))
	f.Add([]byte("secret secret"), []byte("secret"))
	f.Add([]byte("ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ012345"), []byte(""))
	f.Add([]byte{0xbb, '0', '0'}, []byte{0xbb, '0'})
	f.Fuzz(func(t *testing.T, input, secret []byte) {
		if len(input) > 64<<10 || len(secret) > 4<<10 {
			t.Skip()
		}
		original := append([]byte(nil), input...)
		out, _ := RedactWith(input, [][]byte{secret})
		if !bytes.Equal(input, original) {
			t.Fatal("RedactWith mutated caller input")
		}
		if len(secret) > 0 && bytes.Contains(original, secret) && bytes.Contains(out, secret) {
			t.Fatalf("specific credential leaked: input=%x secret=%x output=%x", original, secret, out)
		}
	})
}
