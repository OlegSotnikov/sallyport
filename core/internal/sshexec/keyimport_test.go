package sshexec

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestNormalizeKey(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	plain, _ := ssh.MarshalPrivateKey(priv, "")
	plainPEM := string(pem.EncodeToMemory(plain))
	enc, err := ssh.MarshalPrivateKeyWithPassphrase(priv, "", []byte("s3cret"))
	if err != nil {
		t.Fatal(err)
	}
	encPEM := string(pem.EncodeToMemory(enc))

	// 1. Unencrypted key: passes through and stays usable.
	out, err := NormalizeKey(plainPEM, "")
	if err != nil {
		t.Fatalf("unencrypted key rejected: %v", err)
	}
	if _, err := ssh.ParsePrivateKey([]byte(out)); err != nil {
		t.Fatalf("normalized unencrypted key must parse: %v", err)
	}

	// 2. Encrypted key, no passphrase → the typed "needs passphrase" signal.
	if _, err := NormalizeKey(encPEM, ""); !errors.Is(err, ErrKeyPassphraseRequired) {
		t.Fatalf("encrypted key without passphrase should be ErrKeyPassphraseRequired, got %v", err)
	}

	// 3. Encrypted key, WRONG passphrase → an error (not the needs-passphrase one).
	if _, err := NormalizeKey(encPEM, "wrong"); err == nil || errors.Is(err, ErrKeyPassphraseRequired) {
		t.Fatalf("wrong passphrase should fail with a decrypt error, got %v", err)
	}

	// 4. Encrypted key, RIGHT passphrase → decrypts to a usable UNENCRYPTED key.
	dec, err := NormalizeKey(encPEM, "s3cret")
	if err != nil {
		t.Fatalf("correct passphrase should decrypt: %v", err)
	}
	signer, err := ssh.ParsePrivateKey([]byte(dec))
	if err != nil {
		t.Fatalf("decrypted key must parse without a passphrase: %v", err)
	}
	// The decrypted key must be the SAME key (same public key).
	want := ssh.MarshalAuthorizedKey(pubOf(t, priv))
	got := ssh.MarshalAuthorizedKey(signer.PublicKey())
	if string(want) != string(got) {
		t.Fatal("decrypted key is not the same key that was imported")
	}

	// 5. Garbage is rejected.
	if _, err := NormalizeKey("-----BEGIN nonsense-----", ""); err == nil {
		t.Fatal("garbage must be rejected")
	}
}

func pubOf(t *testing.T, priv ed25519.PrivateKey) ssh.PublicKey {
	t.Helper()
	pk, err := ssh.NewPublicKey(priv.Public())
	if err != nil {
		t.Fatal(err)
	}
	return pk
}
