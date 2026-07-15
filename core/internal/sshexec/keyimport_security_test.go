package sshexec

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/pem"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestNormalizeKeyEncryptedAlgorithmsPreserveIdentity(t *testing.T) {
	edPublic, edPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ecdsaPrivate, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rsaPrivate, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name       string
		privateKey any
		publicKey  any
	}{
		{name: "ed25519", privateKey: edPrivate, publicKey: edPublic},
		{name: "ecdsa", privateKey: ecdsaPrivate, publicKey: &ecdsaPrivate.PublicKey},
		{name: "rsa", privateKey: rsaPrivate, publicKey: &rsaPrivate.PublicKey},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			block, err := ssh.MarshalPrivateKeyWithPassphrase(tt.privateKey, "security-test", []byte("pāss\x00word"))
			if err != nil {
				t.Fatal(err)
			}
			out, err := NormalizeKey(string(pem.EncodeToMemory(block)), "pāss\x00word")
			if err != nil {
				t.Fatal(err)
			}
			signer, err := ssh.ParsePrivateKey([]byte(out))
			if err != nil {
				t.Fatalf("normalized key is still encrypted or invalid: %v", err)
			}
			want, err := ssh.NewPublicKey(tt.publicKey)
			if err != nil {
				t.Fatal(err)
			}
			if string(signer.PublicKey().Marshal()) != string(want.Marshal()) {
				t.Fatal("normalization changed key identity")
			}
		})
	}
}

func TestNormalizeKeyPlaintextIsReturnedByteForByte(t *testing.T) {
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKey(privateKey, "preserve-comment")
	if err != nil {
		t.Fatal(err)
	}
	raw := string(pem.EncodeToMemory(block))
	out, err := NormalizeKey(raw, "")
	if err != nil {
		t.Fatal(err)
	}
	if out != raw {
		t.Fatal("already-valid plaintext key was unexpectedly rewritten")
	}
	if _, err := NormalizeKey("not-a-key", "provided-passphrase"); err == nil {
		t.Fatal("garbage with a passphrase must still be rejected")
	}
}

func TestCryptoKeyNormalizesOnlyEd25519Pointer(t *testing.T) {
	_, edPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := cryptoKey(&edPrivate).(ed25519.PrivateKey); !ok {
		t.Fatal("ed25519 pointer was not converted to a value")
	}
	rsaPrivate, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	if got := cryptoKey(rsaPrivate); got != rsaPrivate {
		t.Fatal("non-ed25519 private key should pass through unchanged")
	}
}

func FuzzNormalizeKeyMalformedInputNeverPanics(f *testing.F) {
	f.Add("")
	f.Add("not a key")
	f.Add("-----BEGIN OPENSSH PRIVATE KEY-----\n-----END OPENSSH PRIVATE KEY-----\n")
	f.Fuzz(func(t *testing.T, raw string) {
		if len(raw) > maxHelperRequestBytes {
			t.Skip()
		}
		out, err := NormalizeKey(raw, "")
		if err == nil {
			if _, err := ssh.ParsePrivateKey([]byte(out)); err != nil {
				t.Fatalf("NormalizeKey returned unusable key: %v", err)
			}
		}
	})
}
