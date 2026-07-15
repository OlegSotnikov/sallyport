package sshexec

import (
	"crypto"
	"crypto/ed25519"
	"encoding/pem"
	"errors"
	"fmt"

	"golang.org/x/crypto/ssh"
)

// ErrKeyPassphraseRequired signals that an imported SSH private key is encrypted
// and a passphrase is needed. The UI turns this into a passphrase prompt.
var ErrKeyPassphraseRequired = errors.New("ssh private key is passphrase-protected; provide the passphrase")

// NormalizeKey validates Ed25519, RSA, or ECDSA private keys and returns an
// unencrypted OpenSSH PEM for encrypted vault storage. Passphrases are not
// retained.
func NormalizeKey(raw, passphrase string) (string, error) {
	data := []byte(raw)
	if passphrase == "" {
		switch _, err := ssh.ParsePrivateKey(data); {
		case err == nil:
			return raw, nil // already valid and unencrypted
		case isPassphraseMissing(err):
			return "", ErrKeyPassphraseRequired
		default:
			return "", fmt.Errorf("invalid ssh private key: %w", err)
		}
	}
	rawKey, err := ssh.ParseRawPrivateKeyWithPassphrase(data, []byte(passphrase))
	if err != nil {
		return "", fmt.Errorf("could not decrypt ssh key (wrong passphrase?): %w", err)
	}
	block, err := ssh.MarshalPrivateKey(cryptoKey(rawKey), "sallyport")
	if err != nil {
		return "", fmt.Errorf("re-encode ssh key: %w", err)
	}
	return string(pem.EncodeToMemory(block)), nil
}

// isPassphraseMissing reports whether parsing failed only because the key is
// encrypted (x/crypto/ssh returns a typed *PassphraseMissingError).
func isPassphraseMissing(err error) bool {
	var pm *ssh.PassphraseMissingError
	return errors.As(err, &pm)
}

// cryptoKey normalizes the concrete types ParseRaw* returns into what
// MarshalPrivateKey accepts (ed25519 wants the value, not a pointer).
func cryptoKey(k any) crypto.PrivateKey {
	if p, ok := k.(*ed25519.PrivateKey); ok {
		return *p
	}
	return k
}
