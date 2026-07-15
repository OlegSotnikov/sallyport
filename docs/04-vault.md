# 04: Vault

## Key model

The Secure Enclave stores P-256 keys, not arbitrary secrets. API tokens, SSH keys, and other vault data live in `vault.db`, encrypted with keys derived from the DEK.

```text
Touch ID
  -> Secure Enclave K-wrap
  -> opens a sealed P-256 vault identity
  -> vault identity unwraps the DEK
  -> DEK opens vault records
```

Production uses two hardware keys:

| Key | Access | Purpose |
|---|---|---|
| K-wrap | `WhenUnlockedThisDeviceOnly`, `.biometryAny` | opens the sealed vault identity after Touch ID |
| Audit signer | `AfterFirstUnlockThisDeviceOnly`, no biometric prompt | signs audit row hashes and the integrity anchor |

Approval decisions are not signed. The separate audit signer can sign locked-vault denial events without Touch ID.

The audit recipient also uses P-256. Its public key remains available while locked, so the app can append encrypted events. Its private identity is sealed under the DEK, so reading event contents requires unlock.

## Storage

`vault.db` uses schema v2:

- `secrets`: opaque id, version, `sealed_meta`, and `sealed_value`;
- `blobs`: sealed settings, SSH inventory, MCP upstreams, allowlist, and audit identity;
- `meta`: schema version, wrapped DEK, and public audit recipient.

For each record, Sallyport derives a subkey with HKDF-SHA256. ChaCha20-Poly1305 binds ciphertext to its domain, record id, and version through AAD. Moving ciphertext between fields or versions fails authentication.

Key names, providers, host bindings, confirmation flags, SSH inventory, and settings are encrypted.
In production, plaintext on disk is limited to public or structural data:

- the wrapped DEK and schema version;
- public data in `keystore.json` and the audit recipient;
- SSH server keys in `known_hosts`;
- socket and filesystem metadata.

## Unlock and lock

Release builds accept only the hardware-gated keystore. Unlock follows this sequence:

1. Touch ID authorizes K-wrap use.
2. K-wrap opens the identity stored at `~/Library/Application Support/dev.sallyport.mac/identity.sealed`.
3. The identity is delivered to `SEDelegatedKeystore`, which unwraps the DEK.
4. The vault hydrates sealed state and verifies the audit chain, signer, anchor, and replay floor.
5. The state becomes `ready` only after those checks pass.

Lock clears the delivered identity and DEK best-effort, ends sessions and pending approvals, cancels credential requests, and stops stdio MCP children. The DEK is held in a `[UInt8]`; `mlock` is not used.

Auto-lock defaults to 480 minutes after unlock. Setting it to `0` disables only the TTL. Manual lock, app exit, and sleep still lock the vault. Screen lock does so when `lockOnScreenLock` is enabled.

## Development backend

Debug builds and tests can use `FileAgeKeystore`. It stores its raw wrapping key in a mode-`0600`
file and provides no hardware boundary. Release builds reject it. This backend is not a headless or
server mode.

## SSH keys and recordings

Sallyport imports Ed25519, RSA, and ECDSA OpenSSH private keys. An encrypted key is normalized once with its passphrase; the passphrase is not stored. Native Secure Enclave SSH key generation is not implemented.

During production `ssh.exec`, the private key is opened only in the app process. The app's SSH signer answers `sp-ssh` over an inherited socket. The helper receives signatures, not the private key. A legacy stdin-key exec path remains for tests. Key import uses stdin because the key is not yet in the vault.

`sp-ssh` applies fixed-pattern redaction to output and the asciicast. The app then applies exact-value redaction to stdout and stderr, seals the cast with a separate DEK-derived recording key, and writes `~/.sallyport/recordings/*.cast.sealed`.

## Files

```text
~/.sallyport/
  vault.db
  keystore.json
  known_hosts
  audit/
  recordings/
  sallyport.sock
```

The directory and agent socket use mode `0700`; sensitive files use mode `0600`. For the default home, `identity.sealed` and `integrity-anchor.json` live in `~/Library/Application Support/dev.sallyport.mac/`. Incompatible vault files are archived with a `.pre-v2-<id>` suffix before new state is created. Ciphertext is not migrated.

## Recovery and limits

The vault has no reveal, credential export, or recovery key. Losing the device, K-wrap, or sealed identity requires a new vault and reissued credentials.

The Secure Enclave protects against an offline copy, not decrypted memory in an unlocked process. Same-user malware, root, and code execution inside Sallyport remain separate risks. See [08-security-model.md](08-security-model.md) for limits, [14-trust-model.md](14-trust-model.md) for lifecycle and authorization, and [06-audit-dlp.md](06-audit-dlp.md) for the audit format.
