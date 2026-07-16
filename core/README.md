# sp-ssh

`core/` builds the stateless Go SSH helper bundled with `Sallyport.app`. The Swift app owns the vault, decision ladder, approvals, audit, and agent socket.

Module: `github.com/sallyport/sallyport`

Go: 1.26.4

## Operations

`sp-ssh` reads one bounded JSON request from stdin and writes one JSON response to stdout.

| Operation | Purpose |
|---|---|
| `exec` or empty | connect to an SSH host and run one command |
| `normalize_key` | validate an imported OpenSSH key and remove its import passphrase before vault storage |

For `exec`, the app keeps the private key in its own process and exposes one in-process SSH signer over an inherited socketpair. The helper receives `agentFD`, not the private key. The app verifies the bundled helper's signature, team, code hash, and suspended live process before allowing it to run.

For `normalize_key`, the not-yet-imported key and optional passphrase travel through stdin. The helper bounds and overwrites that request buffer best-effort.

## Request fields

| Field | Meaning |
|---|---|
| `op` | `exec`, `normalize_key`, or empty for exec |
| `host`, `user`, `port` | SSH destination |
| `hostKeyPolicy` | `accept-new` or `strict` |
| `command` | command for exec |
| `timeoutS` | bounded command timeout |
| `knownHostsPath` | caller-owned known-hosts file |
| `returnCast` | return an in-memory asciicast |
| `agentFD` | inherited SSH-agent socket for exec |
| `privateKeyB64`, `passphrase` | import data for `normalize_key`; legacy exec fallback in tests |

## Response fields

Exec returns base64 stdout and stderr, exit code, byte count, truncation flag, duration, host-key fingerprint, TOFU status, and optional `castB64`. Normalize returns `normalizedKeyB64`.

The helper does not rewrite retained stdout, stderr, or recording content based on credential-like
patterns. Text decoding and documented retention limits still apply. Treat command output and
decrypted recordings as sensitive.

When recording is enabled, the helper returns the cast in memory. The app seals it before writing `~/.sallyport/recordings/*.cast.sealed`. The helper does not write a plaintext cast in production.

## Host keys

- `accept-new` stages the first observed public key during key exchange and
  appends it to the supplied known-hosts file only after client authentication
  succeeds, before any SSH session or command is opened.
- `strict` rejects unknown or changed keys.
- The response includes the observed fingerprint for audit.

## Build and test

```bash
make build
make vet
make test
go test -race ./...
```

The tests use an in-process SSH server and do not require external network access.

## Layout

```text
core/
  cmd/sp-ssh/       executable
  internal/sshexec/ helper protocol, SSH execution, recording, host keys
  internal/sshtest/ test server and fixtures
```

The helper makes no authorization decision and stores no vault state. SSH errors, invalid keys, host-key failures, output limits, and missing recordings return errors to the app.
