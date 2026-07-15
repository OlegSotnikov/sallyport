# 01: Architecture

Sallyport ships as one stateful Mac app with two bundled helpers. The app owns the vault, decision engine, approvals, audit journal, management UI, and agent socket. There is no daemon, LaunchAgent, or server process.

## Components

```text
MCP client
    |
    v
sp mcp  ->  ~/.sallyport/sallyport.sock  ->  Sallyport.app
                                                |  process provenance
                                                |  fixed decision ladder
                                                |  approval UI
                                                |  vault and audit
                              +-----------------+-----------------+
                              |                                   |
                              v                                   v
                       HTTP and MCP                         private signer socket
                                                                  |
                                                                  v
                                                               sp-ssh
                                                                  |
                                                                  v
                                                              SSH host
```

| Component | Responsibility |
|---|---|
| `Sallyport.app` | Owns all persistent and in-memory product state. |
| `sp mcp` | Translates MCP over stdio to newline-delimited JSON on the app socket. It stores no state. |
| `sp-ssh` | Runs one SSH operation. It stores no vault state and receives signatures instead of the stored private key. |
| Engine | Applies the fixed ladder, records intent, dispatches the action, and redacts output. |
| Approval UI | Resolves session and per-call cards in process. Touch ID is used only by biometric modes. |
| Vault | Seals credentials and configuration and resolves bound credentials at use time. |
| Audit | Appends encrypted, hash-chained, signed events. A durable intent gates each side effect. |

Approvals are ordinary in-process decisions, not signed grants. A separate Secure Enclave key signs audit rows and integrity anchors.

## Call path

For each tool call, the app:

1. Captures the socket peer PID and builds process provenance.
2. Denies the call unless the vault is ready.
3. Resolves the required target and any bound credential metadata.
4. Applies per-call confirmation, an existing session, the optional allowlist, or the session gate.
5. Writes a durable audit intent. Failure stops execution.
6. Commits any new session and rechecks the vault lifecycle.
7. Executes HTTP, SSH, credential provisioning, or an upstream MCP call.
8. Rechecks the lifecycle, redacts output, attempts to append the outcome event, and returns the result.

A lifecycle change before execution rejects admission. A change during execution discards the result but cannot undo a side effect that already completed.

The exact authorization order is defined in [14-trust-model.md](14-trust-model.md).

## Process identity and sessions

The request's `identity` field is a label. Authorization uses the kernel-observed peer PID, process start time, executable path, parent chain, and code-signing data.

A session represents one live process. It ends on process exit, revocation, vault lock, or app exit. Sessions and their ended-state UI are held only for the current app run. Session lifecycle events are also written to the audit journal.

The optional allowlist matches a live process by exact cdhash or publisher requirement. It skips only the session card. Per-call approval, the vault gate, target binding, audit, redaction, and lifecycle checks still apply.

## State

`vault.db` uses schema v2:

- `secrets` stores sealed metadata and values;
- `blobs` stores sealed settings, SSH inventory, MCP upstreams, allowlist, and audit identity;
- `meta` stores structural data, the wrapped DEK, and the public audit recipient.

Production unlock follows this chain:

```text
Touch ID -> Secure Enclave K-wrap -> sealed vault identity -> DEK -> vault records
```

The audit journal under `~/.sallyport/audit` is sealed to a separate P-256 recipient and signed by the audit signer. Its chain structure can be checked while locked; event contents require unlock. SSH recordings are encrypted separately under `~/.sallyport/recordings`.

Live sessions, pending approvals, credential prompts, and cached upstream state are memory-only and are cleared on lock. The software keystore is limited to development and tests.

See [04-vault.md](04-vault.md) and [06-audit-dlp.md](06-audit-dlp.md) for storage details.

## Channel boundaries

| Channel | Execution boundary |
|---|---|
| HTTP | The app resolves a host-and-path binding and injects authentication inside `HTTPExecutor`. |
| SSH | The app holds the private key and answers signing requests from `sp-ssh` over an inherited socket. |
| Local MCP | The app launches the configured process and places bound credentials in its environment. |
| Remote MCP | The app attaches a host-bound API key or uses its sealed OAuth grant. |
| Credential request | The app collects the value in a separate sheet and returns only provisioning metadata. |

All channels use the same engine, approval flow, audit chain, and output redaction. Traffic sent outside Sallyport is outside its control.

## Deployment and failure behavior

The shipped target is Apple Silicon macOS. Production vault creation requires the signed app, Secure Enclave, and data-protection-keychain entitlements. The software keystore is not a production or headless mode.

| Failure | Behavior |
|---|---|
| App closed or socket unavailable | `sp mcp` returns a connection error. |
| Vault locked, unlocking, or quarantined | Agent tools deny; management exposes status only. |
| Approval unavailable or unanswered | The call times out and denies. |
| Audit intent cannot be written or signed | No executor runs. |
| Vault lifecycle changes during execution | Output is discarded; an external side effect may already have occurred. |
| SSH helper verification fails | SSH execution is denied before the helper can sign. |

Linux, Docker, server, cloud-control-plane, and headless modes are roadmap work. See [10-roadmap.md](10-roadmap.md).
