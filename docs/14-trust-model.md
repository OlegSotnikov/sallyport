# 14: Trust model

This is the source of truth for local authorization. Other documents must not describe a different ladder, approval scope, or vault state.

## Guarantees

- A locked, unlocking, or quarantined vault does not execute agent tools or expose sealed metadata.
- Sallyport does not intentionally put managed credential values into agent results, approval
  payloads, audit events, logs, or errors. Executor results are not inspected or rewritten and may
  contain sensitive data supplied by the target or upstream server.
- Approvals resolve inside `Sallyport.app`. They are not signed grants.
- Every side effect requires a durable audit intent row first.
- Locking clears the DEK, live sessions, pending approvals, credential requests, and stdio MCP processes.
- There is no credential recovery, reveal, or export path.

## Vault states

| State | Agent tools | Management | Sessions |
|---|---|---|---|
| `locked` | denied with `SALLYPORT_LOCKED` | `status` only | cleared |
| `unlocking` | denied | `status` only | cleared |
| `ready` | decision ladder applies | available | live in memory |
| `quarantined` | denied with `SALLYPORT_QUARANTINED` | `status` only; UI may lock or re-adopt | cleared |

Unlock first unwraps the vault identity and DEK, then hydrates sealed state and runs integrity checks. The vault becomes `ready` only after those checks pass.

Production unlock uses the Secure Enclave K-wrap key and Touch ID. The software backend exists for development and tests. A newly created vault may start ready; a restarted production app starts sealed.

Auto-lock defaults to 480 minutes. `0` disables TTL auto-lock. Manual lock, sleep, app exit, and screen lock when enabled still close the vault.

Losing the Secure Enclave key or device loses the vault. Recreate it and reissue credentials at their providers.

## Authorization controls

### Session approval

`sessionAuth` controls the first call from a process:

| Value | Behavior |
|---|---|
| `off` | run in observe mode and journal the process |
| `click` | require one click; default |
| `touchid` | require Touch ID |

A session represents one live process. Its identity uses kernel-observed PID and start time plus executable and code-signing data. Sallyport revalidates live identity on later calls.

The control socket pins each connection to one peer process instance at accept: the connect-time audit token (`LOCAL_PEERTOKEN`) plus kernel start time. Every `invoke` frame re-validates that the peer PID still belongs to that instance and is denied (`server.peer`) otherwise, so a descriptor that outlives its shim cannot attribute frames through a reused PID. Code-signing guest lookups for the peer use the audit token rather than the reusable PID. Connection descriptors are `FD_CLOEXEC` on both ends.

An approved session lasts until process exit, revoke, vault lock, or app exit. Sessions are never persisted.

### Per-call approval

Keys and upstream MCP servers have `confirm` set to `""`, `click`, or `touchid`. A non-empty value requires confirmation on every applicable call, including calls from approved, observed, or allowlisted processes.

When a key and upstream both apply, the stricter ceremony wins. Per-call approval is never remembered. There are no TTL grants or persist buttons.

If a new process also needs session approval, one card can satisfy the session and the current call.

### Agent allowlist

An allowlist entry is either:

- an exact code-directory hash, which stops matching after a binary update;
- a publisher requirement based on signing identity, which can survive updates.

Entries may be scoped to hosts. Sallyport matches them against the live process on each call. A match skips only the session card. It does not bypass vault state, host binding, per-call approval, audit, or lifecycle checks.

Adding, updating, or removing an allowlist entry always requires Touch ID. The allowlist is sealed under the DEK.

Two management conveniences change nothing in the gate itself. A known-agents registry (label, bundle ID, Team ID, standard install paths for Claude Desktop, Claude Code, Codex CLI) locates binaries and cross-checks captures; entries are still captured from the binary on disk and verified by Security.framework. When a captured identity carries the same valid Team ID and bundle ID as an existing cdhash entry but a new hash — the pinned agent updated — the UI offers a one-ceremony pin replacement that keeps the entry's scope.

An allowlist authenticates process identity, not intent. With an inherited descriptor, Sallyport cannot prove which component authored each byte.

## Decision ladder

Every `http.request`, `ssh.exec`, `sallyport.request_credential`, and proxied MCP call follows this order:

```text
1. vault state is not ready             -> deny
2. required target or credential metadata cannot resolve -> deny
3. per-call confirmation applies        -> ask
4. existing approved session             -> run
5. allowlist matches                     -> run
6. sessionAuth is click or touchid        -> ask
7. sessionAuth is off                     -> run as observed
8. write audit intent                     -> deny if it fails
9. execute, attempt result row, return the bounded executor result
```

An unidentifiable process is denied while session approval is enabled. Observe mode may run it without a card and records what identity is available.

The engine captures a vault lifecycle epoch before authorization. A change before execution rejects
admission. A change during execution discards the result but cannot undo a completed side effect. A
session is committed only after the audit intent is durable.

`sallyport.request_credential` uses the same vault and session gates. After admission, the app opens a separate credential sheet. The agent receives `provisioned`, `message`, and an optional key name.

## Configuration changes

`requireTouchIDForChanges` defaults to true. While enabled, key, SSH-host, and MCP-server mutations require Touch ID at the management boundary.

The following always require Touch ID, even when the general mutation gate is off:

- `settings.set`;
- `allowlist.add`;
- `allowlist.delete`;
- integrity re-adoption and destructive reset through their UI flows.

The biometric prompt names the requested change. Reads, `status`, vault lock, and `sessions.revoke` do not require Touch ID. Revocation only reduces access and must remain immediate.

If Touch ID is required but unavailable or rejected, no mutation is committed. Mutations are serialized with the vault generation, audit anchor, and replay floor. A lifecycle change during confirmation cancels the write.

## Settings surface

| Field | Default | Effect |
|---|---:|---|
| `sessionAuth` | `click` | new-process ceremony |
| `requireTouchIDForChanges` | `true` | general mutation gate |
| `logBodies` | `false` | compatibility field; currently unused |
| `autoLockMinutes` | `480` | TTL after unlock; `0` disables it |
| `lockOnScreenLock` | `true` | lock when the macOS screen locks |

Per-key and per-upstream `confirm` fields add per-call approval. Host and path bindings define where an HTTP credential may be injected. The allowlist affects only session admission.

`logBodies` is persisted but no current executor or audit path consumes it. Payload capture remains roadmap work.

## Audit and integrity

Audit events are ECIES-sealed to a dedicated recipient. Its public key is available while locked, so Sallyport can record locked-vault denials. The private identity is sealed under the DEK, so event contents require unlock.

Rows form a hash chain over ciphertext. A separate audit signer signs every row and the integrity anchor. Approval decisions do not use that signer.

The external anchor binds the journal head, configuration generation, and trust-bearing vault ciphertext. Unlock detects edits, truncation, signer replacement, and partial rollback. Divergence quarantines the vault until explicit Touch ID re-adoption.

A complete consistent rollback of all local state can resemble restoration from backup. Detecting that requires an off-device witness.

SSH recordings are encrypted separately under a DEK-derived key. SSH output and recordings are
preserved without content inspection; returned output and decrypted recordings may contain sensitive
session data.

## Security limits

- Approval identifies a process or operation, not human or agent intent.
- A prompt-injected approved agent may use any available non-per-call credential.
- Observe mode permits local processes to use non-per-call credentials while the vault is ready.
- Secure Enclave protects private keys, not UI pixels or decrypted process memory.
- Root, disabled SIP, or code execution inside Sallyport can control an unlocked vault.
- Same-user malware can inspect credentials passed to local stdio MCP servers through their environment.
- HTTP, remote MCP, and OAuth pin each validated DNS snapshot through connection; a later logical
  request performs a fresh lookup.
- HTTP, SSH, and MCP results and errors are not inspected or rewritten and may contain credentials or
  other sensitive target-supplied data.
- Authenticated MCP catalog metadata is arbitrary upstream-controlled content outside the invocation
  ladder and is returned without content inspection.
- HTTP, SSH, and MCP targets are trusted credential recipients for credentials Sallyport sends them.
- Sallyport cannot govern traffic sent outside its tools.
- The local operator can approve harmful actions. Multi-party approval is not implemented.

## Removed behavior

The current local model has no policy language, service trust list, first-contact grants, approval TTLs, agent tokens, remote approvers, or server mode. The optional process allowlist is the only standing session bypass. Planned controls belong in [10-roadmap.md](10-roadmap.md).
