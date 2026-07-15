# 08: Security model and limits

The decision model is defined in [14-trust-model.md](14-trust-model.md). This file lists assets, attackers, controls, and residual risk.

## Assets

- API credentials, SSH private keys, and OAuth grants.
- The vault DEK and Secure Enclave K-wrap key.
- Audit recipient, audit signer, journal, and integrity anchor.
- Host bindings, approval settings, allowlist, and upstream configuration.
- The Sallyport process and update channel.

## Attackers

| Actor | In scope |
|---|---|
| Prompt-injected agent using Sallyport tools | yes |
| Malicious API, SSH host, or MCP server | yes |
| Another process under the same macOS user | partial |
| Offline copy of the Sallyport directory | yes |
| Root, disabled SIP, or code execution inside Sallyport | no complete defense |
| Operator who approves a malicious action | detection only |

## Controls

### Prompt-injected agent

- The agent receives results, not Sallyport-managed credential values.
- Host and path bindings limit where HTTP credentials are injected.
- Per-call keys and MCP servers require confirmation for every use.
- Sessions end on process exit, revoke, vault lock, or app exit.
- Exact injected values and common credential formats are redacted from output.
- Each intent is audited before the side effect.

An approved or allowlisted agent can still misuse any non-per-call credential available to it. Approval identifies a process or operation, not intent.

### Malicious external service

- Credentialed redirects are not followed.
- HTTPS-to-HTTP and cross-host credential forwarding are blocked.
- Cloud metadata targets are blocked. Private targets require an explicit credential binding.
- Responses have size limits and output redaction.

Current DNS validation and connection use separate resolution steps. A DNS rebind between them can bypass the address check. Pinning the validated address is roadmap work.

### Same-user process

- The socket is private and the server obtains the peer PID from the kernel.
- Session identity includes process start time and live signing data.
- Secure Enclave keys use data-protection-keychain access controls tied to the signed app.
- Touch ID can protect new-agent, per-call, and configuration operations.

These controls do not make the macOS user account a hard isolation boundary. Same-user code with Accessibility rights can drive UI, inspect some process metadata, and wait for an unlocked vault. An inherited socket or pipe also does not prove which process authored each byte. The allowlist therefore authenticates an identity, not intent or byte authorship.

Local stdio MCP servers receive configured credentials in their environment. Same-user malware may read that environment through process inspection. Use remote HTTP MCP for a stronger credential boundary.

### Offline copy

Secret values, metadata, settings, inventories, and OAuth grants are sealed under the DEK. In production, the Secure Enclave K-wrap key opens a sealed vault identity, which unwraps the DEK. Audit events and SSH recordings are encrypted separately. A copied Sallyport directory without the device keys does not reveal their contents.

There is no recovery or export path. Losing the device or K-wrap key loses the vault.

### Audit tampering

Each row is chained over ciphertext and signed. The signed external anchor and replay floor detect journal edits, tail truncation, signer replacement, and partial local rollback at unlock. Detected divergence quarantines the vault.

A complete consistent rollback of the vault, journal, anchor, and external state can resemble restoration from backup. An off-device witness is required to distinguish it.

## Explicit limits

- Root or code execution inside Sallyport can act through an unlocked vault.
- Secure Enclave protects private keys, not UI pixels or decrypted process memory.
- Observe mode lets any identifiable local process use non-per-call credentials while the vault is unlocked.
- Click approval can be rubber-stamped; Touch ID raises the bar but does not validate intent.
- DLP is pattern and exact-value redaction, not general data-flow control.
- Caller-supplied commands, arguments, audit previews, and decrypted SSH recordings may contain sensitive data.
- Sallyport does not control traffic sent outside its own tools.
- A configured upstream MCP server is trusted for its tool catalog. Its output is redacted, but catalog text is passed through.
- One local operator can approve harmful actions. Multi-party approval is roadmap work.

Any claim stronger than these controls belongs in [10-roadmap.md](10-roadmap.md), not current product copy.
