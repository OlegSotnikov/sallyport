# 07: Process identity and deployment

## Agent identity

`sp mcp` connects to `~/.sallyport/sallyport.sock`. The app obtains the peer PID with `LOCAL_PEERPID`, walks its parent chain, resolves executable paths, and inspects code signatures.

The request's `identity` string is only a label. Session authorization uses kernel-observed process data.

A session key combines PID and process start time. Sallyport rechecks the live executable and signing data on later calls. PID reuse, process exit, signature drift, revoke, vault lock, and app exit invalidate the session.

The optional allowlist stores either an exact cdhash or a publisher requirement. Matching is performed against the live process on each call. It skips only the session gate.

Identity establishes which process sent a request. It does not establish the process's intent or prove which component wrote bytes to an inherited socket. Per-call approval and audit address different parts of that risk.

## Current deployment

- Apple Silicon macOS only.
- One signed and notarized `Sallyport.app`.
- Vault, engine, approvals, management, and agent socket run in that process.
- `sp` provides `sp mcp` and `sp version`.
- The bundled Go `sp-ssh` helper is spawned for `ssh.exec`.
- No LaunchAgent, LaunchDaemon, server, Linux, or Docker component is installed.

Production vault creation requires the Secure Enclave and the signed-app entitlements used by the data-protection keychain. Unsigned development builds cannot exercise the production hardware gate and audit signer reliably.

## Current hardening

- Hardened runtime, code signing, notarization, and signed Sparkle updates.
- Data-protection-keychain Secure Enclave keys bound to the app's signing identity.
- Private Sallyport directory and agent socket.
- Ephemeral HTTP sessions without cookies or cache.
- Bounded socket frames, MCP frames, HTTP bodies, SSH helper output, and timeouts.
- Best-effort zeroization of DEK and credential buffers.
- Fail-closed audit intent writes and integrity quarantine.

XPC audit tokens, reproducible-build evidence, SBOM publication, SLSA provenance, and an external audit witness are roadmap work. Do not cite them as shipped controls.
