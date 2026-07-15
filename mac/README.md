# Sallyport.app

`Sallyport.app` is the Apple Silicon Mac product. It hosts the vault, decision engine, approvals, management backend, audit log, and agent socket in one process.

Bundled executables:

- `sp`: stateless MCP stdio shim;
- `sp-ssh`: stateless Go SSH helper.

There is no daemon, LaunchAgent, server, Linux, or Docker component.

## Build and run

```bash
swift build
swift test
swift run sallyport-app --demo

./build-app.sh
open build/Sallyport.app
build/Sallyport.app/Contents/MacOS/Sallyport --selftest
```

`--demo` uses fixtures and a mock management backend. Production vault creation and Secure Enclave tests require the signed app bundle.

`--init`, `--render-ui`, and `--verify-unlock` are internal diagnostic or automation entry points. They are not `sp` commands.

## Package layout

```text
Sources/
  SallyportKit/      shared models, management client, provenance UI logic, keystore adapters
  SallyportVault/    encrypted store, engine, sessions, audit, HTTP, SSH, MCP, agent socket
  SallyportApp/      SwiftUI app, runtime, approvals, in-process management backend
  SallyportCLI/      MCP stdio shim implementation
  sp/                sp executable
Tests/
  SallyportKitTests/
  SallyportVaultTests/
```

The app UI calls `VaultMgmtDaemon` through `MgmtClient` in process. `ControlCodec` remains a testable JSON-shaped compatibility layer; production management does not use the agent socket.

## Agent connection

Socket: `~/.sallyport/sallyport.sock`

The app creates the socket with mode 0700. `sp mcp` connects to it and maps MCP `tools/list` and `tools/call` to `list_tools` and `invoke` frames.

The server obtains each connection's peer PID with `LOCAL_PEERPID`, builds process provenance, and passes the request through the fixed ladder. Approval resolves in the app process. No grant or approval signature crosses the socket.

See [../PROTOCOL.md](../PROTOCOL.md).

## Vault and keys

Production K-wrap uses a permanent P-256 Key Agreement key in the Secure Enclave. The biometric policy uses `.privateKeyUsage` and `.biometryAny` with `WhenUnlockedThisDeviceOnly`. Adding a fingerprint does not intentionally destroy the key.

The audit signer is a separate P-256 signing key without a biometric requirement so locked-vault events can still be signed. It signs audit hashes, not approvals.

Both production keys use the data-protection keychain and the app's keychain access group. `build-app.sh` embeds the required provisioning profile and entitlements, signs nested binaries, and then signs the app bundle.

The software key path is for development and tests. Release setup refuses to present it as production protection.

## SSH boundary

Before executing SSH, the app verifies the bundled `sp-ssh` signature, team, code hash, and suspended live child. The private key stays in the app and serves one ephemeral SSH agent over an inherited socketpair. The helper receives signing operations, not the private key.

Imported key normalization is the exception: the not-yet-stored key and optional passphrase are sent to `sp-ssh` through stdin for validation and conversion before vault storage.

## Onboarding

Current steps:

1. Create vault.
2. Confirm protection is active.
3. Connect an MCP client to the bundled `sp mcp` shim.

Onboarding installs no background agent. Incompatible state is archived with a `.pre-v2-<timestamp>` suffix before a new vault is created. There is no migration, recovery key, reveal, or credential export.

## UI surfaces

| Section | Screen |
|---|---|
| Monitor | Approvals, Activity, Sessions |
| Configure | Keys & APIs, SSH Hosts, MCP Servers, Agent Allowlist |
| System | Integrations, Vault & Keys, Settings, Onboarding |

Locked data screens show an unlock state because their content is sealed. Sessions can be revoked without Touch ID. Keys, hosts, MCP servers, settings, and allowlist entries use the management mutation gates in [../docs/14-trust-model.md](../docs/14-trust-model.md).

`logBodies` remains in the settings model for compatibility but has no runtime consumer and no current UI control. Payload capture is not implemented.

## Verification

`swift test` covers:

- vault encryption and locked reads;
- decision ladder and lifecycle races;
- process sessions and allowlist matching;
- audit sealing, signatures, anchors, rollback detection, and quarantine;
- HTTP credential injection, redirects, network guard, and output limits;
- SSH helper boundary, agent signing, host keys, recordings, and import;
- stdio and remote MCP upstreams, OAuth, and output redaction;
- management models and operations;
- approval and app-state safety logic.

`--selftest` exercises the signed Secure Enclave seal and unseal path. `verify-loop.sh` runs a local end-to-end HTTP path with debug auto-approval. The auto-approval environment flag is compiled for debug builds only.

Release and runner setup are in [ci/README.md](ci/README.md). UI conventions are in [UI.md](UI.md).
