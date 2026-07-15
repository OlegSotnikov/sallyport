# Sallyport

Sallyport is an Apple Silicon Mac app that executes agent API calls, SSH commands, and proxied MCP tools without returning Sallyport-managed credentials to the agent.

`Sallyport.app` hosts the vault, decision engine, approvals, audit, management UI, and agent socket in one process. The bundle includes the `sp mcp` shim and stateless `sp-ssh` helper. There is no daemon, server, Linux, or Docker build.

## Repository

This public repository contains one source snapshot per Sallyport release. Pull requests are not accepted here. Report bugs and security issues as described in [CONTRIBUTING.md](CONTRIBUTING.md).

Install the signed and notarized DMG from [sallyport.dev](https://sallyport.dev), [Releases](../../releases), or Homebrew:

```bash
brew install --cask olegsotnikov/tap/sallyport
```

Release checksums are published with each release and in `https://sallyport.dev/downloads/manifest.json`.

## Authorization

Every action follows the fixed ladder in [docs/14-trust-model.md](docs/14-trust-model.md):

1. The vault must be ready.
2. A marked key or MCP server requires per-call approval.
3. A new process requires session approval unless observe mode or the optional allowlist applies.
4. Sallyport audits and executes the action.

Approvals use a click or Touch ID and resolve in process. They are not signed grants. A separate Secure Enclave signer signs audit rows and integrity anchors.

The app supports `http.request`, `ssh.exec`, `sallyport.request_credential`, and configured upstream MCP tools. The agent receives results, not credential values.

## Build

```bash
(cd core && go test -race ./...)
(cd mac && swift build && swift test)
(cd mac && ./build-app.sh)
open mac/build/Sallyport.app
```

Run the Secure Enclave self-test from the signed bundle:

```bash
mac/build/Sallyport.app/Contents/MacOS/Sallyport --selftest
```

Configure an MCP client to run `Sallyport.app/Contents/MacOS/sp mcp`. The shipped `sp` CLI contains only `mcp` and `version`.

## Documentation

| File | Contents |
|---|---|
| [docs/14-trust-model.md](docs/14-trust-model.md) | authorization and vault states |
| [docs/01-architecture.md](docs/01-architecture.md) | components and call flow |
| [docs/02-channels.md](docs/02-channels.md) | HTTP, SSH, and upstream MCP |
| [docs/04-vault.md](docs/04-vault.md) | vault and keystore |
| [docs/05-approvals.md](docs/05-approvals.md) | session and per-call approvals |
| [docs/06-audit-dlp.md](docs/06-audit-dlp.md) | audit, recordings, redaction |
| [docs/08-security-model.md](docs/08-security-model.md) | threats and residual risk |
| [docs/11-reference.md](docs/11-reference.md) | settings, tools, operations, errors |

## License

Source is available under [FSL-1.1-ALv2](LICENSE.md). Each release converts to Apache-2.0 two years after publication. Sallyport is not currently OSI open source.

The Sallyport name, glyph, and logo are trademarks. See [TRADEMARK.md](TRADEMARK.md).
