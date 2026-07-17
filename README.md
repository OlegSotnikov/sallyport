# Sallyport

**Let your agent touch prod. Keep the keys.**

Sallyport is a free Mac app that holds API and SSH credentials in an encrypted local vault and executes authenticated actions for AI agents. The agent asks for an operation over MCP; Sallyport runs it, records it in a signed journal, and the key never appears in the agent's environment. There is no command that reveals a stored credential, and no export or recovery route either.

Website: [sallyport.dev](https://sallyport.dev)

## Why

Coding agents read `.env` files, shell variables, and config files, and so does every package they pull in. Recent npm supply-chain attacks harvested credentials from exactly those places, and a prompt-injected agent can leak a token without any malware at all.

Traditional secret managers still deliver the secret to the workload. That model breaks when the workload itself is untrusted. Sallyport inverts it: the workload gets an action, the vault keeps the secret.

The exact security boundary, including what Sallyport does not stop, is written down in [docs/14-trust-model.md](docs/14-trust-model.md) and [docs/08-security-model.md](docs/08-security-model.md). Executor responses are returned as received, so a target that echoes sensitive data is outside the credential-isolation guarantee.

## Repository

This public repository contains one source snapshot per Sallyport release. Pull requests are not accepted here. Report bugs and security issues as described in [CONTRIBUTING.md](CONTRIBUTING.md).

## Install

Install the signed and notarized DMG from [sallyport.dev](https://sallyport.dev), [Releases](../../releases), or Homebrew:

```bash
brew install --cask olegsotnikov/tap/sallyport
```

Launch the app, create the vault, add a credential, and point your MCP client at the gate:

```bash
claude mcp add sallyport -- /Applications/Sallyport.app/Contents/MacOS/sp mcp
```

From install to the first gated call takes about two minutes. Requires Apple Silicon and macOS 14 or newer. Release checksums are published with each release and in `https://sallyport.dev/downloads/manifest.json`.

## Authorization

Every action follows the fixed ladder in [docs/14-trust-model.md](docs/14-trust-model.md):

1. The vault must be ready.
2. A marked key or MCP server requires per-call approval.
3. A new process requires session approval unless observe mode or the optional allowlist applies.
4. Sallyport audits and executes the action.

Approvals use a click or Touch ID and resolve in process. They are not signed grants. A separate Secure Enclave signer signs audit rows and integrity anchors.

The app supports `http.request`, `ssh.exec`, `sallyport.request_credential`, and configured upstream MCP tools. There is no credential-reveal route, but target and upstream results may contain credentials or other sensitive data.

## Build

```bash
(cd core && go test -race ./...)
(cd mac && swift build -c release && swift test)
```

Creating the signed `.app` bundle requires the matching Apple signing identity
and provisioning profile and is performed by release CI. The public snapshot
supports source compilation and tests; it cannot reproduce Apple's signature
without the private signing material.

Run the Secure Enclave self-test from an official signed bundle:

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
| [docs/06-audit.md](docs/06-audit.md) | audit, result handling, and recordings |
| [docs/07-identity-deployment.md](docs/07-identity-deployment.md) | process identity and deployment |
| [docs/08-security-model.md](docs/08-security-model.md) | threats and residual risk |
| [docs/11-reference.md](docs/11-reference.md) | settings, tools, operations, errors |
| [docs/15-messaging.md](docs/15-messaging.md) | messaging and claims policy |

## License

Source is available under [FSL-1.1-ALv2](LICENSE.md). Each release converts to Apache-2.0 two years after publication. Sallyport is not currently OSI open source.

The Sallyport name, glyph, and logo are trademarks. See [TRADEMARK.md](TRADEMARK.md).
