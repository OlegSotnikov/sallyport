# 02: Channels

Agents connect to Sallyport as an MCP server through `sp mcp`. The app exposes three action
channels: HTTP, SSH, and configured upstream MCP servers. Every call uses the decision ladder in
[14-trust-model.md](14-trust-model.md) and writes to the same audit chain.

Sallyport is not a TLS interception proxy. It performs structured actions as the authenticated
client, which keeps approval and audit data at the tool level. Traffic sent outside Sallyport is
outside its control.

## HTTP

`http.request` accepts:

```text
method: GET | POST | PUT | PATCH | DELETE | HEAD
url: full HTTP or HTTPS URL
params: optional query parameters
headers: optional non-credential headers
body: optional request body
```

The app resolves a credential from the URL host and path. The agent cannot select a vault key or
set reserved authentication headers. A request with no matching binding runs without credentials.

Implemented authentication adapters:

| Adapter | Behavior |
|---|---|
| `bearer` | sets a bearer authorization header |
| `basic` | sets HTTP Basic authentication |
| `header` | formats a value into a configured header |
| `aws-sigv4` | signs the request with configured region and service values |
| `oauth2` | obtains and caches an OAuth 2 client-credentials access token |

Credentials require HTTPS except for exact loopback development hosts. Credentialed redirects are
not followed. Uncredentialed requests may follow a bounded same-origin redirect chain.

Before the request, the network guard resolves the destination:

- cloud metadata and link-local addresses are always blocked;
- private, loopback, and unique-local addresses require an explicit credential binding;
- public addresses are allowed.

The validated A/AAAA snapshot is pinned for that logical request. URLSession connects through a
request-scoped, capability-authenticated loopback tunnel that can dial only numeric members of the
snapshot, while TLS still verifies and sends SNI for the original hostname. A later request resolves
and validates a fresh snapshot; retries inside the current request cannot silently re-resolve.

Responses are capped at 8 MiB by default. Sallyport returns parsed JSON when possible, otherwise a
body string. It does not inspect, classify, redact, or otherwise rewrite response and error content.
The target is a trusted credential recipient and its response may contain sensitive data, including
values it received in the request. Request and response body capture is not implemented.

## SSH

`ssh.exec` accepts a configured host name, a command, and an optional timeout. The host inventory
provides the address, user, port, SSH key reference, and host-key policy.

Sallyport imports Ed25519, RSA, and ECDSA OpenSSH private keys. During production execution:

1. The app opens the selected private key.
2. It starts `sp-ssh` with one end of a private inherited socket.
3. The helper asks the app to sign SSH authentication challenges.
4. The helper runs the command and returns output and an in-memory asciicast.
5. The app seals the recording before writing it to disk.

The private key stays in the app process. `sp-ssh` receives signatures, not key material. Key import
uses stdin because the key has not entered the vault yet; the stdin-key exec path remains only for
legacy tests.

Host-key policies are:

- `accept-new`: stage the first key during key exchange, store it in Sallyport's
  `known_hosts` only after client authentication succeeds, and reject later changes;
- `strict`: require an existing matching key.

New TOFU fingerprints are included in the audit data. A shared 8 MiB retention budget bounds
stdout, stderr, and recording data while the helper continues draining the remote process.

SSH stdout, stderr, and recording bytes are preserved without content inspection. The app seals
recordings under a DEK-derived key. Returned output and decrypted recordings may contain sensitive
commands, output, or credentials.

Sallyport does not expose a user-facing `SSH_AUTH_SOCK`. SSH-agent compatibility, git credential
integration, `ssh.copy`, and native Secure Enclave SSH-key generation are roadmap work.

## Upstream MCP

Sallyport can proxy third-party MCP servers. Discovered tools appear as `<server>.<tool>` and pass
through the same vault, approval, session, and audit checks as built-in tools. Agent-visible call
results, errors, and catalog metadata are returned without content inspection or rewriting. Treat
the upstream server as a trusted credential recipient; its output may contain sensitive data.

### Local stdio

The app launches the configured command and arguments. Secret bindings are added to the child
environment. A server with per-call credentials is started for one approved call and then stopped;
other servers may remain warm while the vault is ready.

The child process necessarily holds its environment credentials in memory. Same-user code may be
able to inspect them. Use remote HTTP MCP when that boundary is unacceptable.

### Remote HTTP

The app speaks streamable HTTP MCP over HTTPS. Loopback HTTP is allowed for development. It handles
JSON or SSE responses and sends the `Mcp-Session-Id` on later requests when the server supplies
one.

Remote authentication supports:

- an API key resolved from the endpoint's host binding;
- OAuth 2.1 with discovery, dynamic client registration, PKCE, sealed grants, and token refresh.

The current OAuth flow requires servers that support dynamic client registration. Pre-issued client
credentials are roadmap work. Redirects are refused on authenticated and OAuth requests.

An MCP server can require approval for every call. Bound keys can also carry a per-call setting; the
stronger ceremony applies. Locking the vault stops local children, clears cached sessions, and
removes vault-derived upstream tools from the catalog.

Sallyport does not warm upstreams that require per-call approval, so their tools are absent from the
initial `tools/list`. A caller that already knows `<server>.<tool>` can invoke it through the normal
approval path. A successful remote HTTP call can populate the catalog; one-shot stdio calls do not.
Automatic discovery for these upstreams is not implemented.

Authenticated MCP initialization and catalog metadata enter the agent-visible catalog without
content inspection or rewriting. Tool names, descriptions, and schemas remain arbitrary
upstream-controlled content and may include sensitive data supplied by the upstream.

## Credential requests

`sallyport.request_credential` lets an agent ask the user to add a credential. It follows the normal
vault and session gates. After admission, the app shows a separate form with the requested host,
purpose, and metadata. The agent receives `provisioned`, `message`, and an optional key name, never
the credential value.

## Summary

| Channel | Credential use | Main boundary |
|---|---|---|
| HTTP | app attaches host-bound authentication | validated DNS snapshot is pinned through connect |
| SSH | app signs for the private `sp-ssh` channel | decrypted output and recordings may be sensitive |
| Local MCP | app injects values into a child environment | the child and same-user inspection can expose them |
| Remote MCP | app attaches an API key or OAuth token | the remote server receives the authorized credential |

See [04-vault.md](04-vault.md) for key storage, [05-approvals.md](05-approvals.md) for confirmation
scope, and [06-audit.md](06-audit.md) for audit, result handling, and recordings.
