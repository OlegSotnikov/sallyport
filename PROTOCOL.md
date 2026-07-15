# Sallyport protocol

`Sallyport.app` hosts the vault, decision engine, approval UI, audit log, and agent socket in one process. `sp mcp` is a stateless MCP-to-socket shim. `sp-ssh` is a stateless SSH helper bundled with the app.

There is no daemon-to-app approval protocol. Approvals resolve in process and are not signed. The audit signer signs audit rows and integrity anchors separately.

## Agent socket

Path: `~/.sallyport/sallyport.sock`

- The Sallyport directory and socket use mode `0700`.
- Frames are UTF-8 JSON objects terminated by `\n`.
- Valid requests and their correlated replies use a string `id`. Connection-level and malformed-frame
  errors may omit it.
- The server captures the peer PID with `LOCAL_PEERPID` and builds process provenance itself.
- The caller-supplied `identity` is a label, not the provenance trust boundary.
- The server accepts at most 32 concurrent connections and applies bounded frame and request timeouts.

### List tools

Request:

```json
{"type":"list_tools","id":"l1"}
```

Reply:

```json
{"type":"list_tools_result","id":"l1","tools":[...]}
```

While the vault is locked, the catalog contains only static built-in tools and no vault-derived host, key, or upstream names.

### Invoke a tool

Request:

```json
{
  "type":"invoke",
  "id":"c1",
  "identity":"agent://local",
  "action":{"tool":"http.request","args":{"method":"GET","url":"https://api.example.com/v1"}}
}
```

Reply:

```json
{
  "type":"invoke_result",
  "id":"c1",
  "result":{
    "ok":true,
    "output":{},
    "rule":"session.gate",
    "decision":"allow"
  }
}
```

Denied calls set `ok:false` and may include `error_code`, `reason`, `rule`, and `decision`. Secret values never appear in a reply.

Malformed frames may return:

```json
{"type":"error","error":"bad frame: ..."}
```

Unsupported frame types include the request `id` when available. Generic protocol errors may omit
both `id` and `code`.

## MCP shim

`sp mcp` reads MCP JSON-RPC from stdin and writes replies to stdout. It supports:

- `initialize`
- `notifications/initialized`
- `tools/list`
- `tools/call`

`tools/list` maps to `list_tools`. `tools/call` maps to `invoke`. The shim does not read the vault or handle credentials.

The shipped CLI has two commands:

```text
sp mcp
sp version
```

All configuration is in the Mac app.

## Decision flow

For each `invoke`, the app:

1. Denies the call if the vault is locked or quarantined.
2. Applies a per-call key requirement, if configured.
3. Applies the new-agent session gate, unless the process is already approved or allowlisted.
4. Selects observe mode when the session gate is off.
5. Writes a durable audit intent. Failure prevents execution.
6. Injects only credentials bound to the target, executes the request, and scrubs output.
7. Attempts to append the sealed, hash-chained, signed result row.

Session approval lasts until the process exits, the session is revoked, or the vault locks. A per-call approval covers one invocation. If both gates apply, one card can satisfy both.

Approval modes are `session`, `session-touchid`, `per-call`, and `per-call-touchid`. Click modes resolve directly in the app. Touch ID modes call `LAContext` before resolution. Neither mode creates a signed grant.

## Management interface

The GUI uses an in-process `MgmtClient` and `VaultMgmtDaemon`. Management messages do not cross the agent socket in production. The JSON-shaped typed interface remains testable through `ControlCodec` and the mock backend.

Operations:

| Area | Operations |
|---|---|
| Keys | `secrets.list`, `secrets.set`, `secrets.update`, `secrets.rotate`, `secrets.delete` |
| SSH hosts | `hosts.list`, `hosts.set`, `hosts.delete` |
| MCP servers | `upstreams.list`, `upstreams.set`, `upstreams.delete`, `upstreams.authorize`, `upstreams.disconnect` |
| Settings | `settings.get`, `settings.set` |
| Sessions | `sessions.list`, `sessions.history`, `sessions.revoke` |
| Allowlist | `allowlist.list`, `allowlist.capture`, `allowlist.add`, `allowlist.delete` |
| Status | `status` |

`status` is the only operation available while the vault is locked. Secret listing returns metadata only. Only `secrets.set` and `secrets.rotate` carry a secret value into the in-process management backend, and neither returns it.

When `requireTouchIDForChanges` is enabled, configuration mutations require Touch ID. `settings.set`, `allowlist.add`, and `allowlist.delete` always require Touch ID. Reads and `sessions.revoke` do not.

Settings are:

```json
{
  "sessionAuth":"off|click|touchid",
  "requireTouchIDForChanges":true,
  "logBodies":false,
  "autoLockMinutes":480,
  "lockOnScreenLock":true
}
```

`settings.set` is partial. A key's `confirm` field is `""`, `"click"`, or `"touchid"`.
`logBodies` is persisted but no current executor or audit path consumes it.

## Security invariants

1. Secret values never reach agents, audit payloads, activity rows, approval payloads, logs, or errors.
2. A locked, sealed, or quarantined vault denies tool calls.
3. The process identity used by the decision engine comes from the kernel-observed socket peer.
4. Credential injection is limited to configured hosts and paths. Credentialed cross-host and HTTPS-to-HTTP redirects are blocked.
5. Audit rows are sealed to a dedicated recipient, chained over ciphertext, and signed by the audit signer. Approval decisions are not signatures.
6. Locking clears the DEK, sessions, pending approvals, and credential requests. It also stops configured stdio MCP servers.
7. Management reads require an unlocked vault, except `status`. Management mutations use the vault's serialized integrity transaction.

## Implemented channels

- `http.request`: host-bound HTTP credentials, redirect checks, internal-network checks, and output scrubbing.
- `ssh.exec`: configured SSH hosts and imported SSH keys through `sp-ssh`, with sealed recordings when enabled.
- `sallyport.request_credential`: asks the user to add a credential and returns metadata only.
- `<upstream>.<tool>`: configured stdio or streamable-HTTP MCP servers. Remote authentication uses a host-bound API key or OAuth 2.1.

See [docs/14-trust-model.md](docs/14-trust-model.md) for the fixed decision ladder. This protocol covers implemented behavior.
