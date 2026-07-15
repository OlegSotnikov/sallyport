# 11: Reference

## CLI

```text
sp mcp
sp version
```

`sp mcp` is the stdio MCP shim. Configuration and vault lifecycle are managed in `Sallyport.app`.

## Settings

Settings are sealed in `vault.db`.

| Field | Default | Values or effect |
|---|---:|---|
| `sessionAuth` | `click` | `off`, `click`, `touchid` |
| `requireTouchIDForChanges` | `true` | gates key, host, and upstream mutations |
| `logBodies` | `false` | compatibility field; stored but not consumed |
| `autoLockMinutes` | `480` | `0` disables TTL auto-lock |
| `lockOnScreenLock` | `true` | lock when the macOS screen locks |

`settings.set` and allowlist mutations always require Touch ID. Other configuration mutations require it while `requireTouchIDForChanges` is true. Reads and `sessions.revoke` are exempt.

Keys and upstream MCP servers have a `confirm` field:

| Value | Effect |
|---|---|
| `""` | no per-call card |
| `click` | require a click for every call |
| `touchid` | require Touch ID for every call |

The optional allowlist can skip the session gate for a matching process. It does not skip unlock or per-call approval.

## MCP tools

| Tool | Arguments |
|---|---|
| `http.request` | required `method`, `url`; optional `params`, `headers`, `body` |
| `ssh.exec` | required inventory `host`, `cmd`; optional `timeout_s` |
| `sallyport.request_credential` | required `host`, `purpose`; optional `hosts`, `kind`, `header`, `format`, `name`, `docs_url`, `scopes` |

Discovered upstream tools appear as `<upstream>.<tool>`. Upstreams that require per-call approval are
not warmed and are absent from the initial `tools/list`. Known namespaced tools can still be invoked;
a successful remote HTTP call can populate the catalog, while one-shot stdio calls remain unlisted.

While locked, `tools/list` returns only the static built-in catalog without vault-derived names. Every tool call returns `SALLYPORT_LOCKED`, including `sallyport.request_credential`.

## Management operations

Production management is in process. `status` is the only operation available while locked.

| Area | Operations |
|---|---|
| Keys | `secrets.list`, `secrets.set`, `secrets.update`, `secrets.rotate`, `secrets.delete` |
| SSH hosts | `hosts.list`, `hosts.set`, `hosts.delete` |
| MCP servers | `upstreams.list`, `upstreams.set`, `upstreams.delete`, `upstreams.authorize`, `upstreams.disconnect` |
| Allowlist | `allowlist.list`, `allowlist.capture`, `allowlist.add`, `allowlist.delete` |
| Settings | `settings.get`, `settings.set` |
| Sessions | `sessions.list`, `sessions.history`, `sessions.revoke` |
| Runtime | `status` |

Rules:

- `secrets.list` returns metadata only.
- `secrets.set` and `secrets.rotate` are the only operations carrying a secret value into the management backend. They do not return it.
- `secrets.update` changes bindings, injection format, `confirm`, and optional `insecure_tls` without changing the value.
- `allowlist.capture` reads identity from a live PID or binary path. Entries use exact cdhash or publisher requirements and may be host-scoped.
- `settings.set` is partial.
- Locked `status` returns `vault.locked=true` and zero secret and host counts.

## Error codes

| Code | Meaning |
|---|---|
| `SALLYPORT_LOCKED` | vault is sealed, locked, or still unlocking |
| `SALLYPORT_QUARANTINED` | integrity check blocked the vault pending re-adoption |
| `SALLYPORT_DENIED` | operator denied the approval |
| `SALLYPORT_ASK_TIMEOUT` | approval was not resolved before its deadline |
| `SALLYPORT_NO_APPROVER` | credential request has no available credential UI |
| `SALLYPORT_UNIDENTIFIABLE` | session authorization is on and process identity is unavailable |
| `SALLYPORT_BAD_REQUEST` | malformed invoke arguments, oversized JSON arguments, or an invalid credential request |
| `SALLYPORT_UNKNOWN_TOOL` | tool has no built-in or configured upstream route |
| `SALLYPORT_UNKNOWN_HOST` | SSH inventory name is missing |
| `SALLYPORT_BLOCKED` | network target was blocked by the HTTP guard |
| `SALLYPORT_UPSTREAM_DOWN` | HTTP, SSH, or MCP execution failed |
| `SALLYPORT_BUSY` | agent socket connection limit reached |
| `SALLYPORT_TIMEOUT` | server deadline expired |
| `SALLYPORT_UNAVAILABLE` | metadata read, engine, result encoding, or required audit write failed |

The result may also include `reason`, `rule`, and `decision`. Agents should not retry a denial without changing the request or obtaining operator action.

## Terms

- Action: canonical `{tool, args}` processed by the ladder and audit.
- Session: one live agent process identified by PID, start time, path, and signing data.
- Per-call approval: confirmation required for every use of a marked key or upstream.
- K-wrap: key that protects the vault identity and unlock path.
- DEK: 256-bit data-encryption key held in memory while unlocked and best-effort overwritten on lock.
- Sealed: encrypted under a DEK-derived key or to the audit recipient.

See [14-trust-model.md](14-trust-model.md) for decision semantics and [PROTOCOL.md](../PROTOCOL.md) for socket frames.
