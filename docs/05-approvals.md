# 05: Approvals

Approvals run inside `Sallyport.app`. There is no approval daemon, grant protocol, or decision signature.

## Modes and scope

| Mode | Trigger | Scope |
|---|---|---|
| `session` | first call from a new process when `sessionAuth=click` | until process exit, revoke, vault lock, or app exit |
| `session-touchid` | first call when `sessionAuth=touchid` | same session scope after Touch ID |
| `per-call` | key or MCP server has `confirm=click` | one invocation |
| `per-call-touchid` | key or MCP server has `confirm=touchid` | one invocation after Touch ID |

Per-call approval still applies inside approved, observed, or allowlisted sessions. If a new process also needs admission, one card satisfies the current call and admits that process. The stronger of the session and per-call modes wins.

The optional allowlist skips only the session card. It does not bypass per-call approval, unlock, host binding, audit, or lifecycle checks.

## Flow

```text
Engine selects an approval mode
  -> AppModel queues one ApprovalRequest
  -> notification or fallback panel presents the card
  -> click or Touch ID resolves the request
  -> Engine rechecks vault lifecycle
  -> durable audit intent
  -> session commit and execution
```

The request contains a generated id, mode, rule, reason, channel, tool, bounded summary, target, and process provenance. It does not contain the resolved credential value.

Requests time out after 120 seconds and return `SALLYPORT_ASK_TIMEOUT`. Denial returns `SALLYPORT_DENIED`. Duplicate in-flight ids are rejected, and late decisions do not resume an expired request.

Any lock or unlock while a card is pending changes the vault epoch. The engine rejects the stale approval even if the user completed it.

## Card contents

The primary card shows:

- approval scope and whether Touch ID is required;
- caller code-signing status and authority;
- executable path and process chain;
- tool, target, and bounded action summary;
- decision rule and reason;
- Deny and Approve controls.

SSH summaries include the command and host. HTTP summaries include method and URL. Upstream MCP summaries are bounded because their arguments are server-defined.

The app uses a user notification when alerts are available and an approval panel otherwise. Opening details activates the app. Notification actions resolve the same in-process request as the panel.

## Touch ID

Only biometric modes call LocalAuthentication during approval. Click modes resolve directly because vault unlock already established user presence. Touch ID confirms the local operation; it does not sign the approval or prove that the operator understood the request.

Configuration-change prompts are separate from action cards. `requireTouchIDForChanges` gates ordinary mutations, while settings and allowlist changes always require Touch ID. See [14-trust-model.md](14-trust-model.md).

## Credential requests

`sallyport.request_credential` uses the normal vault and session gates. After admission, the app opens a separate sheet where the user can review metadata and enter a value. The agent receives `provisioned`, `message`, and an optional key name.

## Prompt volume

Session approval is the default because it asks once per process run. Per-call approval is opt-in for selected keys or MCP servers. Observe mode removes session cards but retains the vault gate, per-call controls, and audit. A global biometric prompt for every action is not implemented.

## Limits

Approval identifies a process or one operation, not intent. An approved process can misuse any non-per-call credential available through Sallyport. Click approval can be automated through UI access; Touch ID raises the bar but does not protect decrypted memory or UI pixels from native code running as the user.

Approval decisions are ordinary in-process outcomes. A separate Secure Enclave audit signer signs audit rows and the integrity anchor. See [06-audit.md](06-audit.md) for journal details and [08-security-model.md](08-security-model.md) for residual risk.
