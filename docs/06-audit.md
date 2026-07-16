# 06: Audit and result handling

## Audit log

Sallyport stores one JSONL audit chain under `~/.sallyport/audit`. Activity restores from that chain.
Sessions reads in-process live and ended state, which is not restored after app exit; session
lifecycle events are also appended to the audit.

Each disk row contains:

```json
{
  "seq": 42,
  "sealed": "<base64 ECIES ciphertext>",
  "prev_hash": "<hex>",
  "this_hash": "<hex>",
  "sig": "<base64 DER ECDSA>"
}
```

`sealed` is canonical event JSON encrypted to the vault's P-256 audit recipient. The recipient public key is available while locked; its private identity is sealed under the DEK. Sallyport can therefore record locked-vault denials without decrypting the vault, but it can read event contents only after unlock.

The chain hash is computed over `seq` and ciphertext. Structural verification does not require the DEK. In production, a separate Secure Enclave audit signer signs each `this_hash`. Development and tests may use a software signer.

An external `integrity-anchor.json` binds the journal head, configuration generation, and trust-bearing vault ciphertext. Unlock verifies the journal, signer, anchor, replay floor, and sealed state before the vault enters `ready`. A mismatch places the vault in quarantine. Re-adoption requires Touch ID.

An intent row is durably written before a side effect. Write, signature, or `fsync` failure at this
stage prevents execution. After execution, Sallyport attempts to append a result row. If the result
row for a successful action cannot be written, Sallyport returns `SALLYPORT_UNAVAILABLE`; the action
may have completed and must not be retried automatically.

## Events

Activity events include:

- timestamp, channel, tool, and target;
- bounded arguments preview;
- decision and ladder rule;
- origin process and code-signing data;
- result status and byte count;
- SSH host-key fingerprint and recording path when applicable.

Session events record admission, observation, exit, revoke, vault lock, and orphan reconciliation after an unclean shutdown. Live sessions remain in memory and are cleared on lock or app exit.

Sallyport-injected secret values are not intentionally written to the audit event. Caller-supplied
commands and argument previews can still contain sensitive data. Treat a decrypted journal as
sensitive.

`logBodies` is a persisted setting but no current executor or audit path consumes it. Request and response body capture is not implemented.

## Executor results

HTTP and MCP results, errors, and catalog metadata are returned after protocol parsing and within
their resource limits. Sallyport does not inspect, classify, redact, or otherwise rewrite their
application content. The target or upstream server is a trusted credential recipient and may return
credentials or other sensitive data. Sallyport has no credential reveal route and does not
intentionally add stored credentials to a result, but that is not a non-disclosure guarantee for
target-controlled content.

Exact byte coincidences are left untouched. This avoids corrupting legitimate results and keeps
Sallyport out of the role of a content-classification layer.

## SSH recordings

`sp-ssh` returns an asciicast to the app. The app seals it under a DEK-derived key and writes `~/.sallyport/recordings/*.cast.sealed`. Failure to create the recording denies `ssh.exec`.

The Activity detail can decrypt and save a recording while the vault is unlocked. SSH stdout,
stderr, and recordings are preserved without content inspection. The private key does not enter the
helper, but commands and remote output can contain credentials or other sensitive data. Treat
returned output and decrypted recordings as sensitive.

HTTP responses are capped at 8 MiB by default. SSH helper output and MCP frames also have fixed resource limits.

See [08-security-model.md](08-security-model.md) for residual risks and [10-roadmap.md](10-roadmap.md) for planned hardening.
