# 15: Messaging and claims policy

This document governs marketing copy: the website (`website/src/messages/`), the repository
README, release notes, blog posts, and launch materials. Engineering docs stay factual and are
not covered. When a claim here conflicts with [14-trust-model.md](14-trust-model.md), the trust
model wins and this document must be corrected.

## Positioning

- Audience: engineers who let local coding agents (Claude Code, Cursor, Codex, and other MCP
  clients) touch real infrastructure.
- The alternative Sallyport replaces is the default habit, not another vendor: keys in `.env`,
  shell variables, and agent config files that any process and any dependency can read.
- Promise: the agent gets an action, the vault keeps the secret, the journal keeps the receipt.
- Proof: named supply-chain incidents (see below), the fixed decision ladder, and a published
  boundary section that says what Sallyport does not stop.

## Claims tiers

Each surface carries the level of qualification its reader needs. Headline surfaces state a
claim plainly and link to the boundary; the security page and the engineering docs carry the
full precision. One caveat stated in the right place beats the same caveat repeated on every
page.

| Tier | Surfaces | Rules |
|---|---|---|
| 1 | Home page, footer, meta tags, README opening, social posts | Only claims from the approved list below, stated plainly, no inline caveats. Link toward the boundary instead of restating it. |
| 2 | /features, quickstart, blog posts | Mechanism language. May reference the boundary in one sentence with a link to /security. |
| 3 | /security, docs/, FAQ answers that need nuance | Full precision: "not intentionally added", "without content inspection", "may contain sensitive data" belong here. |

## Approved tier-1 claims

Each claim is anchored to documented behavior. Do not strengthen them.

| Claim | Truth anchor |
|---|---|
| There is no command that reveals a stored credential, and no export or recovery route. | 14-trust-model; vault has no reveal/export/recovery. |
| For built-in HTTP and SSH, the key never appears in the agent's environment. | 02-channels; credential attaches inside the executor. |
| You approve runs with a click or Touch ID; a synthetic click cannot satisfy the biometric prompt. | 05-approvals. |
| Local only: no account, no cloud service, no telemetry. Free download. | 00-vision principles; FSL-1.1-ALv2 licensing. |
| Every admitted action lands in an encrypted, hash-chained, tamper-evident journal. | 06-audit. |
| While the vault is locked, every agent action is denied. | 14-trust-model vault gate. |
| Setup is about two minutes: brew install, add a key, add the MCP shim. | download quickstart; keep honest if onboarding grows. |

## Claims we do not make

- "The agent can never see a secret." False: executor responses are returned as received and a
  target can echo sensitive data. The tier-3 phrasing covers this.
- "Stops prompt injection." Sallyport contains the blast radius; it does not detect or block
  injected instructions.
- Anything implying content inspection, request-intent analysis, sandboxing of MCP upstreams,
  host firewalling, or antivirus behavior.
- "Open source" without qualification. It is Fair Source (FSL-1.1-ALv2) converting to
  Apache-2.0 after two years.
- Blanket key-isolation claims that ignore local stdio MCP servers, which do receive bound
  credentials in their environment.

## Incident facts for reuse

Verified against the /security page sources; recheck before citing in new material.

- May 2026, TanStack npm attack: 84 malicious versions across 42 packages harvested cloud
  credentials, GitHub tokens, and SSH keys at install time, then spread through victims' packages.
- Late 2025, Shai-Hulud campaigns: compromised npm packages stole secrets on install and used
  stolen credentials to propagate; later variants abused CI and self-hosted runners.
- August 2025, Nx S1ngularity: malicious versions scanned developer machines for secrets,
  attempted to use local AI tools, and exfiltrated through the GitHub CLI.

The common line: all of them read credentials from environment variables and files on disk.

## Voice

- Confident, concrete, engineer-to-engineer. Lead with what the reader gets or loses.
- Keep the "What Sallyport doesn't promise" section on the home page. Published limits are part
  of the pitch, not a concession.
- Write like a person: plain verbs, varied sentence length, specific nouns. No em dashes, no
  inflated significance, no formula contrasts, no filler transitions.
- English (`en.json`) is the source locale; translations carry meaning and tone, not word order.
- Numbers beat adjectives. "84 malicious versions" is stronger than any warning about a
  dangerous ecosystem.
