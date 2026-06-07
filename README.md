# Throughproof

**Guided. Secured. Approved.**

Write compliant code **once** — satisfy **SOC 2, ISO 27001:2022, PCI-DSS v4, and HIPAA** at the
same time.

A free, portable set of **Agent Skills** that make your AI coding agent emit the right control the
moment it touches a sensitive action — **audit logging, access control, and encryption** — done
right, with secrets and PII kept out of your logs. Each control path emits a **framework-neutral
control key** that maps across **4 frameworks × 8 control keys = 32 mappings** via the
[Throughproof crosswalk](compliance/) ([coverage matrix](compliance/COVERAGE.md)). No framework
lock-in: write the event once, satisfy every auditor. Works in **Claude Code, Cursor, GitHub
Copilot, Gemini CLI, and Google Antigravity**, and any tool that supports the `SKILL.md` standard.

## The problem

Compliance platforms (Vanta, Drata, Shasta) tell you *what's failing* and collect evidence from
systems you've **already built**. None of them sit in your editor and help you **write the compliant
code in the first place**. So the developer is still left to figure out:

- *Which* actions need an audit trail, and what fields auditors expect.
- How to log failures (the actual detection signal) — not just successes.
- How to keep secrets and PII **out** of logs while still capturing useful signal.

These skills close that gap at **authoring time** — starting with audit logging (the control most
teams get wrong), and extending the same write-it-right-the-first-time approach to access control and
encryption.

## What the free skills do

When active, your agent applies the right control **only** for genuinely **sensitive actions** — it
stays silent on ordinary code, so no noise:

- **Audit logging** — emits a single **canonical audit event** through your *existing* logger (no new
  dependency), on both success and failure paths, and refuses to log secrets, tokens, PII, or raw
  request bodies. ([`compliant-logging`](skills/compliant-logging/SKILL.md))
- **Access control** — makes authorization **deny-by-default** and least-privilege, and emits an audit
  event for every authorization decision and privileged action. ([`secure-access-control`](skills/secure-access-control/SKILL.md))
- **Encryption** — keeps sensitive data encrypted **in transit** (TLS enforced, never plaintext, never
  disabled cert verification) and **at rest**. ([`crypto-data-protection`](skills/crypto-data-protection/SKILL.md))

## See it work

The audit-logging skill is the most visceral example. **Without it**, your agent ships code like this
every day — no audit trail, PII in the log:

```python
@router.post("/users/{user_id}/delete")
def delete_user(user_id, request):
    db.delete_user(user_id)
    logger.info(f"Deleted user {user.email}")        # ❌ PII in log, no audit trail
```

**With the skill active**, the agent writes it compliant by default — structured audit event on
success *and* failure, ids instead of PII, mapped to the control:

```python
@router.post("/users/{user_id}/delete")
def delete_user(user_id, request):
    actor = getattr(request.state, "user_id", None)
    try:
        db.delete_user(user_id)
    except Exception as exc:
        logger.info({"audit": True, "control": "log.audit", "action": "user.delete",
                     "actor": actor, "target": {"type": "user", "id": user_id},
                     "outcome": "failure", "reason": type(exc).__name__})   # ✅ failure path
        raise
    logger.info({"audit": True, "control": "log.audit", "action": "user.delete",
                 "actor": actor, "target": {"type": "user", "id": user_id},
                 "outcome": "success"})                                     # ✅ id, not email
```

It does nothing on ordinary, non-sensitive code — no log spam.

## Install

Three composable, framework-neutral skills — install the domains you care about:

| Skill | Covers | Control keys |
|---|---|---|
| [`compliant-logging`](skills/compliant-logging/SKILL.md) | audit logging + log hygiene | `log.audit`, `hygiene.no-secrets` |
| [`secure-access-control`](skills/secure-access-control/SKILL.md) | authorization, privileged ops, authentication | `access.authz`, `access.privileged`, `access.authn` |
| [`crypto-data-protection`](skills/crypto-data-protection/SKILL.md) | encryption in transit + at rest | `crypto.in-transit`, `crypto.at-rest` |

The `SKILL.md` format is portable; only the install location differs per tool.

- **Claude Code** — copy the skill folder(s) into your skills dir:
  ```bash
  cp -r skills/compliant-logging ~/.claude/skills/        # user-wide
  # or, per-project:  cp -r skills/compliant-logging .claude/skills/
  ```
- **Cursor / Copilot / Gemini CLI / Google Antigravity** — place the skill folder(s) in that tool's
  skills directory (commonly `.agents/skills/`; Antigravity reads the `SKILL.md` standard natively);
  the skill body is identical across tools.

Then just write code that touches a sensitive action — the agent applies the skill automatically.

## Scope & honesty

These skills help you **implement and self-check** the technical controls behind audit logging,
log hygiene, access control, and encryption. Each framework-neutral control key (e.g. `log.audit`,
`access.authz`, `crypto.in-transit`) maps across **SOC 2** (`CC7.2 / CC6.x`), **ISO 27001:2022**
(`A.8.15 / A.8.3 / A.8.24`), **PCI-DSS v4** (`Req 10.2 / 7.2 / 4.2`), and **HIPAA** (`164.312`) via
the [Throughproof crosswalk](compliance/) — write the control once, satisfy every framework. See the
generated [coverage matrix](compliance/COVERAGE.md) for all 32 mappings. It does **not** certify
compliance — that is an auditor's determination. It makes the *code* satisfy the control and makes
that **machine-detectable**.

## Pro: deterministic verifier + audit evidence  ·  ⟶ join the waitlist

The free skills write compliant code. **Throughproof Pro** proves it: a deterministic verifier
(static analysis over your repo) that finds every sensitive code path, confirms it routes through the
right control, flags gaps and PII/secret leaks, and **exports control-to-code evidence**
(this code path ↔ `log.audit` ↔ SOC 2 `CC7.2` / ISO 27001 `A.8.15` / PCI-DSS `Req 10.2` / HIPAA
`164.312(b)`) that you can hand to an auditor — across all your repos, every framework at once,
continuously.

No LLM guesswork in the evidence layer; it's deterministic and reproducible.

**Coming soon — agent-native:** call the Pro verifier straight from your AI coding agent
(**Claude Code, Cursor, Antigravity, Gemini**) via **MCP**, to find and fix compliance gaps without
leaving your editor.

**→ Want it? Join the waitlist: https://throughproof.com**

## License

Skill content: Apache-2.0. See [`skills/compliant-logging/SKILL.md`](skills/compliant-logging/SKILL.md).
