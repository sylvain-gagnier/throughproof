# Throughproof

**Guided. Secured. Approved.**

A free, portable **Agent Skill** that makes your AI coding agent write **audit-ready logging**
as you code — every sensitive action gets a structured, tamper-evident audit event, and secrets/PII
never leak into your logs. Code emits a framework-neutral control key that maps to **SOC 2 and
ISO 27001** at once (PCI-DSS and HIPAA on the roadmap) via the [Throughproof crosswalk](compliance/).
Works in **Claude Code, Cursor, GitHub Copilot, Gemini CLI**, and any tool that supports the
`SKILL.md` standard.

## The problem

Compliance platforms (Vanta, Drata, Shasta) tell you *what's failing* and collect evidence from
systems you've **already built**. None of them sit in your editor and help you **write the compliant
code in the first place**. So the developer is still left to figure out:

- *Which* actions need an audit trail, and what fields auditors expect.
- How to log failures (the actual detection signal) — not just successes.
- How to keep secrets and PII **out** of logs while still capturing useful signal.

This skill closes that gap at **authoring time**.

## What the free skill does

When active, your agent will — only for genuinely **sensitive actions** (auth changes, sensitive-data
mutations/exports, privileged ops) — emit a single **canonical audit event** through your *existing*
logger (it does not add a dependency), on both success and failure paths, and will refuse to log
secrets, tokens, PII, or raw request bodies. See [`skills/compliant-logging/SKILL.md`](skills/compliant-logging/SKILL.md).

## See it work

**Without the skill**, your agent ships code like this every day — no audit trail, PII in the log:

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
- **Cursor / Copilot / Gemini CLI** — place the skill folder(s) in that tool's skills directory
  (commonly `.agents/skills/`); the skill body is identical across tools.

Then just write code that touches a sensitive action — the agent applies the skill automatically.

## Scope & honesty

This skill helps you **implement and self-check** the technical controls behind audit logging
(control key `log.audit`) and log hygiene (`hygiene.no-secrets`). Those framework-neutral keys map
to **SOC 2** (`CC7.2 / CC7.3 / CC6.x`), **ISO 27001:2022** (`A.8.15 / A.8.16 / A.8.12`), and more via
the [Throughproof crosswalk](compliance/) — write the event once, satisfy every framework. See the
generated [coverage matrix](compliance/COVERAGE.md). It does **not** certify compliance — that is an
auditor's determination. It makes the *code* satisfy the control and makes that **machine-detectable**.

## Pro: deterministic verifier + audit evidence  ·  ⟶ join the waitlist

The free skill writes compliant logs. **Throughproof Pro** proves it: a deterministic verifier
(static analysis over your repo) that finds every sensitive code path, confirms it routes through the
canonical audit event, flags gaps and PII/secret leaks, and **exports control-to-code evidence**
(this code path ↔ `log.audit` ↔ SOC 2 `CC7.2` / ISO 27001 `A.8.15`) that you can hand to an auditor —
across all your repos, every framework at once, continuously.

No LLM guesswork in the evidence layer; it's deterministic and reproducible.

**→ Want it? Join the waitlist: https://throughproof.com**

## License

Skill content: Apache-2.0. See [`skills/compliant-logging/SKILL.md`](skills/compliant-logging/SKILL.md).
