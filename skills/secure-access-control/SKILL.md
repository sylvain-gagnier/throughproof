---
name: secure-access-control
description: >-
  Use when writing or modifying code that ENFORCES ACCESS — authorization checks
  (who may do what), privileged/admin operations, or authentication (login, password
  handling, sessions, MFA). Ensures access is deny-by-default and least-privilege, that
  every authorization decision and privileged action emits an audit event (control keys
  `access.authz` / `access.privileged`), and that authentication uses strong password
  hashing and safe session handling (control key `access.authn`). The neutral control
  keys map to SOC 2, ISO 27001 and more via the Throughproof crosswalk
  (compliance/control-keys.yaml). Applies in any stack; use the project's existing
  auth/logger — do not invent a new framework.
license: Apache-2.0
---

# Secure access control (`access.authz` / `access.privileged` / `access.authn`) — authoring-time guidance

> Scope: this skill helps you *implement* the technical access-control controls in code. It does
> **not** make a system "compliant" — certification is the auditor's call. It makes the code satisfy
> the control and produces machine-detectable evidence.
>
> **Framework-neutral by design.** Code emits stable Throughproof *control keys* (`access.authz`,
> `access.privileged`), not framework ids. The crosswalk resolves them to SOC 2 (`CC6.1`–`CC6.3`),
> ISO 27001 (`A.8.2` / `A.8.3` / `A.8.5`), and more at once.

## When this applies

Apply this skill whenever the code under edit **enforces or grants access**:

- **Authorization decision**: a check that gates an action or resource on a role, permission,
  ownership, or scope (`require_role`, policy check, `if not user.can(...)`).
- **Privileged / admin operation**: impersonation, granting/revoking access, changing another
  user's data, config or feature-flag overrides, destructive admin jobs.
- **Authentication**: login, password set/verify/reset, session/token issuance, MFA.

If the code is an ordinary, already-authorized read with no access decision, do **not** add an
access event — over-logging is itself a finding.

## 1. Authorization — deny by default, least privilege

- **Deny by default.** The absence of an explicit *allow* is a *deny*. Never `allow` unless a check
  passed; never fall through to permit on an unknown role/branch.
- **Check at the boundary**, before the side effect — not after.
- **Least privilege.** Grant the narrowest scope that works; don't reach for admin/superuser.
- **Emit the decision** as an audit event on **both allow and deny** — the *deny* path is the
  detection signal for privilege-escalation attempts.

```python
# authorization decision — sensitive: access.authz
def open_invoice(actor, invoice_id, correlation_id):
    inv = repo.get_invoice(invoice_id)
    if not actor.can_view(inv):                       # deny-by-default
        logger.info("audit", audit=True, control="access.authz", action="invoice.view",
                    actor=actor.id, target={"type": "invoice", "id": invoice_id},
                    outcome="denied", reason="not_owner",
                    ts=now(), correlation_id=correlation_id)
        raise Forbidden()
    logger.info("audit", audit=True, control="access.authz", action="invoice.view",
                actor=actor.id, target={"type": "invoice", "id": invoice_id},
                outcome="allowed", ts=now(), correlation_id=correlation_id)
    return inv
```

## 2. Privileged operations — `access.privileged`

Grant/revoke access, impersonation, and admin overrides emit an audit event with
`control="access.privileged"`, on success **and** failure, using **ids** (never PII) for
`actor`/`target`. Same canonical shape as `access.authz`; only the control key and `action` differ.

## 3. Authentication — `access.authn` (static control)

- **Hash passwords with a strong, salted KDF**: bcrypt, argon2, scrypt, or PBKDF2. **Never** md5,
  sha1, or plaintext. **Never** compare passwords with `==` — use the library's constant-time verify.
- **Sessions/tokens**: high-entropy, httpOnly + secure cookies, sensible expiry, rotate on login,
  invalidate on logout/password-change.
- **Prefer MFA** for privileged accounts.
- Apply [`compliant-logging`](../compliant-logging/SKILL.md) hygiene: never log passwords, tokens,
  or session ids.

```python
# secure authentication — access.authn
import bcrypt
def set_password(user, raw):
    user.pw_hash = bcrypt.hashpw(raw.encode(), bcrypt.gensalt())   # ✅ salted, strong KDF
def verify_password(user, raw):
    return bcrypt.checkpw(raw.encode(), user.pw_hash)              # ✅ constant-time verify
```

### Anti-patterns (do NOT do this)

```python
if user.password == submitted:            # ❌ plaintext compare
stored = hashlib.md5(pw.encode())         # ❌ weak, unsalted hash
def admin(): do_admin()                   # ❌ no authorization check (implicit allow)
# (grant role with no audit event)        # ❌ missing detection signal on a privileged op
```

## How to apply (checklist while editing)

1. Is this an access decision, privileged op, or auth code? If no → add nothing.
2. Make authorization **deny-by-default**; check before the side effect; grant least privilege.
3. Emit `access.authz` / `access.privileged` audit events on **allow and deny / success and failure**.
4. For auth: strong salted hashing, constant-time verify, safe sessions, no secrets in logs.
5. Use the project's existing auth + logger; do not add a new dependency.

## Why the shape matters

The stable `control` + `action` + `outcome` shape lets a deterministic verifier trace each access
decision to the control it satisfies — and `access.authn` insecurities (md5/sha1, plaintext compare)
are statically detectable — so evidence maps to SOC 2 / ISO 27001 without LLM guesswork.
