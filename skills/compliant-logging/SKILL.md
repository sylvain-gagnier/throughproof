---
name: compliant-logging
description: >-
  Use when writing or modifying code that performs a SENSITIVE ACTION —
  authentication or authorization changes, creating/updating/deleting records that hold
  personal, financial, or health data, permission/role changes, data exports, or admin
  operations. Ensures every sensitive action emits a structured, tamper-evident AUDIT
  EVENT (control key `log.audit`) and that secrets and PII never leak into logs
  (control key `hygiene.no-secrets`). The neutral control keys map to SOC 2, ISO 27001
  and more via the Throughproof crosswalk (compliance/control-keys.yaml).
  Applies in any stack; do not invent a new logging library — use the project's logger.
license: Apache-2.0
---

# Compliant logging (control keys `log.audit` / `hygiene.no-secrets`) — authoring-time guidance

> Scope: this skill helps you *implement* the audit-logging and log-hygiene controls in code.
> It does **not** make a system "compliant" — certification is the auditor's call. It makes the
> code satisfy the technical control and produces machine-detectable evidence of that.
>
> **Framework-neutral by design.** Code emits a stable Throughproof *control key*
> (`log.audit`), not a framework id. The crosswalk (`compliance/control-keys.yaml` +
> `compliance/frameworks/*.yaml`) resolves that key to every framework at once — SOC 2 `CC7.2`,
> ISO 27001 `A.8.15`, and so on. Write the event once; it counts as evidence for all of them.
> Legacy events that still emit `control: "CC7.2"` keep working — the verifier aliases them to
> `log.audit`.

## When this applies

Apply this skill whenever the code under edit performs a **sensitive action**:

- **AuthN / AuthZ**: login, logout, failed login, password/MFA change, token issue/revoke, role or
  permission change, impersonation, SSO/account link.
- **Sensitive data mutation**: create / update / **delete** of records containing personal,
  financial, health, or credential data (users, payments, PHI, API keys, billing).
- **Access to sensitive data**: bulk read / **export** / download of the above.
- **Privileged / admin operations**: config changes, feature-flag overrides, data migrations,
  destructive jobs, access grants.

If the action is **not** in this list (ordinary reads, non-sensitive CRUD, health checks), do **not**
add an audit event — over-logging is itself a finding and creates noise.

## The canonical audit event (emit exactly this shape)

Every sensitive action MUST emit one structured audit event through the project's existing logger.
The shape below is the **adoption marker**: keep the field names and the `"audit": true` flag stable
so the event is machine-detectable and maps deterministically to the control.

Required fields:

| field | meaning |
|---|---|
| `audit` | always `true` — the stable marker that tags this as an audit event |
| `control` | the Throughproof control key — `"log.audit"` for an audit event (maps to SOC 2 `CC7.2`, ISO 27001 `A.8.15`, … via the crosswalk) |
| `action` | stable verb.noun, e.g. `"user.delete"`, `"role.grant"`, `"data.export"` |
| `actor` | **id** of who did it (user id / service id / `"system"`) — never the name/email |
| `target` | **id** of the affected resource (and its type), e.g. `{ "type": "user", "id": "u_123" }` |
| `outcome` | `"success"` or `"failure"` — **log both paths** (failures are the detection signal) |
| `ts` | ISO-8601 UTC timestamp |
| `correlation_id` | request/trace id to tie the event to a request |
| `reason` | present on `"failure"` — short, non-sensitive cause (e.g. `"insufficient_role"`) |

Rules:
1. **Log the failure path too.** Missing failed-login / denied-access events is the #1 real audit gap
   — they are how brute-force and privilege-escalation get detected.
2. **Emit after the action's outcome is known**, in the same unit of work, so the event reflects reality.
3. **Never block the business action on a logging failure**, but never silently swallow it either —
   surface logging failures to your monitoring.

## Log hygiene — secrets & PII must never enter logs (control key `hygiene.no-secrets`)

When constructing **any** log line (not just audit events):

- **Never log**: passwords, tokens, API keys, secrets, session cookies, full card numbers, full SSNs,
  raw request/response bodies, `Authorization` headers.
- **Reference, don't expose** sensitive subjects: log **ids**, not names/emails/PII values. If a human
  label is unavoidable, mask it (`a***@example.com`, last-4 only).
- **No blanket body dumps.** Do not log entire request bodies "for debugging" — allow-list specific
  non-sensitive fields instead.
- Route logging through a **redaction helper** if the project has one; if not, redact at the call site.

## How to apply (checklist while editing)

1. Is the edited code a sensitive action (list above)? If no → stop, add nothing.
2. Add the canonical audit event on **both** success and failure paths, using the project's logger.
3. Use **ids**, not PII, in `actor`/`target`. Add `correlation_id` from the request context.
4. Scan every log statement you touched for secrets/PII; redact or remove.
5. Do not add a new logging dependency — adapt to the project's existing logger/format.

## Examples

### Python (structlog / stdlib logging)

```python
# user deletion endpoint — sensitive: data.delete on a user record
def delete_user(actor_id: str, user_id: str, correlation_id: str) -> None:
    try:
        repo.delete_user(user_id)
    except Exception as e:
        logger.info(
            "audit",
            audit=True, control="log.audit", action="user.delete",
            actor=actor_id, target={"type": "user", "id": user_id},
            outcome="failure", reason=type(e).__name__,
            ts=datetime.now(timezone.utc).isoformat(), correlation_id=correlation_id,
        )
        raise
    logger.info(
        "audit",
        audit=True, control="log.audit", action="user.delete",
        actor=actor_id, target={"type": "user", "id": user_id},
        outcome="success",
        ts=datetime.now(timezone.utc).isoformat(), correlation_id=correlation_id,
    )
```

### TypeScript (pino / winston)

```ts
// role grant — sensitive: authorization change
async function grantRole(actorId: string, userId: string, role: string, correlationId: string) {
  const base = {
    audit: true, control: "log.audit", action: "role.grant",
    actor: actorId, target: { type: "user", id: userId },
    ts: new Date().toISOString(), correlationId,
  };
  try {
    await db.grantRole(userId, role);
    logger.info({ ...base, outcome: "success" });
  } catch (err) {
    logger.info({ ...base, outcome: "failure", reason: "grant_failed" });
    throw err;
  }
}
```

### Anti-patterns (do NOT do this)

```ts
logger.info(`User ${user.email} logged in with ${password}`); // ❌ PII + secret in log
logger.debug(req.body);                                       // ❌ blanket body dump
// (no failure-path logging on a denied access)               // ❌ missing detection signal
await audit(...).catch(() => {});                             // ❌ silently swallowed
```

## Why the shape matters

The stable `audit:true` + `control` + `action` + `outcome` shape is what lets a deterministic verifier
later trace each sensitive code path to the control it satisfies and export audit-ready evidence. Keep
it consistent across the codebase — consistency *is* the evidence.
