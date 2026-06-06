---
name: crypto-data-protection
description: >-
  Use when writing or modifying code that MOVES OR STORES SENSITIVE DATA — outbound
  HTTP/API calls, network clients, TLS/SSL configuration, database schema or writes for
  personal/financial/health/credential data, file or object storage, backups, or caches.
  Ensures sensitive data is encrypted IN TRANSIT (TLS enforced, never plaintext http, never
  disabled certificate verification — control key `crypto.in-transit`) and AT REST (strong
  encryption for sensitive fields/blobs — control key `crypto.at-rest`). The neutral control
  keys map to SOC 2 (`CC6.7` / `CC6.1`), ISO 27001 (`A.8.24`) and more via the Throughproof
  crosswalk. Applies in any stack; use the platform's crypto/TLS — do not roll your own.
license: Apache-2.0
---

# Crypto data protection (`crypto.in-transit` / `crypto.at-rest`) — authoring-time guidance

> Scope: this skill helps you *implement* the encryption controls in code. It does **not** certify
> compliance. It makes the code satisfy the control and makes that **statically detectable** (these
> are code properties, not runtime events — there is no marker to emit).
>
> **Framework-neutral by design.** The control keys `crypto.in-transit` / `crypto.at-rest` map to
> SOC 2 (`CC6.7` / `CC6.1`), ISO 27001 (`A.8.24`), and more via the crosswalk.

## When this applies

- **In transit**: any outbound request, network client, webhook, or service-to-service call;
  any TLS/SSL setup.
- **At rest**: schema or writes for sensitive data (PII, financial, health, credentials, tokens);
  file/object/blob storage; backups; caches that hold the above.

Ordinary in-process data with no network or persistence boundary does not need this skill.

## 1. Encrypt in transit — `crypto.in-transit`

- **Always `https://` / `wss://`** for anything leaving the process. Never `http://` to a remote
  host (localhost during dev is fine).
- **Never disable certificate verification.** No `verify=False` (Python requests),
  no `rejectUnauthorized: false` (Node), no `NODE_TLS_REJECT_UNAUTHORIZED=0`, no
  `_create_unverified_context`. If a cert is failing, fix the trust store — don't turn off TLS.
- Prefer **TLS 1.2+**; let the platform negotiate rather than pinning weak ciphers.

```python
# ✅ encrypted transport, verification on (the default)
requests.post("https://api.payments.example.com/charge", json=payload, timeout=10)
```

## 2. Encrypt at rest — `crypto.at-rest`

- **Encrypt sensitive fields/blobs** with a vetted library (Fernet, AES-GCM, libsodium/NaCl) or the
  datastore's native encryption (column encryption, KMS-backed envelope encryption).
- **Keys come from a secrets manager / KMS**, never hard-coded, never committed.
- **Credentials are hashed, not encrypted** — see [`secure-access-control`](../secure-access-control/SKILL.md)
  (`access.authn`) for password hashing; this skill is for data you must later read back.

```python
# ✅ field-level encryption at rest with a KMS-managed key
from cryptography.fernet import Fernet
cipher = Fernet(kms.get_data_key())
record.ssn_enc = cipher.encrypt(ssn.encode())     # store ciphertext, not plaintext
```

### Anti-patterns (do NOT do this)

```python
requests.get(url, verify=False)                      # ❌ TLS verification disabled
fetch("http://internal.api/charge")                  # ❌ plaintext http to a remote host
new https.Agent({ rejectUnauthorized: false })       # ❌ TLS verification disabled (Node)
db.save(ssn=ssn)                                      # ❌ sensitive field stored in plaintext
key = "hardcoded-secret-key"                          # ❌ key in source
```

## How to apply (checklist while editing)

1. Does this code cross a network or persistence boundary with sensitive data? If no → nothing.
2. In transit: enforce `https`/`wss`; never disable certificate verification.
3. At rest: encrypt sensitive fields/blobs with a vetted library; keys from KMS/secrets manager.
4. Hash (don't encrypt) passwords — defer to `secure-access-control`.
5. Use the platform's crypto/TLS; do not roll your own.

## Why it matters

`crypto.in-transit` and `crypto.at-rest` are **static code properties** the Throughproof verifier
detects directly (plaintext `http://`, disabled TLS verification, missing encryption) and maps to
SOC 2 / ISO 27001 — deterministic evidence, no runtime marker required.
