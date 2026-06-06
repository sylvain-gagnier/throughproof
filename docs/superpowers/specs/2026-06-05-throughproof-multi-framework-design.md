# Throughproof — Multi-Framework Compliance Design

**Date:** 2026-06-05
**Status:** Design approved, pending spec review
**Scope:** Extend Throughproof from a single SOC 2 audit-logging skill to a framework-neutral,
multi-compliance platform covering logging, access control, and cryptography — with a data-driven
extension mechanism and an eval-gated continuous-improvement loop.

---

## 1. Background & motivation

Today Throughproof ships one free skill, `compliant-logging`, that makes an AI coding agent emit a
canonical audit event on sensitive code actions, mapped to SOC 2 controls (`CC7.2`, `CC6.x`). The
marker the agent writes is the literal SOC 2 control id (`control: "CC7.2"`).

We want to support **multiple compliance frameworks** (ISO 27001 next, then PCI-DSS, HIPAA) without
forking the skill per framework. The code an agent writes to satisfy "log a privileged action" is
identical regardless of whether you call that control SOC 2 `CC7.2`, ISO `A.8.15`, or PCI `Req 10.2`
— only the *id* differs. So frameworks should be **data (columns in a crosswalk)**, not **code
(separate skills)**.

### Boundary decision (explicit)

The **free tier stays strictly authoring-time**: the skills make the agent *write* compliant code.
Repo-wide **gap analysis / triage** ("what am I missing to be compliant?") lives **only in Throughproof
Pro** (the deterministic verifier). This keeps a crisp free→Pro line: *free writes compliant code; Pro
proves it's complete.* There is no advisory/triage skill in the free tier.

---

## 2. Architecture — the spine

### 2.1 Framework-neutral control keys

Code emits a **Throughproof control key**, not a framework id. The crosswalk resolves the key to every
framework's id at verify/evidence-export time.

```
{ "audit": true, "control": "log.audit", "action": "user.delete", ... }
                            ^^^^^^^^^^^ neutral key, not "CC7.2"
```

Rationale: multi-framework was always the goal, so a SOC-2-shaped marker is the wrong anchor — it would
fight every new framework. We are early (pre-Pro, waitlist, minimal adopters), so the small breaking
change to the marker is cheapest now. A neutral key is emitted once and satisfies N frameworks.

### 2.2 Two evidence types, one map

Not every control is a runtime marker. The crosswalk treats both uniformly:

- **Runtime markers** (`log.*`, `access.*`): the agent emits `control: "<key>"` in the event. The
  verifier traces code path → marker → crosswalk → all frameworks.
- **Static / negative controls** (`crypto.*`, `hygiene.*`): no runtime marker. These are code
  *properties* (TLS enforced, column encrypted) or *absences* (no secret in a log line). The verifier
  detects them statically; the crosswalk still maps them to framework ids for evidence.

### 2.3 Control-key taxonomy + crosswalk

| TP control key      | Evidence type      | SOC 2       | ISO 27001:2022 | PCI-DSS v4 (Phase 3) |
|---------------------|--------------------|-------------|----------------|----------------------|
| `log.audit`         | runtime marker     | CC7.2       | A.8.15         | Req 10.2             |
| `log.monitor`       | runtime / config   | CC7.3       | A.8.16         | Req 10.4             |
| `access.authz`      | runtime marker     | CC6.1/6.3   | A.8.3          | Req 7                |
| `access.privileged` | runtime marker     | CC6.2       | A.8.2          | Req 7.2              |
| `access.authn`      | static + runtime   | CC6.1       | A.8.5          | Req 8                |
| `hygiene.no-secrets`| static (negative)  | CC6.x       | A.8.12         | Req 3.x              |
| `crypto.in-transit` | static             | CC6.7       | A.8.24         | Req 4                |
| `crypto.at-rest`    | static             | CC6.7       | A.8.24         | Req 3.5              |

### 2.4 Backward compatibility

The crosswalk registers legacy literals as aliases of the neutral keys:

- `CC7.2 → log.audit`
- `CC6.x → hygiene.no-secrets`

so events already emitted by current SOC-2 adopters still verify and map. Cheap insurance.

---

## 3. The data model — making "add a compliance" a data drop

### 3.1 Crosswalk as structured data

The crosswalk is a structured file (one row per TP control key), **not prose**, so a framework is a
column of mappings.

### 3.2 Framework pack format

A framework = **one file**: `frameworks/<framework-id>.yaml`. Adding a framework touches no skill code.

```yaml
framework: iso27001
framework_version: "2022"          # provenance (built in from day 1, item #7)
source: "ISO/IEC 27001:2022 Annex A"
mappings:
  log.audit:         { id: "A.8.15", clause: "Logging" }
  log.monitor:       { id: "A.8.16", clause: "Monitoring activities" }
  access.authz:      { id: "A.8.3",  clause: "Information access restriction" }
  access.privileged: { id: "A.8.2",  clause: "Privileged access rights" }
  access.authn:      { id: "A.8.5",  clause: "Secure authentication" }
  hygiene.no-secrets:{ id: "A.8.12", clause: "Data leakage prevention" }
  crypto.in-transit: { id: "A.8.24", clause: "Use of cryptography" }
  crypto.at-rest:    { id: "A.8.24", clause: "Use of cryptography" }
```

### 3.3 Schema + CI validation (provable coverage)

A JSON schema defines the pack format. CI validates every pack and **fails if a pack maps an unknown
key or silently omits a known key** — an omission must be explicit (`n/a` with a reason). Coverage is
provable, not assumed — critical for a compliance product where a silent gap is a liability.

### 3.4 Auto-generated coverage matrix

A generator reads all packs + the key taxonomy and emits a frameworks × keys matrix (published to
README/site as a badge). Filled cells = marketing ("N controls across M frameworks"); empty cells = the
roadmap. Self-documenting and always honest.

### 3.5 Provenance

Every pack entry carries `framework_version` + `source` from day 1 (cheap now, annoying to retrofit).
For a compliance tool, "where did this mapping come from" is the trust anchor. No tooling around
provenance yet — just the fields.

### 3.6 Richer control model (Phase 2)

Each TP control key gains a definition file describing *what evidence the control needs*: required
fields, retention expectation, the auditor question it answers, severity. Designed across all three
domains at once (the only way to model it consistently). Lets the free skill teach precisely and gives
Pro a credible export contract.

### 3.7 Optional repo config

`throughproof.config.yaml` (repo root) lists `frameworks: [iso27001, soc2]`. The free skill ignores it
(always emits neutral keys); Pro uses it to pick which crosswalk columns to export.

---

## 4. The skill set

Three domain skills, all framework-neutral, all linking to the one shared crosswalk:

- **`compliant-logging`** *(migrate existing)* — emits `log.audit` on sensitive actions; enforces
  `hygiene.no-secrets`. Re-pointed from `CC7.2` to neutral key, with legacy aliasing.
- **`secure-access-control`** *(new, Phase 2)* — authorization (deny-by-default, least privilege),
  privileged ops, secure authentication (hashed passwords, MFA). Emits `access.authz` /
  `access.privileged` on access *decisions*; `access.authn` is part static, part runtime.
- **`crypto-data-protection`** *(new, Phase 2)* — enforce TLS in transit, encrypt sensitive data at
  rest. No runtime marker — static code properties the verifier detects; the skill makes the agent
  write them correctly.

Skills = code patterns. Frameworks = an evidence concern (columns). A user installs the *domains* they
care about; framework selection is config the Pro verifier reads.

---

## 5. The continuous-improvement engine

### 5.1 Eval harness (the quality ratchet)

A corpus of code snippets with known expected outcomes:

- **should-emit** — sensitive action → expect the correct marker.
- **should-NOT-emit** — ordinary code → expect silence (over-logging is itself a finding).
- **should-redact** — log line with PII/secret → expect redaction/removal.

Run the skill against the corpus; measure **precision/recall**. Every skill edit — and every new domain
skill — gates on this score. Uses `skill-creator` eval tooling. This is the mechanism for *measurable,
continuous* improvement rather than guesswork. Established in Phase 1 for `compliant-logging`; each new
domain skill ships with its own corpus held to the same bar.

### 5.2 Framework version-watch (Phase 3)

Packs are versioned. A scheduled job (fits the existing `/schedule` workflow) watches for framework
revisions and flags "PCI v4.0.1 released — review the pack."

### 5.3 Multi-framework multiplier surface (Phase 3)

Make the payoff visible: one audit event you wrote = evidence for SOC 2 CC7.2 **and** ISO A.8.15 **and**
PCI Req 10.2. Surface "this code path satisfies N frameworks" in README/CLI output. Only meaningful at
≥3 frameworks, hence Phase 3.

---

## 6. Delivery plan — all eight improvements, sequenced for quality

The phases are a **build order**, not a cut list. Every item below ships; each is sequenced to the point
where it can be built *well* (several are only buildable well once their dependencies are real — the
multiplier needs ≥3 frameworks, the richer model needs all 3 domains, version-watch needs multiple
versioned packs).

### Phase 1 — Spine, proven on logging
- #1 crosswalk-as-data + pack format
- #2 schema + CI validation
- #7 provenance fields (built in from line one)
- #6 eval harness (becomes the quality gate for all later work)
- #3 coverage matrix
- Migrate `compliant-logging` → neutral keys + legacy alias
- Ship **SOC 2 + ISO 27001** packs (two packs is what proves multi-framework works)

### Phase 2 — Fan out the domains
- `secure-access-control` skill + `access.*` keys + own eval corpus
- `crypto-data-protection` skill + `crypto.*` keys + own eval corpus
- #5 richer control model, designed across all three domains
- Extend SOC 2 + ISO packs to cover the new keys

### Phase 3 — Scale frameworks + keep fresh
- **PCI-DSS v4** pack, then **HIPAA** pack (real diversity hardens the pack format)
- #8 framework version-watch scheduled job
- #4 multi-framework multiplier surface

---

## 7. The eight improvements — coverage check

| # | Improvement                         | Phase |
|---|-------------------------------------|-------|
| 1 | Crosswalk-as-data + framework packs | 1     |
| 2 | Schema + CI validation              | 1     |
| 3 | Auto-generated coverage matrix      | 1     |
| 4 | Multi-framework multiplier surface  | 3     |
| 5 | Richer control model                | 2     |
| 6 | Eval harness                        | 1     |
| 7 | Mapping provenance                  | 1     |
| 8 | Framework version-watch             | 3     |

All eight are committed; none is parked indefinitely.

---

## 8. Out of scope (free tier)

- Repo-wide gap analysis / compliance triage — **Pro only** (the deterministic verifier).
- The verifier itself, evidence export, multi-repo continuous monitoring — **Pro**.
- Organizational/process ISO Annex A controls (policies, HR, physical security) — not code-expressible,
  outside the authoring-time wedge.

---

## 9. Open questions for spec review

1. Crosswalk file format: YAML vs JSON (schema validation works for either; YAML is more readable for
   contributors, JSON is easier to consume programmatically).
2. Where the shared crosswalk + packs live in the repo (`compliance/` top-level vs under a skill).
3. Whether `log.monitor` is a distinct runtime marker or subsumed by `log.audit` in Phase 1.
