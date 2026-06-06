"""Deterministic detection of canonical audit events and log-hygiene leaks.

This is the seed of the Throughproof Pro verifier and the scoring backbone of the
eval harness: given source text, decide objectively whether it carries a valid
audit event (and whether a log line leaks a secret/PII). No LLM involved.

It is intentionally a lightweight textual analyzer, not a full parser — it works
across Python and JS/TS by recognising the stable field names of the canonical
event rather than language grammar.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

# Canonical audit-event fields (see skills/compliant-logging/SKILL.md).
REQUIRED_FIELDS = {"control", "action", "actor", "target", "outcome"}
RECOMMENDED_FIELDS = {"ts", "correlation_id"}
ALL_FIELDS = REQUIRED_FIELDS | RECOMMENDED_FIELDS | {"audit", "reason"}

# Names that must never have their *value* logged (secrets + common PII).
SENSITIVE_NAMES = {
    "password", "passwd", "pwd", "secret", "token", "api_key", "apikey",
    "access_key", "authorization", "auth", "auth_token", "private_key",
    "ssn", "card", "credit_card", "cvv", "email", "phone",
}
# Raw request/response body dumps.
BODY_PATTERNS = ("req.body", "request.body", "res.body", "response.body")

_LOG_CALL = re.compile(
    r"\b(?:print|console|logger|log)\b\s*(?:\.\s*[A-Za-z]+\s*)?\(",
    re.IGNORECASE,
)


def _string_or_bool(name: str) -> re.Pattern:
    # matches  name = "v" | name: "v" | name='v' | name=True/true
    return re.compile(
        rf"""\b{re.escape(name)}\s*[:=]\s*(?:"([^"]*)"|'([^']*)'|(True|true|False|false))""",
    )


def extract_fields(source: str) -> dict[str, list[str]]:
    """Return {field_name: [string/bool values]} for canonical fields with literal values.

    Only captures string- or bool-valued fields (control, outcome, audit). Fields
    whose value is an identifier or object (actor, target, ...) won't appear here;
    use `present_fields` for presence regardless of value type.
    """
    found: dict[str, list[str]] = {}
    for name in ALL_FIELDS:
        values = []
        for m in _string_or_bool(name).finditer(source):
            values.append(next(g for g in m.groups() if g is not None))
        if values:
            found[name] = values
    return found


def present_fields(source: str) -> set[str]:
    """Return the set of canonical fields that are assigned anything (any value type)."""
    return {name for name in ALL_FIELDS if re.search(rf"\b{re.escape(name)}\s*[:=]", source)}


@dataclass
class AuditAnalysis:
    has_audit_marker: bool
    controls: list[str]
    outcomes: list[str]
    present_fields: set[str]
    errors: list[str] = field(default_factory=list)

    @property
    def is_valid(self) -> bool:
        return self.has_audit_marker and not self.errors


def analyze_audit(source: str, valid_keys, aliases: dict | None = None) -> AuditAnalysis:
    """Analyze `source` for a canonical audit event and validate its shape."""
    valid_keys = set(valid_keys)
    aliases = aliases or {}
    accepted = valid_keys | set(aliases)

    fields = extract_fields(source)
    audit_vals = fields.get("audit", [])
    has_marker = any(str(v).lower() == "true" for v in audit_vals)
    controls = fields.get("control", [])
    outcomes = fields.get("outcome", [])
    present = present_fields(source)

    errors: list[str] = []
    if not has_marker:
        # Not an audit event — nothing more to validate.
        return AuditAnalysis(False, controls, outcomes, present, errors)

    if not controls:
        errors.append("audit event has no `control` key")
    for c in controls:
        if c not in accepted:
            errors.append(f"unknown control key: {c!r} is not in the taxonomy or aliases")

    missing = sorted(REQUIRED_FIELDS - present)
    if missing:
        errors.append("missing required field(s): " + ", ".join(missing))

    return AuditAnalysis(has_marker, controls, outcomes, present, errors)


@dataclass
class StaticFinding:
    key: str          # the control key this finding bears on (e.g. crypto.in-transit)
    severity: str     # low | medium | high
    detail: str
    line: int = 0


@dataclass
class StaticAnalysis:
    bad: list[StaticFinding] = field(default_factory=list)   # insecure patterns found
    good: list[StaticFinding] = field(default_factory=list)  # secure signals credited

    @property
    def is_secure(self) -> bool:
        return not self.bad


def _scan(source: str, rules, target: str):
    """rules: list of (regex, key, severity, detail). Returns matching findings."""
    out = []
    for i, line in enumerate(source.splitlines(), start=1):
        for pattern, key, severity, detail in rules:
            if pattern.search(line):
                out.append(StaticFinding(key, severity, detail, i))
    return out


# crypto.in-transit — insecure transport
_CRYPTO_BAD = [
    (re.compile(r"http://(?!localhost|127\.0\.0\.1|0\.0\.0\.0)", re.I),
     "crypto.in-transit", "high", "plaintext http:// to a non-local host"),
    (re.compile(r"verify\s*=\s*False"),
     "crypto.in-transit", "high", "TLS certificate verification disabled (verify=False)"),
    (re.compile(r"rejectUnauthorized\s*:\s*false", re.I),
     "crypto.in-transit", "high", "TLS verification disabled (rejectUnauthorized: false)"),
    (re.compile(r"_create_unverified_context|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['\"]?0"),
     "crypto.in-transit", "high", "TLS verification globally disabled"),
]
_CRYPTO_GOOD = [
    (re.compile(r"https://|wss://", re.I),
     "crypto.in-transit", "low", "encrypted transport (https/wss)"),
    (re.compile(r"\b(?:Fernet|AES|aes-256|encrypt|kms|crypto_secretbox|nacl)\b", re.I),
     "crypto.at-rest", "low", "encryption-at-rest primitive in use"),
]

# secure authentication
_AUTH_BAD = [
    (re.compile(r"\b(?:md5|sha1)\s*\(", re.I),
     "access.authn", "high", "weak/unsalted hash (md5/sha1) used for credentials"),
    (re.compile(r"\.password\s*==|password\s*==\s*\w|==\s*\w*password", re.I),
     "access.authn", "high", "plaintext password comparison"),
]
_AUTH_GOOD = [
    (re.compile(r"\b(?:bcrypt|argon2|scrypt|pbkdf2|hashpw|checkpw)\b", re.I),
     "access.authn", "low", "strong password hashing (bcrypt/argon2/scrypt/pbkdf2)"),
]


def analyze_crypto(source: str) -> StaticAnalysis:
    return StaticAnalysis(bad=_scan(source, _CRYPTO_BAD, "crypto"),
                          good=_scan(source, _CRYPTO_GOOD, "crypto"))


def analyze_auth(source: str) -> StaticAnalysis:
    return StaticAnalysis(bad=_scan(source, _AUTH_BAD, "auth"),
                          good=_scan(source, _AUTH_GOOD, "auth"))


@dataclass
class Leak:
    line: int
    token: str
    reason: str


def find_log_leaks(source: str) -> list[Leak]:
    """Find log statements that interpolate/pass a secret or PII value."""
    leaks: list[Leak] = []
    for i, raw in enumerate(source.splitlines(), start=1):
        if not _LOG_CALL.search(raw):
            continue

        # Raw body dumps.
        for bp in BODY_PATTERNS:
            if bp in raw:
                leaks.append(Leak(i, bp, "raw request/response body logged"))

        # Interpolated / concatenated / passed variable names.
        candidates = set()
        candidates.update(re.findall(r"\$\{?\s*([A-Za-z_][\w.]*)", raw))   # ${x} / $x (JS)
        candidates.update(re.findall(r"\{\s*([A-Za-z_][\w.]*)", raw))       # {x} (py f-string)
        candidates.update(re.findall(r"\+\s*([A-Za-z_][\w.]*)", raw))       # + x (concat)
        candidates.update(re.findall(r"([A-Za-z_][\w.]*)\s*\+", raw))       # x + (concat)
        for name in candidates:
            leaf = name.split(".")[-1].lower()
            if leaf in SENSITIVE_NAMES:
                leaks.append(Leak(i, leaf, f"sensitive value {name!r} written to log"))

    # De-dupe (line, token) pairs while preserving order.
    seen = set()
    unique = []
    for lk in leaks:
        key = (lk.line, lk.token)
        if key not in seen:
            seen.add(key)
            unique.append(lk)
    return unique
