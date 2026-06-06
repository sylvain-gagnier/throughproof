"""Tests for the deterministic canonical audit-event / log-hygiene detector."""
from throughproof import detector

KEYS = {"log.audit", "log.monitor", "hygiene.no-secrets"}
ALIASES = {"CC7.2": "log.audit"}

PY_VALID = '''
logger.info("audit", audit=True, control="log.audit", action="user.delete",
            actor=actor_id, target={"type": "user", "id": user_id},
            outcome="success", ts=now, correlation_id=cid)
'''

TS_VALID = '''
logger.info({ audit: true, control: "log.audit", action: "role.grant",
  actor: actorId, target: { type: "user", id: userId },
  outcome: "failure", ts: nowIso, correlationId: cid });
'''


def test_detects_valid_python_audit_event():
    a = detector.analyze_audit(PY_VALID, KEYS, ALIASES)
    assert a.has_audit_marker
    assert "log.audit" in a.controls
    assert "success" in a.outcomes
    assert a.is_valid
    assert a.errors == []


def test_detects_valid_typescript_audit_event():
    a = detector.analyze_audit(TS_VALID, KEYS, ALIASES)
    assert a.has_audit_marker
    assert a.is_valid


def test_legacy_alias_control_is_accepted():
    src = PY_VALID.replace('control="log.audit"', 'control="CC7.2"')
    a = detector.analyze_audit(src, KEYS, ALIASES)
    assert a.is_valid
    assert a.errors == []


def test_unknown_control_key_is_flagged():
    src = PY_VALID.replace('control="log.audit"', 'control="made.up"')
    a = detector.analyze_audit(src, KEYS, ALIASES)
    assert not a.is_valid
    assert any("made.up" in e for e in a.errors)


def test_missing_required_field_is_flagged():
    src = PY_VALID.replace('outcome="success",', "")
    a = detector.analyze_audit(src, KEYS, ALIASES)
    assert not a.is_valid
    assert any("outcome" in e for e in a.errors)


def test_ordinary_code_has_no_audit_marker():
    src = 'logger.info(f"deleted user {user_id}")\nreturn db.delete(user_id)'
    a = detector.analyze_audit(src, KEYS, ALIASES)
    assert not a.has_audit_marker
    assert not a.is_valid


# --- log hygiene (secret/PII leak) detection ---

def test_detects_password_in_log():
    src = 'logger.info(f"login {user} with {password}")'
    leaks = detector.find_log_leaks(src)
    assert leaks
    assert any("password" in f.token for f in leaks)


def test_detects_email_pii_in_log():
    src = 'logger.info(f"user {user.email} logged in")'
    leaks = detector.find_log_leaks(src)
    assert any("email" in f.token for f in leaks)


def test_detects_request_body_dump():
    src = "logger.debug(req.body)"
    leaks = detector.find_log_leaks(src)
    assert any("body" in f.token for f in leaks)


def test_clean_log_with_ids_has_no_leak():
    src = 'logger.info("audit", actor=actor_id, target=user_id, correlation_id=cid)'
    assert detector.find_log_leaks(src) == []
