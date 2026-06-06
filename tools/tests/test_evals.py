"""Tests for the deterministic eval scorer (precision/recall via the detector)."""
from throughproof import evals

KEYS = {"log.audit", "hygiene.no-secrets"}
ALIASES = {"CC7.2": "log.audit"}

VALID_EVENT = '''
logger.info("audit", audit=True, control="log.audit", action="user.delete",
            actor=a, target=t, outcome="success", ts=now, correlation_id=cid)
'''


def score(case, output):
    return evals.score_case(case, output, KEYS, ALIASES)


def test_should_emit_with_correct_event_passes():
    r = score({"id": "e1", "kind": "should-emit", "expect_control": "log.audit"}, VALID_EVENT)
    assert r["passed"] and r["predicted_positive"]


def test_should_emit_without_marker_is_false_negative():
    r = score({"id": "e2", "kind": "should-emit", "expect_control": "log.audit"},
              "db.delete(user_id)")
    assert not r["passed"] and not r["predicted_positive"]


def test_should_emit_with_wrong_control_fails():
    bad = VALID_EVENT.replace('control="log.audit"', 'control="hygiene.no-secrets"')
    r = score({"id": "e3", "kind": "should-emit", "expect_control": "log.audit"}, bad)
    assert not r["passed"]
    assert not r["predicted_positive"]


def test_should_not_emit_with_marker_is_false_positive():
    r = score({"id": "n1", "kind": "should-not-emit"}, VALID_EVENT)
    assert not r["passed"] and r["predicted_positive"]


def test_should_not_emit_clean_passes():
    r = score({"id": "n2", "kind": "should-not-emit"}, "return db.get_health()")
    assert r["passed"] and not r["predicted_positive"]


def test_should_redact_with_leak_fails():
    r = score({"id": "r1", "kind": "should-redact"}, 'logger.info(f"pw={password}")')
    assert not r["passed"]


def test_should_redact_clean_passes():
    r = score({"id": "r2", "kind": "should-redact"}, 'logger.info("login", actor=user_id)')
    assert r["passed"]


def test_aggregate_computes_precision_recall_and_hygiene():
    scored = [
        {"kind": "should-emit", "passed": True, "predicted_positive": True},      # TP
        {"kind": "should-emit", "passed": False, "predicted_positive": False},    # FN
        {"kind": "should-not-emit", "passed": False, "predicted_positive": True}, # FP
        {"kind": "should-not-emit", "passed": True, "predicted_positive": False}, # TN
        {"kind": "should-redact", "passed": True, "predicted_positive": None},
        {"kind": "should-redact", "passed": False, "predicted_positive": None},
    ]
    m = evals.aggregate(scored)
    assert m["precision"] == 0.5
    assert m["recall"] == 0.5
    assert m["hygiene_pass_rate"] == 0.5
    assert m["counts"] == {"tp": 1, "fp": 1, "fn": 1, "tn": 1}
