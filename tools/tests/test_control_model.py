"""The richer control model: every key must carry severity, an auditor question,
and the evidence detail appropriate to its type (required_fields or verify hint)."""
from throughproof import repo

TAXONOMY = repo.load_taxonomy()
KEYS = TAXONOMY["keys"]
SEVERITIES = {"low", "medium", "high"}


def test_every_key_has_severity_and_auditor_question():
    for k in KEYS:
        assert k.get("severity") in SEVERITIES, f"{k['key']}: bad/missing severity"
        assert k.get("auditor_question", "").strip(), f"{k['key']}: missing auditor_question"


def test_runtime_markers_declare_required_fields():
    for k in KEYS:
        if k["evidence_type"] == "runtime_marker":
            fields = k.get("required_fields")
            assert isinstance(fields, list) and fields, f"{k['key']}: needs required_fields"
            assert "control" in fields and "outcome" in fields


def test_static_controls_declare_verify_hint():
    for k in KEYS:
        if k["evidence_type"] in {"static", "static_negative"}:
            assert k.get("verify", "").strip(), f"{k['key']}: static control needs a verify hint"
