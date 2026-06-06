"""Deterministic eval scorer for the compliant-logging skill.

A corpus case has a `kind`:
  should-emit     - a sensitive action; the agent's output must contain a valid
                    audit event with the expected control key.
  should-not-emit - ordinary code; the agent must NOT add an audit event
                    (over-logging is itself a finding).
  should-redact   - a log line with a secret/PII; the output must not leak it.

Scoring is fully deterministic (it runs the detector over the agent's output), so
the precision/recall numbers are reproducible and CI-friendly. The non-deterministic
part — actually asking an agent to produce the output — lives in run_evals.py.
"""
from __future__ import annotations

from . import detector


def score_case(case: dict, output: str, valid_keys, aliases: dict | None = None) -> dict:
    kind = case["kind"]
    result = {"id": case.get("id"), "kind": kind, "passed": False,
              "predicted_positive": None, "detail": ""}

    if kind == "should-emit":
        a = detector.analyze_audit(output, valid_keys, aliases)
        want = case.get("expect_control")
        control_ok = (want in a.controls) if want else bool(a.controls)
        emitted = a.is_valid and control_ok
        result["predicted_positive"] = emitted
        result["passed"] = emitted
        if not emitted:
            result["detail"] = "; ".join(a.errors) or f"expected control {want!r} not emitted"

    elif kind == "should-not-emit":
        a = detector.analyze_audit(output, valid_keys, aliases)
        result["predicted_positive"] = a.has_audit_marker
        result["passed"] = not a.has_audit_marker
        if a.has_audit_marker:
            result["detail"] = "over-logging: audit event added to non-sensitive code"

    elif kind == "should-redact":
        leaks = detector.find_log_leaks(output)
        result["passed"] = not leaks
        if leaks:
            result["detail"] = "leak(s): " + ", ".join(f"{l.token}@{l.line}" for l in leaks)

    elif kind == "should-secure":
        domain = case.get("domain")
        analyze = {"crypto": detector.analyze_crypto, "auth": detector.analyze_auth}.get(domain)
        if analyze is None:
            raise ValueError(f"should-secure case needs domain crypto|auth, got {domain!r}")
        analysis = analyze(output)
        result["passed"] = analysis.is_secure
        if analysis.bad:
            result["detail"] = "; ".join(f"{b.key}: {b.detail}" for b in analysis.bad)

    else:
        raise ValueError(f"unknown case kind: {kind!r}")

    return result


def aggregate(scored: list[dict]) -> dict:
    tp = fp = fn = tn = 0
    hygiene_total = hygiene_pass = 0
    static_total = static_pass = 0

    for r in scored:
        kind = r["kind"]
        if kind == "should-emit":
            if r["predicted_positive"]:
                tp += 1
            else:
                fn += 1
        elif kind == "should-not-emit":
            if r["predicted_positive"]:
                fp += 1
            else:
                tn += 1
        elif kind == "should-redact":
            hygiene_total += 1
            if r["passed"]:
                hygiene_pass += 1
        elif kind == "should-secure":
            static_total += 1
            if r["passed"]:
                static_pass += 1

    precision = tp / (tp + fp) if (tp + fp) else 1.0
    recall = tp / (tp + fn) if (tp + fn) else 1.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    hygiene_rate = hygiene_pass / hygiene_total if hygiene_total else 1.0
    static_rate = static_pass / static_total if static_total else 1.0
    passed = sum(1 for r in scored if r["passed"])

    return {
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "hygiene_pass_rate": hygiene_rate,
        "static_pass_rate": static_rate,
        "counts": {"tp": tp, "fp": fp, "fn": fn, "tn": tn},
        "passed": passed,
        "total": len(scored),
    }
