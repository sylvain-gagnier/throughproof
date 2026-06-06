"""Scorer support for static controls (should-secure: crypto + auth)."""
from throughproof import evals

KEYS = {"crypto.in-transit", "crypto.at-rest", "access.authn"}


def s(case, output):
    return evals.score_case(case, output, KEYS, {})


def test_should_secure_crypto_https_passes():
    r = s({"id": "c1", "kind": "should-secure", "domain": "crypto"},
          'requests.post("https://api.example.com/charge", json=p)')
    assert r["passed"]


def test_should_secure_crypto_http_fails():
    r = s({"id": "c2", "kind": "should-secure", "domain": "crypto"},
          'requests.post("http://api.example.com/charge", json=p)')
    assert not r["passed"]
    assert "crypto.in-transit" in r["detail"]


def test_should_secure_auth_bcrypt_passes():
    r = s({"id": "a1", "kind": "should-secure", "domain": "auth"},
          "user.pw_hash = bcrypt.hashpw(raw.encode(), bcrypt.gensalt())")
    assert r["passed"]


def test_should_secure_auth_md5_fails():
    r = s({"id": "a2", "kind": "should-secure", "domain": "auth"},
          "stored = hashlib.md5(password.encode()).hexdigest()")
    assert not r["passed"]


def test_aggregate_reports_static_pass_rate():
    scored = [
        {"kind": "should-secure", "passed": True, "predicted_positive": None},
        {"kind": "should-secure", "passed": False, "predicted_positive": None},
    ]
    m = evals.aggregate(scored)
    assert m["static_pass_rate"] == 0.5
