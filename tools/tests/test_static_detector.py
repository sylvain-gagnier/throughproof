"""Tests for the static (heuristic) crypto + secure-auth detectors."""
from throughproof import detector


# --- crypto: transport security ---

def test_flags_plaintext_http_url():
    f = detector.analyze_crypto('requests.post("http://api.example.com/pay", data=d)')
    assert any(x.key == "crypto.in-transit" for x in f.bad)


def test_allows_https_url():
    f = detector.analyze_crypto('requests.post("https://api.example.com/pay", data=d)')
    assert not any(x.key == "crypto.in-transit" for x in f.bad)
    assert f.good  # https credited as a good signal


def test_localhost_http_is_not_flagged():
    f = detector.analyze_crypto('requests.get("http://localhost:8000/health")')
    assert not f.bad


def test_flags_disabled_tls_verification_python():
    f = detector.analyze_crypto("requests.get(url, verify=False)")
    assert any(x.key == "crypto.in-transit" for x in f.bad)


def test_flags_disabled_tls_verification_node():
    f = detector.analyze_crypto("const a = new https.Agent({ rejectUnauthorized: false });")
    assert any(x.key == "crypto.in-transit" for x in f.bad)


def test_credits_encryption_at_rest_signal():
    f = detector.analyze_crypto("token = Fernet(key).encrypt(secret.encode())")
    assert any(x.key == "crypto.at-rest" for x in f.good)


# --- secure authentication ---

def test_flags_md5_password_hashing():
    f = detector.analyze_auth("stored = hashlib.md5(password.encode()).hexdigest()")
    assert f.bad
    assert any("md5" in x.detail.lower() for x in f.bad)


def test_flags_plaintext_password_comparison():
    f = detector.analyze_auth("if user.password == password:\n    login()")
    assert f.bad


def test_credits_bcrypt():
    f = detector.analyze_auth("ok = bcrypt.checkpw(password.encode(), user.pw_hash)")
    assert not f.bad
    assert f.good


def test_findings_carry_severity():
    f = detector.analyze_auth("stored = hashlib.sha1(password.encode())")
    assert all(x.severity in {"low", "medium", "high"} for x in f.bad)
