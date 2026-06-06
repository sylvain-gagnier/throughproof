"""Tests for the framework version-watch."""
from throughproof import versions

REGISTRY = {"soc2": "2022", "iso27001": "2022", "pci-dss-v4": "4.0"}


def packs(*pairs):
    return [{"framework": f, "framework_version": v} for f, v in pairs]


def test_current_version_is_ok():
    findings = versions.check_versions(packs(("iso27001", "2022")), REGISTRY)
    assert findings[0]["status"] == "current"


def test_behind_version_is_flagged():
    findings = versions.check_versions(packs(("pci-dss-v4", "3.2.1")), REGISTRY)
    assert findings[0]["status"] == "behind"
    assert findings[0]["pinned"] == "3.2.1"
    assert findings[0]["latest"] == "4.0"


def test_unknown_framework_is_reported():
    findings = versions.check_versions(packs(("mystery", "1.0")), REGISTRY)
    assert findings[0]["status"] == "unknown"


def test_has_drift_true_when_any_behind():
    findings = versions.check_versions(
        packs(("iso27001", "2022"), ("pci-dss-v4", "3.2.1")), REGISTRY)
    assert versions.has_drift(findings)


def test_has_drift_false_when_all_current():
    findings = versions.check_versions(packs(("soc2", "2022")), REGISTRY)
    assert not versions.has_drift(findings)
