"""Framework version-watch: flag packs pinned to a version older than the latest known.

The "latest known" registry (compliance/framework-latest.yaml) is maintained by hand
(or, later, by a web check). Comparing it to each pack's framework_version surfaces
drift so a scheduled job can alert when, e.g., a new PCI DSS revision ships.
"""
from __future__ import annotations


def check_versions(packs: list[dict], registry: dict[str, str]) -> list[dict]:
    findings = []
    for pack in packs:
        fw = pack.get("framework")
        pinned = pack.get("framework_version")
        latest = registry.get(fw)
        if latest is None:
            status = "unknown"
        elif str(pinned) == str(latest):
            status = "current"
        else:
            status = "behind"
        findings.append({"framework": fw, "pinned": pinned, "latest": latest, "status": status})
    return findings


def has_drift(findings: list[dict]) -> bool:
    return any(f["status"] == "behind" for f in findings)
