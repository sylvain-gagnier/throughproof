#!/usr/bin/env python3
"""Framework version-watch — flag packs pinned to an out-of-date framework revision.

Compares each compliance/frameworks/*.yaml against compliance/framework-latest.yaml.
Exits non-zero on drift, so it can run as a scheduled job and alert. Example:

    # weekly, via /schedule or cron:
    python tools/check_versions.py
"""
import sys

from throughproof import packs, repo, versions

REGISTRY = repo.COMPLIANCE / "framework-latest.yaml"


def main() -> int:
    registry = packs.load_yaml(REGISTRY)
    findings = versions.check_versions(repo.load_packs(), registry)
    for f in findings:
        icon = {"current": "✓", "behind": "⚠", "unknown": "?"}[f["status"]]
        line = f"  {icon} {f['framework']:<14} pinned={f['pinned']}"
        if f["status"] == "behind":
            line += f"  → latest={f['latest']} (REVIEW THE PACK)"
        elif f["status"] == "unknown":
            line += "  → not in framework-latest.yaml"
        print(line)
    if versions.has_drift(findings):
        print("\nframework drift detected — a pack is behind its latest known revision.",
              file=sys.stderr)
        return 1
    print("\nall framework packs are current.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
