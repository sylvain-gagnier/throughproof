#!/usr/bin/env python3
"""Validate every framework pack against the schema + control-key taxonomy.

Exits non-zero (and prints the offending entries) if any pack maps an unknown key,
silently omits a known key, or violates the schema. This is the CI gate that makes
coverage provable rather than assumed.
"""
import sys

from throughproof import repo


def main() -> int:
    problems = repo.validate_all()
    packs = repo.load_packs()
    if not packs:
        print("no framework packs found in compliance/frameworks/", file=sys.stderr)
        return 1
    if problems:
        for framework, errors in problems.items():
            print(f"\n✗ {framework}:")
            for e in errors:
                print(f"    - {e}")
        print(f"\n{len(problems)} pack(s) failed validation.", file=sys.stderr)
        return 1
    print(f"✓ all {len(packs)} framework pack(s) valid.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
