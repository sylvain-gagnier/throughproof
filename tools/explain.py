#!/usr/bin/env python3
"""Show how many frameworks one control key satisfies — the multi-framework multiplier.

    python tools/explain.py log.audit
"""
import sys

from throughproof import coverage, packs, repo


def main() -> int:
    if len(sys.argv) != 2:
        keys = [k["key"] for k in repo.load_taxonomy()["keys"]]
        print("usage: python tools/explain.py <control-key>")
        print("keys:  " + ", ".join(keys))
        return 2
    key = sys.argv[1]
    rows = coverage.explain(key, repo.load_packs())
    if not rows:
        print(f"no framework mappings for {key!r}", file=sys.stderr)
        return 1
    print(f"`{key}` — one control path satisfies {len(rows)} frameworks:\n")
    for r in rows:
        print(f"  • {r['framework']:<14} {r['id']:<22} {r['clause']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
