#!/usr/bin/env python3
"""Generate compliance/COVERAGE.md from the taxonomy + framework packs."""
import sys

from throughproof import repo


def main() -> int:
    content = repo.coverage_markdown().rstrip() + "\n"
    check = "--check" in sys.argv
    current = repo.COVERAGE_PATH.read_text() if repo.COVERAGE_PATH.exists() else ""
    if check:
        if current != content:
            print("COVERAGE.md is stale — run: python tools/gen_coverage.py", file=sys.stderr)
            return 1
        print("COVERAGE.md is up to date.")
        return 0
    repo.COVERAGE_PATH.write_text(content)
    print(f"Wrote {repo.COVERAGE_PATH.relative_to(repo.REPO)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
