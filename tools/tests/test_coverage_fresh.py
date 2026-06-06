"""Freshness guard: compliance/COVERAGE.md must match the generated output.

This is the CI check that the published matrix can never silently drift from the
underlying taxonomy + packs.
"""
from throughproof import repo


def test_coverage_file_is_fresh():
    expected = repo.coverage_markdown().rstrip() + "\n"
    assert repo.COVERAGE_PATH.exists(), "COVERAGE.md missing — run tools/gen_coverage.py"
    assert repo.COVERAGE_PATH.read_text() == expected, (
        "COVERAGE.md is stale — run: python tools/gen_coverage.py"
    )


def test_all_real_packs_validate():
    assert repo.validate_all() == {}
