"""Tests for the multi-framework multiplier surface (#4)."""
from throughproof import coverage

TAXONOMY = {
    "version": 1,
    "keys": [
        {"key": "log.audit", "evidence_type": "runtime_marker"},
        {"key": "crypto.at-rest", "evidence_type": "static"},
    ],
}
PACKS = [
    {"framework": "soc2", "framework_version": "x", "source": "x",
     "mappings": {"log.audit": {"id": "CC7.2", "clause": "c"},
                  "crypto.at-rest": {"id": "CC6.1", "clause": "c"}}},
    {"framework": "iso27001", "framework_version": "x", "source": "x",
     "mappings": {"log.audit": {"id": "A.8.15", "clause": "c"},
                  "crypto.at-rest": {"na": True, "reason": "n/a"}}},
    {"framework": "pci-dss-v4", "framework_version": "x", "source": "x",
     "mappings": {"log.audit": {"id": "Req 10.2", "clause": "c"},
                  "crypto.at-rest": {"id": "Req 3.5", "clause": "c"}}},
]


def test_row_counts_frameworks_satisfied():
    m = coverage.build_matrix(TAXONOMY, PACKS)
    row = next(r for r in m["rows"] if r["key"] == "log.audit")
    assert row["frameworks_satisfied"] == 3      # soc2 + iso + pci
    na_row = next(r for r in m["rows"] if r["key"] == "crypto.at-rest")
    assert na_row["frameworks_satisfied"] == 2   # iso is n/a


def test_explain_lists_frameworks_for_a_key():
    out = coverage.explain("log.audit", PACKS)
    ids = {e["framework"]: e["id"] for e in out}
    assert ids == {"soc2": "CC7.2", "iso27001": "A.8.15", "pci-dss-v4": "Req 10.2"}


def test_markdown_has_frameworks_column():
    md = coverage.render_markdown(coverage.build_matrix(TAXONOMY, PACKS))
    assert "Frameworks" in md
    # the multiplier headline names the best multiplier
    assert "satisfies" in md.lower()
