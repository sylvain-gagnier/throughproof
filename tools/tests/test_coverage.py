"""Tests for the coverage-matrix generator."""
from throughproof import coverage

TAXONOMY = {
    "version": 1,
    "keys": [
        {"key": "log.audit", "domain": "logging", "evidence_type": "runtime_marker"},
        {"key": "crypto.at-rest", "domain": "crypto", "evidence_type": "static"},
    ],
}
PACKS = [
    {"framework": "soc2", "framework_version": "2022", "source": "x",
     "mappings": {"log.audit": {"id": "CC7.2", "clause": "c"},
                  "crypto.at-rest": {"id": "CC6.1", "clause": "c"}}},
    {"framework": "iso27001", "framework_version": "2022", "source": "y",
     "mappings": {"log.audit": {"id": "A.8.15", "clause": "c"},
                  "crypto.at-rest": {"na": True, "reason": "n/a here"}}},
]


def test_matrix_has_row_per_key_and_column_per_framework():
    m = coverage.build_matrix(TAXONOMY, PACKS)
    assert [r["key"] for r in m["rows"]] == ["log.audit", "crypto.at-rest"]
    assert m["frameworks"] == ["iso27001", "soc2"]  # sorted


def test_matrix_cell_shows_mapped_id():
    m = coverage.build_matrix(TAXONOMY, PACKS)
    row = next(r for r in m["rows"] if r["key"] == "log.audit")
    assert row["cells"]["soc2"] == "CC7.2"
    assert row["cells"]["iso27001"] == "A.8.15"


def test_matrix_marks_na_cell():
    m = coverage.build_matrix(TAXONOMY, PACKS)
    row = next(r for r in m["rows"] if r["key"] == "crypto.at-rest")
    assert row["cells"]["iso27001"] == "n/a"


def test_render_markdown_contains_header_and_ids():
    md = coverage.render_markdown(coverage.build_matrix(TAXONOMY, PACKS))
    assert "| Control key |" in md
    assert "iso27001" in md and "soc2" in md
    assert "CC7.2" in md
    assert "log.audit" in md


def test_summary_counts_covered_controls():
    m = coverage.build_matrix(TAXONOMY, PACKS)
    # log.audit covered by both; crypto.at-rest covered by soc2 only (iso is n/a)
    assert m["summary"]["frameworks"] == 2
    assert m["summary"]["control_keys"] == 2
    assert m["summary"]["mapped_cells"] == 3
