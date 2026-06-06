"""Lint guard: every eval corpus must be well-formed and reference real control keys."""
from pathlib import Path

import pytest

from throughproof import packs, repo

CORPUS_DIR = Path(__file__).resolve().parents[1] / "evals" / "corpus"
CORPUS_FILES = sorted(CORPUS_DIR.glob("*.yaml"))
EMIT_KINDS = {"should-emit", "should-not-emit"}
KINDS = EMIT_KINDS | {"should-redact", "should-secure"}
DOMAINS = {"crypto", "auth"}

VALID_KEYS = packs.extract_keys(repo.load_taxonomy())


def test_corpus_files_exist():
    names = {p.stem for p in CORPUS_FILES}
    assert {"compliant-logging", "secure-access-control", "crypto-data-protection"} <= names


@pytest.mark.parametrize("corpus_file", CORPUS_FILES, ids=lambda p: p.stem)
def test_every_case_well_formed(corpus_file):
    cases = packs.load_yaml(corpus_file)
    assert isinstance(cases, list) and cases
    seen = set()
    for c in cases:
        cid = c["id"]
        assert cid not in seen, f"duplicate case id {cid!r}"
        seen.add(cid)
        assert c["kind"] in KINDS, f"{cid}: bad kind {c['kind']!r}"
        assert c.get("prompt", "").strip(), f"{cid}: empty prompt"
        if c["kind"] == "should-emit":
            assert c.get("expect_control") in VALID_KEYS, f"{cid}: expect_control must be a real key"
        if c["kind"] == "should-secure":
            assert c.get("domain") in DOMAINS, f"{cid}: should-secure needs domain crypto|auth"
