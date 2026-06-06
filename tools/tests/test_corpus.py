"""Lint guard: the eval corpus must be well-formed and reference real control keys."""
from pathlib import Path

from throughproof import packs, repo

CORPUS = Path(__file__).resolve().parents[1] / "evals" / "corpus" / "compliant-logging.yaml"
KINDS = {"should-emit", "should-not-emit", "should-redact"}


def load_corpus():
    return packs.load_yaml(CORPUS)


def test_corpus_exists_and_nonempty():
    cases = load_corpus()
    assert isinstance(cases, list) and cases


def test_every_case_well_formed():
    valid_keys = packs.extract_keys(repo.load_taxonomy())
    seen = set()
    for c in load_corpus():
        assert c["id"] not in seen, f"duplicate case id {c['id']!r}"
        seen.add(c["id"])
        assert c["kind"] in KINDS, f"{c['id']}: bad kind {c['kind']!r}"
        assert c.get("prompt", "").strip(), f"{c['id']}: empty prompt"
        if c["kind"] == "should-emit":
            assert c.get("expect_control") in valid_keys, (
                f"{c['id']}: expect_control must be a real control key"
            )


def test_corpus_covers_all_three_kinds():
    kinds = {c["kind"] for c in load_corpus()}
    assert kinds == KINDS
