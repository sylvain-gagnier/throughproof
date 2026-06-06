"""Phase 2 eval discrimination: access + crypto corpora separate compliant from not.

Honest limitation encoded below: heuristic static detection catches insecure transport
and weak auth, but it CANNOT detect *missing* at-rest encryption (absence isn't a
pattern), so the crypto-off replay still partially passes. The test pins that reality
rather than pretending coverage is total.
"""
import json
from pathlib import Path

from throughproof import evals, packs, repo

EVALS = Path(__file__).resolve().parents[1] / "evals"
CORPUS = EVALS / "corpus"


def run(corpus_name, replay_name):
    cases = packs.load_yaml(CORPUS / corpus_name)
    taxonomy = repo.load_taxonomy()
    keys = packs.extract_keys(taxonomy)
    aliases = taxonomy.get("aliases", {})
    outputs = json.loads((EVALS / replay_name).read_text())
    scored = [evals.score_case(c, outputs.get(c["id"], ""), keys, aliases) for c in cases]
    return evals.aggregate(scored)


def test_access_skill_on_scores_high():
    m = run("secure-access-control.yaml", "golden-access-on.json")
    assert m["recall"] == 1.0
    assert m["static_pass_rate"] == 1.0


def test_access_skill_off_scores_low():
    m = run("secure-access-control.yaml", "golden-access-off.json")
    assert m["recall"] == 0.0          # no access events emitted
    assert m["static_pass_rate"] == 0.0  # md5 + plaintext compare both flagged


def test_crypto_skill_on_scores_high():
    m = run("crypto-data-protection.yaml", "golden-crypto-on.json")
    assert m["static_pass_rate"] == 1.0


def test_crypto_skill_off_scores_low_except_at_rest_blind_spot():
    m = run("crypto-data-protection.yaml", "golden-crypto-off.json")
    # 3 in-transit cases flagged; the 1 at-rest absence is a known false negative.
    assert m["static_pass_rate"] == 0.25


def test_each_skill_separates_on_from_off():
    for corpus, on, off in [
        ("secure-access-control.yaml", "golden-access-on.json", "golden-access-off.json"),
        ("crypto-data-protection.yaml", "golden-crypto-on.json", "golden-crypto-off.json"),
    ]:
        assert run(corpus, on)["passed"] > run(corpus, off)["passed"]
