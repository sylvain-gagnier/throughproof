"""The eval must actually discriminate: compliant code scores high, non-compliant low.

An eval that can't fail is worthless. These golden replays pin both ends so a
regression that makes the detector blind (always-pass) breaks CI.
"""
import json
from pathlib import Path

from throughproof import evals, packs, repo

EVALS = Path(__file__).resolve().parents[1] / "evals"
CORPUS = EVALS / "corpus" / "compliant-logging.yaml"


def run(replay_name):
    cases = packs.load_yaml(CORPUS)
    taxonomy = repo.load_taxonomy()
    keys = packs.extract_keys(taxonomy)
    aliases = taxonomy.get("aliases", {})
    outputs = json.loads((EVALS / replay_name).read_text())
    scored = [evals.score_case(c, outputs.get(c["id"], ""), keys, aliases) for c in cases]
    return evals.aggregate(scored)


def test_skill_on_scores_perfect():
    m = run("golden-skill-on.json")
    assert m["recall"] == 1.0
    assert m["precision"] == 1.0
    assert m["hygiene_pass_rate"] == 1.0


def test_skill_off_scores_poorly():
    m = run("golden-skill-off.json")
    assert m["recall"] == 0.0          # no audit events emitted
    assert m["hygiene_pass_rate"] == 0.0  # every log line leaks


def test_eval_separates_the_two():
    on = run("golden-skill-on.json")
    off = run("golden-skill-off.json")
    assert on["passed"] > off["passed"]
