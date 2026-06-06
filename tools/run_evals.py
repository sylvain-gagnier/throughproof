#!/usr/bin/env python3
"""Run the compliant-logging eval corpus and report precision/recall/hygiene.

Two modes:

  Replay (deterministic — recorded agent outputs):
    python tools/run_evals.py --replay responses.json

  Live (ask an agent per case; the prompt is fed on stdin, stdout is the output):
    python tools/run_evals.py --responder 'ollama run qwen2.5-coder' --record responses.json
    python tools/run_evals.py --responder 'claude -p'

responses.json is a flat map: { "<case-id>": "<agent output code>" }.

Scoring is deterministic (the detector decides pass/fail), so replay runs are
reproducible and CI-friendly; only the live responder is non-deterministic.
"""
import argparse
import json
import subprocess
import sys
from pathlib import Path

from throughproof import evals, packs, repo

CORPUS = Path(__file__).resolve().parent / "evals" / "corpus" / "compliant-logging.yaml"


def get_outputs(cases, args) -> dict[str, str]:
    if args.replay:
        return json.loads(Path(args.replay).read_text())
    if not args.responder:
        sys.exit("error: pass --replay <file> or --responder '<cmd>'")
    outputs = {}
    for c in cases:
        proc = subprocess.run(args.responder, shell=True, input=c["prompt"],
                              capture_output=True, text=True)
        outputs[c["id"]] = proc.stdout
        print(f"  · responded: {c['id']}", file=sys.stderr)
    if args.record:
        Path(args.record).write_text(json.dumps(outputs, indent=2))
        print(f"recorded outputs -> {args.record}", file=sys.stderr)
    return outputs


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--replay", help="score recorded agent outputs (JSON map)")
    ap.add_argument("--responder", help="shell command; prompt on stdin, output on stdout")
    ap.add_argument("--record", help="when live, save outputs to this JSON file")
    ap.add_argument("--min-f1", type=float, default=0.0, help="fail if F1 below this")
    ap.add_argument("--min-hygiene", type=float, default=0.0, help="fail if hygiene rate below this")
    args = ap.parse_args()

    cases = packs.load_yaml(CORPUS)
    taxonomy = repo.load_taxonomy()
    valid_keys = packs.extract_keys(taxonomy)
    aliases = taxonomy.get("aliases", {})
    outputs = get_outputs(cases, args)

    scored = []
    for c in cases:
        out = outputs.get(c["id"], "")
        r = evals.score_case(c, out, valid_keys, aliases)
        scored.append(r)
        mark = "PASS" if r["passed"] else "FAIL"
        print(f"[{mark}] {c['id']:<22} {c['kind']:<16} {r['detail']}")

    m = evals.aggregate(scored)
    print("\n--- summary ---")
    print(f"cases       : {m['passed']}/{m['total']} passed")
    print(f"precision   : {m['precision']:.2f}   recall: {m['recall']:.2f}   f1: {m['f1']:.2f}")
    print(f"hygiene     : {m['hygiene_pass_rate']:.2f}")
    print(f"confusion   : {m['counts']}")

    if m["f1"] < args.min_f1:
        print(f"\nFAIL: f1 {m['f1']:.2f} < min {args.min_f1}", file=sys.stderr)
        return 1
    if m["hygiene_pass_rate"] < args.min_hygiene:
        print(f"\nFAIL: hygiene {m['hygiene_pass_rate']:.2f} < min {args.min_hygiene}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
