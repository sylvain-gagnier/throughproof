# Throughproof tooling

Deterministic tooling behind the framework-neutral compliance spine. No LLM in the
evidence/validation path — everything here is reproducible.

## Setup

```bash
python -m venv .venv && . .venv/bin/activate
pip install -r tools/requirements.txt
```

## Commands

| Command | What it does |
|---|---|
| `pytest` | Unit tests for the validator, detector, coverage generator, and eval scorer. |
| `python tools/validate_packs.py` | Validate every `compliance/frameworks/*.yaml` against the schema + taxonomy. Fails on unknown keys or silent gaps. |
| `python tools/gen_coverage.py` | Regenerate `compliance/COVERAGE.md` from the data. |
| `python tools/gen_coverage.py --check` | CI guard: fail if `COVERAGE.md` is stale. |
| `python tools/run_evals.py --replay <file.json>` | Score recorded agent outputs (deterministic). |
| `python tools/run_evals.py --corpus <name>.yaml --responder '<cmd>' --record out.json` | Run a corpus live against an agent (prompt on stdin, output on stdout), e.g. `--responder 'ollama run qwen2.5-coder'` or `--responder 'claude -p'`. |
| `python tools/check_versions.py` | Version-watch: flag any pack pinned behind `compliance/framework-latest.yaml`. Schedule it. |
| `python tools/explain.py <control-key>` | Show how many frameworks one control path satisfies (the multiplier). |

## Layout

```
compliance/
  control-keys.yaml          # the control-key taxonomy (single source of truth)
  schema/framework-pack.*    # JSON schema for a framework pack
  frameworks/*.yaml          # one pack per framework (soc2, iso27001, ...)
  COVERAGE.md                # generated frameworks x keys matrix
tools/throughproof/
  packs.py        # load + validate framework packs
  detector.py     # deterministic audit-event / log-hygiene detection (seed of Pro)
  coverage.py     # build + render the coverage matrix
  evals.py        # deterministic precision/recall scorer
tools/evals/
  corpus/*.yaml              # eval cases (should-emit / should-not-emit / should-redact)
  golden-skill-on.json       # compliant outputs — must score 1.0
  golden-skill-off.json      # non-compliant outputs — must score poorly (proves the eval discriminates)
```

## Adding a framework

Drop one file in `compliance/frameworks/<id>.yaml` mapping every control key (or
`{na: true, reason: ...}`), then run `validate_packs.py` and `gen_coverage.py`. No
code changes.
