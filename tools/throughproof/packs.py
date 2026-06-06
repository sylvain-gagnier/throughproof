"""Load and validate Throughproof framework packs.

A framework pack maps Throughproof control keys to a specific compliance
framework's control ids. Validation enforces two things the JSON schema cannot:
no unknown keys, and no silent omissions (every known key must be mapped or
explicitly marked not-applicable with a reason).
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable

import yaml
from jsonschema import Draft7Validator


def load_yaml(path: str | Path) -> dict:
    return yaml.safe_load(Path(path).read_text())


def load_json(path: str | Path) -> dict:
    return json.loads(Path(path).read_text())


def extract_keys(taxonomy: dict) -> set[str]:
    """Return the set of valid control-key names from the control-keys taxonomy."""
    return {entry["key"] for entry in taxonomy.get("keys", [])}


def validate_pack(pack: dict, valid_keys: Iterable[str], schema: dict) -> list[str]:
    """Validate a framework pack. Returns a list of human-readable errors ([] = valid)."""
    valid_keys = set(valid_keys)
    errors: list[str] = []

    # 1. Structural / provenance / na-requires-reason rules live in the schema.
    for err in sorted(Draft7Validator(schema).iter_errors(pack), key=lambda e: e.path):
        location = "/".join(str(p) for p in err.path) or "<root>"
        errors.append(f"schema: {location}: {err.message}")

    mappings = pack.get("mappings", {})

    # 2. No unknown keys.
    for key in mappings:
        if key not in valid_keys:
            errors.append(f"unknown control key: {key!r} is not in the control-keys taxonomy")

    # 3. No silent omissions — every known key must be present (mapped or na+reason).
    for key in sorted(valid_keys):
        if key not in mappings:
            errors.append(
                f"missing mapping for control key: {key!r} "
                f"(map it, or use {{na: true, reason: ...}} if intentionally not applicable)"
            )

    return errors
