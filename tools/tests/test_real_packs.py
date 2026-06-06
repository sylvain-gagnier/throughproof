"""Integration guard: the real taxonomy + shipped framework packs must validate."""
import json
from pathlib import Path

import pytest

from throughproof import packs

REPO = Path(__file__).resolve().parents[2]
SCHEMA = json.loads((REPO / "compliance/schema/framework-pack.schema.json").read_text())
TAXONOMY = packs.load_yaml(REPO / "compliance/control-keys.yaml")
VALID_KEYS = packs.extract_keys(TAXONOMY)
PACK_FILES = sorted((REPO / "compliance/frameworks").glob("*.yaml"))


def test_packs_exist():
    assert PACK_FILES, "no framework packs found in compliance/frameworks/"
    names = {p.stem for p in PACK_FILES}
    assert {"soc2", "iso27001"} <= names


@pytest.mark.parametrize("pack_file", PACK_FILES, ids=lambda p: p.stem)
def test_real_pack_is_valid(pack_file):
    pack = packs.load_yaml(pack_file)
    errors = packs.validate_pack(pack, VALID_KEYS, SCHEMA)
    assert errors == [], f"{pack_file.name}:\n" + "\n".join(errors)


def test_aliases_point_to_real_keys():
    for alias, target in TAXONOMY.get("aliases", {}).items():
        assert target in VALID_KEYS, f"alias {alias!r} points to unknown key {target!r}"
