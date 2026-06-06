"""Tests for the framework-pack loader + validator."""
import json
from pathlib import Path

import pytest

from throughproof import packs

REPO = Path(__file__).resolve().parents[2]
SCHEMA = json.loads((REPO / "compliance/schema/framework-pack.schema.json").read_text())

VALID_KEYS = {"log.audit", "hygiene.no-secrets", "crypto.at-rest"}


def make_pack(mappings, **overrides):
    pack = {
        "framework": "demo",
        "framework_version": "2022",
        "source": "Demo source document",
        "mappings": mappings,
    }
    pack.update(overrides)
    return pack


def test_valid_pack_passes():
    pack = make_pack({
        "log.audit": {"id": "A.8.15", "clause": "Logging"},
        "hygiene.no-secrets": {"id": "A.8.12", "clause": "Data leakage prevention"},
        "crypto.at-rest": {"id": "A.8.24", "clause": "Use of cryptography"},
    })
    assert packs.validate_pack(pack, VALID_KEYS, SCHEMA) == []


def test_unknown_key_fails():
    pack = make_pack({
        "log.audit": {"id": "A.8.15", "clause": "Logging"},
        "hygiene.no-secrets": {"id": "A.8.12", "clause": "Data leakage prevention"},
        "crypto.at-rest": {"id": "A.8.24", "clause": "Use of cryptography"},
        "made.up.key": {"id": "X.1", "clause": "Nope"},
    })
    errors = packs.validate_pack(pack, VALID_KEYS, SCHEMA)
    assert any("made.up.key" in e for e in errors)


def test_missing_key_fails():
    # crypto.at-rest omitted entirely -> a silent gap, must be flagged
    pack = make_pack({
        "log.audit": {"id": "A.8.15", "clause": "Logging"},
        "hygiene.no-secrets": {"id": "A.8.12", "clause": "Data leakage prevention"},
    })
    errors = packs.validate_pack(pack, VALID_KEYS, SCHEMA)
    assert any("crypto.at-rest" in e for e in errors)


def test_na_with_reason_passes():
    pack = make_pack({
        "log.audit": {"id": "A.8.15", "clause": "Logging"},
        "hygiene.no-secrets": {"id": "A.8.12", "clause": "Data leakage prevention"},
        "crypto.at-rest": {"na": True, "reason": "framework has no at-rest crypto control"},
    })
    assert packs.validate_pack(pack, VALID_KEYS, SCHEMA) == []


def test_na_without_reason_fails():
    pack = make_pack({
        "log.audit": {"id": "A.8.15", "clause": "Logging"},
        "hygiene.no-secrets": {"id": "A.8.12", "clause": "Data leakage prevention"},
        "crypto.at-rest": {"na": True},
    })
    errors = packs.validate_pack(pack, VALID_KEYS, SCHEMA)
    assert errors  # schema rejects na without reason


def test_missing_provenance_field_fails():
    pack = make_pack({
        "log.audit": {"id": "A.8.15", "clause": "Logging"},
        "hygiene.no-secrets": {"id": "A.8.12", "clause": "Data leakage prevention"},
        "crypto.at-rest": {"id": "A.8.24", "clause": "Use of cryptography"},
    })
    del pack["source"]
    errors = packs.validate_pack(pack, VALID_KEYS, SCHEMA)
    assert errors  # provenance is mandatory


def test_extract_keys_reads_taxonomy():
    taxonomy = {
        "version": 1,
        "keys": [
            {"key": "log.audit", "evidence_type": "runtime_marker"},
            {"key": "crypto.at-rest", "evidence_type": "static"},
        ],
        "aliases": {"CC7.2": "log.audit"},
    }
    assert packs.extract_keys(taxonomy) == {"log.audit", "crypto.at-rest"}
