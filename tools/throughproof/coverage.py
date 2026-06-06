"""Build the frameworks x control-keys coverage matrix from the taxonomy + packs.

Filled cells are coverage (marketing); empty/n-a cells are the roadmap. The matrix
is generated, never hand-maintained, so it can never silently drift from the data.
"""
from __future__ import annotations


def build_matrix(taxonomy: dict, packs: list[dict]) -> dict:
    keys = [entry["key"] for entry in taxonomy.get("keys", [])]
    frameworks = sorted(p["framework"] for p in packs)
    by_fw = {p["framework"]: p.get("mappings", {}) for p in packs}

    rows = []
    mapped_cells = 0
    for key in keys:
        cells = {}
        satisfied = 0
        for fw in frameworks:
            entry = by_fw[fw].get(key)
            if entry is None:
                cells[fw] = "—"
            elif entry.get("na"):
                cells[fw] = "n/a"
            else:
                cells[fw] = entry["id"]
                mapped_cells += 1
                satisfied += 1
        rows.append({"key": key, "cells": cells, "frameworks_satisfied": satisfied})

    return {
        "frameworks": frameworks,
        "rows": rows,
        "summary": {
            "frameworks": len(frameworks),
            "control_keys": len(keys),
            "mapped_cells": mapped_cells,
        },
    }


def explain(key: str, packs: list[dict]) -> list[dict]:
    """Return every framework (and its id/clause) that a single control key satisfies."""
    out = []
    for p in sorted(packs, key=lambda p: p["framework"]):
        entry = p.get("mappings", {}).get(key)
        if entry and not entry.get("na"):
            out.append({"framework": p["framework"], "id": entry["id"], "clause": entry.get("clause", "")})
    return out


def render_markdown(matrix: dict) -> str:
    frameworks = matrix["frameworks"]
    header = "| Control key | " + " | ".join(frameworks) + " | Frameworks |"
    sep = "|" + "---|" * (len(frameworks) + 2)
    lines = [header, sep]
    for row in matrix["rows"]:
        cells = " | ".join(row["cells"][fw] for fw in frameworks)
        lines.append(f"| `{row['key']}` | {cells} | **{row['frameworks_satisfied']}** |")

    s = matrix["summary"]
    # The multiplier headline: name the key with the widest reach.
    best = max(matrix["rows"], key=lambda r: r["frameworks_satisfied"], default=None)
    multiplier = ""
    if best and best["frameworks_satisfied"] > 1:
        multiplier = (
            f"\n> **Write once, satisfy many.** A single `{best['key']}` control path "
            f"satisfies **{best['frameworks_satisfied']} frameworks** at once.\n"
        )
    summary = (
        f"\n**{s['mapped_cells']} control mappings** across "
        f"**{s['frameworks']} frameworks** x **{s['control_keys']} control keys**.\n"
    )
    return "\n".join(lines) + "\n" + multiplier + summary
