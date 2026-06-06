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
        for fw in frameworks:
            entry = by_fw[fw].get(key)
            if entry is None:
                cells[fw] = "—"
            elif entry.get("na"):
                cells[fw] = "n/a"
            else:
                cells[fw] = entry["id"]
                mapped_cells += 1
        rows.append({"key": key, "cells": cells})

    return {
        "frameworks": frameworks,
        "rows": rows,
        "summary": {
            "frameworks": len(frameworks),
            "control_keys": len(keys),
            "mapped_cells": mapped_cells,
        },
    }


def render_markdown(matrix: dict) -> str:
    frameworks = matrix["frameworks"]
    header = "| Control key | " + " | ".join(frameworks) + " |"
    sep = "|" + "---|" * (len(frameworks) + 1)
    lines = [header, sep]
    for row in matrix["rows"]:
        cells = " | ".join(row["cells"][fw] for fw in frameworks)
        lines.append(f"| `{row['key']}` | {cells} |")

    s = matrix["summary"]
    summary = (
        f"\n**{s['mapped_cells']} control mappings** across "
        f"**{s['frameworks']} frameworks** x **{s['control_keys']} control keys**.\n"
    )
    return "\n".join(lines) + "\n" + summary
