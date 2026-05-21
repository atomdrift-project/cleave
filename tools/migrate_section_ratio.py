#!/usr/bin/env python3
"""Migrate `type: section_ratio` to either a pre-computed metric or a
`type: section` with compare_to/ratio_min/ratio_max.

Rewrites in-place across a trait tree. The pre-computed metrics cover the three
common `section → total-file` ratios; everything else falls back to the
extended `type: section` condition that accepts `compare_to` + `ratio_*`.

  - section matches {.text, text, __text} AND compare_to=total
        -> type: metrics, field: binary.text_to_file_ratio, (min/max)
  - section matches {.data, data, __data, \\.data, __DATA.__data} AND compare_to=total
        -> type: metrics, field: binary.data_to_file_ratio
  - section matches {.rsrc, "\\.rsrc"} AND compare_to=total
        -> type: metrics, field: binary.rsrc_to_file_ratio
  - Everything else: rewrite as `type: section, regex: <section>,
    compare_to: <orig>, ratio_min: X, ratio_max: Y`.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

TEXT_SECTIONS = {".text", "text", "__text", "\\.text", '"\\.text"', "\"\\\\.text\""}
DATA_SECTIONS = {".data", "data", "__data", "\\.data", "__DATA.__data"}
RSRC_SECTIONS = {".rsrc", '".rsrc"'}


def _norm_section(s: str) -> str:
    return s.strip().strip('"').strip("'")


def _metric_for(section: str, compare_to: str) -> str | None:
    if compare_to.strip() != "total":
        return None
    s = _norm_section(section)
    if s in TEXT_SECTIONS:
        return "binary.text_to_file_ratio"
    if s in DATA_SECTIONS:
        return "binary.data_to_file_ratio"
    if s in RSRC_SECTIONS:
        return "binary.rsrc_to_file_ratio"
    return None


def migrate_file(path: Path) -> int:
    text = path.read_text()
    lines = text.splitlines(keepends=True)
    out: list[str] = []
    i = 0
    n = len(lines)
    changes = 0
    while i < n:
        m = re.match(r"^(\s*)(-\s+)?type:\s*section_ratio\s*$", lines[i])
        if not m:
            out.append(lines[i])
            i += 1
            continue

        prefix = m.group(1)
        dash = m.group(2) or ""
        base_indent = len(prefix) + len(dash)
        field_indent = " " * base_indent

        # Collect the inner fields
        j = i + 1
        fields: dict[str, str] = {}
        while j < n:
            nxt = lines[j]
            if not nxt.strip():
                j += 1
                continue
            stripped = nxt.lstrip(" ")
            cur_indent = len(nxt) - len(stripped)
            if cur_indent < base_indent:
                break
            k, _, v = nxt.strip().partition(":")
            fields[k.strip()] = v.strip()
            j += 1

        section = fields.get("section", "")
        compare_to = fields.get("compare_to", "total")
        min_v = fields.get("min")
        max_v = fields.get("max")
        metric = _metric_for(section, compare_to)

        if metric is not None:
            out.append(f"{prefix}{dash}type: metrics\n")
            out.append(f"{field_indent}field: {metric}\n")
        else:
            out.append(f"{prefix}{dash}type: section\n")
            out.append(f"{field_indent}regex: {section}\n")
            out.append(f"{field_indent}compare_to: {compare_to}\n")
        if min_v is not None:
            key = "min" if metric is not None else "ratio_min"
            out.append(f"{field_indent}{key}: {min_v}\n")
        if max_v is not None:
            key = "max" if metric is not None else "ratio_max"
            out.append(f"{field_indent}{key}: {max_v}\n")

        changes += 1
        i = j
    if changes > 0:
        path.write_text("".join(out))
    return changes


def main() -> int:
    root = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("/Users/t/dev/atomdrift/cleave-traits")
    total = 0
    for yaml in sorted(root.rglob("*.yaml")):
        if "section_ratio" not in yaml.read_text():
            continue
        n = migrate_file(yaml)
        if n:
            total += n
            print(f"{yaml}: {n} migrated")
    print(f"\nTotal: {total} section_ratio -> metrics/section")
    return 0


if __name__ == "__main__":
    sys.exit(main())
