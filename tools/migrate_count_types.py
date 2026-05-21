#!/usr/bin/env python3
"""Migrate `type: exports_count` and `type: string_count` to metric/string types.

Rewrites in-place across a trait tree. Preserves indentation. Fails loudly on
shapes it does not recognize so a human can inspect them.

  - `type: exports_count [min:] [max:]`
        -> `type: metrics, field: binary.export_count, [min:] [max:]`
  - `type: string_count  [min:] [max:]`   (no regex, min_length absent or <= 4)
        -> `type: metrics, field: binary.string_count, [min:] [max:]`
  - `type: string_count regex: P [min:N|max:N]`
        -> lift `min:` to trait-level `count_min:` and rewrite the condition to
           `type: string, regex: P` (count_max is rare; we emit it as
           `count_max:` at trait level if present).
"""

from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass
from pathlib import Path


@dataclass
class Block:
    lines: list[str]  # indented lines of a single `if:` block (no leading "if:")
    indent: int       # indent of the inner fields (e.g. 6 spaces)
    start: int        # first line index in parent (the `type: ...` line)
    end: int          # line index just past the block


def find_type_blocks(lines: list[str], wanted_type: str) -> list[Block]:
    """Return blocks whose first `type:` line matches `wanted_type`.

    A "block" is the contiguous run of same-indent key: value lines starting
    with `type: <wanted_type>`. We also capture the preceding `if:` or list
    `- type:` line so we know the owning trait's context.
    """
    blocks: list[Block] = []
    n = len(lines)
    i = 0
    while i < n:
        m = re.match(r"^(\s*)(-\s+)?type:\s*" + re.escape(wanted_type) + r"\s*$", lines[i])
        if not m:
            i += 1
            continue
        base_indent = len(m.group(1)) + (2 if m.group(2) else 0)
        j = i + 1
        while j < n:
            nxt = lines[j]
            if not nxt.strip():
                j += 1
                continue
            stripped = nxt.lstrip(" ")
            cur_indent = len(nxt) - len(stripped)
            if cur_indent < base_indent:
                break
            j += 1
        blocks.append(Block(lines=lines[i:j], indent=base_indent, start=i, end=j))
        i = j
    return blocks


def parse_kvs(block_lines: list[str]) -> dict[str, str]:
    """Parse simple `key: value` lines inside a block. First line is `type: ...`."""
    out: dict[str, str] = {}
    for raw in block_lines:
        s = raw.strip()
        if not s or s.startswith("#"):
            continue
        if s.startswith("- "):
            s = s[2:]
        if ":" not in s:
            continue
        k, _, v = s.partition(":")
        out[k.strip()] = v.strip()
    return out


def rewrite_exports_count(lines: list[str]) -> tuple[list[str], int]:
    """Replace `type: exports_count` blocks in place. Returns (new_lines, count)."""
    count = 0
    i = 0
    while i < len(lines):
        m = re.match(r"^(\s*)(-\s+)?type:\s*exports_count\s*$", lines[i])
        if not m:
            i += 1
            continue
        prefix = m.group(1)
        dash = m.group(2) or ""
        base_indent = len(prefix) + (len(dash))
        # Find end of block
        j = i + 1
        while j < len(lines):
            nxt = lines[j]
            if not nxt.strip():
                j += 1
                continue
            stripped = nxt.lstrip(" ")
            cur_indent = len(nxt) - len(stripped)
            if cur_indent < base_indent:
                break
            j += 1
        # Rewrite: swap `type: exports_count` for `type: metrics` and add `field:`
        new_lines = list(lines[:i])
        new_lines.append(f"{prefix}{dash}type: metrics\n")
        field_indent = " " * base_indent
        new_lines.append(f"{field_indent}field: binary.export_count\n")
        # Preserve other keys (min/max/etc.)
        new_lines.extend(lines[i + 1 : j])
        new_lines.extend(lines[j:])
        lines = new_lines
        count += 1
        i = j + 1  # skip past the added `field:` line
    return lines, count


def rewrite_string_count(lines: list[str], path: Path) -> tuple[list[str], int]:
    """Replace `type: string_count` blocks. Returns (new_lines, count).

    Migration rules:
      - regex present: rewrite as `type: string, regex: ...` and lift
        min→count_min, max→count_max to trait-level keys.
      - no regex: rewrite as `type: metrics, field: binary.string_count`.
    """
    count = 0
    i = 0
    while i < len(lines):
        m = re.match(r"^(\s*)(-\s+)?type:\s*(?:string_count|string_value_count)\s*$", lines[i])
        if not m:
            i += 1
            continue
        prefix = m.group(1)
        dash = m.group(2) or ""
        base_indent = len(prefix) + len(dash)
        # Find end of this block
        j = i + 1
        while j < len(lines):
            nxt = lines[j]
            if not nxt.strip():
                j += 1
                continue
            stripped = nxt.lstrip(" ")
            cur_indent = len(nxt) - len(stripped)
            if cur_indent < base_indent:
                break
            j += 1
        kvs = parse_kvs(lines[i:j])
        has_regex = "regex" in kvs
        field_indent = " " * base_indent
        new_block: list[str] = []

        if has_regex:
            # Lift count_min / count_max to the owning trait. We find the trait
            # boundary by scanning upward for the nearest `if:` (or shallower
            # `- id:` list item) to insert count_* alongside the rule keys.
            count_min = kvs.get("min")
            count_max = kvs.get("max")
            # Re-emit as `type: string`; regex carries over; min_length drops.
            new_block.append(f"{prefix}{dash}type: text\n")
            for orig in lines[i + 1 : j]:
                # Preserve only regex + case_insensitive + section (rare)
                s = orig.strip()
                if s.startswith("regex:") or s.startswith("case_insensitive:") \
                        or s.startswith("section:") or s.startswith("exact:") \
                        or s.startswith("substr:"):
                    new_block.append(orig)
                # Drop min/max/min_length (migrated to trait level)
            # Patch min/max up into the trait by prepending at the outer trait
            # level. We find the line that begins this `if:` or list item.
            trait_insert = []
            # determine trait-level indent: look at parent `if:` or nearest
            # dash. Scan upward from `i`.
            k = i - 1
            parent_indent = None
            while k >= 0:
                pm = re.match(r"^(\s*)if:\s*$", lines[k])
                if pm:
                    parent_indent = len(pm.group(1))
                    break
                dm = re.match(r"^(\s*)-\s+type:\s*(?:string_count|string_value_count)", lines[k])
                if dm and k == i:
                    break
                k -= 1
            if parent_indent is None:
                sys.stderr.write(
                    f"{path}: could not locate `if:` above string_count at line {i+1}; "
                    "skipping (likely nested in list — migrate by hand)\n"
                )
                i = j
                continue
            insert_indent = " " * parent_indent
            if count_min is not None:
                trait_insert.append(f"{insert_indent}count_min: {count_min}\n")
            if count_max is not None:
                trait_insert.append(f"{insert_indent}count_max: {count_max}\n")
            # Need to insert these AFTER the `if:` block closes, at trait level.
            # Simpler: insert before the `if:` line (count_min/count_max order
            # doesn't matter for parsing but reads better after).
            lines = (
                list(lines[:k])
                + trait_insert
                + list(lines[k:i])
                + new_block
                + list(lines[j:])
            )
            count += 1
            i = k + len(trait_insert) + (i - k) + len(new_block)
            continue

        # No regex: straight metric swap, drop min_length, regex absent.
        new_block.append(f"{prefix}{dash}type: metrics\n")
        new_block.append(f"{field_indent}field: binary.string_count\n")
        for orig in lines[i + 1 : j]:
            s = orig.strip()
            if s.startswith("min:") or s.startswith("max:"):
                new_block.append(orig)
            # drop min_length
        lines = list(lines[:i]) + new_block + list(lines[j:])
        count += 1
        i = i + len(new_block)
    return lines, count


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("root", type=Path, help="trait tree root (e.g. cleave-traits/)")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    total_exports = 0
    total_strings = 0
    touched_files: list[Path] = []
    for p in sorted(args.root.rglob("*.yaml")):
        text = p.read_text()
        if (
            "exports_count" not in text
            and "string_count" not in text
            and "string_value_count" not in text
        ):
            continue
        lines = text.splitlines(keepends=True)
        lines, n_exp = rewrite_exports_count(lines)
        lines, n_str = rewrite_string_count(lines, p)
        if n_exp == 0 and n_str == 0:
            continue
        touched_files.append(p)
        total_exports += n_exp
        total_strings += n_str
        if args.dry_run:
            print(f"[DRY] {p}: exports={n_exp} strings={n_str}")
        else:
            p.write_text("".join(lines))
            print(f"{p}: exports={n_exp} strings={n_str}")

    print(
        f"\nTotal: exports_count={total_exports} string_count={total_strings} "
        f"across {len(touched_files)} file(s) "
        f"({'dry-run' if args.dry_run else 'written'})"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
