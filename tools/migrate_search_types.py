#!/usr/bin/env python3
from __future__ import annotations

import argparse
import collections
import dataclasses
import pathlib
import re
import sys
from typing import Iterable

import yaml
from yaml.nodes import MappingNode, Node, ScalarNode, SequenceNode


ALL_FILE_TYPES = {
    "unknown",
    "elf",
    "macho",
    "pe",
    "dylib",
    "so",
    "dll",
    "class",
    "pyc",
    "dex",
    "shell",
    "batch",
    "python",
    "javascript",
    "ruby",
    "php",
    "perl",
    "lua",
    "powershell",
    "applescript",
    "vbs",
    "html",
    "markdown",
    "java",
    "c",
    "rust",
    "go",
    "csharp",
    "swift",
    "objectivec",
    "groovy",
    "kotlin",
    "scala",
    "zig",
    "elixir",
    "package.json",
    "cargo.toml",
    "pyproject.toml",
    "composer.json",
    "chrome-manifest",
    "vsixmanifest",
    "github-actions",
    "plist",
    "pkginfo",
    "lnk",
    "jpeg",
    "png",
    "pickle",
    "rtf",
    "pdf",
    "oledoc",
    "msi",
    "ooxml",
    "archive",
    "zip",
    "apk",
    "jar",
    "tar",
    "npm",
    "nupkg",
    "gem",
    "whl",
    "deb",
    "rpm",
    "crx",
    "vsix-archive",
    "xpi",
    "ipa",
}

BINARY_GROUP = {
    "elf",
    "macho",
    "pe",
    "dylib",
    "so",
    "dll",
    "class",
    "pyc",
    "dex",
}

SCRIPT_GROUP = {
    "shell",
    "batch",
    "python",
    "javascript",
    "ruby",
    "php",
    "perl",
    "lua",
    "powershell",
    "applescript",
    "vbs",
}

SOURCE_GROUP = {
    "rust",
    "java",
    "c",
    "go",
    "csharp",
    "swift",
    "objectivec",
    "groovy",
    "kotlin",
    "scala",
    "zig",
    "elixir",
}

MANIFEST_GROUP = {
    "package.json",
    "chrome-manifest",
    "vsixmanifest",
    "cargo.toml",
    "pyproject.toml",
    "github-actions",
    "composer.json",
    "pkginfo",
    "plist",
    "lnk",
}

DOCUMENT_GROUP = {
    "pdf",
    "rtf",
    "html",
    "markdown",
    "oledoc",
    "ooxml",
}

IMAGE_GROUP = {"jpeg", "png"}
DATA_GROUP = {"ipa"}
ARCHIVE_GROUP = {
    "archive",
    "zip",
    "apk",
    "jar",
    "tar",
    "npm",
    "nupkg",
    "gem",
    "whl",
    "deb",
    "rpm",
    "crx",
    "vsix-archive",
    "xpi",
}

GROUPS = {
    "binaries": BINARY_GROUP,
    "scripts": SCRIPT_GROUP,
    "source": SOURCE_GROUP,
    "manifests": MANIFEST_GROUP,
    "documents": DOCUMENT_GROUP,
    "images": IMAGE_GROUP,
    "media": IMAGE_GROUP,
    "data": DATA_GROUP,
    "ipa": DATA_GROUP,
    "archives": ARCHIVE_GROUP,
}

FILE_TYPE_ALIASES = {
    "unknown": {"unknown"},
    "elf": {"elf"},
    "macho": {"macho"},
    "pe": {"pe"},
    "dylib": {"dylib"},
    "so": {"so"},
    "dll": {"dll"},
    "shell": {"shell"},
    "sh": {"shell"},
    "batch": {"batch"},
    "bat": {"batch"},
    "cmd": {"batch"},
    "python": {"python"},
    "py": {"python"},
    "javascript": {"javascript"},
    "js": {"javascript"},
    "typescript": {"javascript"},
    "ts": {"javascript"},
    "ruby": {"ruby"},
    "rb": {"ruby"},
    "php": {"php"},
    "perl": {"perl"},
    "pl": {"perl"},
    "powershell": {"powershell"},
    "ps1": {"powershell"},
    "lua": {"lua"},
    "applescript": {"applescript"},
    "scpt": {"applescript"},
    "vbs": {"vbs"},
    "vbe": {"vbs"},
    "wsf": {"vbs"},
    "wsc": {"vbs"},
    "vbscript": {"vbs"},
    "html": {"html"},
    "htm": {"html"},
    "markdown": {"markdown"},
    "md": {"markdown"},
    "java": {"java"},
    "class": {"class"},
    "pyc": {"pyc"},
    "python-bytecode": {"pyc"},
    "c": {"c"},
    "cpp": {"c"},
    "c++": {"c"},
    "cc": {"c"},
    "cxx": {"c"},
    "rust": {"rust"},
    "go": {"go"},
    "csharp": {"csharp"},
    "cs": {"csharp"},
    "swift": {"swift"},
    "objective-c": {"objectivec"},
    "objc": {"objectivec"},
    "groovy": {"groovy"},
    "kotlin": {"kotlin"},
    "kt": {"kotlin"},
    "scala": {"scala"},
    "zig": {"zig"},
    "elixir": {"elixir"},
    "package.json": {"package.json"},
    "cargo.toml": {"cargo.toml"},
    "pyproject.toml": {"pyproject.toml"},
    "composer.json": {"composer.json"},
    "chrome-manifest": {"chrome-manifest"},
    "manifest.json": {"chrome-manifest"},
    "vsixmanifest": {"vsixmanifest"},
    "vsix-manifest": {"vsixmanifest"},
    "github-actions": {"github-actions"},
    "jpeg": {"jpeg"},
    "jpg": {"jpeg"},
    "png": {"png"},
    "pickle": {"pickle"},
    "pkl": {"pickle"},
    "plist": {"plist"},
    "pkginfo": {"pkginfo"},
    "rtf": {"rtf"},
    "lnk": {"lnk"},
    "pdf": {"pdf"},
    "oledoc": {"oledoc"},
    "ole": {"oledoc"},
    "doc": {"oledoc"},
    "xls": {"oledoc"},
    "ppt": {"oledoc"},
    "msg": {"oledoc"},
    "msi": {"msi"},
    "msp": {"msi"},
    "mst": {"msi"},
    "msm": {"msi"},
    "dex": {"dex"},
    "dalvik": {"dex"},
    "ooxml": {"ooxml"},
    "docx": {"ooxml"},
    "xlsx": {"ooxml"},
    "pptx": {"ooxml"},
    "docm": {"ooxml"},
    "xlsm": {"ooxml"},
    "pptm": {"ooxml"},
    "archive": {"archive"},
    "rar": {"archive"},
    "7z": {"archive"},
    "zip": {"zip"},
    "apk": {"apk"},
    "jar": {"jar"},
    "tar": {"tar"},
    "tgz": {"tar"},
    "npm": {"npm"},
    "nupkg": {"nupkg"},
    "gem": {"gem"},
    "whl": {"whl"},
    "deb": {"deb"},
    "rpm": {"rpm"},
    "crx": {"crx"},
    "vsix-archive": {"vsix-archive"},
    "xpi": {"xpi"},
}

RAW_TEXT_TYPES = (
    SCRIPT_GROUP
    | SOURCE_GROUP
    | {"html", "markdown"}
    | {
        "package.json",
        "chrome-manifest",
        "vsixmanifest",
        "cargo.toml",
        "pyproject.toml",
        "github-actions",
        "composer.json",
        "pkginfo",
        "plist",
    }
)

AST_TYPES = {
    "c",
    "python",
    "javascript",
    "rust",
    "go",
    "java",
    "ruby",
    "shell",
    "php",
    "csharp",
    "lua",
    "perl",
    "powershell",
    "swift",
    "objectivec",
    "groovy",
    "scala",
    "zig",
    "elixir",
}

FUNC_CALL_RE = re.compile(r"[a-zA-Z_][a-zA-Z0-9_.]*\(")
IMPORT_RE = re.compile(r"^(import\s+\w|from\s+\w+\s+import\b)")
REGEX_CODE_RE = re.compile(
    r"(?:require\b|\\brequire|exec\(|execSync|eval\(|shell_exec\(|child_process\\?\.|from\\s|import\\s|\\bimport\\b)"
)


@dataclasses.dataclass(frozen=True)
class RuleMeta:
    count_min: int | None
    count_max: int | None
    per_kb_min: float | None
    per_kb_max: float | None


@dataclasses.dataclass(frozen=True)
class Rewrite:
    old_type: str
    new_type: str
    reason: str


@dataclasses.dataclass(frozen=True)
class Patch:
    start: int
    end: int
    replacement: str
    line: int
    rule_id: str
    condition_path: str
    old_type: str
    new_type: str
    reason: str


@dataclasses.dataclass(frozen=True)
class Skip:
    rule_id: str
    condition_path: str
    old_type: str
    reason: str


def scalar_text(node: Node | None) -> str | None:
    if isinstance(node, ScalarNode):
        return node.value
    return None


def scalar_value(node: Node | None):
    if not isinstance(node, ScalarNode):
        return None
    try:
        return yaml.safe_load(node.value)
    except yaml.YAMLError:
        return node.value


def mapping_get(node: Node | None, key: str) -> Node | None:
    if not isinstance(node, MappingNode):
        return None
    for key_node, value_node in node.value:
        if isinstance(key_node, ScalarNode) and key_node.value == key:
            return value_node
    return None


def sequence_items(node: Node | None) -> list[Node]:
    if isinstance(node, SequenceNode):
        return list(node.value)
    return []


def string_list(node: Node | None) -> list[str]:
    if isinstance(node, ScalarNode):
        return [node.value]
    if isinstance(node, SequenceNode):
        values: list[str] = []
        for item in node.value:
            if isinstance(item, ScalarNode):
                values.append(item.value)
        return values
    return []


def parse_file_types(entries: Iterable[str] | None) -> set[str] | None:
    if not entries:
        return None

    inclusions: set[str] = set()
    exclusions: set[str] = set()
    has_explicit_inclusion = False
    include_all = False

    for raw_entry in entries:
        for part in raw_entry.split(","):
            part = part.strip()
            if not part:
                continue

            if part.startswith("!"):
                is_exclusion = True
                name = part[1:]
            elif part.startswith("-"):
                is_exclusion = True
                name = part[1:]
            else:
                is_exclusion = False
                name = part

            lower_name = name.lower()
            if lower_name in {"all", "*"}:
                if is_exclusion:
                    exclusions.update(ALL_FILE_TYPES)
                else:
                    include_all = True
                    has_explicit_inclusion = True
                continue

            variants = GROUPS.get(lower_name)
            if variants is None:
                variants = FILE_TYPE_ALIASES.get(lower_name, set())

            if not variants:
                continue

            if is_exclusion:
                exclusions.update(variants)
            else:
                inclusions.update(variants)
                has_explicit_inclusion = True

    if include_all or (not has_explicit_inclusion and exclusions):
        final_set = set(ALL_FILE_TYPES)
    elif not has_explicit_inclusion:
        return None
    else:
        final_set = set(inclusions)

    final_set.difference_update(exclusions)
    return final_set


def raw_text_only(file_types: set[str] | None) -> bool:
    return bool(file_types) and all(ft in RAW_TEXT_TYPES for ft in file_types)


def ast_only(file_types: set[str] | None) -> bool:
    return bool(file_types) and all(ft in AST_TYPES for ft in file_types)


def extracted_text_types(file_types: set[str] | None) -> set[str]:
    if not file_types:
        return set()
    return {ft for ft in file_types if ft not in RAW_TEXT_TYPES}


def has_any_text_matcher(condition: MappingNode) -> bool:
    return any(
        scalar_text(mapping_get(condition, field))
        for field in ("exact", "substr", "regex", "word")
    )


def has_position_constraints(condition: MappingNode) -> bool:
    return any(
        mapping_get(condition, field) is not None
        for field in ("section", "offset", "offset_range", "section_offset", "section_offset_range")
    )


def has_binary_raw_behavioral_risk(condition: MappingNode, rule_meta: RuleMeta) -> str | None:
    if has_position_constraints(condition):
        return "positional constraint"
    if rule_meta.count_min not in (None, 1):
        return "count_min changes match-count semantics"
    if rule_meta.count_max is not None:
        return "count_max changes match-count semantics"
    if rule_meta.per_kb_min is not None or rule_meta.per_kb_max is not None:
        return "density constraint changes match-count semantics"
    if mapping_get(condition, "is") is not None:
        return "validator may depend on raw match context"
    if mapping_get(condition, "not") is not None:
        return "not: filtering may depend on raw match context"
    return None


def regex_is_effectively_literal(pattern: str) -> bool:
    i = 0
    while i < len(pattern):
        ch = pattern[i]
        if ch == "\\":
            i += 2
            continue
        if ch in ".*+?[](){}|^$":
            return False
        i += 1
    return True


def literal_length(pattern: str) -> int:
    count = 0
    i = 0
    while i < len(pattern):
        if pattern[i] == "\\" and i + 1 < len(pattern):
            i += 2
            count += 1
        else:
            i += 1
            count += 1
    return count


def binary_raw_text_candidate(condition: MappingNode) -> tuple[str, str] | None:
    exact = scalar_text(mapping_get(condition, "exact"))
    substr = scalar_text(mapping_get(condition, "substr"))
    word = scalar_text(mapping_get(condition, "word"))
    regex = scalar_text(mapping_get(condition, "regex"))

    for field_name, value in (("exact", exact), ("substr", substr), ("word", word)):
        if value and len(value) >= 5:
            return value, field_name

    if regex and regex_is_effectively_literal(regex) and literal_length(regex) >= 5:
        return regex, "regex (literal)"

    return None


def code_structure_pattern(condition: MappingNode) -> tuple[str, str] | None:
    for field_name in ("substr", "exact"):
        value = scalar_text(mapping_get(condition, field_name))
        if value and (FUNC_CALL_RE.search(value) or IMPORT_RE.search(value)):
            return value, field_name

    regex = scalar_text(mapping_get(condition, "regex"))
    if regex and REGEX_CODE_RE.search(regex):
        return regex, "regex"

    return None


def classify_rewrite(
    condition: MappingNode,
    file_types: set[str] | None,
    rule_meta: RuleMeta,
) -> tuple[Rewrite | None, str | None]:
    type_node = mapping_get(condition, "type")
    old_type = scalar_text(type_node)
    if old_type not in {"raw", "string_value"}:
        return None, None

    if old_type == "raw":
        if not has_any_text_matcher(condition):
            return None, "no text matcher"

        if raw_text_only(file_types):
            return Rewrite("raw", "text", "raw-text file types use the same semantics"), None

        if not file_types:
            return None, "unscoped or all file types"

        extracted_types = extracted_text_types(file_types)
        if not extracted_types:
            return None, "mixed or unsupported file types"

        risk = has_binary_raw_behavioral_risk(condition, rule_meta)
        if risk:
            return None, risk

        candidate = binary_raw_text_candidate(condition)
        if candidate is None:
            return None, "binary raw pattern is too short or not literal enough"

        pattern, kind = candidate
        if len(extracted_types) == len(file_types):
            reason = f"binary-like {kind} search '{pattern}' is string-like"
        else:
            reason = (
                f"mixed {kind} search '{pattern}' is raw-text on text files and string-like elsewhere"
            )
        return Rewrite("raw", "text", reason), None

    if not file_types:
        return None, "unscoped or all file types"

    code_pattern = code_structure_pattern(condition)
    if code_pattern is not None:
        pattern, kind = code_pattern
        return (
            Rewrite(
                "string_value",
                "text",
                f"{kind} pattern '{pattern}' matches code structure, not literals",
            ),
            None,
        )

    if not ast_only(file_types):
        return (
            Rewrite(
                "string_value",
                "text",
                "non-AST or mixed file types should use the general text search type",
            ),
            None,
        )

    return (
        Rewrite(
            "string_value",
            "string_literal",
            "AST-backed source types should use literal-only search explicitly",
        ),
        None,
    )


def replace_with_style(original_text: str, start: int, end: int, new_type: str) -> str:
    original = original_text[start:end]
    if len(original) >= 2 and original[0] == original[-1] and original[0] in {"'", '"'}:
        return f"{original[0]}{new_type}{original[0]}"
    return new_type


def rule_meta(rule_node: MappingNode) -> RuleMeta:
    return RuleMeta(
        count_min=scalar_value(mapping_get(rule_node, "count_min")),
        count_max=scalar_value(mapping_get(rule_node, "count_max")),
        per_kb_min=scalar_value(mapping_get(rule_node, "per_kb_min")),
        per_kb_max=scalar_value(mapping_get(rule_node, "per_kb_max")),
    )


def rule_id(rule_node: MappingNode) -> str:
    return scalar_text(mapping_get(rule_node, "id")) or "<unknown>"


def effective_file_types(rule_node: MappingNode, defaults_for: set[str] | None) -> set[str] | None:
    local = parse_file_types(string_list(mapping_get(rule_node, "for")))
    if local is not None:
        return local
    return defaults_for


def collect_condition_patches(
    text: str,
    condition_node: Node,
    file_types: set[str] | None,
    meta: RuleMeta,
    current_rule_id: str,
    condition_path: str,
    patches: list[Patch],
    skips: list[Skip],
) -> None:
    if not isinstance(condition_node, MappingNode):
        return

    type_node = mapping_get(condition_node, "type")
    old_type = scalar_text(type_node)
    if not isinstance(type_node, ScalarNode) or old_type not in {"raw", "string_value"}:
        return

    rewrite, skip_reason = classify_rewrite(condition_node, file_types, meta)
    if rewrite is None:
        if skip_reason is not None:
            skips.append(
                Skip(
                    rule_id=current_rule_id,
                    condition_path=condition_path,
                    old_type=old_type,
                    reason=skip_reason,
                )
            )
        return

    patches.append(
        Patch(
            start=type_node.start_mark.index,
            end=type_node.end_mark.index,
            replacement=replace_with_style(text, type_node.start_mark.index, type_node.end_mark.index, rewrite.new_type),
            line=type_node.start_mark.line + 1,
            rule_id=current_rule_id,
            condition_path=condition_path,
            old_type=rewrite.old_type,
            new_type=rewrite.new_type,
            reason=rewrite.reason,
        )
    )


def walk_rule_conditions(
    text: str,
    rule_node: MappingNode,
    defaults_for: set[str] | None,
    is_composite: bool,
    patches: list[Patch],
    skips: list[Skip],
) -> None:
    current_rule_id = rule_id(rule_node)
    meta = rule_meta(rule_node)
    file_types = effective_file_types(rule_node, defaults_for)

    if not is_composite:
        if_node = mapping_get(rule_node, "if")
        if if_node is not None:
            collect_condition_patches(
                text,
                if_node,
                file_types,
                meta,
                current_rule_id,
                "if",
                patches,
                skips,
            )

    for list_key in ("all", "any", "unless"):
        for index, item in enumerate(sequence_items(mapping_get(rule_node, list_key)), start=1):
            collect_condition_patches(
                text,
                item,
                file_types,
                meta,
                current_rule_id,
                f"{list_key}[{index}]",
                patches,
                skips,
            )

    downgrade = mapping_get(rule_node, "downgrade")
    if isinstance(downgrade, MappingNode):
        for list_key in ("any", "all", "none"):
            for index, item in enumerate(sequence_items(mapping_get(downgrade, list_key)), start=1):
                collect_condition_patches(
                    text,
                    item,
                    file_types,
                    meta,
                    current_rule_id,
                    f"downgrade.{list_key}[{index}]",
                    patches,
                    skips,
                )


def apply_patches(text: str, patches: list[Patch]) -> str:
    updated = text
    for patch in sorted(patches, key=lambda item: item.start, reverse=True):
        updated = updated[: patch.start] + patch.replacement + updated[patch.end :]
    return updated


def yaml_files(root: pathlib.Path) -> list[pathlib.Path]:
    if root.is_file():
        return [root]
    return sorted(
        path
        for path in root.rglob("*")
        if path.suffix.lower() in {".yaml", ".yml"}
    )


def process_file(path: pathlib.Path, apply: bool) -> tuple[list[Patch], list[Skip], str | None]:
    text = path.read_text(encoding="utf-8")
    try:
        document = yaml.compose(text)
    except yaml.YAMLError as exc:
        return [], [], f"YAML parse error: {exc}"

    meaningful_lines = [
        line for line in text.splitlines() if line.strip() and not line.lstrip().startswith("#")
    ]
    if document is None and not meaningful_lines:
        return [], [], None

    if not isinstance(document, MappingNode):
        return [], [], "top-level document is not a mapping"

    defaults_for = parse_file_types(
        string_list(mapping_get(mapping_get(document, "defaults"), "for"))
    )

    patches: list[Patch] = []
    skips: list[Skip] = []

    for trait_node in sequence_items(mapping_get(document, "traits")):
        if isinstance(trait_node, MappingNode):
            walk_rule_conditions(text, trait_node, defaults_for, False, patches, skips)

    for composite_node in sequence_items(mapping_get(document, "composite_rules")):
        if isinstance(composite_node, MappingNode):
            walk_rule_conditions(text, composite_node, defaults_for, True, patches, skips)

    if apply and patches:
        updated = apply_patches(text, patches)
        try:
            yaml.compose(updated)
        except yaml.YAMLError as exc:
            return [], [], f"patched YAML did not re-parse cleanly: {exc}"
        path.write_text(updated, encoding="utf-8")

    return patches, skips, None


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Dry-run migration for cleave trait YAML search types. "
            "Rewrites only type scalars and preserves surrounding formatting."
        )
    )
    parser.add_argument(
        "target",
        type=pathlib.Path,
        help="Trait directory or YAML file to inspect.",
    )
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Write the rewrites back to disk. Dry-run is the default.",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Print every patch and skip instead of only summary counts.",
    )
    return parser


def main() -> int:
    args = build_parser().parse_args()
    target = args.target

    if not target.exists():
        print(f"error: path does not exist: {target}", file=sys.stderr)
        return 2

    all_patches: list[tuple[pathlib.Path, Patch]] = []
    all_skips: list[tuple[pathlib.Path, Skip]] = []
    errors: list[tuple[pathlib.Path, str]] = []

    files = yaml_files(target)

    for path in files:
        patches, skips, error = process_file(path, args.apply)
        if error is not None:
            errors.append((path, error))
            continue
        all_patches.extend((path, patch) for patch in patches)
        all_skips.extend((path, skip) for skip in skips)

    rewrite_counts = collections.Counter(
        f"{patch.old_type} -> {patch.new_type}" for _, patch in all_patches
    )
    skip_counts = collections.Counter(skip.reason for _, skip in all_skips)
    changed_files = collections.Counter(path for path, _ in all_patches)

    mode = "applied" if args.apply else "dry-run"
    print(f"{mode}: scanned {len(files)} YAML files")
    print(f"{mode}: would rewrite {len(all_patches)} conditions across {len(changed_files)} files")

    if rewrite_counts:
        print("rewrites:")
        for label, count in sorted(rewrite_counts.items()):
            print(f"  {label}: {count}")

    if skip_counts:
        print("skips:")
        for reason, count in skip_counts.most_common():
            print(f"  {reason}: {count}")

    if errors:
        print("errors:")
        for path, error in errors:
            print(f"  {path}: {error}")

    if args.verbose:
        if all_patches:
            print("patches:")
            for path, patch in all_patches:
                print(
                    f"  {path}:{patch.line}: {patch.rule_id} {patch.condition_path}: "
                    f"{patch.old_type} -> {patch.new_type} ({patch.reason})"
                )
        if all_skips:
            print("detailed skips:")
            for path, skip in all_skips:
                print(
                    f"  {path}: {skip.rule_id} {skip.condition_path}: "
                    f"{skip.old_type} skipped ({skip.reason})"
                )

    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
