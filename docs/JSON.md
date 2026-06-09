# Cleave JSON Report

Every cleave analysis produces an `AnalysisReport`, serialised to
JSON. The same shape is returned by `analyze_file`, written by the
CLI, and embedded as the `raw` field of [litmus's
envelope](../../litmus/docs/JSON.md).

For the library that produces these reports, see
[RUST_API.md](RUST_API.md). For the HTTP server, see
[SERVER_API.md](SERVER_API.md).

## Schema versioning

`version` carries the report schema version. The current value is
`"3"` for finalised reports and `"2.0"` for cached intermediates.
Consumers should treat unknown versions as a hard error.


## Compact JSON v7

The CLI `--json` output uses compact schema v7. The top-level object is:

| JSON | Type | Meaning |
| ---- | ---- | ------- |
| `v` | string | Compact schema version, currently `"7"`. |
| `files` | array | Per-file compact records. |

Byte offsets in the compact report carry no `0x` prefix, and each context uses
its slimmest valid-JSON encoding:

- `fact` tuple offsets are **bare integers** (`["__text", 1816, …]`). A standalone
  JSON integer is smaller than a quoted hex string — the two `"` cost more than
  hex saves in digits — so numbers win here.
- A trait's evidence locations (`loc`) are **single strings** of the form
  `"<file-id>:<offset>"` (e.g. `"7:3718c0"`). The offset is already inside a
  string, so hex is the compact choice there (fewer digits, no extra quotes).

(The verbose `Trait`/`Function`/`Section` types further down still use
`0x`-prefixed hex strings; that representation is unchanged.)

Each `files[]` entry keeps cleave verdict data at the file level and packs filefacts data under `fact`. The `fact` object is intentionally not a lossless mirror of the full report; it is the dense, ML/UI-oriented fact surface.

| `fact` key | Meaning |
| ---------- | ------- |
| `id` | File identity/type from filefacts, such as `pe`, `elf`, `macho`, `js`, or `zip`. |
| `met` | Metrics grouped by prefix: `{"binary":{"overall_entropy":7.12}}` instead of flat `binary.overall_entropy`. |
| `val` | Residual values only. Typed fact families are not duplicated here. |
| `str` | Strings as `[offset, encoding, value]`. |
| `imp` | Imports as `[library, symbol]` or `[library, symbol, offset]`. |
| `exp` | Exports as `[symbol]` or `[symbol, offset]`. |
| `fn` | Functions as `[name]`, `[name, offset]`, or `[name, offset, kind]`. |
| `sec` | Sections as `[name, file_offset, file_size, entropy, flags]`. |
| `tgt` | Source AST call targets. |
| `mbr` | Source AST member chains. |
| `arg` | Source AST string call arguments as `[callee, value]`. |
| `err` | Recoverable parse errors as `[kind, stage]`. |

The important invariant is that `fact.val` is residual. If a fact has a typed family (`str`, `imp`, `exp`, `fn`, `sec`, `tgt`, `mbr`, `arg`, or `err`), it must not also be emitted under `fact.val` by default.

## Top-level shape

`AnalysisReport`, `src/types/core.rs:71`. All array and option fields
are omitted from JSON when empty or `None`.

| JSON                  | Type                          | Meaning                                                          |
| --------------------- | ----------------------------- | ---------------------------------------------------------------- |
| `version`             | string                        | Schema version.                                                  |
| `analysis_timestamp`  | RFC 3339 string               | When analysis ran. UTC.                                          |
| `target`              | `TargetInfo`                  | Input metadata: path, type, size, SHA-256, architectures.        |
| `traits`              | array of `Trait`              | Observable facts. No interpretation.                             |
| `findings`            | array of `Finding`            | Interpretive conclusions: capabilities, indicators, weaknesses.  |
| `structure`           | array of `StructuralFeature`  | Binary-format properties: packing, entropy, obfuscation.         |
| `functions`           | array of `Function`           | Disassembled functions with complexity and CFG metrics.          |
| `strings`             | array of `StringInfo`         | Extracted literals.                                              |
| `sections`            | array of `Section`            | Binary sections with entropy and permissions.                    |
| `imports`             | array of `Import`             | Imported symbols.                                                |
| `exports`             | array of `Export`             | Exported symbols.                                                |
| `yara_matches`        | array of `YaraMatch`          | YARA rule matches with matched strings.                          |
| `syscalls`            | array of `SyscallInfo`        | Syscalls observed in disassembly.                                |
| `binary_properties`   | `BinaryProperties`            | Format-specific: PE manifests and signing, Mach-O entitlements, DWARF producer. |
| `code_metrics`        | `CodeMetrics`                 | Cyclomatic complexity, nesting depth, CFG stats.                 |
| `source_code_metrics` | `SourceCodeMetrics`           | Import counts, class counts, function metrics.                   |
| `overlay_metrics`     | `OverlayMetrics`              | Appended overlay data (self-extracting archives).                |
| `metrics`             | `Metrics`                     | Unified feature vector for downstream ML.                        |
| `values_tree`             | JSON object                   | Format-specific metadata: manifest, DWARF, EXIF, etc.            |
| `paths`               | array of `PathInfo`           | Discovered file and directory paths with access patterns.        |
| `directories`         | array of `DirectoryAccess`    | Paths grouped by parent directory.                               |
| `env_vars`            | array of `EnvVarInfo`         | Environment variable references.                                 |
| `archive_contents`    | array of `ArchiveEntry`       | Archive members: path, type, SHA-256, size.                      |
| `scanned_path`        | string                        | Root directory, for directory scans.                             |
| `files`               | array of `FileAnalysis`       | Per-file sub-reports, for directory scans and decoded payloads.  |
| `summary`             | `ReportSummary`               | Aggregates across `files`.                                       |
| `metadata`            | `AnalysisMetadata`            | Tool versions, timing, errors.                                   |
| `diff`                | `DiffReportV1`                | Differential findings. Only present on `cleave diff` output.     |

## The trait / finding distinction

Cleave separates two things downstream consumers routinely conflate:

- A **`Trait`** is an observation. The file imports `CreateRemoteThread`.
  A string `"http://1.2.3.4/c2"` exists at offset `0x4120` in the
  `.rdata` section. The function `main` calls `ptrace`. Traits carry
  no judgement.
- A **`Finding`** is a conclusion. `objectives/evasion/process::injection`,
  with `crit = 5` (hostile), supported by the traits above. Findings
  carry confidence, criticality, MBC, and ATT&CK references.

Traits feed findings. A single finding may reference many traits
through `trait_refs`. The two are kept in separate top-level arrays so
that machine learning can read raw traits while humans read findings.

## `Trait`

`src/types/traits_findings.rs:44`.

| JSON       | Rust       | Type             | Meaning                                                  |
| ---------- | ---------- | ---------------- | -------------------------------------------------------- |
| `kind`     | `kind`     | `TraitKind`      | String / Path / EnvVar / Import / Export / Ip / Url / Domain / Email / Base64 / Hash / Registry / Function. |
| `value`    | `value`    | string           | Raw value. Truncated to 4 KiB; null bytes stripped.      |
| `offset`   | `offset`   | hex string       | File offset, e.g. `"0x4120"`. Omitted if unknown.        |
| `encoding` | `encoding` | string           | `utf16le`, `utf16be`. Omitted for `utf8` / `ascii`.      |
| `section`  | `section`  | string           | Binary section: `.text`, `.data`, `.rodata`. Omitted if unknown. |
| `source`   | `source`   | string           | Discovery tool: `stng`, `goblin`, `radare2`, `yara-x`, `tree-sitter-*`. |

## `Finding`

`src/types/traits_findings.rs:94`.

| JSON          | Rust          | Type             | Meaning                                                          |
| ------------- | ------------- | ---------------- | ---------------------------------------------------------------- |
| `id`          | `id`          | string           | Trait id with `/` delimiters, e.g. `objectives/evasion/process::injection`. |
| `kind`        | `kind`        | `FindingKind`    | `capability` (default; omitted), `structural`, `indicator`, `weakness`. |
| `desc`        | `desc`        | string           | Human-readable description. Omitted if empty.                    |
| `conf`        | `conf`        | f32 in `[0, 1]`  | Confidence. 0.5 = heuristic, 1.0 = definitive.                   |
| `crit`        | `crit`        | `Criticality`    | 0 filtered, 1 component, 2 baseline, 3 notable, 4 suspicious, 5 hostile. |
| `mbc`         | `mbc`         | string           | MBC code, e.g. `C0002`. Omitted if unset.                        |
| `attack`      | `attack`      | string           | MITRE ATT&CK technique, e.g. `T1055`. Omitted if unset.          |
| `trait_refs`  | `trait_refs`  | array of string  | Trait ids that contributed to this finding.                      |
| `evidence`    | `evidence`    | array of `Evidence` | Supporting evidence.                                          |
| `match_count` | `match_count` | usize            | Total matches when `evidence` is truncated. Omitted if 0.        |

The `conf` field accepts the JSON alias `confidence` on input for
backward compatibility; output always uses `conf`.

## `Evidence`

`src/types/traits_findings.rs:278`.

| JSON       | Type            | Meaning                                                                  |
| ---------- | --------------- | ------------------------------------------------------------------------ |
| `method`   | string          | Detection method: `symbol`, `yara`, `tree-sitter`, `radare2`, `entropy`, `magic`. |
| `source`   | string          | Tool name. Omitted if empty.                                             |
| `value`    | string          | Discovered value: symbol name, matched substring. Truncated to 4 KiB.    |
| `location` | string          | Context, e.g. `import` or `archive.zip!!inner/lib.so`. Omitted if unset. |
| `offsets`  | array of u64    | Up to 8 byte offsets. Use `count` for the total when truncated.          |
| `count`    | usize           | Total match count when `offsets` is truncated. Omitted if 0.             |

## `Criticality`

`src/types/core.rs:39`. An ordinal scale; rank order matters more than
the names. Score weights below are what feeds the litmus model.

| Ordinal | Name        | Weight | Meaning                                                                |
| ------- | ----------- | ------ | ---------------------------------------------------------------------- |
| 0       | Filtered    | 0      | Matched, but wrong file type. Preserved for ML; hidden from humans.    |
| 1       | Component   | 0      | Composite building block. Hidden unless a composite that uses it fires.|
| 2       | Baseline    | 0      | Universal noise. Low signal on its own.                                |
| 3       | Notable     | 1      | Defines program purpose. Flagged in diffs.                             |
| 4       | Suspicious  | 40     | Unusual or evasive. Investigate.                                       |
| 5       | Hostile     | 120    | Almost certainly malicious. Rare.                                      |

Composite rules combine `Component` traits to produce higher-criticality
findings; component traits are suppressed from output unless the
composite fires.

## Binary-format types

These appear when the input is a compiled binary.

### `Function` (`src/types/binary.rs:12`)

`name`, `offset` (hex string), `size`, `complexity` (cyclomatic),
`calls` (array of names), `source` (`radare2` / `tree-sitter`),
`control_flow`, `instruction_analysis`, `register_usage`, `constants`,
`properties`, `signature`, `nesting`, `call_patterns`. All optional
fields are omitted when absent.

### `StringInfo` (`src/types/binary.rs:193`)

| JSON              | Type             | Meaning                                                  |
| ----------------- | ---------------- | -------------------------------------------------------- |
| `value`           | string           | String content. Truncated to 4 KiB.                      |
| `offset`          | hex string       | File offset. Omitted if unknown.                         |
| `encoding`        | string           | `utf16le`, `utf16be`. Omitted for `utf8` / `ascii`.      |
| `type`            | `StringType`     | `Const`, `Fmt`, etc. Omitted if unset.                   |
| `encoding_chain`  | array of string  | Decoded layers, e.g. `["base64", "zlib"]`. Omitted if empty. |
| `fragments`       | array of string  | Stack-constructed string pieces. Omitted if absent.      |

### `Section` (`src/types/binary.rs:228`)

`name`, `address`, `offset`, `size`, `entropy` (Shannon, 0.0–8.0),
`permissions` (e.g. `r-x`).

### `Import` / `Export` (`src/types/binary.rs:261`, `:312`)

`symbol` (normalised; leading underscores stripped), `library`,
`source`, `offset` (hex string).

### `YaraMatch` (`src/types/binary.rs:359`)

| JSON              | Type             | Meaning                                                          |
| ----------------- | ---------------- | ---------------------------------------------------------------- |
| `rule`            | string           | YARA rule name.                                                  |
| `namespace`       | string           | Rule file name.                                                  |
| `crit`            | string           | Criticality (rule-declared).                                     |
| `desc`            | string           | Human description.                                               |
| `matched_strings` | array of `MatchedString` | Specific patterns that triggered.                        |
| `is_capability`   | bool             | When true, this match upgrades to a `Finding`. Omitted if false. |
| `mbc`             | string           | MBC code. Omitted if unset.                                      |
| `attack`          | string           | ATT&CK code. Omitted if unset.                                   |
| `trait_id`        | string           | Derived trait id, e.g. `third_party/elastic/backdoor`. Omitted if unset. |

## Errors and partial reports

Cleave is liberal about partial output. A report from a file that
caused rizin to crash, or whose archive could not be fully unpacked,
will still contain whatever was extracted before the failure. The
`metadata` block carries the error chain so consumers can distinguish
"benign-looking but incomplete" from "fully analysed and clean".

Library consumers see this via `Result<AnalysisReport, Error>` at the
top level (a hard failure produces no report) plus `metadata.errors`
inside successful reports (a soft failure produces a partial report).

## Worked example

A trimmed report for a Linux ELF that bundles a process-injection
helper:

    {
      "version": "3",
      "analysis_timestamp": "2026-05-14T18:22:00Z",
      "target": {
        "path": "/tmp/payload",
        "file_type": "elf",
        "size": 84128,
        "sha256": "9a1f...c0",
        "architectures": ["x86_64"]
      },
      "traits": [
        { "kind": "Import", "value": "ptrace",  "source": "goblin" },
        { "kind": "Import", "value": "mprotect","source": "goblin" },
        { "kind": "String", "value": "/proc/self/maps", "offset": "0x4120",
          "section": ".rodata", "source": "stng" }
      ],
      "findings": [
        {
          "id": "objectives/evasion/process::injection",
          "desc": "writes to another process's address space",
          "conf": 0.95,
          "crit": 5,
          "mbc": "B0017",
          "attack": "T1055",
          "trait_refs": ["import:ptrace", "import:mprotect"],
          "evidence": [
            { "method": "symbol", "source": "goblin", "value": "ptrace",
              "location": "import" }
          ]
        }
      ],
      "metadata": { "...": "tool versions, timing, errors" }
    }

The `Finding` interprets the three `Trait` observations as a single
behavioural capability with a hostile criticality. Downstream
consumers — including [litmus](../../litmus/docs/JSON.md) — read
`findings` for verdicts and keep `traits` for audit and retraining.
