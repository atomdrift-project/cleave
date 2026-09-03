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


## Compact JSON v8

The CLI `--json` output uses compact schema v8 (`src/types/compact.rs`). Each
`files[]` entry is fully self-contained — splittable for per-file DB storage.
The top-level object is:

| JSON | Type | Meaning |
| ---- | ---- | ------- |
| `v` | string | Compact schema version, currently `"8"`. |
| `rev` | string | Traits-repo revision (first 8 chars of commit hash). Omitted if unknown. |
| `files` | array | Per-file compact records. |

Byte offsets in the compact report are **bare integers**, not `0x`-prefixed hex
strings — a standalone JSON integer is smaller than a quoted hex string. (The
verbose `Trait`/`Function`/`Section` types further down still use `0x`-prefixed
hex strings; that representation is unchanged.)

### `files[]` entry

| JSON | Type | Meaning |
| ---- | ---- | ------- |
| `id` | u32 | Sequential file id, referenced by `refs.file` and `from.file`. |
| `path` | string | File path; archive members use the `!!` delimiter. |
| `type` | string | File type, e.g. `pe`, `elf`, `macho`, `python`, `zip`. |
| `sha` | string | SHA-256. |
| `size` | u64 | File size in bytes. |
| `risk` | u32 | Weighted risk score. Omitted when 0. |
| `depth` | u32 | Archive nesting depth. Omitted when 0. |
| `mol` | string | Molecular formula. Omitted if absent. |
| `ident` | `Identity` | Normalised identity claims: name, version, signer, trust tier (from filefacts). Omitted if absent. |
| `traits` | array | Findings, as compact traits (below). Omitted if empty. |
| `supp` | array | Suppressions: notable-or-above traits that matched but were withheld or demoted (below). Omitted if empty. |
| `refs` | array | Declared references (deps, URLs, repository) — the file→dependency edges. Omitted if empty. |
| `ctx` | array | Merged context windows: raw match-highlight bytes in file order. Omitted if empty. |
| `facts` | object | Dense filefacts-derived facts (below). Omitted if empty. |

### Compact trait (`traits[]`)

| JSON | Type | Meaning |
| ---- | ---- | ------- |
| `id` | string | Trait id, e.g. `objectives/execution/shell/bash`. |
| `crit` | u8 | Criticality ordinal 0–5 (see below). |
| `desc` | string | Description. Omitted if empty. |
| `conf` | f32 | Confidence. Always emitted; a missing `conf` (only from builds that omitted it) decodes to `0.0`. |
| `mbc` | string | MBC id. Omitted if unset. |
| `atk` | string | ATT&CK technique. Omitted if unset. |
| `from` | array | Cross-file composite provenance: `{file, line?, off?}` per contributing member. Omitted when the finding is native to this file. |
| `spans` | array | Evidence byte spans `[[offset, length], …]`, capped at 8. Locate matches in `ctx` by range intersection. Omitted if empty. |
| `uses` | array | For a composite: ascending indices into this file's own `traits[]` of the components it fired on — the composite→component edges of the trait graph. Omitted for atomic traits and when empty. |

`uses` is index-based rather than id-based because the ids are already in the
array: repeating them would cost far more than a small integer, and on a
30k-trait corpus the edges add under 1% to the report. Composites chain — a
`uses` entry may itself be a composite with its own `uses`.

Containers resolve their own edges. Archive and encoding-layer inheritance
copies a composite *and* the components it fired on into the parent, so a
member's composite re-emitted on the enclosing zip indexes the zip's own
`traits[]`, while `from` names the member it came from: `uses` is the shape of
the detection, `from` is where it happened, and a cross-file composite carries
both. Indices never dangle — a ref the report does not carry is dropped, which
happens for roughly 0.6% of edges (an `unless:`-suppressed component the
composite still recorded, or a leg that stayed behind in a member).

`from[].line` carries the 1-based source line of a component match when known —
so a composite that fires across members cites each leg down to the line.

### Suppression (`supp[]`)

What the analysis decided *not* to report: a trait that matched the file but was
withheld by an `unless:` leg or demoted by a `downgrade:` leg. Recorded so a
reader can weigh that call on the same evidence instead of taking silence for
absence — a credential path withheld because the file "looks like a test
fixture" is a judgement worth checking, not a fact.

| JSON | Type | Meaning |
| ---- | ---- | ------- |
| `id` | string | The trait that matched. No description is carried — the taxonomy path says what the trait is, and a copy of the prose here would be a second place for it to go stale. |
| `crit` | string | The criticality it would have carried. |
| `kind` | string | `unless` (withheld outright) or `downgrade` (demoted one level). |
| `by` | array | The legs that fired: `{id, spans?}`, where `spans` are `[[offset, length], …]` byte spans. Omitted if empty. |

Only notable-or-above suppressions are recorded: below that the engine withholds
constantly and none of it changes an assessment. A trait is recorded only when
its positive condition *also* matched — `unless:` is evaluated first as a cheap
early-out, so most `unless:` hits land on rules that were never going to fire,
and reporting those would be false. Legs carry spans rather than rendered bytes
because the most common suppressors are `crit: exception` composites, stripped
from the report before anything could resolve them; the span is enough to pull
the bytes from the file.

`cleave --format tiny` (the payload `scan --format interpret` prints verbatim)
renders each as a `withheld`/`downgraded` line naming the trait, the legs, and
their spans. A file is never skipped from that output for having nothing but
withheld traits to report, and a per-file cap on how many are listed still ends
with a `+N more suppressed` count — an assessment built on what the analysis
reported is only as good as its account of what it withheld.

### Compact reference (`refs[]`)

Byte-anchored file→target edges (consumed by prism's galaxy view):

| JSON | Type | Meaning |
| ---- | ---- | ------- |
| `to` | string | Locator: a PURL/URL for an external target, or the raw specifier (e.g. `./util`) for an internal one. |
| `kind` | string | `dependency`, `command`, `url_fetch`, `repository`, … |
| `off` | u64 | Byte offset of the reference — the citation anchor. |
| `file` | u32 | When the reference resolves to another file in this bundle, that file's `id` (the intra-bundle file→file edge). Absent for external targets. |

Local references resolve to sibling members via
`src/types/reference_graph.rs` (relative-path join bounded by the archive
container, Node-style extension/index resolution). A package registry lookup is
grafted onto the artifact node as its own `registry` file whose provenance leg a
package-scoped composite can then reference.

### Compact facts (`facts`)

| JSON | Meaning |
| ---- | ------- |
| `metrics` | Metrics tree, floats rounded to 2 dp (from filefacts' flat metric map). |
| `imp` | Imports as `[library, name]` or `[library, name, ordinal]`. |
| `exp` | Exports as `[name]` or `[name, forward_to]`. |
| `funcs` | Functions as `[name]`, `[name, offset]`, or `[name, offset, kind]`. |
| `sec` | Sections as `[name, file_offset, file_size, entropy, flags]`. |
| `tgt` | Source AST call targets. |
| `mbr` | Source AST member chains. |

Each field is omitted when empty. The `facts` block is intentionally not a
lossless mirror of the full report; it is the dense, ML/UI-oriented fact
surface. Extracted strings are not duplicated here — they surface as the raw
bytes of the `ctx` context windows.

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
| `context`             | array of `ContextLine`        | Merged match-highlight windows: raw bytes in file order.         |
| `structure`           | array of `StructuralFeature`  | Binary-format properties: packing, entropy, obfuscation.         |
| `functions`           | array of `Function`           | Disassembled functions with complexity and CFG metrics.          |
| `strings`             | array of `StringInfo`         | Extracted literals.                                              |
| `comments`            | array of `StringInfo`         | Source comments extracted from parsed code.                     |
| `sections`            | array of `Section`            | Binary sections with entropy and permissions.                    |
| `imports`             | array of `Import`             | Imported symbols.                                                |
| `exports`             | array of `Export`             | Exported symbols.                                                |
| `yara_matches`        | array of `YaraMatch`          | YARA rule matches with matched strings.                          |
| `syscalls`            | array of `SyscallInfo`        | Syscalls observed in disassembly.                                |
| `filefacts`           | `FilefactsView`               | Format-specific metadata from filefacts: PE manifests and signing, Mach-O entitlements, DWARF producer, etc. |
| `identity`            | `Identity`                    | Normalised identity claims: name, version, signer, trust tier.   |
| `values_tree`         | JSON object                   | Format-specific metadata: manifest, DWARF, EXIF, etc.            |
| `filefacts_metrics`   | object                        | Flat numeric metric map, e.g. `{"binary.overall_entropy": 7.12}`. The sole numeric metric surface. |
| `filefacts_metric_spans` | object                     | Byte-span provenance for located metrics: metric name → `[Span, …]` where each was measured. |
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

There is one further, assembly-only criticality — `Exception` — used purely as
a benign-context leg inside composite `unless:`/`downgrade:` clauses (e.g. to
signal intent that suppresses a match). Exception findings are stripped before
serialization and never appear in output; in the compact context-note wire
encoding they would carry ordinal `6`, past the emitted `0..=5` range.

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
