# Integrating with Cleave

Two paths in. Pick by volume.

| Path        | Pick when                                              | Reference                              |
| ----------- | ------------------------------------------------------ | -------------------------------------- |
| CLI         | One-shot or batch use.                                 | `cleave --help`                        |
| Rust library| You are already in Rust and need direct access.       | [RUST_API.md](RUST_API.md)             |

Both emit the same `AnalysisReport`. Schema and field names:
[JSON.md](JSON.md).

## Notes

**Criticality** runs 0–5 (filtered, component, baseline, notable,
suspicious, hostile). Score weights: baseline/component/filtered=0,
notable=1, suspicious=40, hostile=120. Reference:
[JSON.md#criticality](JSON.md#criticality).

**File format coverage** lives in [../FILE_FORMATS.md](../FILE_FORMATS.md).

**CLI streaming**: `--format jsonl` emits one report per line for
pipelines.

**Library stability** is weaker than the CLI surface: the Rust API may
change between minor releases, so pin a version or commit. The JSON
`AnalysisReport` is stable within a major version.

**Operational requirements** for the library: 8 MB rayon stack,
`kill_all_rizin_groups()` at shutdown, cooperative cancellation via
`AnalysisOptions::cancellation`. See
[RUST_API.md#operational-notes](RUST_API.md#operational-notes).

