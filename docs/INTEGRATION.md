# Integrating with Cleave

Three paths in. Pick by volume.

| Path        | Pick when                                              | Reference                              |
| ----------- | ------------------------------------------------------ | -------------------------------------- |
| CLI         | One-shot or batch use up to ~5 analyses / minute.      | `cleave --help`                        |
| HTTP server | Sustained traffic past ~5 analyses / minute.           | [SERVER_API.md](SERVER_API.md)         |
| Rust library| You are already in Rust and need direct access.       | [RUST_API.md](RUST_API.md)             |

All three emit the same `AnalysisReport`. Schema and field names:
[JSON.md](JSON.md).

## Notes

**Criticality** runs 0–5 (filtered, component, baseline, notable,
suspicious, hostile). Score weights: baseline/component/filtered=0,
notable=1, suspicious=40, hostile=120. Reference:
[JSON.md#criticality](JSON.md#criticality).

**File format coverage** lives in [../FILE_FORMATS.md](../FILE_FORMATS.md).

**CLI streaming**: `--format jsonl` emits one report per line for
pipelines.

**Library stability** is weaker than the CLI and HTTP surfaces.
Breaking changes between minor releases until 1.0. Pin a commit. The
JSON `AnalysisReport` is stable within a major version regardless of
path.

**Operational requirements** for the library: 8 MB rayon stack,
`kill_all_rizin_groups()` at shutdown, cooperative cancellation via
`AnalysisOptions::cancellation`. See
[RUST_API.md#operational-notes](RUST_API.md#operational-notes).

## Upstream

[Litmus](https://github.com/atomdrift-project/litmus) is the canonical
consumer: it embeds the library, exposes its own HTTP and worker
modes, and wraps each `AnalysisReport` as the `raw` field of a
classification envelope. See its
[INTEGRATION.md](../../litmus/docs/INTEGRATION.md).
