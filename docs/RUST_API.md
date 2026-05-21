# Cleave Rust API

Cleave is a Rust library for static analysis of binaries, source
code, archives, and documents. It extracts observable traits and
interprets them as findings against a catalogue of MBC and ATT&CK
rules.

This file documents the library API for Rust embedders. For the CLI,
run `cleave --help`. For the HTTP server, see
[SERVER_API.md](SERVER_API.md). For the output schema, see
[JSON.md](JSON.md). The format coverage matrix lives in
[../FILE_FORMATS.md](../FILE_FORMATS.md); this document does not
duplicate it.

Cleave is also a library dependency of [litmus](https://codeberg.org/atomdrift/litmus);
litmus's response envelope embeds an `AnalysisReport` as the `raw`
field.

## Library entry points

All entry points live in the `cleave` crate root.

| Function                               | Purpose                                                    |
| -------------------------------------- | ---------------------------------------------------------- |
| `analyze_file(path, &opts)`            | Analyse a file on disk.                                    |
| `analyze_bytes(&bytes, ft, &opts)`     | Analyse an in-memory buffer of known file type.            |
| `analyze_bytes_owned(bytes, ft, &opts)`| Same, taking ownership of the buffer.                      |
| `analyze_file_with_mapper(path, &opts, mapper)` | Analyse with a custom `CapabilityMapper`.         |
| `scan_directory(path, &opts, cb)`      | Recursive directory walk; callback per file.               |
| `diff_files(old, new)`                 | Differential analysis for supply-chain triage.             |
| `detect_file_type(&bytes)`             | Magic-byte / heuristic file type detection.                |
| `validate_traits()`                    | Verify the loaded trait catalogue is internally consistent.|
| `version_info()`                       | Build version, commit, dependency versions.                |
| `formula_from_report(&report)`         | Compute the molecular formula from findings.               |

Each `analyze_*` function returns `Result<AnalysisReport, Error>`.
`AnalysisReport` is the canonical output — its shape is documented in
[JSON.md](JSON.md).

### Warming caches

The first call pays for trait loading, YARA compilation, and capability
mapping. For long-running processes, warm them up front:

    cleave::prefetch_yara_engine();
    cleave::prefetch_capability_mapper();
    cleave::prefetch_shared_resources();

### Disabling expensive components

Each component can be disabled globally for the process:

    cleave::disable_rayon();
    expose::rizin::disable();
    cleave::disable_upx();

Or per call, via `AnalysisOptions`. Use the global switches when the
host explicitly forbids subprocess execution.

### Shutdown

    cleave::kill_all_rizin_groups();

Cleave spawns rizin as a child process group for ELF, PE, and Mach-O
disassembly. Call this at shutdown so stuck disassemblers do not
outlive the parent.

## `AnalysisOptions`

The options struct (`src/lib.rs:555`) is plain `pub` fields with
`Default`. Build it field-by-field; there is no builder.

| Field                       | Type                    | Default       | Effect                                                 |
| --------------------------- | ----------------------- | ------------- | ------------------------------------------------------ |
| `enable_third_party_yara`   | bool                    | false         | Load the third-party YARA rule set.                    |
| `zip_passwords`             | `Vec<String>`           | malware list  | Passwords tried on encrypted archives.                 |
| `disable_yara`              | bool                    | false         | Skip YARA scanning.                                    |
| `disable_radare2`           | bool                    | false         | Skip disassembly. No functions, no syscalls.           |
| `disable_upx`               | bool                    | false         | Skip UPX unpacking.                                    |
| `all_files`                 | bool                    | false         | In directory scans, include unknown file types.        |
| `platforms`                 | `Vec<Platform>`         | all           | Restrict composite rules to target OSes.               |
| `min_hostile_precision`     | f32                     | 0.0           | Drop composite rules below this precision.             |
| `min_suspicious_precision`  | f32                     | 0.0           | Same, for suspicious-level composites.                 |
| `enable_precision_scoring`  | bool                    | false         | Warn on low-precision rules at load.                   |
| `enable_full_validation`    | bool                    | false         | Comprehensive trait-definition checks.                 |
| `max_memory_file_size`      | u64                     | 256 MiB       | Max bytes loaded per archive member.                   |
| `max_scan_file_size`        | u64                     | 0 (unlimited) | Skip files larger than this in directory scans.        |
| `slow_rule_ms`              | u64                     | 4000          | Warn when a rule's evaluation exceeds this.            |
| `sample_extraction`         | `Option<SampleExtractionConfig>` | none | Write analysed archive members to disk.              |
| `cancellation`              | `Option<Arc<AtomicBool>>` | none        | Cooperative cancellation flag.                         |
| `phase`                     | `Option<PhaseTracker>`  | none          | Observability handle for in-flight work.               |

### `PhaseTracker`

A small handle for telling external observers (a server's `/_/requests`
endpoint, a profiler, a watchdog) which phase a long analysis is in.

    let phase = PhaseTracker::with_label("incoming.zip");
    opts.phase = Some(phase.clone());
    // ... cleave updates phase internally: "extract", "yara", "disasm", ...
    println!("currently: {}", phase.get());

`PhaseTracker::new()` builds an unregistered tracker; `with_label`
registers it in cleave's global in-flight list.

### `SampleExtractionConfig`

Used when the caller wants archive members written to disk for later
inspection.

    let cfg = SampleExtractionConfig::new(PathBuf::from("/var/samples"))
        .with_archive_sha256(archive_hash);
    opts.sample_extraction = Some(cfg);

Members land under `extract_dir/<sha256[0:6]>/<relative-path>`.

## Configuration

### Environment variables

| Variable                  | Effect                                                         |
| ------------------------- | -------------------------------------------------------------- |
| `CLEAVE_TRAITS_DIR`       | Path to the [cleave-traits](https://codeberg.org/atomdrift/cleave-traits) checkout. Required at first call. |
| `CLEAVE_RAYON_THREADS`    | Rayon pool size. Default is system parallelism.                |
| `CLEAVE_SKIP_CACHE`       | `1` disables both the analysis cache and the YARA match cache. |
| `CLEAVE_SKIP_YARA_CACHE`  | `1` disables the YARA match cache only.                        |
| `CLEAVE_VALIDATE`         | `1` runs full trait validation on startup.                     |
| `CLEAVE_LOG_LEVEL`        | tracing level: `error`, `warn`, `info`, `debug`, `trace`.      |
| `CLEAVE_LOGS_DIR`         | Write tracing logs to this directory instead of stderr.        |

### Cargo features

| Feature          | Default | Effect                                                        |
| ---------------- | ------- | ------------------------------------------------------------- |
| `jemalloc`       | on      | Use jemalloc. Worth keeping on for long-running processes.    |
| `jemalloc-prof`  | off     | jemalloc with heap profiling.                                 |
| `test_fast`      | off     | Skip YARA loading in tests.                                   |

## Workspace crates

Cleave is a workspace. The top-level crate re-exports the public API;
the rest are dependencies or single-purpose tools.

| Crate           | Purpose                                                          |
| --------------- | ---------------------------------------------------------------- |
| `cleave`        | Engine and public API.                                           |
| `fileid`        | Magic-byte and shebang file-type detection.                      |
| `yara-classify` | YARA-based file-type and tier classification.                    |
| `pyinstx`       | Pure-Rust PyInstaller bundle extraction.                         |
| `scpt`          | AppleScript `.scpt` parser and symbol extractor.                 |
| `malecule`      | Molecular formula synthesis from findings.                       |
| `sysmem`        | Dependency-free system memory queries.                           |
| `lzx`           | LZX decompression (CAB delta, CHM framing).                      |

## Operational notes

- **Stack size.** Embed cleave behind an 8 MB rayon stack. The default
  2 MB stack is exhausted by recursive archive extraction on
  adversarial inputs. Litmus does this in `main.rs`; library
  consumers must do the same.
- **Rizin subprocesses.** Cleave runs rizin in a separate process
  group. Stuck disassemblers are killed by group, not just by pid.
  Always call `kill_all_rizin_groups()` at shutdown.
- **Panic policy.** The workspace denies `panic!`, `unwrap`, and
  `expect` at lint level. Library code returns `Result`; do not catch
  panics defensively.
- **Cancellation.** Long analyses honour the `AnalysisOptions::cancellation`
  flag at safe points (between archive members, between YARA scans,
  between functions). Set the flag from a watchdog; do not rely on
  thread-killing.
- **Memory.** With jemalloc enabled, archive-heavy workloads keep RSS
  flat; without it, malloc arena fragmentation can grow without
  bound. Leave the `jemalloc` feature on unless you have a reason.

## Example

    use cleave::{AnalysisOptions, Platform};

    let mut opts = AnalysisOptions::default();
    opts.platforms = vec![Platform::Linux];
    opts.enable_third_party_yara = true;

    let report = cleave::analyze_file("sample.elf", &opts)?;
    println!("{}", serde_json::to_string_pretty(&report)?);

The JSON shape printed here is documented in
[JSON.md](JSON.md).
