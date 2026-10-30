# Cleave Rust API

Cleave is a Rust library for static analysis of binaries, source
code, archives, and documents. It extracts observable traits and
interprets them as findings against a catalogue of MBC and ATT&CK
rules.

This file documents the library API for Rust embedders. For the CLI,
run `cleave --help`. For the output schema, see
[JSON.md](JSON.md). The format coverage matrix lives in
[../FILE_FORMATS.md](../FILE_FORMATS.md); this document does not
duplicate it.

## Library entry points

All entry points live in the `cleave` crate root.

| Function                                         | Purpose                                                  |
| ------------------------------------------------ | -------------------------------------------------------- |
| `analyze_file(path, &opts)`                      | Analyze a file on disk.                                  |
| `analyze_bytes(&bytes, filename, &opts)`         | Analyze an in-memory buffer; `filename` labels it.       |
| `analyze_bytes_owned(bytes, filename, &opts)`    | Same, taking ownership of the buffer.                    |
| `analyze_bytes_shared(bytes, filename, &opts)`   | Same, for a shared `Bytes` buffer (no copy).             |
| `analyze_file_with_mapper(path, &opts, mapper)`  | Analyze with a caller-supplied `CapabilityMapper`.       |
| `scan_directory(path, &opts, cb)`                | Recursive directory walk; callback per file.             |
| `scan_paths(paths, &opts, cb)`                   | A pre-walked path list, filtered like `scan_directory`.  |
| `scan_files(&paths, &opts, cb)`                  | Explicit files, analyzed as given (no type/size filter). |
| `diff_files(old, new)`                           | Differential analysis for supply-chain triage.           |
| `detect_file_type(&bytes)`                       | Magic-byte / heuristic file type detection.              |
| `validate_traits()`                              | Verify the loaded trait catalogue is internally consistent. |
| `version_info()`                                 | Build version, commit, dependency versions.              |
| `formula_from_report(&report)`                   | Compute the molecular formula from findings.             |

Each `analyze_*` function returns `anyhow::Result<AnalysisReport>`.
`AnalysisReport` is the canonical output; its shape is documented in
[JSON.md](JSON.md).

### Engines

`Engine::for_options(&opts)` builds the rules, YARA engine and settings
`opts` describe once; `engine.analyze_file(path)`, `analyze_bytes` and
`analyze_bytes_shared` then analyze under exactly that engine.
`Engine::with_compact_members(true)` returns a copy that folds archive
members compactly. Engines with different settings can analyze side by side.

### Rules

`CapabilityMapper::try_new()` loads the configured traits with the defaults;
`CapabilityMapper::load(LoadOptions { full_validation: true, ..Default::default() })`
sets the precision thresholds, full validation and precision scoring. Both
return an error rather than an empty rule set when the traits cannot be loaded.
Pass the result to `Engine::from_rules` or `analyze_file_with_mapper`.

### Warming caches

The first call pays for trait loading, YARA compilation, and capability
mapping. For long-running processes, warm them up front:

    cleave::prefetch_shared_resources(true); // true: include third-party YARA

`prefetch_yara_engine(bool)` and `prefetch_capability_mapper()` warm one
each. Call them from a non-rayon thread.

### Disabling expensive components

Per call, via `AnalysisOptions` (`yara`, `rizin`, `upx`). rizin and UPX are
the only subprocesses; a host that forbids subprocess execution sets
`rizin: false` and `upx: false` on every call.

### Shutdown

    cleave::kill_all_rizin_groups();

Cleave spawns rizin as a child process group for ELF, PE, and Mach-O
disassembly. Call this at shutdown so stuck disassemblers do not
outlive the parent.

## `AnalysisOptions`

Plain `pub` fields with `Default`; build it with struct-update syntax
(`AnalysisOptions { yara: false, ..Default::default() }`). Every switch is
positive: `true` turns the component on.

| Field                       | Type                      | Default        | Effect                                                 |
| --------------------------- | ------------------------- | -------------- | ------------------------------------------------------ |
| `yara`                      | bool                      | true           | Scan with YARA.                                        |
| `third_party_yara`          | bool                      | true           | Load the third-party YARA rules too.                   |
| `rizin`                     | bool                      | true           | Disassemble native binaries (functions, syscalls).     |
| `rizin_timeout`             | `Option<Duration>`        | filefacts'     | Wall-clock budget for one rizin run.                   |
| `rizin_retry_timeout`       | `Option<Duration>`        | none           | Larger deadline for one retry of a timed-out binary.   |
| `rizin_max_bytes`           | `Option<usize>`           | none           | Skip rizin for native binaries larger than this.       |
| `rizin_native_arch_only`    | bool                      | false          | Disassemble only the host-native slice of a fat Mach-O.|
| `upx`                       | bool                      | true           | Unpack UPX-packed binaries.                            |
| `compact_members`           | bool                      | false          | Fold archive members keeping only the compact projection. |
| `zip_passwords`             | `Vec<String>`             | malware list   | Passwords tried on encrypted archives.                 |
| `all_files`                 | bool                      | false          | In directory scans, include unknown file types.        |
| `platforms`                 | `Vec<Platform>`           | all            | Restrict composite rules to target OSes.               |
| `min_hostile_precision`     | f32                       | 1.6            | Drop hostile composites below this precision.          |
| `min_suspicious_precision`  | f32                       | 0.0            | Same, for suspicious composites.                       |
| `precision_scoring`         | bool                      | false          | Warn on low-precision rules at load.                   |
| `full_validation`           | bool                      | false          | Run full trait validation at load.                     |
| `max_memory_file_size`      | u64                       | 512 MiB        | Max bytes loaded per archive member.                   |
| `max_scan_file_size`        | u64                       | 600 MiB        | Skip larger files in directory scans (0: no limit).    |
| `slow_rule_ms`              | u64                       | 4000           | Warn when a rule's evaluation exceeds this.            |
| `cancellation`              | `Option<Arc<AtomicBool>>` | none           | Cooperative cancellation flag.                         |
| `phase`                     | `Option<PhaseTracker>`    | none           | Observability handle for in-flight work.               |
| `dedicated_pool`            | bool                      | false          | The caller runs cleave on its own rayon pool.          |
| `skip_predicate`            | `Option<SkipPredicate>`   | none           | Skip archive members the predicate rejects.            |

### `PhaseTracker`

A small handle for telling external observers (a server's `/_/requests`
endpoint, a profiler, a watchdog) which phase a long analysis is in.

    let phase = PhaseTracker::with_label("incoming.zip");
    opts.phase = Some(phase.clone());
    // ... cleave updates phase internally: "extract", "yara", "disasm", ...
    println!("currently: {}", phase.get());

`PhaseTracker::new()` builds an unregistered tracker; `with_label`
registers it in cleave's global in-flight list.

## Configuration

### Environment variables

See the configuration table in the [README](../README.md); `src/env.rs`
classifies every variable cleave reads.

### Cargo features

| Feature              | Default | Effect                                                        |
| -------------------- | ------- | ------------------------------------------------------------- |
| `jemalloc`           | on      | Use jemalloc. Worth keeping on for long-running processes.    |
| `lint`               | on      | The trait-rule linter (`cleave validate`, full validation). Analysis-only embedders can drop it. |
| `jemalloc-prof`      | off     | jemalloc with heap profiling.                                 |
| `memprofile`         | off     | Phase-tagged heap-growth accounting (diagnostic).             |
| `memprofile-win`     | off     | The same accounting on Windows.                               |
| `deadlock-detection` | off     | `parking_lot` deadlock detection (debug aid).                 |

## Workspace crates

| Crate           | Purpose                                                          |
| --------------- | ---------------------------------------------------------------- |
| `cleave`        | Engine and public API.                                           |
| `yara-classify` | YARA-based file-type and tier classification.                    |
| `pyinstx`       | Pure-Rust PyInstaller bundle extraction.                         |
| `scpt`          | AppleScript `.scpt` parser and symbol extractor.                 |
| `sysmem`        | Dependency-free system memory queries.                           |
| `lzx`           | LZX decompression (CAB delta, CHM framing).                      |
| `cleave-macros` | Derive macros for the trait field-path tables.                   |

Parsing lives in the [filefacts](https://github.com/atomdrift-project/filefacts)
crate, a git dependency.

## Operational notes

- **Stack size.** Embed cleave behind an 8 MB rayon stack. The default
  2 MB stack is exhausted by recursive archive extraction on
  adversarial inputs; library consumers must configure their pool the
  same way.
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

    let opts = AnalysisOptions {
        platforms: vec![Platform::Linux],
        rizin: false,
        ..AnalysisOptions::default()
    };

    let report = cleave::analyze_file("sample.elf", &opts)?;
    println!("{}", serde_json::to_string_pretty(&report)?);

The JSON shape printed here is documented in
[JSON.md](JSON.md).
