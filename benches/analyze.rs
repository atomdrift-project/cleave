//! End-to-end analysis benchmarks using real testdata samples.
//!
//! These benchmarks exercise the full analysis pipeline on representative
//! binaries so that profiling tools (perf, samply, flamegraph) can identify
//! real-world hotspots.
//!
//! Run all:        cargo bench --bench analyze
//! Profile one:    cargo bench --bench analyze -- "pe_test_exe"
//! With flamegraph: cargo flamegraph --bench analyze -- --bench "pe_test_exe"
//! With samply:    cargo bench --bench analyze --no-run && samply record target/release/deps/analyze-*

#![allow(missing_docs)]

use criterion::{BenchmarkId, Criterion, Throughput, black_box, criterion_group, criterion_main};
use std::time::Duration;

/// Load a testdata file, returning None if it doesn't exist (CI may lack large fixtures).
fn load(path: &str) -> Option<Vec<u8>> {
    std::fs::read(path).ok()
}

/// Options with YARA and radare2 disabled for focused CPU profiling of the analysis core.
fn fast_options() -> cleave::AnalysisOptions {
    cleave::AnalysisOptions {
        disable_yara: true,
        disable_radare2: true,
        ..Default::default()
    }
}

/// Options with radare2 disabled but YARA enabled.
fn yara_options() -> cleave::AnalysisOptions {
    cleave::AnalysisOptions {
        disable_radare2: true,
        ..Default::default()
    }
}

/// Full pipeline options (YARA + radare2 enabled).
fn full_options() -> cleave::AnalysisOptions {
    cleave::AnalysisOptions::default()
}

/// Representative binary samples used across multiple benchmark groups.
const CORE_SAMPLES: &[(&str, &str)] = &[
    ("pe_test_exe_2.5mb", "tests/fixtures/test.exe"),
    (
        "go_linux_amd64_2.3mb",
        "tests/fixtures/lang_strings/go_linux_amd64",
    ),
    (
        "go_darwin_arm64_2.4mb",
        "tests/fixtures/lang_strings/go_darwin_arm64",
    ),
    (
        "go_windows_2.5mb",
        "tests/fixtures/lang_strings/go_windows_amd64.exe",
    ),
    (
        "rust_native_525kb",
        "tests/fixtures/lang_strings/rust_native",
    ),
    (
        "script_kworker_23kb",
        "tests/fixtures/malware/kworker_obfuscated_1",
    ),
    (
        "python_xmrig_1kb",
        "tests/fixtures/malware/ultralytics_xmrig.py",
    ),
    (
        "java_suspicious_1.4kb",
        "tests/fixtures/java/Suspicious.class",
    ),
    ("java_hello_427b", "tests/fixtures/java/HelloWorld.class"),
];

// ---------------------------------------------------------------------------
// Core analysis pipeline — uncached (YARA disabled)
// ---------------------------------------------------------------------------

fn bench_analyze_bytes(c: &mut Criterion) {
    cleave::cache::set_skip_cache_override(Some(true));

    let mut g = c.benchmark_group("analyze_bytes");
    g.sample_size(10);
    g.measurement_time(Duration::from_secs(15));

    let opts = fast_options();

    for (name, path) in CORE_SAMPLES {
        let Some(data) = load(path) else { continue };
        let len = data.len() as u64;

        g.throughput(Throughput::Bytes(len));
        g.bench_with_input(BenchmarkId::new("no_yara", name), &data, |b, data| {
            b.iter(|| cleave::analyze_bytes(black_box(data), black_box(path), black_box(&opts)));
        });
    }

    g.finish();
}

// ---------------------------------------------------------------------------
// With YARA scanning but no radare2 — uncached
// ---------------------------------------------------------------------------

fn bench_analyze_yara(c: &mut Criterion) {
    cleave::cache::set_skip_cache_override(Some(true));

    let mut g = c.benchmark_group("analyze_yara");
    g.sample_size(10);
    g.measurement_time(Duration::from_secs(20));

    let samples: &[(&str, &str)] = &[
        ("pe_test_exe_2.5mb", "tests/fixtures/test.exe"),
        (
            "go_linux_amd64_2.3mb",
            "tests/fixtures/lang_strings/go_linux_amd64",
        ),
        (
            "rust_native_525kb",
            "tests/fixtures/lang_strings/rust_native",
        ),
        (
            "script_kworker_23kb",
            "tests/fixtures/malware/kworker_obfuscated_1",
        ),
    ];

    let opts = yara_options();

    for (name, path) in samples {
        let Some(data) = load(path) else { continue };
        let len = data.len() as u64;

        g.throughput(Throughput::Bytes(len));
        g.bench_with_input(BenchmarkId::new("yara_no_r2", name), &data, |b, data| {
            b.iter(|| cleave::analyze_bytes(black_box(data), black_box(path), black_box(&opts)));
        });
    }

    g.finish();
}

// ---------------------------------------------------------------------------
// Full pipeline (YARA + radare2) — uncached
// ---------------------------------------------------------------------------

fn bench_analyze_full(c: &mut Criterion) {
    cleave::cache::set_skip_cache_override(Some(true));

    let mut g = c.benchmark_group("analyze_full");
    g.sample_size(10);
    g.measurement_time(Duration::from_secs(30));

    let samples: &[(&str, &str)] = &[
        ("pe_test_exe_2.5mb", "tests/fixtures/test.exe"),
        (
            "go_linux_amd64_2.3mb",
            "tests/fixtures/lang_strings/go_linux_amd64",
        ),
    ];

    let opts = full_options();

    for (name, path) in samples {
        let Some(data) = load(path) else { continue };
        let len = data.len() as u64;

        g.throughput(Throughput::Bytes(len));
        g.bench_with_input(BenchmarkId::new("yara_and_r2", name), &data, |b, data| {
            b.iter(|| cleave::analyze_bytes(black_box(data), black_box(path), black_box(&opts)));
        });
    }

    g.finish();
}

// ---------------------------------------------------------------------------
// analyze_file — cached (measures cache-hit fast path after warmup)
// ---------------------------------------------------------------------------

fn bench_analyze_file_cached(c: &mut Criterion) {
    cleave::cache::set_skip_cache_override(Some(false));

    let mut g = c.benchmark_group("analyze_file_cached");
    g.sample_size(10);
    g.measurement_time(Duration::from_secs(15));

    let samples: &[(&str, &str)] = &[
        ("pe_test_exe_2.5mb", "tests/fixtures/test.exe"),
        (
            "go_linux_amd64_2.3mb",
            "tests/fixtures/lang_strings/go_linux_amd64",
        ),
        (
            "script_kworker_23kb",
            "tests/fixtures/malware/kworker_obfuscated_1",
        ),
    ];

    let opts = fast_options();

    for (name, path) in samples {
        if !std::path::Path::new(path).exists() {
            continue;
        }
        let len = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);

        // Prime the cache with one analysis before measuring
        let _ = cleave::analyze_file(path, &opts);

        g.throughput(Throughput::Bytes(len));
        g.bench_function(BenchmarkId::new("cached", name), |b| {
            b.iter(|| cleave::analyze_file(black_box(path), black_box(&opts)));
        });
    }

    g.finish();
}

// ---------------------------------------------------------------------------
// analyze_file — uncached (measures full analysis including disk I/O)
// ---------------------------------------------------------------------------

fn bench_analyze_file_uncached(c: &mut Criterion) {
    cleave::cache::set_skip_cache_override(Some(true));

    let mut g = c.benchmark_group("analyze_file_uncached");
    g.sample_size(10);
    g.measurement_time(Duration::from_secs(15));

    let samples: &[(&str, &str)] = &[
        ("pe_test_exe_2.5mb", "tests/fixtures/test.exe"),
        (
            "go_linux_amd64_2.3mb",
            "tests/fixtures/lang_strings/go_linux_amd64",
        ),
        (
            "script_kworker_23kb",
            "tests/fixtures/malware/kworker_obfuscated_1",
        ),
    ];

    let opts = fast_options();

    for (name, path) in samples {
        if !std::path::Path::new(path).exists() {
            continue;
        }
        let len = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);

        g.throughput(Throughput::Bytes(len));
        g.bench_function(BenchmarkId::new("uncached", name), |b| {
            b.iter(|| cleave::analyze_file(black_box(path), black_box(&opts)));
        });
    }

    g.finish();
}

// ---------------------------------------------------------------------------
// LNK file analysis (small files, tests parser overhead)
// ---------------------------------------------------------------------------

fn bench_analyze_lnk(c: &mut Criterion) {
    cleave::cache::set_skip_cache_override(Some(true));

    let mut g = c.benchmark_group("analyze_lnk");

    let samples: &[(&str, &str)] = &[
        ("benign_notepad", "tests/fixtures/lnk/benign_notepad.lnk"),
        (
            "powershell_hidden",
            "tests/fixtures/lnk/powershell_hidden.lnk",
        ),
        ("cmd_download", "tests/fixtures/lnk/cmd_download.lnk"),
        ("encoded_command", "tests/fixtures/lnk/encoded_command.lnk"),
        ("mshta_payload", "tests/fixtures/lnk/mshta_payload.lnk"),
    ];

    let opts = fast_options();

    for (name, path) in samples {
        let Some(data) = load(path) else { continue };
        let len = data.len() as u64;

        g.throughput(Throughput::Bytes(len));
        g.bench_with_input(BenchmarkId::new("no_yara", name), &data, |b, data| {
            b.iter(|| cleave::analyze_bytes(black_box(data), black_box(path), black_box(&opts)));
        });
    }

    g.finish();
}

// ---------------------------------------------------------------------------
// Archive extraction + analysis
// ---------------------------------------------------------------------------

fn bench_analyze_archive(c: &mut Criterion) {
    cleave::cache::set_skip_cache_override(Some(true));

    let mut g = c.benchmark_group("analyze_archive");
    g.sample_size(10);
    g.measurement_time(Duration::from_secs(15));

    let samples: &[(&str, &str)] = &[
        ("zip_187b", "tests/fixtures/archives/test.zip"),
        ("tar_gz_356b", "tests/fixtures/archives/test.tar.gz"),
        ("encrypted_7z_239b", "testdata/encrypted.7z"),
        ("malware_zip_424kb", "testdata/malware/midd.zip"),
    ];

    let opts = fast_options();

    for (name, path) in samples {
        let Some(data) = load(path) else { continue };
        let len = data.len() as u64;

        g.throughput(Throughput::Bytes(len));
        g.bench_with_input(BenchmarkId::new("no_yara", name), &data, |b, data| {
            b.iter(|| cleave::analyze_bytes(black_box(data), black_box(path), black_box(&opts)));
        });
    }

    g.finish();
}

// ---------------------------------------------------------------------------
// diff_files — differential analysis between two samples
// ---------------------------------------------------------------------------

fn bench_diff(c: &mut Criterion) {
    cleave::cache::set_skip_cache_override(Some(true));

    let mut g = c.benchmark_group("diff_files");
    g.sample_size(10);
    g.measurement_time(Duration::from_secs(15));

    let pairs: &[(&str, &str, &str)] = &[
        (
            "go_linux_vs_darwin",
            "tests/fixtures/lang_strings/go_linux_amd64",
            "tests/fixtures/lang_strings/go_darwin_arm64",
        ),
        (
            "java_hello_vs_suspicious",
            "tests/fixtures/java/HelloWorld.class",
            "tests/fixtures/java/Suspicious.class",
        ),
    ];

    for (name, old, new) in pairs {
        if !std::path::Path::new(old).exists() || !std::path::Path::new(new).exists() {
            continue;
        }

        g.bench_function(*name, |b| {
            b.iter(|| cleave::diff_files(black_box(old), black_box(new)));
        });
    }

    g.finish();
}

criterion_group!(
    benches,
    bench_analyze_bytes,
    bench_analyze_yara,
    bench_analyze_full,
    bench_analyze_file_cached,
    bench_analyze_file_uncached,
    bench_analyze_lnk,
    bench_analyze_archive,
    bench_diff,
);
criterion_main!(benches);
