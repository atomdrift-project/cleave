//! Per-format regression tests for filefacts-backed emission.
//!
//! These tests load representative fixtures and assert the canonical
//! metric paths trait authors are expected to read from. Compact v8 stores
//! filefacts data under `facts`: typed fact families (`imp`/`exp`/`sec`/…)
//! sit alongside grouped metrics under `facts.metrics`. The residual `val`
//! kv tree was retired in v8.
//!
//! - Cross-format counts: `sections.count`, `imports.count`,
//!   `exports.count`, `functions.count`, `dependencies.count`,
//!   `parse.error_count`.
//! - Per-format residual detail under the format namespace (`pe.*`,
//!   `elf.*`, `macho.*`, `lnk.*`, `archive.*`, ...).
//!
//! Each test runs cleave via subprocess on a real fixture and parses the
//! compact JSON output. Fixtures not present on the test host silently
//! skip; the goal is catching regressions on what the host can extract,
//! not requiring every fixture everywhere.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use serde_json::Value;
use std::collections::HashMap;
use std::path::Path;

/// Run `cleave --json analyze <path>` and return the full compact report.
/// Skips YARA + cache for speed and determinism. Returns `None` when the
/// fixture is not present on the test host (binary fixtures are gitignored;
/// we test what the host can extract, not require every one).
fn analyze_report(path: &Path) -> Option<Value> {
    if !path.exists() {
        crate::support::skip_missing(&path.display().to_string());
        return None;
    }
    let mut cmd = assert_cmd::cargo_bin_cmd!("cleave");
    let output = cmd
        .env("CLEAVE_SKIP_YARA", "1")
        .env("CLEAVE_SKIP_CACHE", "1")
        .args(["--json", "analyze", path.to_str().unwrap()])
        .output()
        .expect("cleave run");
    assert!(
        output.status.success(),
        "cleave failed: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let line = stdout
        .lines()
        .find(|l| l.trim_start().starts_with('{'))
        .expect("no JSON line in cleave output");
    Some(serde_json::from_str(line).unwrap_or_else(|e| panic!("bad JSON: {e}")))
}

/// Run `cleave --json analyze <path>` and return the first file's compact view.
fn analyze(path: &Path) -> Option<Value> {
    let report = analyze_report(path)?;
    Some(
        report["files"]
            .as_array()
            .and_then(|a| a.first())
            .cloned()
            .expect("report has no files"),
    )
}

/// Compact v8 metrics as a flat dotted-key map.
fn metrics(file: &Value) -> HashMap<String, f64> {
    let mut out = HashMap::new();
    let groups = file
        .pointer("/facts/metrics")
        .and_then(Value::as_object)
        .expect("compact v8 filefacts metrics missing");
    for (group, fields) in groups {
        let Some(fields) = fields.as_object() else {
            continue;
        };
        for (field, value) in fields {
            if let Some(value) = value.as_f64() {
                out.insert(format!("{group}.{field}"), value);
            }
        }
    }
    out
}

/// `true` when every canonical cross-format count is present in `m`.
/// Returns the list of missing keys so the calling test can produce
/// an informative panic.
fn missing_canonical_counts(m: &HashMap<String, f64>, expected: &[&str]) -> Vec<String> {
    expected
        .iter()
        .filter(|k| !m.contains_key(**k))
        .map(|k| (*k).to_string())
        .collect()
}

// ────────────────────────────────────────────────────────────────────
//  Cross-format canonical paths
// ────────────────────────────────────────────────────────────────────

/// Every binary file type (PE/ELF/Mach-O) must surface the unified
/// `sections.*`, `imports.*`, `exports.*`, `dependencies.*` counts.
/// These are the canonical names that replaced the format-scoped
/// `pe.import_count` / `elf.import_count` / `macho.import_count`
/// aliases and the legacy `binary.section_count` / `binary.dependency_count`.
#[test]
fn pe_emits_canonical_cross_format_counts() {
    let Some(f) = analyze(Path::new("tests/fixtures/test.exe")) else {
        return;
    };
    assert_eq!(f["type"].as_str(), Some("pe"));
    let m = metrics(&f);
    let missing = missing_canonical_counts(
        &m,
        &[
            "sections.count",
            "sections.executable_count",
            "sections.writable_count",
            "sections.executable_writable_count",
            "sections.code_size",
            "sections.name_entropy",
            "sections.nonstandard_count",
            "imports.count",
            "dependencies.count",
        ],
    );
    assert!(missing.is_empty(), "missing canonical metrics: {missing:?}");
    assert!(m["sections.count"] > 0.0);
    assert!(m["imports.count"] > 0.0);
    assert!(m["dependencies.count"] > 0.0);
}

#[test]
fn elf_emits_canonical_cross_format_counts() {
    let Some(f) = analyze(Path::new("tests/fixtures/test.elf")) else {
        return;
    };
    assert_eq!(f["type"].as_str(), Some("elf"));
    let m = metrics(&f);
    let missing = missing_canonical_counts(
        &m,
        &[
            "sections.count",
            "sections.executable_count",
            "sections.writable_count",
            "sections.executable_writable_count",
            "sections.code_size",
            "sections.name_entropy",
            "sections.nonstandard_count",
            "imports.count",
            "exports.count",
            "dependencies.count",
        ],
    );
    assert!(missing.is_empty(), "missing canonical metrics: {missing:?}");
    assert!(m["sections.count"] > 0.0);
    assert!(m["imports.count"] > 0.0);
    assert!(m["exports.count"] > 0.0);
}

#[test]
fn macho_emits_canonical_cross_format_counts() {
    let Some(f) = analyze(Path::new("tests/fixtures/test.macho")) else {
        return;
    };
    assert_eq!(f["type"].as_str(), Some("macho"));
    let m = metrics(&f);
    let missing = missing_canonical_counts(
        &m,
        &[
            "sections.count",
            "sections.executable_count",
            "sections.writable_count",
            "sections.executable_writable_count",
            "sections.code_size",
            "sections.name_entropy",
            "sections.nonstandard_count",
            "imports.count",
            "exports.count",
            "dependencies.count",
        ],
    );
    assert!(missing.is_empty(), "missing canonical metrics: {missing:?}");
    assert!(m["sections.count"] > 0.0);
}

/// The retired legacy aliases must NOT re-appear. If anyone re-adds
/// `binary.section_count` / `binary.import_count` / etc., this test
/// catches the regression immediately.
#[test]
fn no_retired_aliases_emit() {
    for path in [
        "tests/fixtures/test.exe",
        "tests/fixtures/test.elf",
        "tests/fixtures/test.macho",
    ] {
        let Some(f) = analyze(Path::new(path)) else {
            continue;
        };
        let m = metrics(&f);
        for retired in [
            "binary.section_count",
            "binary.import_count",
            "binary.export_count",
            "binary.dependency_count",
            "binary.wx_section_count",
            "binary.has_signature",
            "binary.signed",
            "binary.has_executable_stack",
            "binary.has_malformed_structure",
            "binary.aliased_exports",
            "binary.function_count",
            "binary.rizin_function_count",
            "binary.signed_with_individual_cert",
            "pe.import_count",
            "pe.export_count",
            "pe.imported_library_count",
            "elf.import_count",
            "elf.export_count",
            "elf.section_count",
            "elf.needed_count",
            "macho.import_count",
            "macho.export_count",
            "macho.library_count",
            "imports.total",
            "functions.total",
            "archive.compression_ratio",
            "archive.symlink_count",
            "archive.encrypted_count",
            "chm.itsf_lcid",
        ] {
            assert!(
                !m.contains_key(retired),
                "retired alias {retired} re-emitted for {path}"
            );
        }
    }
}

// ────────────────────────────────────────────────────────────────────
//  PE format-specific
// ────────────────────────────────────────────────────────────────────

#[test]
fn pe_emits_typed_import_family() {
    let Some(f) = analyze(Path::new("tests/fixtures/test.exe")) else {
        return;
    };
    // Imports are a typed fact family in v8 (`facts.imp`), each entry a
    // `[library, name]` tuple — not residual `pe.imports[0].*` kv keys.
    let imports = f
        .pointer("/facts/imp")
        .and_then(Value::as_array)
        .expect("PE imports should be present under facts.imp");
    assert!(imports.iter().any(|entry| {
        entry.as_array().is_some_and(|fields| {
            fields.first().and_then(Value::as_str).is_some()
                && fields.get(1).and_then(Value::as_str).is_some()
        })
    }));
}

// ────────────────────────────────────────────────────────────────────
//  ELF format-specific
// ────────────────────────────────────────────────────────────────────

#[test]
fn elf_emits_format_specific_metrics() {
    let Some(f) = analyze(Path::new("tests/fixtures/test.elf")) else {
        return;
    };
    let m = metrics(&f);
    // Hardening flags expressed as flat metrics — keep them locked in.
    for key in ["elf.bits", "elf.little_endian", "elf.program_header_count"] {
        assert!(m.contains_key(key), "missing ELF metric {key}");
    }
}

// ────────────────────────────────────────────────────────────────────
//  Mach-O format-specific
// ────────────────────────────────────────────────────────────────────

#[test]
fn macho_emits_typed_import_family_and_metrics() {
    let Some(f) = analyze(Path::new("tests/fixtures/test.macho")) else {
        return;
    };
    // Mach-O load-command structure surfaces as flat metrics in v8.
    let m = metrics(&f);
    assert!(
        m.contains_key("macho.load_command_count"),
        "missing Mach-O metric macho.load_command_count"
    );
    // Imports are a typed fact family (`facts.imp`), not indexed kv keys.
    let imports = f
        .pointer("/facts/imp")
        .and_then(Value::as_array)
        .expect("Mach-O imports should be present under facts.imp");
    assert!(!imports.is_empty(), "Mach-O should surface imports");
}

// ────────────────────────────────────────────────────────────────────
//  LNK format-specific
// ────────────────────────────────────────────────────────────────────

/// LNK extractor surfaces argument-whitespace-obfuscation metrics
/// (CVE-2025-9491 detection signal). All four metrics must be
/// emitted whenever the LNK has an arguments field.
#[test]
fn lnk_emits_argument_whitespace_metrics() {
    let Some(f) = analyze(Path::new("tests/fixtures/lnk/powershell_hidden.lnk")) else {
        return;
    };
    assert_eq!(f["type"].as_str(), Some("lnk"));
    let m = metrics(&f);
    for key in [
        "lnk.args_leading_spaces",
        "lnk.args_leading_tabs",
        "lnk.args_whitespace_total",
        "lnk.args_max_whitespace_run",
    ] {
        assert!(m.contains_key(key), "missing LNK metric {key}");
    }
}

// ────────────────────────────────────────────────────────────────────
//  ZIP archive
// ────────────────────────────────────────────────────────────────────

/// ZIP archive aggregates landed under the canonical `archive.*`
/// namespace with the `archive.security.*` sub-namespace for hostile
/// permission flags. The flat aliases (`archive.symlink_count`,
/// `archive.encrypted_count`, `archive.compression_ratio`) were
/// retired in favor of the nested forms.
#[test]
fn zip_emits_canonical_archive_keys() {
    let Some(f) = analyze(Path::new("tests/fixtures/archives/test.zip")) else {
        return;
    };
    assert_eq!(f["type"].as_str(), Some("zip"));
    let m = metrics(&f);
    for key in [
        "archive.file_count",
        "archive.directory_count",
        "archive.member_count",
        "archive.uncompressed_size",
        "archive.compressed_size",
        "archive.security.symlink_count",
        "archive.security.encrypted_count",
        "archive.security.setuid_count",
        "archive.security.setgid_count",
        "archive.security.world_writable_count",
    ] {
        assert!(m.contains_key(key), "missing ZIP archive metric {key}");
    }
    // The legacy flat aliases are retired.
    assert!(!m.contains_key("archive.symlink_count"));
    assert!(!m.contains_key("archive.encrypted_count"));
    assert!(!m.contains_key("archive.compression_ratio"));
}

// ────────────────────────────────────────────────────────────────────
//  Tar (gzipped)
// ────────────────────────────────────────────────────────────────────

/// Tar.gz is handled by cleave's archive analyzer (which decompresses and
/// recurses). In v8 the wrapper is typed `tar.gz` and each member is surfaced
/// as its own `files[]` entry (path `<archive>!!<member>`, `depth > 0`) rather
/// than the retired `archive.members[N].*` kv keys — those member files are
/// what traits targeting tar.gz contents now analyze.
#[test]
fn targz_emits_members_as_child_files() {
    let Some(report) = analyze_report(Path::new("tests/fixtures/archives/test.tar.gz")) else {
        return;
    };
    let files = report["files"]
        .as_array()
        .expect("report should contain file entries");
    assert_eq!(
        files[0]["type"].as_str(),
        Some("tar.gz"),
        "wrapper file should be typed tar.gz"
    );
    let member = files.iter().find(|f| {
        f["path"].as_str().is_some_and(|p| p.contains("!!")) && f["depth"].as_u64().unwrap_or(0) > 0
    });
    assert!(
        member.is_some(),
        "tar.gz member should be surfaced as a child file: {files:?}"
    );
}

// ────────────────────────────────────────────────────────────────────
//  parse.error_count is the universal "malformed" signal
// ────────────────────────────────────────────────────────────────────

/// Healthy fixtures emit no parse errors; the metric is absent. A
/// regression that introduces spurious parse errors on a benign
/// binary catches here.
#[test]
fn healthy_pe_has_no_parse_errors() {
    let Some(f) = analyze(Path::new("tests/fixtures/test.exe")) else {
        return;
    };
    let m = metrics(&f);
    let errs = m.get("parse.error_count").copied().unwrap_or(0.0);
    assert_eq!(errs, 0.0, "unexpected parse errors on healthy PE: {errs}");
}
