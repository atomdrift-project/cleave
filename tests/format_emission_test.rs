//! Per-format regression tests for filefacts-backed emission.
//!
//! These tests load representative fixtures and assert the canonical
//! metric/value paths trait authors are expected to read from. Compact
//! v5 stores filefacts data under `ff`: typed fact families are kept out
//! of residual values, grouped metrics live under `ff.m`, and residual
//! values live under `ff.v`.
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

/// Run `cleave --json analyze <path>` and return the first file's
/// compact view. Skips YARA + cache for speed and determinism.
fn analyze(path: &Path) -> Option<Value> {
    // Fixtures not present on the test host silently skip (the binary fixtures
    // are gitignored); we test what the host can extract, not require every one.
    if !path.exists() {
        eprintln!("skipping: fixture {} not present", path.display());
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
    let report: Value = serde_json::from_str(line).unwrap_or_else(|e| panic!("bad JSON: {e}"));
    Some(
        report["files"]
            .as_array()
            .and_then(|a| a.first())
            .cloned()
            .expect("report has no files"),
    )
}

/// Compact v5 metrics as a flat dotted-key map.
fn metrics(file: &Value) -> HashMap<String, f64> {
    let mut out = HashMap::new();
    let groups = file
        .pointer("/fact/met")
        .and_then(Value::as_object)
        .expect("compact v5 filefacts metrics missing");
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

/// Compact v5 residual values as a flat dotted-key map.
fn kv(file: &Value) -> HashMap<String, Value> {
    file.pointer("/fact/val")
        .and_then(Value::as_object)
        .expect("compact v5 filefacts values missing")
        .iter()
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect()
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
fn pe_emits_format_specific_kv() {
    let Some(f) = analyze(Path::new("tests/fixtures/test.exe")) else {
        return;
    };
    let k = kv(&f);
    for key in [
        "pe.machine",
        "pe.subsystem",
        "pe.timestamp",
        "pe.entry_point",
        "pe.entry_section",
        "pe.image_base",
        "pe.imphash",
        "pe.image_hash.sha256",
    ] {
        assert!(k.contains_key(key), "missing PE kv key {key}");
    }
    // Imports are a typed fact family in v5, not residual values.
    let imports = f
        .pointer("/fact/imp")
        .and_then(Value::as_array)
        .expect("PE imports should be present under ff.i");
    assert!(imports.iter().any(|entry| {
        entry.as_array().is_some_and(|fields| {
            fields.first().and_then(Value::as_str).is_some()
                && fields.get(1).and_then(Value::as_str).is_some()
        })
    }));
    assert!(!k.contains_key("pe.imports[0].library"));
    assert!(!k.contains_key("pe.imports[0].functions[0]"));
}

// ────────────────────────────────────────────────────────────────────
//  ELF format-specific
// ────────────────────────────────────────────────────────────────────

#[test]
fn elf_emits_format_specific_kv_and_metrics() {
    let Some(f) = analyze(Path::new("tests/fixtures/test.elf")) else {
        return;
    };
    let m = metrics(&f);
    let k = kv(&f);
    assert!(k.contains_key("elf.machine"));
    assert!(k.contains_key("elf.type"));
    assert!(k.contains_key("elf.entry_section"));
    // Hardening flags expressed as flat metrics — keep them locked in.
    for key in ["elf.bits", "elf.little_endian", "elf.program_header_count"] {
        assert!(m.contains_key(key), "missing ELF metric {key}");
    }
}

// ────────────────────────────────────────────────────────────────────
//  Mach-O format-specific
// ────────────────────────────────────────────────────────────────────

#[test]
fn macho_emits_format_specific_kv() {
    let Some(f) = analyze(Path::new("tests/fixtures/test.macho")) else {
        return;
    };
    let k = kv(&f);
    assert!(k.contains_key("macho.cpu_type"));
    // Indexed import structure should be there.
    assert!(k.contains_key("macho.imports[0]") || k.contains_key("macho.libraries[0]"));
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
    // Arguments value should be in the kv tree, not just analyzed.
    let k = kv(&f);
    assert!(k.contains_key("lnk.arguments"));
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
        "archive.total_uncompressed",
        "archive.total_compressed",
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

/// Tar.gz is handled by cleave's archive analyzer (which decompresses
/// and recurses); filefacts itself only carries `archive.*` extraction for
/// uncompressed tar by design. The compressed wrapper still shows
/// `archive.format.kind = "tar.gz"` in kv and surfaces member-level
/// detail via `archive.members[N].*` — those are the keys traits
/// targeting tar.gz actually rely on.
#[test]
fn targz_emits_member_level_kv_and_format_kind() {
    let Some(f) = analyze(Path::new("tests/fixtures/archives/test.tar.gz")) else {
        return;
    };
    let k = kv(&f);
    assert_eq!(
        k.get("archive.format.kind").and_then(|v| v.as_str()),
        Some("tar.gz")
    );
    assert!(k.contains_key("archive.member_count"));
    assert!(k.contains_key("archive.members[0].path"));
    assert!(k.contains_key("archive.members[0].sha256"));
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
