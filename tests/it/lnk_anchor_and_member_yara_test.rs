//! Two regression guards for LNK analysis, both first seen on the same sample:
//! a shortcut nested in a zip that rendered no annotated byte spans and lost
//! its third-party YARA hits.
//!
//! 1. **Every LNK finding must anchor.** LNK traits match on structural values
//!    (`lnk.arguments`, `lnk.target_path`, …). `capture()` can only build a
//!    context window from evidence carrying a byte offset, which for a `value`
//!    match comes from filefacts' `<path>_offset` companion. Without those
//!    companions every LNK finding fell back to the semantic `value:<path>`
//!    label and the report showed no spans at all.
//!
//! 2. **An archive member's YARA hits must become findings.** The member path
//!    collected `report.yara_matches` but never converted them, so third-party
//!    rules that fire on a standalone file were silently dropped once the same
//!    bytes sat inside an archive.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::Path;

use cleave::{AnalysisOptions, AnalysisReport, analyze_file};

const FLAG_HAS_ARGUMENTS: u32 = 0x0000_0020;
const FLAG_IS_UNICODE: u32 = 0x0000_0080;

/// A minimal but structurally valid shortcut: the 76-byte header the LNK magic
/// requires, followed by one StringData field holding the arguments. The
/// arguments carry `cmd /c` plus PowerShell tokens, which is what both cleave's
/// own `lnk.arguments` traits and the shipped third-party LNK rulesets key on.
fn synthetic_lnk() -> Vec<u8> {
    const ARGS: &str = "/c powershell -nop -w hidden -enc QQBBAEEAQQA=";

    let mut lnk = vec![0x4C, 0x00, 0x00, 0x00, 0x01, 0x14, 0x02, 0x00];
    lnk.resize(76, 0);
    lnk[20..24].copy_from_slice(&(FLAG_HAS_ARGUMENTS | FLAG_IS_UNICODE).to_le_bytes());

    let chars: Vec<u16> = ARGS.encode_utf16().collect();
    lnk.extend_from_slice(&(chars.len() as u16).to_le_bytes());
    for unit in &chars {
        lnk.extend_from_slice(&unit.to_le_bytes());
    }
    lnk
}

fn write_zip(path: &Path, member: &str, bytes: &[u8]) -> anyhow::Result<()> {
    let mut zip = zip::ZipWriter::new(std::fs::File::create(path)?);
    zip.start_file(member, zip::write::SimpleFileOptions::default())?;
    std::io::Write::write_all(&mut zip, bytes)?;
    zip.finish()?;
    Ok(())
}

fn third_party_ids<'a>(findings: impl IntoIterator<Item = &'a cleave::Finding>) -> Vec<String> {
    let mut ids: Vec<String> = findings
        .into_iter()
        .map(|f| f.id.to_string())
        .filter(|id| id.starts_with("third_party/"))
        .collect();
    ids.sort();
    ids
}

/// Findings on the `.lnk` member of an archive report.
fn member_lnk_findings(report: &AnalysisReport) -> &[cleave::Finding] {
    report
        .files
        .iter()
        .find(|f| f.file_type == "lnk")
        .map(|f| f.findings.as_slice())
        .expect("archive report must contain the LNK member")
}

#[test]
fn lnk_value_findings_carry_byte_offsets() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("shortcut.lnk");
    std::fs::write(&path, synthetic_lnk())?;

    let report = analyze_file(&path, &AnalysisOptions::default())?;
    assert!(
        !report.findings.is_empty(),
        "synthetic LNK must produce findings to anchor",
    );

    // No finding may fall back to the semantic `value:<path>` label: that
    // fallback means filefacts published the fact without a `<path>_offset`
    // companion, and an unanchored finding renders no span.
    let unanchored: Vec<(String, String)> = report
        .findings
        .iter()
        .flat_map(|f| {
            f.evidence
                .iter()
                .filter_map(|e| e.location.clone())
                .filter(|l| l.starts_with("value:"))
                .map(move |l| (f.id.to_string(), l))
        })
        .collect();
    assert!(
        unanchored.is_empty(),
        "every LNK finding must anchor to a byte offset; unanchored: {unanchored:?}",
    );

    assert!(
        !report.context.is_empty(),
        "an anchored LNK must render context windows",
    );
    Ok(())
}

#[test]
fn archive_member_keeps_the_yara_findings_it_gets_standalone() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let bytes = synthetic_lnk();

    let standalone_path = dir.path().join("shortcut.lnk");
    std::fs::write(&standalone_path, &bytes)?;
    let standalone = analyze_file(&standalone_path, &AnalysisOptions::default())?;
    let expected = third_party_ids(&standalone.findings);
    assert!(
        !expected.is_empty(),
        "standalone LNK produced no third-party YARA findings — the shipped \
         third-party rulesets this test compares against are missing",
    );

    let zip_path = dir.path().join("shortcut.zip");
    write_zip(&zip_path, "shortcut.lnk", &bytes)?;
    let archived = analyze_file(&zip_path, &AnalysisOptions::default())?;

    assert_eq!(
        third_party_ids(member_lnk_findings(&archived)),
        expected,
        "a LNK inside an archive must keep the YARA findings it gets standalone",
    );
    Ok(())
}
