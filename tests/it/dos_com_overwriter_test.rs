//! Regression coverage for compact, padded DOS COM overwriters without a
//! recognizable `.com` extension.

use cleave::{AnalysisOptions, analyze_bytes};

#[test]
fn anton_overwriter_is_dispatched_as_dos_com_and_exposes_its_markers() -> anyhow::Result<()> {
    let sample = crate::support::sample("testdata/dos-com/anton-97");
    let report = analyze_bytes(
        &sample,
        "anton-97",
        &AnalysisOptions {
            yara: false,
            rizin: false,
            upx: false,
            ..Default::default()
        },
    )?;

    assert_eq!(report.target.file_type, "dos_com");
    assert!(
        report
            .strings
            .iter()
            .any(|s| s.value.to_ascii_lowercase().contains("*.com")),
        "the DOS analyzer should expose its COM search mask: {:?}",
        report.strings.iter().map(|s| &s.value).collect::<Vec<_>>(),
    );
    assert!(
        report
            .strings
            .iter()
            .any(|s| s.value.contains("Borys; the Dragon of Dark Sun")),
        "the DOS analyzer should expose the specimen's author marker",
    );
    Ok(())
}
