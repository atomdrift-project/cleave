//! Regression coverage for FileFacts recognition of standalone DOS boot sectors.

use cleave::{AnalysisOptions, analyze_bytes};

#[test]
fn shimmer_boot_sector_is_recognized_and_exposes_embedded_strings() -> anyhow::Result<()> {
    let sample = crate::support::sample("testdata/dos-boot/shimmer.d");
    let report = analyze_bytes(
        &sample,
        "shimmer.d",
        &AnalysisOptions {
            yara: false,
            rizin: false,
            upx: false,
            ..Default::default()
        },
    )?;

    // filefacts names a standalone FAT boot sector rather than calling it data.
    assert_eq!(report.target.file_type, "fat_boot_sector");
    assert!(
        report
            .strings
            .iter()
            .any(|s| s.value.contains("winstart.bat")),
        "the copied boot sector should expose its startup-script path: {:?}",
        report.strings.iter().map(|s| &s.value).collect::<Vec<_>>(),
    );
    assert!(
        report
            .strings
            .iter()
            .any(|s| s.value.contains("New Shimmer")),
        "the copied boot sector should expose its author marker",
    );
    Ok(())
}
