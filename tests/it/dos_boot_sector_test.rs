//! Regression coverage for FileFacts recognition of standalone DOS boot sectors.

use cleave::{AnalysisOptions, analyze_file};

#[test]
fn shimmer_boot_sector_is_analyzed_as_data_and_exposes_embedded_strings() -> anyhow::Result<()> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("testdata/dos-boot/shimmer.d");
    let report = analyze_file(
        &path,
        &AnalysisOptions {
            disable_yara: true,
            disable_radare2: true,
            disable_upx: true,
            ..Default::default()
        },
    )?;

    assert_eq!(report.target.file_type, "data");
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
