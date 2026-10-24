//! Registry package types must survive extraction and model report flattening.
use cleave::{AnalysisOptions, Engine};

#[test]
fn source_package_downloads_keep_their_ecosystem_type() {
    let cases: &[(&str, &[u8], &str)] = &[
        (
            "crate",
            include_bytes!("../data/package-types/crate.tar.gz"),
            "Cargo.toml",
        ),
        (
            "pub",
            include_bytes!("../data/package-types/pub.tar.gz"),
            "pubspec.yaml",
        ),
        (
            "cran",
            include_bytes!("../data/package-types/cran.tar.gz"),
            "DESCRIPTION",
        ),
        (
            "cpan",
            include_bytes!("../data/package-types/cpan.tar.gz"),
            "META.json",
        ),
        (
            "hackage",
            include_bytes!("../data/package-types/hackage.tar.gz"),
            "demo.cabal",
        ),
        (
            "hex",
            include_bytes!("../data/package-types/hex.tar"),
            "metadata.config",
        ),
        (
            "composer",
            include_bytes!("../data/package-types/composer.zip"),
            "composer.json",
        ),
    ];
    let dir = tempfile::tempdir().unwrap();
    let engine = Engine::empty().with_compact_members(true);
    for (kind, bytes, manifest) in cases {
        let path = dir.path().join(format!("download-{kind}"));
        std::fs::write(&path, bytes).unwrap();
        let mut report = engine
            .analyze_file(&path, &AnalysisOptions::default())
            .unwrap();
        assert_eq!(report.target.file_type, *kind);
        assert!(
            report
                .archive_contents
                .iter()
                .any(|entry| entry.path.ends_with(manifest)),
            "{kind}: missing manifest after extraction"
        );
        report.finalize();
        assert_eq!(report.files[0].file_type, *kind);
        assert!(
            report.files.len() > 1,
            "{kind}: members must still be analyzed"
        );
    }
}
