//! Regression tests for archive analysis temp-file behavior.

use std::collections::HashSet;
use std::fs;
use std::io::Write;
use std::path::PathBuf;

#[test]
fn zip_analysis_does_not_extract_to_tmpdir_by_default() -> anyhow::Result<()> {
    let _guard = crate::support::global_lock();

    let work = tempfile::tempdir()?;
    let zip_path = work.path().join("sample.zip");

    {
        let zip_file = fs::File::create(&zip_path)?;
        let mut zip = zip::ZipWriter::new(zip_file);
        let options = zip::write::FileOptions::<()>::default();
        zip.start_file(
            "ILSpy-10.0-preview2/ICSharpCode.Decompiler.Tests/TestCases/ILPretty/Issue3552.cs",
            options,
        )?;
        zip.write_all(
            b"class Issue3552 { static void Main() { System.Console.WriteLine(\"ok\"); } }",
        )?;
        zip.start_file("package.json", options)?;
        zip.write_all(br#"{"name":"tmp-regression","version":"1.0.0"}"#)?;
        zip.finish()?;
    }

    // Scan the process's real temp dir rather than pointing TMPDIR at a
    // scratch directory: TMPDIR is process-global, and mutating it here raced
    // with every other test in this binary creating its own temp files.
    let tmp = std::env::temp_dir();
    let before = extraction_leftovers(&tmp)?;

    cleave::set_skip_traits_override(Some(true));
    let result = cleave::analyze_file(
        &zip_path,
        &cleave::AnalysisOptions {
            disable_yara: true,
            disable_radare2: true,
            ..Default::default()
        },
    );
    cleave::set_skip_traits_override(None);
    result?;

    let leftovers: Vec<_> = extraction_leftovers(&tmp)?
        .into_iter()
        .filter(|path| !before.contains(path))
        .collect();
    assert!(
        leftovers.is_empty(),
        "archive analysis left zip-extraction temp entries under TMPDIR: {leftovers:?}"
    );

    Ok(())
}

/// Entries under `dir` whose names look like they came from extracting the
/// zip built above, or from cleave's archive-extraction scratch space.
fn extraction_leftovers(dir: &std::path::Path) -> anyhow::Result<HashSet<PathBuf>> {
    Ok(fs::read_dir(dir)?
        .filter_map(Result::ok)
        .filter(|entry| {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            name.contains("Issue3552")
                || name.contains("ILPretty")
                || name.contains("package.json")
                || name.starts_with("cleave-archive")
        })
        .map(|entry| entry.path())
        .collect())
}
