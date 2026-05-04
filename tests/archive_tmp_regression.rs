//! Regression tests for archive analysis temp-file behavior.

use std::fs;
use std::io::Write;
use std::sync::{Mutex, OnceLock};

fn env_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

#[test]
fn zip_analysis_does_not_extract_to_tmpdir_by_default() -> anyhow::Result<()> {
    let _guard = env_lock()
        .lock()
        .map_err(|e| anyhow::anyhow!("env lock poisoned: {e}"))?;

    let work = tempfile::tempdir()?;
    let tmp = work.path().join("tmp");
    fs::create_dir(&tmp)?;
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

    let old_tmp = std::env::var_os("TMPDIR");
    std::env::set_var("TMPDIR", &tmp);
    let result = cleave::analyze_file(
        &zip_path,
        &cleave::AnalysisOptions {
            disable_yara: true,
            disable_radare2: true,
            ..Default::default()
        },
    );
    match old_tmp {
        Some(value) => std::env::set_var("TMPDIR", value),
        None => std::env::remove_var("TMPDIR"),
    }
    result?;

    // TMPDIR is process-global; other tests running in parallel may legitimately
    // leave their own tempdirs under it. We only fail on entries whose name
    // looks like a zip extraction — i.e., names containing one of the archive
    // members above, or starting with cleave's archive-extraction prefix.
    let leftovers: Vec<_> = fs::read_dir(&tmp)?
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .filter(|entry| {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            name.contains("Issue3552")
                || name.contains("ILPretty")
                || name.contains("package.json")
                || name.starts_with("cleave-archive")
        })
        .collect();
    assert!(
        leftovers.is_empty(),
        "archive analysis left zip-extraction temp entries under TMPDIR: {:?}",
        leftovers
            .iter()
            .map(std::fs::DirEntry::path)
            .collect::<Vec<_>>()
    );

    Ok(())
}
