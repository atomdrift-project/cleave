//! Integration test module.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use serde_json::Value;
use std::process::Command;

#[test]
#[ignore = "Requires specific test data file at /home/t.linux/data/known-bad/flayer/malware/js/2025.tailwind-magic/3.3.1/keylogger.js"]
fn test_keylogger_detection() {
    let file_path =
        "/home/t.linux/data/known-bad/flayer/malware/js/2025.tailwind-magic/3.3.1/keylogger.js";
    let output = Command::new("./target/release/flayer")
        .arg("--format")
        .arg("jsonl")
        .arg(file_path)
        .output()
        .expect("Failed to execute flayer");

    assert!(output.status.success(), "flayer failed");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut found = false;
    for line in stdout.lines() {
        if line.trim().is_empty() || line.starts_with("flayer") {
            continue;
        }
        if let Ok(json) = serde_json::from_str::<Value>(line) {
            if let Some(findings) = json.get("findings").and_then(|f| f.as_array()) {
                for finding in findings {
                    if let Some(id) = finding.get("id").and_then(|i| i.as_str()) {
                        if id == "objectives/credential-access/keylog/capture::js-keylogger-exfil" {
                            found = true;
                            // Check criticality
                            let crit = finding.get("crit").and_then(|c| c.as_str()).unwrap_or("");
                            assert_eq!(
                                crit, "suspicious",
                                "Criticality mismatch for js-keylogger-exfil"
                            );
                        }
                    }
                }
            }
        }
    }
    assert!(found, "js-keylogger-exfil trait not found");
}
