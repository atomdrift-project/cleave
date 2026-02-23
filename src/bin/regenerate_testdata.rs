//! regenerate test data binary
use serde_json::Value;
use std::fs;
use std::io::{BufRead, BufReader};
use std::path::Path;
use std::process::Command;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let data_dir = Path::new(&std::env::var("HOME")?).join("data/flayer");
    let verify_dir = Path::new("tests/verify");

    if !data_dir.exists() {
        eprintln!("Error: {} does not exist", data_dir.display());
        std::process::exit(1);
    }

    println!("Regenerating test data from {}...", data_dir.display());

    // Run flayer on the entire directory with JSONL output
    let mut child = Command::new("./target/release/flayer")
        .arg("--format")
        .arg("jsonl")
        .arg(&data_dir)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()?;

    let stdout = child.stdout.take().ok_or("Failed to capture stdout")?;
    let reader = BufReader::new(stdout);

    // Clean testdata directory
    if verify_dir.exists() {
        fs::remove_dir_all(verify_dir)?;
    }
    fs::create_dir_all(verify_dir)?;

    let mut written_count = 0;
    // Parse JSONL output (one JSON object per line)
    for (line_num, line) in reader.lines().enumerate() {
        let line = line?;
        let line_num = line_num + 1;
        let trimmed = line.trim();

        if trimmed.is_empty() || trimmed.starts_with("flayer") {
            continue;
        }

        let file_result: Value = serde_json::from_str(trimmed)
            .map_err(|e| format!("Failed to parse JSON at line {}: {}", line_num, e))?;

        // Skip non-file objects (e.g., summary metadata)
        if file_result.get("type").and_then(|t| t.as_str()) != Some("file") {
            continue;
        }

        let file_path = file_result
            .get("path")
            .and_then(|p| p.as_str())
            .ok_or_else(|| format!("Missing path in file object at line {}", line_num))?;

        // Create relative path structure in verify/ directory
        let Ok(rel_path) = Path::new(file_path).strip_prefix(&data_dir) else {
            continue;
        };

        let snapshot_dir = verify_dir.join(rel_path.parent().unwrap_or_else(|| Path::new(".")));
        fs::create_dir_all(&snapshot_dir)?;

        let snapshot_path = snapshot_dir.join(format!(
            "{}.json",
            rel_path.file_name().unwrap_or_default().to_string_lossy()
        ));

        let json_content = serde_json::to_string_pretty(&file_result)?;
        fs::write(&snapshot_path, json_content)?;

        written_count += 1;
    }

    let status = child.wait()?;
    if !status.success() {
        eprintln!("Warning: flayer exited with non-zero status");
    }

    println!(
        "✓ Wrote {} snapshot files to {}",
        written_count,
        verify_dir.display()
    );
    Ok(())
}
