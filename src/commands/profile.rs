//! YARA profiling command
//!
//! This module provides functionality to profile individual YARA rule files for performance.
//! It scans a target file against each rule file individually, measuring execution time for each,
//! and comparing with the combined scan time when all rules are compiled together.
//!
//! This helps identify which YARA rules have the longest execution times, enabling
//! optimization of the rule set for better performance.

use anyhow::{Context, Result};
use std::fs;
use std::path::Path;
use std::time::Instant;
use walkdir::WalkDir;

/// Profile individual YARA rule files against a target file.
///
/// Scans the target file against each rule file separately, measuring execution time,
/// and compares with combined scan time. Displays rules that exceed the minimum
/// millisecond threshold, sorted by execution time.
pub(crate) fn run(target: &Path, min_ms: u64) -> Result<()> {
    let data = fs::read(target).with_context(|| format!("Failed to read {}", target.display()))?;

    let third_party_dir = Path::new("third_party");
    if !third_party_dir.exists() {
        anyhow::bail!("third_party/ directory not found");
    }

    // Collect all YARA rule files
    let rule_files: Vec<_> = WalkDir::new(third_party_dir)
        .follow_links(false)
        .into_iter()
        .filter_map(Result::ok)
        .filter(|e| {
            let p = e.path();
            p.is_file()
                && p.extension()
                    .map(|x| x == "yar" || x == "yara")
                    .unwrap_or(false)
        })
        .map(|e| e.path().to_path_buf())
        .collect();

    eprintln!(
        "Profiling {} rule files against {} ...",
        rule_files.len(),
        target.display()
    );

    // For each rule file: compile, scan, record elapsed (including sub-threshold files for total)
    let mut total_individual_ms: u64 = 0;
    let mut results: Vec<(u64, String)> = rule_files
        .iter()
        .filter_map(|path| {
            let source = fs::read(path).ok()?;
            let mut compiler = yara_x::Compiler::new();
            compiler.add_source(source.as_slice()).ok()?;
            let rules = compiler.build();
            let mut scanner = yara_x::Scanner::new(&rules);
            scanner.set_timeout(std::time::Duration::from_secs(30));
            let t = Instant::now();
            let _ = scanner.scan(&data);
            let elapsed_ms = t.elapsed().as_millis() as u64;
            Some((elapsed_ms, path.clone()))
        })
        .inspect(|(ms, _)| total_individual_ms += ms)
        .filter_map(|(ms, path)| {
            if ms >= min_ms {
                let label = path
                    .strip_prefix(third_party_dir)
                    .unwrap_or(&path)
                    .display()
                    .to_string();
                Some((ms, label))
            } else {
                None
            }
        })
        .collect();

    results.sort_by(|a, b| b.0.cmp(&a.0));

    // Measure combined scan time (all rules compiled together, as in normal operation)
    let combined_ms = {
        let mut compiler = yara_x::Compiler::new();
        for path in &rule_files {
            if let Ok(source) = fs::read(path) {
                let _ = compiler.add_source(source.as_slice());
            }
        }
        let rules = compiler.build();
        let mut scanner = yara_x::Scanner::new(&rules);
        scanner.set_timeout(std::time::Duration::from_secs(30));
        let t = Instant::now();
        let _ = scanner.scan(&data);
        t.elapsed().as_millis() as u64
    };

    if !results.is_empty() {
        println!("{:>8}  rule file", "ms");
        println!("{}", "-".repeat(72));
        for (ms, label) in &results {
            println!("{:>8}  {}", ms, label);
        }
        println!();
    }
    println!(
        "{:>8}ms  sum of individual scans ({} files)",
        total_individual_ms,
        rule_files.len()
    );
    println!(
        "{:>8}ms  combined scan (all rules together, as in normal operation)",
        combined_ms
    );
    if !results.is_empty() {
        println!(
            "\n{} rule files shown (>= {}ms threshold)",
            results.len(),
            min_ms
        );
    }

    Ok(())
}
