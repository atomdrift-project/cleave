//! Example program.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! Detailed memory profiling to identify memory hotspots

use cleave::analyzers::{pe::PEAnalyzer, Analyzer};
use cleave::memory_tracker::current_rss;
use std::env;
use std::fs;

fn format_bytes(bytes: u64) -> String {
    if bytes < 1024 * 1024 {
        format!("{:.2} KB", bytes as f64 / 1024.0)
    } else {
        format!("{:.2} MB", bytes as f64 / 1024.0 / 1024.0)
    }
}

fn log_memory(label: &str) -> u64 {
    let rss = current_rss().unwrap_or(0);
    println!("[{}] RSS: {}", label, format_bytes(rss));
    rss
}

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: {} <pe_file>", args[0]);
        std::process::exit(1);
    }

    let file_path = &args[1];
    println!("=== Detailed Memory Profile ==={}", file_path);
    println!();

    let start_rss = log_memory("START");

    let metadata = fs::metadata(file_path)?;
    let file_size = metadata.len();
    println!("File size: {}\n", format_bytes(file_size));

    // Read file
    let before_read = log_memory("BEFORE file read");
    let data = fs::read(file_path)?;
    let after_read = log_memory("AFTER file read");
    println!(
        "File read cost: {}\n",
        format_bytes(after_read - before_read)
    );

    // Parse PE
    let before_parse = log_memory("BEFORE goblin parse");
    let _pe = goblin::pe::PE::parse(&data)?;
    let after_parse = log_memory("AFTER goblin parse");
    println!(
        "Goblin parse cost: {}\n",
        format_bytes(after_parse - before_parse)
    );

    // Create analyzer
    let before_analyzer = log_memory("BEFORE analyzer creation");
    let analyzer = PEAnalyzer::new();
    let after_analyzer = log_memory("AFTER analyzer creation");
    println!(
        "Analyzer creation cost: {}\n",
        format_bytes(after_analyzer - before_analyzer)
    );

    // Full analysis
    let before_analysis = log_memory("BEFORE full analysis");
    let report = analyzer.analyze(std::path::Path::new(file_path))?;
    let after_analysis = log_memory("AFTER full analysis");
    println!(
        "Full analysis cost: {}\n",
        format_bytes(after_analysis - before_analysis)
    );

    // Report memory breakdown
    println!("=== Report Contents ===");
    println!("Strings: {}", report.strings.len());
    println!("Functions: {}", report.functions.len());
    println!("Findings: {}", report.findings.len());
    println!("Traits: {}", report.traits.len());
    println!("Imports: {}", report.imports.len());
    println!("Exports: {}", report.exports.len());
    println!("Sections: {}", report.sections.len());
    println!();

    // Estimate memory per component
    let string_mem: usize = report
        .strings
        .iter()
        .map(|s| s.value.len() + std::mem::size_of_val(s))
        .sum();
    println!("String memory: {}", format_bytes(string_mem as u64));

    let func_mem = report.functions.len() * std::mem::size_of::<cleave::types::Function>();
    println!("Function memory: {}", format_bytes(func_mem as u64));

    let finding_mem: usize = report.findings.iter().map(|f| f.desc.len() + 200).sum();
    println!("Finding memory: {}", format_bytes(finding_mem as u64));

    let import_mem = report.imports.len() * 100;
    println!("Import memory (est): {}", format_bytes(import_mem as u64));

    let export_mem = report.exports.len() * 100;
    println!("Export memory (est): {}", format_bytes(export_mem as u64));

    println!();
    let final_rss = log_memory("FINAL");

    println!("\n=== Memory Breakdown ===");
    println!("Base process: {}", format_bytes(start_rss));
    println!("File data: {}", format_bytes(file_size));
    println!("Total RSS: {}", format_bytes(final_rss));
    println!(
        "Overhead: {}",
        format_bytes(final_rss - start_rss - file_size)
    );
    println!("Amplification: {:.1}x", final_rss as f64 / file_size as f64);

    Ok(())
}
