//! Example program.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! Memory profiling example for PE analysis
//!
//! Run with: cargo run --release --example memory_profile_pe <pe_file>

use cleave::analyzers::pe::PEAnalyzer;
use cleave::analyzers::Analyzer;
use cleave::memory_tracker::{
    current_rss, global_tracker, log_after_file_processing, log_before_file_processing,
};
use std::env;
use std::fs;
use std::time::Instant;

fn format_bytes(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{} B", bytes)
    } else if bytes < 1024 * 1024 {
        format!("{:.2} KB", bytes as f64 / 1024.0)
    } else if bytes < 1024 * 1024 * 1024 {
        format!("{:.2} MB", bytes as f64 / 1024.0 / 1024.0)
    } else {
        format!("{:.2} GB", bytes as f64 / 1024.0 / 1024.0 / 1024.0)
    }
}

fn log_memory(label: &str) {
    if let Some(rss) = current_rss() {
        println!("[{}] RSS: {}", label, format_bytes(rss));
    } else {
        println!("[{}] RSS: Unable to determine", label);
    }
}

fn main() -> anyhow::Result<()> {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: {} <pe_file>", args[0]);
        std::process::exit(1);
    }

    let file_path = &args[1];
    println!("=== Memory Profile: PE Analysis ===");
    println!("File: {}", file_path);
    println!();

    // Get file metadata
    log_memory("START");
    let metadata = fs::metadata(file_path)?;
    let file_size = metadata.len();
    println!("File size: {}", format_bytes(file_size));
    println!();

    // Log before processing
    log_before_file_processing(file_path, file_size);

    // Step 1: Read file into memory
    log_memory("BEFORE file read");
    let start = Instant::now();
    let data = fs::read(file_path)?;
    println!("[FILE READ] Took: {:?}", start.elapsed());
    log_memory("AFTER file read");
    println!(
        "Memory increase from file read: ~{}",
        format_bytes(data.len() as u64)
    );
    println!();

    // Track with global tracker
    global_tracker().record_file_read(file_size, file_path);

    // Step 2: Parse PE headers
    log_memory("BEFORE PE parse");
    let start = Instant::now();
    let pe = goblin::pe::PE::parse(&data)?;
    println!("[PE PARSE] Took: {:?}", start.elapsed());
    log_memory("AFTER PE parse");
    println!("PE sections: {}", pe.sections.len());
    println!("PE imports: {}", pe.imports.len());
    println!("PE exports: {}", pe.exports.len());
    println!();

    // Step 3: Full analysis with PE analyzer
    log_memory("BEFORE full analysis");
    let start = Instant::now();
    let analyzer = PEAnalyzer::new();
    let report = analyzer.analyze(std::path::Path::new(file_path))?;
    println!("[FULL ANALYSIS] Took: {:?}", start.elapsed());
    log_memory("AFTER full analysis");
    println!();

    // Report statistics
    println!("=== Analysis Results ===");
    println!("Strings extracted: {}", report.strings.len());
    println!("Functions found: {}", report.functions.len());
    println!("Findings: {}", report.findings.len());
    println!("Traits detected: {}", report.traits.len());
    println!();

    // Estimate memory per component
    let strings_memory: usize = report
        .strings
        .iter()
        .map(|s| s.value.len() + std::mem::size_of_val(s))
        .sum();
    println!(
        "Estimated string storage: {}",
        format_bytes(strings_memory as u64)
    );

    let functions_memory = report.functions.len() * std::mem::size_of::<cleave::types::Function>();
    println!(
        "Estimated function storage: {}",
        format_bytes(functions_memory as u64)
    );

    let findings_memory: usize = report
        .findings
        .iter()
        .map(|f| f.desc.len() + f.evidence.iter().map(|e| e.value.len()).sum::<usize>() + 200)
        .sum();
    println!(
        "Estimated findings storage: {}",
        format_bytes(findings_memory as u64)
    );

    println!();
    log_memory("END");

    // Final stats
    if let Some(peak_rss) = current_rss() {
        println!();
        println!("=== Summary ===");
        println!("File size: {}", format_bytes(file_size));
        println!("Peak RSS: {}", format_bytes(peak_rss));
        println!(
            "Memory amplification: {:.1}x",
            peak_rss as f64 / file_size as f64
        );
    }

    // Log completion
    log_after_file_processing(file_path, file_size, start.elapsed());

    // Print global stats
    global_tracker().log_stats();

    Ok(())
}
