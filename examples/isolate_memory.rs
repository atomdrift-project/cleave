//! Example program.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use cleave::analyzers::pe::PEAnalyzer;
use cleave::memory_tracker::current_rss;

fn format_mb(bytes: u64) -> String {
    format!("{:.2} MB", bytes as f64 / 1024.0 / 1024.0)
}

fn main() {
    let start = current_rss().unwrap();
    println!("Start: {}", format_mb(start));

    // Just create analyzer
    let analyzer = PEAnalyzer::new();
    let after_new = current_rss().unwrap();
    println!("After PEAnalyzer::new(): {}", format_mb(after_new));
    println!("Cost: {}", format_mb(after_new - start));

    // Keep it alive
    drop(analyzer);

    let after_drop = current_rss().unwrap();
    println!("After drop: {}", format_mb(after_drop));
}
