//! Example program.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! Heap profiling using dhat to identify memory allocation hotspots

use cleave::AnalysisOptions;
use std::env;

#[global_allocator]
static ALLOC: dhat::Alloc = dhat::Alloc;

fn main() -> anyhow::Result<()> {
    let _profiler = dhat::Profiler::new_heap();

    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: {} <file>", args[0]);
        std::process::exit(1);
    }

    let target = &args[1];
    println!("Profiling analysis of: {}", target);
    println!();

    // Run the analysis
    let path = std::path::Path::new(target);
    let options = AnalysisOptions::default();

    let _report = cleave::analyze_file(path, &options)?;

    println!("\n=== Heap Profile Complete ===");
    println!("dhat output written to dhat-heap.json");
    println!("View with: https://nnethercote.github.io/dh_view/dh_view.html");

    Ok(())
}
