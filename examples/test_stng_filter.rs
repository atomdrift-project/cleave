use std::env;
use std::fs;

fn main() {
    let Some(path) = env::args().nth(1) else {
        eprintln!("Usage: cargo run --example test_stng_filter -- <file>");
        std::process::exit(1);
    };

    let data = fs::read(&path).unwrap_or_else(|e| {
        eprintln!("Failed to read {}: {}", path, e);
        std::process::exit(1);
    });

    let opts = stng::ExtractOptions::new(4).with_garbage_filter(true);
    let strings = stng::extract_strings_with_options(&data, &opts);
    println!("Extracted {} strings", strings.len());
}
