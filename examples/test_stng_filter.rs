//! Example program.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::fs;

fn main() -> anyhow::Result<()> {
    let path = std::env::args()
        .nth(1)
        .expect("Usage: test_stng_filter <file>");
    let data = fs::read(&path)?;

    println!(
        "File size: {} bytes ({} MB)",
        data.len(),
        data.len() / 1024 / 1024
    );

    // Test stng with garbage filter ON
    let opts_on = stng::ExtractOptions::new(4)
        .with_garbage_filter(true)
        .with_xor(None);

    let strings_on = stng::extract_strings_with_options(&data, &opts_on);
    println!("stng WITH garbage filter: {} strings", strings_on.len());

    // Test stng with garbage filter OFF
    let opts_off = stng::ExtractOptions::new(4)
        .with_garbage_filter(false)
        .with_xor(None);

    let strings_off = stng::extract_strings_with_options(&data, &opts_off);
    println!("stng WITHOUT garbage filter: {} strings", strings_off.len());

    println!(
        "\nDifference: {} strings filtered out",
        strings_off.len() - strings_on.len()
    );
    println!(
        "Filter effectiveness: {:.1}%",
        100.0 * (strings_off.len() - strings_on.len()) as f64 / strings_off.len() as f64
    );

    // Show first 20 strings
    println!("\nFirst 20 strings (with filter):");
    for (i, s) in strings_on.iter().take(20).enumerate() {
        let preview = s.value.chars().take(60).collect::<String>();
        println!("  [{}] {:?}: {}", i, s.method, preview);
    }

    Ok(())
}
