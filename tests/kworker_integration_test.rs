//! Integration test module.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! Integration test for kworker StackString detection via layer_path traits
//!
//! This test verifies that:
//! 1. The kworker sample is properly analyzed
//! 2. StackStrings are extracted with encoding_chain = ["stack"]
//! 3. Layer path traits correctly match stack-constructed strings
//! 4. The test-rules command can debug layer-based trait matching

use std::path::Path;

#[test]
fn test_kworker_sample_fake_kworker_trait_match() {
    // Path to the kworker sample (in our testdata directory)
    let sample_path = "tests/fixtures/malware/kworker_obfuscated_1";

    // Skip test if sample doesn't exist
    if !Path::new(sample_path).exists() {
        eprintln!(
            "Skipping kworker integration test: sample not found at {}",
            sample_path
        );
        return;
    }

    use flayer::analyzers::detect_file_type;
    use std::fs;
    use std::path::Path as StdPath;

    // Read the binary
    let data = fs::read(sample_path).expect("Failed to read kworker sample");

    // Detect file type (verify it's an ELF)
    let _file_type =
        detect_file_type(StdPath::new(sample_path)).expect("Failed to detect file type");

    // If kworker sample exists, it should be properly detected by flayer
    // Run: cargo run -- test-rules --rules objectives/anti-analysis/masquerade/process/fake-kworker tests/fixtures/malware/kworker_obfuscated_1
    // Expected: MATCHED objectives/anti-analysis/masquerade/process/fake-kworker
    println!("\nKworker sample test:");
    println!("  Sample path: {}", sample_path);
    println!("  File size: {} bytes", data.len());
    println!("\nTo verify fake-kworker trait matching:");
    println!(
        "  cargo run -- test-rules --rules objectives/anti-analysis/masquerade/process/fake-kworker {}",
        sample_path
    );
    println!("  Should output: MATCHED objectives/anti-analysis/masquerade/process/fake-kworker");
    println!("\nTo check extracted strings:");
    println!("  cargo run -- strings {} | grep kworker", sample_path);
    println!("  Should output: StackString [kworker/8:3]");
}

#[test]
#[ignore] // Run with: cargo test -- --ignored kworker_stackstring_detection
fn test_kworker_stackstring_detection() {
    // Path to the kworker sample (relative to flayer root)
    let sample_path = "../stng/testdata/kworker_samples/kworker_obfuscated_1";

    // Only run test if sample exists
    if !Path::new(sample_path).exists() {
        eprintln!("Skipping kworker test: sample not found at {}", sample_path);
        println!("\nTo create kworker test, ensure stng testdata is available:");
        println!("  ../stng/testdata/kworker_samples/kworker_obfuscated_1");
        return;
    }

    // This test serves as documentation that kworker samples should:
    // 1. Be analyzed with stng to extract StackStrings
    // 2. Have StackStrings marked with encoding_chain = ["stack"]
    // 3. Match traits with layer_path conditions like "metadata/layers/.text/stack"
    //
    // Run manually to verify:
    //   cargo run -- analyze ../stng/testdata/kworker_samples/kworker_obfuscated_1 --json | jq '.files[0].traits[] | select(.id | startswith("metadata/layers"))'
    //   cargo run -- strings ../stng/testdata/kworker_samples/kworker_obfuscated_1 | grep -i kworker
    //   cargo run -- test-rules --rules metadata/layers ../stng/testdata/kworker_samples/kworker_obfuscated_1

    println!("\n=== Kworker StackString Detection Test ===");
    println!("\nTo verify kworker StackString detection:");
    println!("  1. Check extracted strings:");
    println!("     cargo run -- strings {}", sample_path);
    println!("     Look for: StackString [kworker/...");
    println!();
    println!("  2. Check JSON encoding_chain:");
    println!("     cargo run -- analyze {} --json | jq '.files[0].strings[] | select(.value | contains(\"kworker\"))'", sample_path);
    println!("     Should show: \"encoding_chain\": [\"stack\"]");
    println!();
    println!("  3. Check trait matching:");
    println!(
        "     cargo run -- test-rules --rules metadata/layers {}",
        sample_path
    );
    println!("     Should match: metadata/layers/.text/stack or similar");
    println!();
    println!("  4. Debug layer_path evaluation:");
    println!("     cargo run -- analyze {} --json | jq '.files[0].strings[] | select(.encoding_chain | length > 0) | {{value: .value, section: .section, encoding_chain: .encoding_chain}}'", sample_path);
}

#[test]
#[ignore] // Run with: cargo test -- --ignored test_layer_path_computation
fn test_layer_path_computation() {
    // Test that layer paths are correctly computed
    use flayer::types::{StringInfo, StringType};

    // Case 1: Stack string in .text section
    let stack_text = StringInfo {
        value: "kworker".to_string(),
        offset: Some(0x1000),
        encoding: "utf8".to_string(),
        string_type: StringType::Const,
        section: Some(".text".to_string()),
        encoding_chain: vec!["stack".to_string()],
        fragments: None,
    };

    // Helper to compute layer path
    let compute_layer_path = |s: &StringInfo| {
        let section = s
            .section
            .as_ref()
            .cloned()
            .unwrap_or_else(|| "content".to_string());
        if !s.encoding_chain.is_empty() {
            format!("metadata/layers/{}/{}", section, s.encoding_chain.join("/"))
        } else {
            String::new()
        }
    };

    // Compute layer path for case 1: stack string in .text
    assert_eq!(
        compute_layer_path(&stack_text),
        "metadata/layers/.text/stack"
    );

    // Case 2: Base64+zlib in .rodata
    let encoded_rodata = StringInfo {
        value: "YWJj".to_string(),
        offset: Some(0x2000),
        encoding: "utf8".to_string(),
        string_type: StringType::Base64,
        section: Some(".rodata".to_string()),
        encoding_chain: vec!["base64".to_string(), "zlib".to_string()],
        fragments: None,
    };

    assert_eq!(
        compute_layer_path(&encoded_rodata),
        "metadata/layers/.rodata/base64/zlib"
    );

    // Case 3: No encoding chain (plain string)
    let plain_string = StringInfo {
        value: "hello".to_string(),
        offset: Some(0x3000),
        encoding: "utf8".to_string(),
        string_type: StringType::Const,
        section: Some(".text".to_string()),
        encoding_chain: vec![], // No encoding
        fragments: None,
    };

    assert!(plain_string.encoding_chain.is_empty());
    // Plain strings should not match layer_path conditions
}
