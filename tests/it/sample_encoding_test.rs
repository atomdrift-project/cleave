//! Untrusted samples must never be committed raw (see testdata/README.md).

use std::path::Path;

/// Directories that hold real malicious samples.
const SAMPLE_DIRS: &[&str] = &[
    "testdata/dos-boot",
    "testdata/dos-com",
    "testdata/xor",
    "tests/fixtures/malware",
];

/// Synthetic fixtures in those directories: written for a test, no live payload.
const SYNTHETIC: &[&str] = &[
    "testdata/xor/xor_base64_stealer.py",
    "testdata/xor/xor_loader.js",
];

#[test]
fn untrusted_samples_are_stored_encoded() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut raw = Vec::new();
    for dir in SAMPLE_DIRS {
        for entry in walkdir::WalkDir::new(root.join(dir)).into_iter().flatten() {
            if !entry.file_type().is_file() {
                continue;
            }
            let rel = entry.path().strip_prefix(root).unwrap_or(entry.path());
            let rel = rel.to_string_lossy().replace('\\', "/");
            let name = entry.file_name().to_string_lossy();
            if !(name.ends_with("_xor_0x42_encoded")
                || name.ends_with(".md")
                || SYNTHETIC.contains(&rel.as_str()))
            {
                raw.push(rel);
            }
        }
    }
    assert!(raw.is_empty(), "raw samples committed: {raw:?}");
}
