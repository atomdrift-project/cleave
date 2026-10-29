//! Untrusted samples used by unit tests.
//!
//! Samples are stored XOR-encoded with [`KEY`] under a `_xor_0x42_encoded`
//! suffix (see `testdata/README.md`), so the repository never holds live
//! malware that endpoint protection would quarantine.
#![allow(clippy::expect_used)]

/// The single-byte XOR key every stored sample is encoded with.
pub(crate) const KEY: u8 = 0x42;

/// Decode the sample stored at `path` (relative to the crate root, without the
/// encoding suffix).
pub(crate) fn read(path: &str) -> Vec<u8> {
    let encoded =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(format!("{path}_xor_0x42_encoded"));
    std::fs::read(&encoded)
        .expect("encoded sample present")
        .into_iter()
        .map(|b| b ^ KEY)
        .collect()
}
