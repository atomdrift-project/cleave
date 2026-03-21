#[cfg(test)]
mod security_tests {
    use super::*;
    use crate::analyzers::archive::guards::ExtractionGuard;
    use std::io::Write;
    use tempfile::tempdir;

    #[test]
    fn test_extract_crx_panic_offsets() {
        let dir = tempdir().unwrap();
        let guard = ExtractionGuard::new();

        // Create a malformed CRX: "Cr24" (4) + version (4) + pubkey_len (4) + sig_len (4)
        // Set pubkey_len to a very large value that exceeds file size
        let mut crx_data = Vec::new();
        crx_data.extend_from_slice(b"Cr24");
        crx_data.extend_from_slice(&2u32.to_le_bytes()); // version
        crx_data.extend_from_slice(&0xFFFFFFFFu32.to_le_bytes()); // massive pubkey_len
        crx_data.extend_from_slice(&0u32.to_le_bytes()); // sig_len

        let crx_path = dir.path().join("panic.crx");
        std::fs::write(&crx_path, &crx_data).unwrap();

        let dest = dir.path().join("out");
        std::fs::create_dir_all(&dest).unwrap();

        // This should return an Err, not panic
        let result = extract_crx_safe(&crx_path, &dest, &guard);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("truncated") || result.unwrap_err().to_string().contains("Invalid"));
    }
}
