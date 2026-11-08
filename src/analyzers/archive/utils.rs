//! Utility functions for archive analysis.

use std::path::Path;

/// Calculate SHA256 hash of data
pub(crate) fn calculate_sha256(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

/// Extract main class from META-INF/MANIFEST.MF
pub(crate) fn find_main_class(temp_dir: &Path) -> Option<String> {
    let manifest_path = temp_dir.join("META-INF/MANIFEST.MF");
    if !manifest_path.exists() {
        return None;
    }

    main_class_from_manifest(&std::fs::read(&manifest_path).ok()?)
}

/// The `Main-Class:` of a JAR manifest. The manifest comes from the archive,
/// so a line that is not UTF-8 must not hide the lines after it.
pub(crate) fn main_class_from_manifest(manifest: &[u8]) -> Option<String> {
    manifest.split(|&b| b == b'\n').find_map(|line| {
        let line = String::from_utf8_lossy(line);
        line.strip_prefix("Main-Class:")
            .map(|class| class.trim().to_string())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn main_class_survives_a_non_utf8_manifest_line() {
        let manifest =
            b"Manifest-Version: 1.0\r\nCreated-By: \xff\xfe\r\nMain-Class: evil.Loader\r\n";
        assert_eq!(
            main_class_from_manifest(manifest).as_deref(),
            Some("evil.Loader")
        );
    }
}
