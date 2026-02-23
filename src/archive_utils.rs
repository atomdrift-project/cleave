//! Archive format detection utilities.

use std::path::Path;

use crate::analyzers::{archive::ArchiveAnalyzer, Analyzer};

/// Check if a file is an archive based on extension
#[allow(dead_code)] // Used by lib.rs, false positive from lib/bin split
pub(crate) fn is_archive(path: &Path) -> bool {
    let analyzer = ArchiveAnalyzer::new();
    analyzer.can_analyze(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_archive_zip() {
        assert!(is_archive(Path::new("test.zip")));
        assert!(is_archive(Path::new("TEST.ZIP")));
    }

    #[test]
    fn test_is_archive_tar() {
        assert!(is_archive(Path::new("test.tar")));
        assert!(is_archive(Path::new("test.tar.gz")));
        assert!(is_archive(Path::new("test.tgz")));
        assert!(is_archive(Path::new("test.tar.bz2")));
        assert!(is_archive(Path::new("test.tar.xz")));
    }

    #[test]
    fn test_is_not_archive() {
        assert!(!is_archive(Path::new("test.txt")));
        assert!(!is_archive(Path::new("test.py")));
        assert!(!is_archive(Path::new("test.elf")));
    }
}
