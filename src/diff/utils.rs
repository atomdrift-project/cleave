//! Utility functions for differential analysis.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//!
//! Provides helper functions for:
//! - Set difference computation
//! - File rename detection (optimized O(n) algorithm)
//! - File similarity scoring (library-aware)

use std::collections::{HashMap, HashSet};
use std::path::Path;

/// Represents a detected file rename
#[derive(Debug, Clone)]
pub(crate) struct FileRename {
    pub baseline_path: String,
    pub target_path: String,
    pub similarity_score: f64,
}

/// Compute set difference for items with an id-like field
#[allow(dead_code)] // Used by binary target
pub(super) fn compute_added_removed<T, F>(
    baseline: &[T],
    target: &[T],
    key_fn: F,
) -> (Vec<T>, Vec<T>)
where
    T: Clone,
    F: Fn(&T) -> String,
{
    let baseline_keys: HashSet<String> = baseline.iter().map(&key_fn).collect();
    let target_keys: HashSet<String> = target.iter().map(&key_fn).collect();

    let added: Vec<T> = target
        .iter()
        .filter(|item| !baseline_keys.contains(&key_fn(item)))
        .cloned()
        .collect();

    let removed: Vec<T> = baseline
        .iter()
        .filter(|item| !target_keys.contains(&key_fn(item)))
        .cloned()
        .collect();

    (added, removed)
}

/// Check if a filename is a shared library based on extension and naming
#[cfg(test)]
pub(super) fn is_shared_library(filename: &str) -> bool {
    // Match patterns like: libssl.so, libssl.so.1, libssl.so.1.0.0
    filename.contains(".so") && (filename.ends_with(".so") || filename.contains(".so."))
}

#[cfg(not(test))]
fn is_shared_library(filename: &str) -> bool {
    // Match patterns like: libssl.so, libssl.so.1, libssl.so.1.0.0
    filename.contains(".so") && (filename.ends_with(".so") || filename.contains(".so."))
}

/// Calculate similarity between two library names, ignoring version differences
#[cfg(test)]
pub(super) fn library_similarity(name1: &str, name2: &str) -> f64 {
    // Extract base name (before .so)
    let base1 = name1.split(".so").next().unwrap_or(name1);
    let base2 = name2.split(".so").next().unwrap_or(name2);

    if base1 == base2 {
        // Same library, different version
        0.95
    } else {
        // Use Levenshtein distance for the full names
        strsim::normalized_levenshtein(name1, name2)
    }
}

#[cfg(not(test))]
fn library_similarity(name1: &str, name2: &str) -> f64 {
    // Extract base name (before .so)
    let base1 = name1.split(".so").next().unwrap_or(name1);
    let base2 = name2.split(".so").next().unwrap_or(name2);

    if base1 == base2 {
        // Same library, different version
        0.95
    } else {
        // Use Levenshtein distance for the full names
        strsim::normalized_levenshtein(name1, name2)
    }
}

/// Calculate similarity score between two file paths
pub(super) fn calculate_file_similarity(path1: &str, path2: &str) -> f64 {
    // Extract just the filename for comparison
    let name1 = Path::new(path1)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(path1);

    let name2 = Path::new(path2)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(path2);

    // Check if both are shared libraries
    if is_shared_library(name1) && is_shared_library(name2) {
        return library_similarity(name1, name2);
    }

    // Use Levenshtein distance for general files
    strsim::normalized_levenshtein(name1, name2)
}

/// Extract library base name (everything before .so)
pub(super) fn extract_library_base(filename: &str) -> Option<&str> {
    if !is_shared_library(filename) {
        return None;
    }
    filename.split(".so").next()
}

/// Detect file renames between removed and added files using optimized multi-pass algorithm
/// This is O(n) instead of O(n*m) for better performance with large file sets
pub(super) fn detect_renames(removed: &[String], added: &[String]) -> Vec<FileRename> {
    let mut matches = Vec::new();
    let mut used_removed = HashSet::new();
    let mut used_added = HashSet::new();

    // Pass 1: Exact basename match when unique (O(n) using HashMap)
    // This catches simple renames like dir1/unique_file.txt -> dir2/unique_file.txt
    // Only match when basename is unique in both removed and added sets
    let mut removed_by_basename: HashMap<String, Vec<&String>> = HashMap::new();
    let mut added_by_basename: HashMap<String, Vec<&String>> = HashMap::new();

    for removed_file in removed {
        if let Some(basename) = Path::new(removed_file).file_name().and_then(|n| n.to_str()) {
            removed_by_basename
                .entry(basename.to_string())
                .or_default()
                .push(removed_file);
        }
    }

    for added_file in added {
        if let Some(basename) = Path::new(added_file).file_name().and_then(|n| n.to_str()) {
            added_by_basename
                .entry(basename.to_string())
                .or_default()
                .push(added_file);
        }
    }

    // Match basenames that appear exactly once in both sets
    for (basename, removed_files) in &removed_by_basename {
        if removed_files.len() == 1 {
            if let Some(added_files) = added_by_basename.get(basename) {
                if added_files.len() == 1 {
                    let removed_file = removed_files[0];
                    let added_file = added_files[0];
                    matches.push(FileRename {
                        baseline_path: (*removed_file).clone(),
                        target_path: (*added_file).clone(),
                        similarity_score: 1.0,
                    });
                    used_removed.insert((*removed_file).clone());
                    used_added.insert((*added_file).clone());
                }
            }
        }
    }

    // Pass 2: Library version matching (O(n) using HashMap)
    // This catches libssl.so.1.0.0 -> libssl.so.1.1.0
    let mut added_by_lib_base: HashMap<String, Vec<&String>> = HashMap::new();
    for added_file in added {
        if used_added.contains(added_file) {
            continue;
        }
        if let Some(basename) = Path::new(added_file).file_name().and_then(|n| n.to_str()) {
            if let Some(lib_base) = extract_library_base(basename) {
                added_by_lib_base
                    .entry(lib_base.to_string())
                    .or_default()
                    .push(added_file);
            }
        }
    }

    for removed_file in removed {
        if used_removed.contains(removed_file) {
            continue;
        }
        if let Some(basename) = Path::new(removed_file).file_name().and_then(|n| n.to_str()) {
            if let Some(lib_base) = extract_library_base(basename) {
                if let Some(candidates) = added_by_lib_base.get(lib_base) {
                    // Take the first match for library renames
                    for added_file in candidates {
                        if !used_added.contains(*added_file) {
                            matches.push(FileRename {
                                baseline_path: removed_file.clone(),
                                target_path: (*added_file).clone(),
                                similarity_score: 0.95,
                            });
                            used_removed.insert(removed_file.clone());
                            used_added.insert((*added_file).clone());
                            break;
                        }
                    }
                }
            }
        }
    }

    // Pass 3: Same directory comparison (O(n) by grouping)
    // Only compare files within the same directory to reduce search space
    let mut removed_by_dir: HashMap<String, Vec<&String>> = HashMap::new();
    for removed_file in removed {
        if used_removed.contains(removed_file) {
            continue;
        }
        let dir = Path::new(removed_file)
            .parent()
            .and_then(|p| p.to_str())
            .unwrap_or("")
            .to_string();
        removed_by_dir.entry(dir).or_default().push(removed_file);
    }

    let mut added_by_dir: HashMap<String, Vec<&String>> = HashMap::new();
    for added_file in added {
        if used_added.contains(added_file) {
            continue;
        }
        let dir = Path::new(added_file)
            .parent()
            .and_then(|p| p.to_str())
            .unwrap_or("")
            .to_string();
        added_by_dir.entry(dir).or_default().push(added_file);
    }

    // Within each directory, compare files (O(k*m) where k,m are small directory sizes)
    for (dir, removed_files) in &removed_by_dir {
        if let Some(added_files) = added_by_dir.get(dir) {
            for removed_file in removed_files {
                if used_removed.contains(*removed_file) {
                    continue;
                }

                let mut best_match: Option<(&String, f64)> = None;
                for added_file in added_files {
                    if used_added.contains(*added_file) {
                        continue;
                    }

                    let score = calculate_file_similarity(removed_file, added_file);
                    if score >= 0.9 && best_match.is_none_or(|(_, s)| score > s) {
                        best_match = Some((added_file, score));
                    }
                }

                if let Some((added_file, score)) = best_match {
                    matches.push(FileRename {
                        baseline_path: (*removed_file).clone(),
                        target_path: (*added_file).clone(),
                        similarity_score: score,
                    });
                    used_removed.insert((*removed_file).clone());
                    used_added.insert((*added_file).clone());
                }
            }
        }
    }

    // Sort by score descending to prioritize best matches
    matches.sort_by(|a, b| {
        b.similarity_score
            .partial_cmp(&a.similarity_score)
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    matches
}

#[cfg(test)]
mod tests {
    use super::*;

    // ==================== is_shared_library Tests ====================

    #[test]
    fn test_is_shared_library_ends_with_so() {
        assert!(is_shared_library("libssl.so"));
        assert!(is_shared_library("libcrypto.so"));
        assert!(is_shared_library("libc.so"));
    }

    #[test]
    fn test_is_shared_library_with_version() {
        assert!(is_shared_library("libssl.so.1"));
        assert!(is_shared_library("libssl.so.1.0.0"));
        assert!(is_shared_library("libssl.so.1.1.1k"));
        assert!(is_shared_library("libc.so.6"));
    }

    #[test]
    fn test_is_shared_library_not_so() {
        assert!(!is_shared_library("libssl.a"));
        assert!(!is_shared_library("libssl.dylib"));
        assert!(!is_shared_library("libssl.dll"));
        assert!(!is_shared_library("program.exe"));
        assert!(!is_shared_library("file.txt"));
    }

    #[test]
    fn test_is_shared_library_edge_cases() {
        // ".so" technically matches the pattern (contains and ends with .so)
        assert!(is_shared_library(".so"));
        assert!(!is_shared_library("noextension"));
        assert!(!is_shared_library(""));
    }

    // ==================== library_similarity Tests ====================

    #[test]
    fn test_library_similarity_same_library_different_version() {
        // Same base library with different versions should have high similarity
        let sim = library_similarity("libssl.so.1.0.0", "libssl.so.1.1.1");
        assert_eq!(sim, 0.95);
    }

    #[test]
    fn test_library_similarity_same_library() {
        let sim = library_similarity("libssl.so", "libssl.so");
        assert_eq!(sim, 0.95);
    }

    #[test]
    fn test_library_similarity_different_libraries() {
        // Different libraries should have lower similarity
        let sim = library_similarity("libssl.so", "libcrypto.so");
        assert!(sim < 0.8);
    }

    #[test]
    fn test_library_similarity_similar_names() {
        // Similar but different library names
        let sim = library_similarity("libfoo.so", "libfoo2.so");
        assert!(sim > 0.7); // Should be reasonably similar
        assert!(sim < 0.95); // But not same library
    }

    // ==================== calculate_file_similarity Tests ====================

    #[test]
    fn test_calculate_file_similarity_identical() {
        let sim = calculate_file_similarity("/path/to/file.txt", "/other/path/to/file.txt");
        assert_eq!(sim, 1.0);
    }

    #[test]
    fn test_calculate_file_similarity_similar_names() {
        let sim = calculate_file_similarity("/path/file1.txt", "/path/file2.txt");
        assert!(sim > 0.8); // Should be similar
    }

    #[test]
    fn test_calculate_file_similarity_different_names() {
        let sim = calculate_file_similarity("/path/foo.txt", "/path/bar.txt");
        // Short filenames have higher Levenshtein similarity even when different
        assert!(sim < 0.9); // Should not be considered a rename match
    }

    #[test]
    fn test_calculate_file_similarity_library_versions() {
        // Library version changes should be detected as similar
        let sim = calculate_file_similarity("/lib/libssl.so.1.0.0", "/lib/libssl.so.1.1.1");
        assert_eq!(sim, 0.95);
    }

    // ==================== extract_library_base Tests ====================

    #[test]
    fn test_extract_library_base_with_version() {
        assert_eq!(extract_library_base("libssl.so.1.0.0"), Some("libssl"));
        assert_eq!(extract_library_base("libc.so.6"), Some("libc"));
    }

    #[test]
    fn test_extract_library_base_without_version() {
        assert_eq!(extract_library_base("libssl.so"), Some("libssl"));
    }

    #[test]
    fn test_extract_library_base_not_library() {
        assert_eq!(extract_library_base("file.txt"), None);
        assert_eq!(extract_library_base("program"), None);
        assert_eq!(extract_library_base("libfoo.a"), None);
    }

    // ==================== detect_renames Tests ====================

    #[test]
    fn test_detect_renames_exact_basename_match() {
        let removed = vec!["dir1/unique_file.txt".to_string()];
        let added = vec!["dir2/unique_file.txt".to_string()];

        let renames = detect_renames(&removed, &added);

        assert_eq!(renames.len(), 1);
        assert_eq!(renames[0].baseline_path, "dir1/unique_file.txt");
        assert_eq!(renames[0].target_path, "dir2/unique_file.txt");
        assert_eq!(renames[0].similarity_score, 1.0);
    }

    #[test]
    fn test_detect_renames_library_version_upgrade() {
        let removed = vec!["/lib/libssl.so.1.0.0".to_string()];
        let added = vec!["/lib/libssl.so.1.1.1".to_string()];

        let renames = detect_renames(&removed, &added);

        assert_eq!(renames.len(), 1);
        assert_eq!(renames[0].similarity_score, 0.95);
    }

    #[test]
    fn test_detect_renames_no_match() {
        let removed = vec!["file1.txt".to_string()];
        let added = vec!["completely_different.dat".to_string()];

        let renames = detect_renames(&removed, &added);

        assert!(renames.is_empty());
    }

    #[test]
    fn test_detect_renames_multiple_files() {
        let removed = vec!["dir1/file1.txt".to_string(), "dir1/file2.txt".to_string()];
        let added = vec!["dir2/file1.txt".to_string(), "dir2/file2.txt".to_string()];

        let renames = detect_renames(&removed, &added);

        assert_eq!(renames.len(), 2);
    }

    #[test]
    fn test_detect_renames_empty_input() {
        let removed: Vec<String> = vec![];
        let added: Vec<String> = vec![];

        let renames = detect_renames(&removed, &added);

        assert!(renames.is_empty());
    }

    #[test]
    fn test_detect_renames_duplicate_basenames_not_matched() {
        // When basename appears multiple times, don't match automatically
        let removed = vec![
            "dir1/config.json".to_string(),
            "dir2/config.json".to_string(),
        ];
        let added = vec!["dir3/config.json".to_string()];

        let renames = detect_renames(&removed, &added);

        // Should not match because basename is not unique in removed set
        assert!(renames.is_empty());
    }

    // ==================== compute_added_removed Tests ====================

    #[test]
    fn test_compute_added_removed_basic() {
        let baseline = vec!["a".to_string(), "b".to_string(), "c".to_string()];
        let target = vec!["b".to_string(), "c".to_string(), "d".to_string()];

        let (added, removed) = compute_added_removed(&baseline, &target, |s| s.clone());

        assert_eq!(added, vec!["d".to_string()]);
        assert_eq!(removed, vec!["a".to_string()]);
    }

    #[test]
    fn test_compute_added_removed_all_new() {
        let baseline: Vec<String> = vec![];
        let target = vec!["a".to_string(), "b".to_string()];

        let (added, removed) = compute_added_removed(&baseline, &target, |s| s.clone());

        assert_eq!(added.len(), 2);
        assert!(removed.is_empty());
    }

    #[test]
    fn test_compute_added_removed_all_removed() {
        let baseline = vec!["a".to_string(), "b".to_string()];
        let target: Vec<String> = vec![];

        let (added, removed) = compute_added_removed(&baseline, &target, |s| s.clone());

        assert!(added.is_empty());
        assert_eq!(removed.len(), 2);
    }

    #[test]
    fn test_compute_added_removed_no_change() {
        let baseline = vec!["a".to_string(), "b".to_string()];
        let target = vec!["a".to_string(), "b".to_string()];

        let (added, removed) = compute_added_removed(&baseline, &target, |s| s.clone());

        assert!(added.is_empty());
        assert!(removed.is_empty());
    }

    #[test]
    fn test_compute_added_removed_with_key_fn() {
        // Test with a custom key function (extracting just the filename)
        #[derive(Clone, Debug, PartialEq)]
        struct FileEntry {
            path: String,
            size: u64,
        }

        let baseline = vec![
            FileEntry {
                path: "/old/file1.txt".to_string(),
                size: 100,
            },
            FileEntry {
                path: "/old/file2.txt".to_string(),
                size: 200,
            },
        ];
        let target = vec![
            FileEntry {
                path: "/new/file2.txt".to_string(),
                size: 200,
            },
            FileEntry {
                path: "/new/file3.txt".to_string(),
                size: 300,
            },
        ];

        let (added, removed) = compute_added_removed(&baseline, &target, |f| {
            std::path::Path::new(&f.path)
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or(&f.path)
                .to_string()
        });

        // file1.txt was removed, file3.txt was added, file2.txt is in both
        assert_eq!(added.len(), 1);
        assert_eq!(added[0].path, "/new/file3.txt");
        assert_eq!(removed.len(), 1);
        assert_eq!(removed[0].path, "/old/file1.txt");
    }
}
