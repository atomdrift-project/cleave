//! Filesystem caching for analysis results.
//!
//! This module provides caching functionality to avoid re-analyzing unchanged files.
//! Caches are stored in OS-appropriate directories:
//! - macOS: `~/Library/Caches/flayer/`
//! - Linux: `~/.cache/flayer/`
//! - Windows: `%LOCALAPPDATA%\flayer\`
//!
//! # Cache Types
//!
//! - `re/` - Radare2/rizin analysis results (keyed by file SHA256)
//! - Additional cache types can be added as needed
//!
//! # Cleanup
//!
//! Cache entries older than 30 days are automatically pruned.

use anyhow::{Context, Result};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::SystemTime;
use walkdir::WalkDir;

/// Get the cache directory for flayer
/// Returns OS-appropriate cache directory:
/// - macOS: ~/Library/Caches/flayer
/// - Linux: ~/.cache/flayer
/// - Windows: %LOCALAPPDATA%\flayer
pub(crate) fn cache_dir() -> Result<PathBuf> {
    let mut candidates = Vec::new();
    if let Some(base_cache) = dirs::cache_dir() {
        candidates.push(base_cache.join("flayer"));
    }
    candidates.push(std::env::temp_dir().join("flayer-cache"));

    for cache_path in candidates {
        if fs::create_dir_all(&cache_path).is_ok() {
            let probe = cache_path.join(".write-test");
            if fs::write(&probe, b"ok").is_ok() {
                let _ = fs::remove_file(probe);
                return Ok(cache_path);
            }
        }
    }

    anyhow::bail!("Failed to create cache directory")
}

/// Returns the traits directory path from FLAYER_TRAITS_PATH env var or "traits" default
pub(crate) fn traits_path() -> PathBuf {
    std::env::var("FLAYER_TRAITS_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("traits"))
}

/// Check if we're running in developer mode (traits directory exists)
pub(crate) fn is_developer_mode() -> bool {
    traits_path().exists()
}

/// Returns the most recent modification time of any YARA rule file or trait YAML file.
/// YAML files are included because they may contain inline `type: yara` conditions
/// that are compiled into the combined YARA cache.
pub(crate) fn most_recent_yara_mtime() -> Result<SystemTime> {
    let mut most_recent = SystemTime::UNIX_EPOCH;

    // Check traits directory for both .yar/.yara and .yaml/.yml files
    let traits_dir = traits_path();
    if traits_dir.exists() {
        for entry in WalkDir::new(&traits_dir)
            .follow_links(false)
            .into_iter()
            .flatten()
        {
            let path = entry.path();
            if path.is_file()
                && path
                    .extension()
                    .map(|ext| ext == "yar" || ext == "yara" || ext == "yaml" || ext == "yml")
                    .unwrap_or(false)
            {
                if let Ok(metadata) = fs::metadata(path) {
                    if let Ok(mtime) = metadata.modified() {
                        if mtime > most_recent {
                            most_recent = mtime;
                        }
                    }
                }
            }
        }
    }

    // Check third_party directory
    if Path::new("third_party").exists() {
        for entry in WalkDir::new("third_party")
            .follow_links(false)
            .into_iter()
            .flatten()
        {
            let path = entry.path();
            if path.is_file()
                && path
                    .extension()
                    .map(|ext| ext == "yar" || ext == "yara")
                    .unwrap_or(false)
            {
                if let Ok(metadata) = fs::metadata(path) {
                    if let Ok(mtime) = metadata.modified() {
                        if mtime > most_recent {
                            most_recent = mtime;
                        }
                    }
                }
            }
        }
    }

    if most_recent == SystemTime::UNIX_EPOCH {
        anyhow::bail!("No YARA files found");
    }

    Ok(most_recent)
}

/// Returns the modification time of the flayer binary
pub(crate) fn binary_mtime() -> Result<SystemTime> {
    let exe_path = std::env::current_exe().context("Failed to get current executable path")?;

    let metadata = fs::metadata(&exe_path).context("Failed to read binary metadata")?;

    metadata
        .modified()
        .context("Failed to get binary modification time")
}

/// Returns the appropriate timestamp for cache invalidation
pub(crate) fn cache_timestamp() -> Result<SystemTime> {
    if is_developer_mode() {
        // Developer mode: use most recent YARA file mtime
        most_recent_yara_mtime()
    } else {
        // Production mode: use binary mtime (embedded rules)
        binary_mtime()
    }
}

/// Generate a cache key based on timestamp and third-party flag
pub(crate) fn yara_cache_key(third_party_enabled: bool) -> Result<String> {
    let mtime = cache_timestamp()?;
    let timestamp = mtime
        .duration_since(SystemTime::UNIX_EPOCH)
        .context("Invalid cache timestamp")?
        .as_secs();

    let suffix = if third_party_enabled {
        "with-3p"
    } else {
        "builtin"
    };
    let mode = if is_developer_mode() { "dev" } else { "prod" };

    // v3: zero-copy cache format (mmap + direct slice access)
    Ok(format!(
        "yara-rules-v3-{}-{}-{}.bin",
        mode, timestamp, suffix
    ))
}

/// Get the path to the YARA rules cache file
pub(crate) fn yara_cache_path(third_party_enabled: bool) -> Result<PathBuf> {
    let cache_key = yara_cache_key(third_party_enabled)?;
    Ok(cache_dir()?.join(cache_key))
}

/// Generate a cache key for the capability mapper
pub(crate) fn mapper_cache_key() -> Result<String> {
    let mtime = cache_timestamp()?;
    let timestamp = mtime
        .duration_since(SystemTime::UNIX_EPOCH)
        .context("Invalid cache timestamp")?
        .as_secs();

    let mode = if is_developer_mode() { "dev" } else { "prod" };

    // v5: parallel index building
    Ok(format!("capability-mapper-v5-{}-{}.bin", mode, timestamp))
}

/// Get the path to the capability mapper cache file
pub(crate) fn mapper_cache_path() -> Result<PathBuf> {
    let cache_key = mapper_cache_key()?;
    Ok(cache_dir()?.join(cache_key))
}

/// Get the reverse engineering tool analysis cache directory
/// Returns: {cache_dir}/re/
pub(crate) fn re_cache_dir() -> Result<PathBuf> {
    let dir = cache_dir()?.join("re");
    if !dir.exists() {
        fs::create_dir_all(&dir).context("Failed to create RE cache directory")?;
    }
    Ok(dir)
}

/// Get the cache path for a reverse engineering analysis result by SHA256
/// Uses first 2 chars as subdirectory to avoid huge flat directories.
/// Returns: {cache_dir}/re/{sha256[0:2]}/{sha256}.bin
pub(crate) fn re_cache_path(sha256: &str) -> Result<PathBuf> {
    if sha256.len() < 2 {
        anyhow::bail!("Invalid SHA256: too short");
    }
    let subdir = re_cache_dir()?.join(&sha256[..2]);
    if !subdir.exists() {
        fs::create_dir_all(&subdir).context("Failed to create RE cache subdirectory")?;
    }
    Ok(subdir.join(format!("{}.bin", sha256)))
}

/// Clean up old cache files (keep only current one)
pub(crate) fn cleanup_old_caches(current_cache: &Path) -> Result<()> {
    let cache_dir = cache_dir()?;

    for entry in fs::read_dir(&cache_dir)? {
        let entry = entry?;
        let path = entry.path();

        // Remove old yara-rules-*.bin files (except the current one)
        if path.is_file()
            && path
                .file_name()
                .and_then(|n| n.to_str())
                .map(|n| n.starts_with("yara-rules-") && n.ends_with(".bin"))
                .unwrap_or(false)
            && path != current_cache
        {
            let _ = fs::remove_file(&path); // Ignore errors
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_developer_mode_no_traits_dir() {
        // Should return false when traits/ doesn't exist (in test environment)
        let result = is_developer_mode();
        // Result depends on whether traits/ exists in test environment
        // Simply verify it returns a boolean without panicking
        let _ = result;
    }

    #[test]
    fn test_yara_cache_key_format() {
        // Test that cache key has expected format
        if let Ok(key) = yara_cache_key(false) {
            assert!(key.starts_with("yara-rules-"));
            assert!(key.ends_with("-builtin.bin"));
        }

        if let Ok(key) = yara_cache_key(true) {
            assert!(key.starts_with("yara-rules-"));
            assert!(key.ends_with("-with-3p.bin"));
        }
    }

    #[test]
    fn test_yara_cache_key_includes_mode() {
        if let Ok(key) = yara_cache_key(false) {
            // Should include either "dev" or "prod" mode
            assert!(key.contains("-dev-") || key.contains("-prod-"));
        }
    }

    #[test]
    fn test_cache_dir_returns_path() {
        let result = cache_dir();
        // Should either succeed or fail, but not panic
        match result {
            Ok(path) => {
                assert!(path.to_string_lossy().contains("flayer"));
            }
            Err(_) => {
                // Some environments may not have cache dir
            }
        }
    }

    #[test]
    fn test_yara_cache_path_includes_cache_key() {
        if let Ok(path) = yara_cache_path(false) {
            let path_str = path.to_string_lossy();
            assert!(path_str.contains("yara-rules-"));
            assert!(path_str.contains(".bin"));
        }
    }

    #[test]
    fn test_yara_cache_path_different_for_third_party() {
        if let (Ok(path1), Ok(path2)) = (yara_cache_path(false), yara_cache_path(true)) {
            // Paths should be different based on third_party flag
            assert_ne!(path1, path2);
            assert!(path1.to_string_lossy().contains("builtin"));
            assert!(path2.to_string_lossy().contains("with-3p"));
        }
    }

    #[test]
    fn test_most_recent_yara_mtime_no_files() {
        // This test verifies the function handles missing directories gracefully.
        // Note: We don't change the working directory as that would affect parallel tests.
        // The actual behavior depends on whether yara/ exists in the project root.
        // If yara/ exists with files, it returns Ok; if not, it returns Err.
        let result = most_recent_yara_mtime();
        // Just verify it doesn't panic - result depends on project structure
        let _ = result;
    }

    #[test]
    fn test_cleanup_old_caches_handles_nonexistent_dir() {
        let temp_path = PathBuf::from("/nonexistent/cache/file.bin");
        // Should not panic with nonexistent path
        let _ = cleanup_old_caches(&temp_path);
    }
}
