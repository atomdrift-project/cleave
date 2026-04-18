//! Filesystem caching for analysis results.
//!
//! This module provides caching functionality to avoid re-analyzing unchanged files.
//! Caches are stored in OS-appropriate directories:
//! - macOS: `~/Library/Caches/cleave/`
//! - Linux: `~/.cache/cleave/`
//! - Windows: `%LOCALAPPDATA%\cleave\`
//!
//! # Cache Types
//!
//! - `re/` - Radare2/rizin analysis results (keyed by file SHA256)
//! - Additional cache types can be added as needed
//!
//! # Cleanup
//!
//! Versioned compiled-rule caches (`yara-rules-*.bin`, `capability-mapper-*.bin`) are
//! pruned automatically when a new version is written. RE cache entries (`re/`) are pruned
//! at server startup via `prune_re_cache()`; they are not evicted automatically on CLI use.

use anyhow::{Context, Result};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::SystemTime;
use walkdir::WalkDir;

/// Returns `true` if the analysis-result cache should be skipped.
///
/// - `CLEAVE_SKIP_CACHE=1` / `true`  → skip
/// - `CLEAVE_SKIP_CACHE=0` / `false` → don't skip
/// - Env var unset + debug build      → skip (debug builds default to no cache)
/// - Env var unset + release build    → don't skip
#[must_use]
pub fn skip_cache() -> bool {
    match std::env::var("CLEAVE_SKIP_CACHE") {
        Ok(v) => v == "1" || v.eq_ignore_ascii_case("true"),
        Err(_) => cfg!(debug_assertions),
    }
}

/// Returns `true` if the YARA rule-compilation cache should be skipped.
///
/// The YARA cache is invalidated by YAR-file mtime changes; re-compiling
/// otherwise costs 4-18 s per process (worst case: debug build, no cache).
/// Prefer `CLEAVE_SKIP_YARA_CACHE=1` when you specifically need to force a
/// recompile (editing inline YARA inside YAML). `CLEAVE_SKIP_CACHE` is
/// honored as a superset for backwards compatibility.
///
/// - `CLEAVE_SKIP_YARA_CACHE=1` / `true` → skip
/// - `CLEAVE_SKIP_CACHE=1`               → skip (legacy behavior)
/// - Env vars unset + debug build        → skip (debug default)
/// - Env vars unset + release build      → don't skip
#[must_use]
pub fn skip_yara_cache() -> bool {
    if let Ok(v) = std::env::var("CLEAVE_SKIP_YARA_CACHE") {
        return v == "1" || v.eq_ignore_ascii_case("true");
    }
    skip_cache()
}

/// Format seconds into a human-readable age string (e.g., "2h 30m", "3d 12h").
#[must_use]
pub fn format_age(secs: u64) -> String {
    match secs {
        0..=59 => format!("{secs}s"),
        60..=3599 => format!("{}m {}s", secs / 60, secs % 60),
        3600..=86399 => format!("{}h {}m", secs / 3600, (secs % 3600) / 60),
        _ => format!("{}d {}h", secs / 86400, (secs % 86400) / 3600),
    }
}

/// Get the cache directory for cleave
/// Returns OS-appropriate cache directory:
/// - macOS: ~/Library/Caches/cleave
/// - Linux: ~/.cache/cleave
/// - Windows: %LOCALAPPDATA%\cleave
pub fn cache_dir() -> Result<PathBuf> {
    let mut candidates = Vec::new();
    if let Some(base_cache) = dirs::cache_dir() {
        candidates.push(base_cache.join("cleave"));
    }
    candidates.push(std::env::temp_dir().join("cleave-cache"));

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

/// Returns the traits directory path from env var, local dir, or platform data dir.
/// Does NOT auto-clone — use `traits_repo::resolve_and_ensure()` for that.
#[must_use]
pub fn traits_path() -> PathBuf {
    if let Ok(explicit) = std::env::var("CLEAVE_TRAITS_DIR") {
        return PathBuf::from(explicit);
    }
    // Platform data dir (same as traits_repo::default_traits_dir)
    dirs::data_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("cleave")
        .join("traits")
}

/// Returns the third-party YARA rules directory (`third-party/` inside the traits directory).
#[must_use]
pub fn third_party_path() -> PathBuf {
    traits_path().join("third-party")
}

/// Returns the most recently modified `.yar`/`.yara` file and its mtime.
///
/// Only pure YARA rule files are considered; trait YAML changes do not invalidate
/// the YARA compilation cache. Inline `type: yara` conditions embedded in YAML files
/// require `CLEAVE_SKIP_CACHE=1` to force recompile if they change.
pub fn most_recent_yar_file() -> Result<(SystemTime, PathBuf)> {
    let mut most_recent = SystemTime::UNIX_EPOCH;
    let mut most_recent_path = PathBuf::new();

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
                    .map(|ext| ext == "yar" || ext == "yara")
                    .unwrap_or(false)
            {
                if let Ok(metadata) = fs::metadata(path) {
                    if let Ok(mtime) = metadata.modified() {
                        if mtime > most_recent {
                            most_recent = mtime;
                            most_recent_path = path.to_path_buf();
                        }
                    }
                }
            }
        }
    }

    if most_recent == SystemTime::UNIX_EPOCH {
        anyhow::bail!("No .yar/.yara files found");
    }

    Ok((most_recent, most_recent_path))
}

/// Returns the most recently modified `.yaml`/`.yml` trait file and its mtime.
///
/// Excludes the `third-party/` directory (YARA vendor rules, not trait definitions).
/// Used to determine the capability mapper cache key.
pub fn most_recent_yaml_file() -> Result<(SystemTime, PathBuf)> {
    let mut most_recent = SystemTime::UNIX_EPOCH;
    let mut most_recent_path = PathBuf::new();

    let traits_dir = traits_path();
    if traits_dir.exists() {
        for entry in WalkDir::new(&traits_dir)
            .follow_links(false)
            .into_iter()
            .flatten()
        {
            let path = entry.path();
            if path.components().any(|c| c.as_os_str() == "third-party") {
                continue;
            }
            if path.is_file()
                && path
                    .extension()
                    .map(|ext| ext == "yaml" || ext == "yml")
                    .unwrap_or(false)
            {
                if let Ok(metadata) = fs::metadata(path) {
                    if let Ok(mtime) = metadata.modified() {
                        if mtime > most_recent {
                            most_recent = mtime;
                            most_recent_path = path.to_path_buf();
                        }
                    }
                }
            }
        }
    }

    if most_recent == SystemTime::UNIX_EPOCH {
        anyhow::bail!("No .yaml/.yml files found");
    }

    Ok((most_recent, most_recent_path))
}

/// Returns the most recent modification time across all rule and trait files.
///
/// Used by the analysis result cache and rule-stats display, which invalidate on any change.
pub(crate) fn most_recent_yara_mtime() -> Result<SystemTime> {
    let mut most_recent = SystemTime::UNIX_EPOCH;

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

    if most_recent == SystemTime::UNIX_EPOCH {
        anyhow::bail!("No YARA/trait files found");
    }

    Ok(most_recent)
}

/// Returns the modification time of the cleave binary
pub(crate) fn binary_mtime() -> Result<SystemTime> {
    let exe_path = std::env::current_exe().context("Failed to get current executable path")?;

    let metadata = fs::metadata(&exe_path).context("Failed to read binary metadata")?;

    metadata
        .modified()
        .context("Failed to get binary modification time")
}

/// Returns the appropriate timestamp for cache invalidation.
///
/// Always prefers rule file mtime so that recompiling the binary
/// (`cargo run`) does not invalidate the YARA / mapper caches.
/// Falls back to binary mtime only when no rule files exist at all
/// (true production builds with embedded rules).
pub(crate) fn cache_timestamp() -> Result<SystemTime> {
    static CACHED: OnceLock<SystemTime> = OnceLock::new();
    if let Some(&ts) = CACHED.get() {
        return Ok(ts);
    }
    let ts = match most_recent_yara_mtime() {
        Ok(mtime) => mtime,
        Err(_) => binary_mtime()?,
    };
    Ok(*CACHED.get_or_init(|| ts))
}

/// Generate a cache key based on the newest `.yar`/`.yara` file mtime and third-party flag.
///
/// Only pure YARA rule files are considered, so editing trait YAMLs does not
/// force a full YARA recompile. Falls back to binary mtime when no rule files exist.
///
/// Includes the cleave version so that upgrading the binary invalidates the cache.
pub(crate) fn yara_cache_key(third_party_enabled: bool) -> Result<String> {
    let mtime = most_recent_yar_file()
        .map(|(t, _)| t)
        .or_else(|_| binary_mtime())?;
    let timestamp = mtime
        .duration_since(SystemTime::UNIX_EPOCH)
        .context("Invalid cache timestamp")?
        .as_secs();

    let suffix = if third_party_enabled {
        "with-3p"
    } else {
        "builtin"
    };
    let version = env!("CARGO_PKG_VERSION");

    Ok(format!("yara-rules-v3-{version}-{timestamp}-{suffix}.bin",))
}

/// Get the path to the YARA rules cache file
pub fn yara_cache_path(third_party_enabled: bool) -> Result<PathBuf> {
    let cache_key = yara_cache_key(third_party_enabled)?;
    Ok(cache_dir()?.join(cache_key))
}

/// Generate a cache key for the capability mapper.
///
/// Keyed on the newest `.yaml`/`.yml` trait file mtime (third-party directory excluded),
/// so YARA-only rule updates do not force a trait mapper rebuild.
/// Falls back to binary mtime when no YAML files exist.
pub(crate) fn mapper_cache_key() -> Result<String> {
    let mtime = most_recent_yaml_file()
        .map(|(t, _)| t)
        .or_else(|_| binary_mtime())?;
    let timestamp = mtime
        .duration_since(SystemTime::UNIX_EPOCH)
        .context("Invalid cache timestamp")?
        .as_secs();

    let version = env!("CARGO_PKG_VERSION");

    Ok(format!("capability-mapper-v5-{version}-{timestamp}.bin",))
}

/// Get the path to the capability mapper cache file
pub fn mapper_cache_path() -> Result<PathBuf> {
    let cache_key = mapper_cache_key()?;
    Ok(cache_dir()?.join(cache_key))
}

/// Rule stats stored in a tiny cache file for fast banner display.
/// Layout: trait_count(8) + composite_count(8) + timestamp(8) = 24 bytes
#[allow(dead_code)] // Used by binary
const STATS_CACHE_SIZE: usize = 24;

/// Get the path to the rule stats cache file
pub(crate) fn rule_stats_cache_path() -> Result<PathBuf> {
    Ok(cache_dir()?.join("rule-stats.bin"))
}

/// Save trait and composite counts to stats cache.
/// Called when mapper cache is saved.
pub fn save_rule_stats(trait_count: usize, composite_count: usize) -> Result<()> {
    use std::io::Write;

    let path = rule_stats_cache_path()?;
    let timestamp = cache_timestamp()?
        .duration_since(SystemTime::UNIX_EPOCH)
        .context("Invalid timestamp")?
        .as_secs();

    let mut file = fs::File::create(&path)?;
    file.write_all(&(trait_count as u64).to_le_bytes())?;
    file.write_all(&(composite_count as u64).to_le_bytes())?;
    file.write_all(&timestamp.to_le_bytes())?;
    Ok(())
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

/// Prune RE cache entries older than `max_age_secs`.
///
/// The `re/` subdirectory has no automatic eviction and grows without bound as
/// new unique binaries are analyzed. Call this periodically (e.g. server startup
/// or scheduled task) to prevent unbounded disk growth.
#[allow(dead_code)] // Called from server::run; binary crate can't see cross-crate usage
pub(crate) fn prune_re_cache(max_age_secs: u64) -> usize {
    let Ok(re_dir) = re_cache_dir() else {
        return 0;
    };
    let cutoff = std::time::SystemTime::now()
        .checked_sub(std::time::Duration::from_secs(max_age_secs))
        .unwrap_or(std::time::SystemTime::UNIX_EPOCH);

    let mut removed = 0usize;
    let Ok(subdirs) = fs::read_dir(&re_dir) else {
        return 0;
    };
    for subdir in subdirs.flatten() {
        let Ok(entries) = fs::read_dir(subdir.path()) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            let stale = fs::metadata(&path)
                .and_then(|m| m.modified())
                .map(|mtime| mtime < cutoff)
                .unwrap_or(false);
            if stale && fs::remove_file(&path).is_ok() {
                removed += 1;
            }
        }
    }
    removed
}

/// Get the cache path for a reverse engineering analysis result by SHA256
/// Uses first 2 chars as subdirectory to avoid huge flat directories.
/// Returns: {cache_dir}/re/{sha256[0:2]}/{sha256}.bin
pub fn re_cache_path(sha256: &str) -> Result<PathBuf> {
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
pub fn cleanup_old_caches(current_cache: &Path) -> Result<()> {
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
    fn test_cache_dir_returns_path() {
        let result = cache_dir();
        // Should either succeed or fail, but not panic
        match result {
            Ok(path) => {
                assert!(path.to_string_lossy().contains("cleave"));
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

    #[test]
    fn test_format_age() {
        assert_eq!(format_age(0), "0s");
        assert_eq!(format_age(45), "45s");
        assert_eq!(format_age(60), "1m 0s");
        assert_eq!(format_age(90), "1m 30s");
        assert_eq!(format_age(3600), "1h 0m");
        assert_eq!(format_age(3661), "1h 1m");
        assert_eq!(format_age(86400), "1d 0h");
        assert_eq!(format_age(90061), "1d 1h");
    }
}
