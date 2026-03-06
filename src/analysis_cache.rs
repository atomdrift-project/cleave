//! SQLite-based analysis result cache.
//!
//! Caches `AnalysisReport` results keyed by `(file SHA256, options hash, traits timestamp)`.
//! Reports are stored as zstd-compressed JSON blobs in a SQLite database with WAL mode.
//!
//! The cache is transparent and gracefully degrades — if SQLite fails to open or any
//! operation errors, analysis proceeds normally without caching.
//!
//! # Cache Invalidation
//!
//! Cache entries are automatically invalidated when:
//! - The file content changes (different SHA256)
//! - Trait definitions are modified (different `cache_timestamp()`)
//! - The cleave binary is updated (different binary mtime in production mode)
//! - Analysis options change (different options hash)
//!
//! # Eviction
//!
//! When the cache exceeds 100,000 entries, the oldest 10% by last access time
//! are evicted. This check runs probabilistically (1-in-100 stores) to avoid
//! overhead on every write.

use crate::cache::{cache_dir, cache_timestamp};
use crate::types::AnalysisReport;
use crate::AnalysisOptions;
use rusqlite::Connection;
use std::sync::{Mutex, OnceLock};
use std::time::SystemTime;

/// Maximum number of cached entries before eviction triggers.
const MAX_ENTRIES: i64 = 100_000;

/// Reciprocal probability of running eviction on each store (1-in-N).
const EVICTION_CHECK_INTERVAL: i64 = 100;

/// SQLite-backed analysis result cache.
struct AnalysisCache {
    conn: Mutex<Connection>,
}

impl AnalysisCache {
    /// Open or create the cache database.
    fn open() -> Result<Self, rusqlite::Error> {
        let db_path = cache_dir()
            .map(|d| d.join("analysis-cache.db"))
            .map_err(|e| rusqlite::Error::InvalidParameterName(format!("cache dir: {e}")))?;

        let conn = Connection::open(&db_path)?;

        // WAL mode for concurrent read/write access
        conn.pragma_update(None, "journal_mode", "WAL")?;
        // NORMAL sync is safe with WAL and significantly faster
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        // Wait up to 1s for locks instead of failing immediately
        conn.pragma_update(None, "busy_timeout", 1000)?;

        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS analysis_cache (
                sha256 TEXT NOT NULL,
                options_hash TEXT NOT NULL,
                traits_timestamp INTEGER NOT NULL,
                report BLOB NOT NULL,
                created_at INTEGER NOT NULL,
                last_accessed INTEGER NOT NULL,
                PRIMARY KEY (sha256, options_hash, traits_timestamp)
            );
            CREATE INDEX IF NOT EXISTS idx_last_accessed
                ON analysis_cache(last_accessed);",
        )?;

        tracing::debug!(path = %db_path.display(), "Analysis cache opened");

        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    /// Look up a cached report. Returns `None` on miss or any error.
    fn lookup(&self, sha256: &str, opts_hash: &str, traits_ts: i64) -> Option<AnalysisReport> {
        let conn = self.conn.lock().ok()?;

        let compressed: Vec<u8> = conn
            .prepare_cached(
                "SELECT report FROM analysis_cache
                 WHERE sha256 = ?1 AND options_hash = ?2 AND traits_timestamp = ?3",
            )
            .ok()?
            .query_row(rusqlite::params![sha256, opts_hash, traits_ts], |row| {
                row.get(0)
            })
            .ok()?;

        // Update last_accessed (best-effort)
        let now = unix_timestamp();
        let _ = conn.execute(
            "UPDATE analysis_cache SET last_accessed = ?1
             WHERE sha256 = ?2 AND options_hash = ?3 AND traits_timestamp = ?4",
            rusqlite::params![now, sha256, opts_hash, traits_ts],
        );

        let json = zstd::decode_all(compressed.as_slice()).ok()?;
        serde_json::from_slice(&json).ok()
    }

    /// Store a report in the cache. Silently ignores errors.
    fn store(&self, sha256: &str, opts_hash: &str, traits_ts: i64, report: &AnalysisReport) {
        let Ok(json) = serde_json::to_vec(report) else {
            return;
        };
        let Ok(compressed) = zstd::encode_all(json.as_slice(), 3) else {
            return;
        };
        let now = unix_timestamp();
        if let Ok(conn) = self.conn.lock() {
            let _ = conn.execute(
                "INSERT OR REPLACE INTO analysis_cache
                 (sha256, options_hash, traits_timestamp, report, created_at, last_accessed)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?5)",
                rusqlite::params![sha256, opts_hash, traits_ts, compressed, now],
            );
        }
    }

    /// Probabilistically evict old entries when the cache is too large.
    fn maybe_evict(&self) {
        // Only check 1-in-N stores to amortize the cost
        let roll = unix_timestamp() % EVICTION_CHECK_INTERVAL;
        if roll != 0 {
            return;
        }

        let Ok(conn) = self.conn.lock() else {
            return;
        };

        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM analysis_cache", [], |row| row.get(0))
            .unwrap_or(0);

        if count > MAX_ENTRIES {
            let to_delete = count / 10;
            let deleted = conn.execute(
                "DELETE FROM analysis_cache WHERE rowid IN
                 (SELECT rowid FROM analysis_cache ORDER BY last_accessed ASC LIMIT ?1)",
                rusqlite::params![to_delete],
            );
            if let Ok(n) = deleted {
                tracing::info!(
                    deleted = n,
                    remaining = count - n as i64,
                    "Evicted old cache entries"
                );
            }
        }
    }
}

/// Compute a short deterministic hash of the result-affecting analysis options.
fn options_hash(options: &AnalysisOptions) -> String {
    use sha2::{Digest, Sha256};

    let platforms_str: String = options
        .platforms
        .iter()
        .map(|p| format!("{:?}", p))
        .collect::<Vec<_>>()
        .join(",");
    let key = format!(
        "3p={},yara={},r2={},upx={},plat={},hp={},sp={},fv={}",
        options.enable_third_party_yara,
        !options.disable_yara,
        !options.disable_radare2,
        !options.disable_upx,
        platforms_str,
        options.min_hostile_precision,
        options.min_suspicious_precision,
        options.enable_full_validation,
    );
    let hash = Sha256::digest(key.as_bytes());
    // First 16 hex chars is plenty for a small option space
    format!("{:x}", hash)[..16].to_string()
}

/// Get the traits timestamp as Unix seconds, or `None` if unavailable.
fn traits_timestamp_secs() -> Option<i64> {
    cache_timestamp()
        .ok()?
        .duration_since(SystemTime::UNIX_EPOCH)
        .ok()
        .map(|d| d.as_secs() as i64)
}

/// Current time as Unix seconds.
fn unix_timestamp() -> i64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Global singleton cache instance.
static ANALYSIS_CACHE: OnceLock<Option<AnalysisCache>> = OnceLock::new();

/// Get the global analysis cache, initializing on first use.
/// Returns `None` if caching is disabled or initialization fails.
fn analysis_cache() -> Option<&'static AnalysisCache> {
    ANALYSIS_CACHE
        .get_or_init(|| {
            if std::env::var("CLEAVE_SKIP_CACHE")
                .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
                .unwrap_or(false)
            {
                tracing::info!("Analysis cache disabled via CLEAVE_SKIP_CACHE");
                return None;
            }
            match AnalysisCache::open() {
                Ok(cache) => Some(cache),
                Err(e) => {
                    tracing::warn!("Failed to open analysis cache: {}", e);
                    None
                }
            }
        })
        .as_ref()
}

/// Look up a cached analysis report for the given file hash and options.
///
/// Returns `Some(report)` on cache hit, `None` on miss or if caching is unavailable.
pub(crate) fn cache_lookup(sha256: &str, options: &AnalysisOptions) -> Option<AnalysisReport> {
    let cache = analysis_cache()?;
    let opts_hash = options_hash(options);
    let traits_ts = traits_timestamp_secs()?;
    cache.lookup(sha256, &opts_hash, traits_ts)
}

/// Store an analysis report in the cache.
///
/// Silently does nothing if caching is unavailable or any error occurs.
pub(crate) fn cache_store(sha256: &str, options: &AnalysisOptions, report: &AnalysisReport) {
    let Some(cache) = analysis_cache() else {
        return;
    };
    let opts_hash = options_hash(options);
    let Some(traits_ts) = traits_timestamp_secs() else {
        return;
    };
    cache.store(sha256, &opts_hash, traits_ts, report);
    cache.maybe_evict();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::core::{AnalysisReport, TargetInfo};

    fn test_report(sha256: &str) -> AnalysisReport {
        let target = TargetInfo {
            path: "/test/sample.bin".to_string(),
            file_type: "elf".to_string(),
            size_bytes: 1024,
            sha256: sha256.to_string(),
            architectures: None,
        };
        AnalysisReport::new(target)
    }

    fn test_cache() -> AnalysisCache {
        // Use in-memory SQLite for tests
        #[allow(clippy::expect_used)]
        let conn = Connection::open_in_memory().expect("in-memory SQLite must succeed in test");
        // WAL may not work with in-memory, that's fine for tests
        let _ = conn.pragma_update(None, "journal_mode", "WAL");
        #[allow(clippy::expect_used)]
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS analysis_cache (
                sha256 TEXT NOT NULL,
                options_hash TEXT NOT NULL,
                traits_timestamp INTEGER NOT NULL,
                report BLOB NOT NULL,
                created_at INTEGER NOT NULL,
                last_accessed INTEGER NOT NULL,
                PRIMARY KEY (sha256, options_hash, traits_timestamp)
            );
            CREATE INDEX IF NOT EXISTS idx_last_accessed
                ON analysis_cache(last_accessed);",
        )
        .expect("table creation must succeed in test");

        AnalysisCache {
            conn: Mutex::new(conn),
        }
    }

    #[test]
    fn test_roundtrip() {
        let cache = test_cache();
        let sha = "abc123def456";
        let opts = "test_opts";
        let ts = 1700000000_i64;
        let report = test_report(sha);

        cache.store(sha, opts, ts, &report);
        let cached = cache.lookup(sha, opts, ts);

        assert!(cached.is_some());
        #[allow(clippy::expect_used)]
        let cached = cached.expect("cache hit expected");
        assert_eq!(cached.target.sha256, sha);
        assert_eq!(cached.target.file_type, "elf");
        assert_eq!(cached.schema_version, "2.0");
    }

    #[test]
    fn test_cache_miss_wrong_sha256() {
        let cache = test_cache();
        let opts = "test_opts";
        let ts = 1700000000_i64;
        let report = test_report("abc123");

        cache.store("abc123", opts, ts, &report);
        let cached = cache.lookup("different_sha", opts, ts);

        assert!(cached.is_none());
    }

    #[test]
    fn test_cache_miss_wrong_timestamp() {
        let cache = test_cache();
        let sha = "abc123";
        let opts = "test_opts";
        let report = test_report(sha);

        cache.store(sha, opts, 1700000000, &report);
        let cached = cache.lookup(sha, opts, 1700000001);

        assert!(cached.is_none());
    }

    #[test]
    fn test_cache_miss_wrong_options() {
        let cache = test_cache();
        let sha = "abc123";
        let ts = 1700000000_i64;
        let report = test_report(sha);

        cache.store(sha, "opts_a", ts, &report);
        let cached = cache.lookup(sha, "opts_b", ts);

        assert!(cached.is_none());
    }

    #[test]
    fn test_options_hash_deterministic() {
        let opts = AnalysisOptions::default();
        let h1 = options_hash(&opts);
        let h2 = options_hash(&opts);
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 16);
    }

    #[test]
    fn test_options_hash_varies_with_options() {
        let opts1 = AnalysisOptions::default();
        let opts2 = AnalysisOptions {
            disable_yara: true,
            ..AnalysisOptions::default()
        };

        assert_ne!(options_hash(&opts1), options_hash(&opts2));
    }

    #[test]
    fn test_store_replaces_existing() {
        let cache = test_cache();
        let sha = "abc123";
        let opts = "test_opts";
        let ts = 1700000000_i64;

        let report1 = test_report(sha);
        cache.store(sha, opts, ts, &report1);

        // Store a different report with same key
        let mut report2 = test_report(sha);
        report2.target.file_type = "pe".to_string();
        cache.store(sha, opts, ts, &report2);

        let cached = cache.lookup(sha, opts, ts);
        assert!(cached.is_some());
        #[allow(clippy::expect_used)]
        let cached = cached.expect("cache hit expected");
        assert_eq!(cached.target.file_type, "pe");
    }
}
