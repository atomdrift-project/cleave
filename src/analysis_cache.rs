//! SQLite-based analysis result cache.
//!
//! Caches `AnalysisReport` results keyed by `(file SHA256, options hash, traits timestamp)`.
//! Reports are stored as zstd-compressed JSON blobs in a SQLite database with WAL mode.
//!
//! # Concurrency
//!
//! Each thread holds its own `Connection` to the database. WAL mode allows all reader
//! threads to proceed concurrently without blocking each other. Writers briefly hold the
//! WAL write lock during the insert — reads are never blocked by writes in WAL mode.
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
use std::cell::RefCell;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::OnceLock;
use std::time::SystemTime;

/// Maximum number of cached entries before eviction triggers.
const MAX_ENTRIES: i64 = 100_000;

/// Reciprocal probability of running eviction on each store (1-in-N).
const EVICTION_CHECK_INTERVAL: u64 = 100;

/// Global store counter for eviction scheduling, shared across all threads.
static STORE_COUNT: AtomicU64 = AtomicU64::new(0);

/// Database path, resolved once at first use. `None` means caching is disabled.
static DB_PATH: OnceLock<Option<PathBuf>> = OnceLock::new();

// Per-thread SQLite connection. Initialized lazily on first use.
thread_local! {
    static CONN: RefCell<Option<Connection>> = const { RefCell::new(None) };
}

/// Resolve the database path, or `None` if caching is disabled or unavailable.
fn db_path() -> Option<&'static Path> {
    DB_PATH
        .get_or_init(|| {
            if std::env::var("CLEAVE_SKIP_CACHE")
                .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
                .unwrap_or(false)
            {
                tracing::info!("Analysis cache disabled via CLEAVE_SKIP_CACHE");
                return None;
            }
            match cache_dir() {
                Ok(dir) => Some(dir.join("analysis-cache.db")),
                Err(e) => {
                    tracing::warn!("Cache directory unavailable: {}", e);
                    None
                }
            }
        })
        .as_deref()
}

/// Open a new connection to `path` with WAL mode and the cache schema.
fn open_connection(path: &Path) -> Result<Connection, rusqlite::Error> {
    let conn = Connection::open(path)?;
    conn.pragma_update(None, "journal_mode", "WAL")?;
    conn.pragma_update(None, "synchronous", "NORMAL")?;
    // Generous timeout: concurrent writers briefly hold the WAL write lock.
    conn.pragma_update(None, "busy_timeout", 5000)?;
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
    tracing::debug!(path = %path.display(), "Analysis cache connection opened");
    Ok(conn)
}

/// Execute `f` with this thread's SQLite connection, initializing it if needed.
/// Returns `None` if caching is disabled or the connection cannot be established.
fn with_conn<T>(f: impl FnOnce(&Connection) -> T) -> Option<T> {
    let path = db_path()?;
    CONN.with(|cell| {
        let mut opt = cell.borrow_mut();
        if opt.is_none() {
            *opt = open_connection(path)
                .or_else(|e| {
                    // Database may be corrupt — delete and recreate.
                    tracing::debug!("Cache open failed, recreating: {}", e);
                    let _ = std::fs::remove_file(path);
                    let _ = std::fs::remove_file(path.with_extension("db-wal"));
                    let _ = std::fs::remove_file(path.with_extension("db-shm"));
                    open_connection(path)
                })
                .map_err(|e| tracing::warn!("Analysis cache unavailable: {}", e))
                .ok();
        }
        opt.as_ref().map(f)
    })
}

/// Look up a report in `conn`. Returns `None` on miss.
fn lookup_conn(
    conn: &Connection,
    sha256: &str,
    opts_hash: &str,
    traits_ts: i64,
) -> Option<AnalysisReport> {
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

    // Update last_accessed best-effort; may lose the race with another writer, that's fine.
    let now = unix_timestamp();
    let _ = conn.execute(
        "UPDATE analysis_cache SET last_accessed = ?1
         WHERE sha256 = ?2 AND options_hash = ?3 AND traits_timestamp = ?4",
        rusqlite::params![now, sha256, opts_hash, traits_ts],
    );

    let json = zstd::decode_all(compressed.as_slice()).ok()?;
    serde_json::from_slice(&json).ok()
}

/// Store a report in `conn`. Silently ignores errors.
fn store_conn(
    conn: &Connection,
    sha256: &str,
    opts_hash: &str,
    traits_ts: i64,
    report: &AnalysisReport,
) {
    let Ok(json) = serde_json::to_vec(report) else {
        return;
    };
    let Ok(compressed) = zstd::encode_all(json.as_slice(), 3) else {
        return;
    };
    let now = unix_timestamp();
    let _ = conn.execute(
        "INSERT OR REPLACE INTO analysis_cache
         (sha256, options_hash, traits_timestamp, report, created_at, last_accessed)
         VALUES (?1, ?2, ?3, ?4, ?5, ?5)",
        rusqlite::params![sha256, opts_hash, traits_ts, compressed, now],
    );
}

/// Evict the oldest 10% of entries if the cache exceeds `MAX_ENTRIES`.
/// Uses a global counter so eviction is distributed across threads without duplication.
fn maybe_evict(conn: &Connection) {
    let count = STORE_COUNT.fetch_add(1, Ordering::Relaxed);
    if !count.is_multiple_of(EVICTION_CHECK_INTERVAL) {
        return;
    }

    let total: i64 = conn
        .query_row("SELECT COUNT(*) FROM analysis_cache", [], |row| row.get(0))
        .unwrap_or(0);

    if total > MAX_ENTRIES {
        let to_delete = total / 10;
        if let Ok(n) = conn.execute(
            "DELETE FROM analysis_cache WHERE rowid IN
             (SELECT rowid FROM analysis_cache ORDER BY last_accessed ASC LIMIT ?1)",
            rusqlite::params![to_delete],
        ) {
            tracing::info!(
                deleted = n,
                remaining = total - n as i64,
                "Evicted old cache entries"
            );
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
        "v=4,3p={},yara={},r2={},upx={},plat={},hp={},sp={},fv={}",
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

/// Look up a cached analysis report for the given file hash and options.
///
/// Returns `Some(report)` on cache hit, `None` on miss or if caching is unavailable.
pub(crate) fn cache_lookup(sha256: &str, options: &AnalysisOptions) -> Option<AnalysisReport> {
    let opts_hash = options_hash(options);
    let traits_ts = traits_timestamp_secs()?;
    with_conn(|conn| lookup_conn(conn, sha256, &opts_hash, traits_ts)).flatten()
}

/// Count entries currently in the analysis cache. Returns `None` if unavailable.
pub(crate) fn cache_entry_count() -> Option<i64> {
    with_conn(|conn| {
        conn.query_row("SELECT COUNT(*) FROM analysis_cache", [], |row| row.get(0))
            .ok()
    })
    .flatten()
}

/// Store an analysis report in the cache.
///
/// Silently does nothing if caching is unavailable or any error occurs.
pub(crate) fn cache_store(sha256: &str, options: &AnalysisOptions, report: &AnalysisReport) {
    let opts_hash = options_hash(options);
    let Some(traits_ts) = traits_timestamp_secs() else {
        return;
    };
    with_conn(|conn| {
        store_conn(conn, sha256, &opts_hash, traits_ts, report);
        maybe_evict(conn);
    });
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

    fn test_conn() -> Connection {
        #[allow(clippy::expect_used)]
        let conn = Connection::open_in_memory().expect("in-memory SQLite must succeed in test");
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
        conn
    }

    #[test]
    fn test_roundtrip() {
        let conn = test_conn();
        let sha = "abc123def456";
        let opts = "test_opts";
        let ts = 1700000000_i64;
        let report = test_report(sha);

        store_conn(&conn, sha, opts, ts, &report);
        let cached = lookup_conn(&conn, sha, opts, ts);

        assert!(cached.is_some());
        #[allow(clippy::expect_used)]
        let cached = cached.expect("cache hit expected");
        assert_eq!(cached.target.sha256, sha);
        assert_eq!(cached.target.file_type, "elf");
        assert_eq!(cached.version, "2.0");
    }

    #[test]
    fn test_cache_miss_wrong_sha256() {
        let conn = test_conn();
        let opts = "test_opts";
        let ts = 1700000000_i64;

        store_conn(&conn, "abc123", opts, ts, &test_report("abc123"));
        assert!(lookup_conn(&conn, "different_sha", opts, ts).is_none());
    }

    #[test]
    fn test_cache_miss_wrong_timestamp() {
        let conn = test_conn();
        let sha = "abc123";
        let opts = "test_opts";

        store_conn(&conn, sha, opts, 1700000000, &test_report(sha));
        assert!(lookup_conn(&conn, sha, opts, 1700000001).is_none());
    }

    #[test]
    fn test_cache_miss_wrong_options() {
        let conn = test_conn();
        let sha = "abc123";
        let ts = 1700000000_i64;

        store_conn(&conn, sha, "opts_a", ts, &test_report(sha));
        assert!(lookup_conn(&conn, sha, "opts_b", ts).is_none());
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
        let conn = test_conn();
        let sha = "abc123";
        let opts = "test_opts";
        let ts = 1700000000_i64;

        store_conn(&conn, sha, opts, ts, &test_report(sha));

        let mut report2 = test_report(sha);
        report2.target.file_type = "pe".to_string();
        store_conn(&conn, sha, opts, ts, &report2);

        #[allow(clippy::expect_used)]
        let cached = lookup_conn(&conn, sha, opts, ts).expect("cache hit expected");
        assert_eq!(cached.target.file_type, "pe");
    }
}
