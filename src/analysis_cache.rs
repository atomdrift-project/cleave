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
use crate::types::FileAnalysis;
use crate::AnalysisOptions;
use rusqlite::Connection;
use std::cell::RefCell;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::OnceLock;
use std::time::SystemTime;

/// Maximum number of toplevel report cache entries before eviction triggers.
const MAX_REPORT_ENTRIES: i64 = 100_000;

/// Maximum number of file analysis cache entries before eviction triggers.
const MAX_FILE_ANALYSIS_ENTRIES: i64 = 500_000;

/// Reciprocal probability of running eviction on each store (1-in-N).
const EVICTION_CHECK_INTERVAL: u64 = 100;

/// Global store counter for report cache eviction scheduling, shared across all threads.
static REPORT_STORE_COUNT: AtomicU64 = AtomicU64::new(0);

/// Global store counter for file analysis cache eviction scheduling.
static FILE_ANALYSIS_STORE_COUNT: AtomicU64 = AtomicU64::new(0);

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
            if crate::cache::skip_cache() {
                tracing::info!("Analysis cache disabled (debug build or CLEAVE_SKIP_CACHE)");
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
        "CREATE TABLE IF NOT EXISTS toplevel_report_cache (
            sha256 TEXT NOT NULL,
            options_hash TEXT NOT NULL,
            traits_timestamp INTEGER NOT NULL,
            report BLOB NOT NULL,
            created_at INTEGER NOT NULL,
            last_accessed INTEGER NOT NULL,
            PRIMARY KEY (sha256, options_hash, traits_timestamp)
        );
        CREATE INDEX IF NOT EXISTS idx_toplevel_report_last_accessed
            ON toplevel_report_cache(last_accessed);
        CREATE TABLE IF NOT EXISTS file_analysis_cache (
            sha256 TEXT NOT NULL,
            options_hash TEXT NOT NULL,
            traits_timestamp INTEGER NOT NULL,
            file_analysis BLOB NOT NULL,
            created_at INTEGER NOT NULL,
            last_accessed INTEGER NOT NULL,
            PRIMARY KEY (sha256, options_hash, traits_timestamp)
        );
        CREATE INDEX IF NOT EXISTS idx_file_analysis_last_accessed
            ON file_analysis_cache(last_accessed);",
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
fn report_cache_lookup_conn(
    conn: &Connection,
    sha256: &str,
    opts_hash: &str,
    traits_ts: i64,
) -> Option<AnalysisReport> {
    let compressed: Vec<u8> = conn
        .prepare_cached(
            "SELECT report FROM toplevel_report_cache
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
        "UPDATE toplevel_report_cache SET last_accessed = ?1
         WHERE sha256 = ?2 AND options_hash = ?3 AND traits_timestamp = ?4",
        rusqlite::params![now, sha256, opts_hash, traits_ts],
    );

    let json = zstd::decode_all(compressed.as_slice()).ok()?;
    serde_json::from_slice(&json).ok()
}

/// Store a report in `conn`. Silently ignores errors.
fn report_cache_store_conn(
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
        "INSERT OR REPLACE INTO toplevel_report_cache
         (sha256, options_hash, traits_timestamp, report, created_at, last_accessed)
         VALUES (?1, ?2, ?3, ?4, ?5, ?5)",
        rusqlite::params![sha256, opts_hash, traits_ts, compressed, now],
    );
}

/// Evict the oldest 10% of toplevel report cache entries if over `MAX_REPORT_ENTRIES`.
/// Uses a global counter so eviction is distributed across threads without duplication.
fn maybe_evict_report_cache(conn: &Connection) {
    let count = REPORT_STORE_COUNT.fetch_add(1, Ordering::Relaxed);
    if !count.is_multiple_of(EVICTION_CHECK_INTERVAL) {
        return;
    }

    let total: i64 = conn
        .query_row("SELECT COUNT(*) FROM toplevel_report_cache", [], |row| {
            row.get(0)
        })
        .unwrap_or(0);

    if total > MAX_REPORT_ENTRIES {
        let to_delete = total / 10;
        if let Ok(n) = conn.execute(
            "DELETE FROM toplevel_report_cache WHERE rowid IN
             (SELECT rowid FROM toplevel_report_cache ORDER BY last_accessed ASC LIMIT ?1)",
            rusqlite::params![to_delete],
        ) {
            tracing::info!(
                deleted = n,
                remaining = total - n as i64,
                "Evicted old toplevel report cache entries"
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
        "v=5,3p={},yara={},r2={},upx={},plat={},hp={},sp={},ps={},fv={}",
        options.enable_third_party_yara,
        !options.disable_yara,
        !options.disable_radare2,
        !options.disable_upx,
        platforms_str,
        options.min_hostile_precision,
        options.min_suspicious_precision,
        options.enable_precision_scoring,
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

/// Look up a cached toplevel analysis report for the given file hash and options.
///
/// Returns `Some(report)` on cache hit, `None` on miss or if caching is unavailable.
pub(crate) fn report_cache_lookup(
    sha256: &str,
    options: &AnalysisOptions,
) -> Option<AnalysisReport> {
    let opts_hash = options_hash(options);
    let traits_ts = traits_timestamp_secs()?;
    with_conn(|conn| report_cache_lookup_conn(conn, sha256, &opts_hash, traits_ts)).flatten()
}

/// Count entries currently in the toplevel report cache. Returns `None` if unavailable.
pub(crate) fn report_cache_entry_count() -> Option<i64> {
    with_conn(|conn| {
        conn.query_row("SELECT COUNT(*) FROM toplevel_report_cache", [], |row| {
            row.get(0)
        })
        .ok()
    })
    .flatten()
}

/// Store a toplevel analysis report in the cache.
///
/// Silently does nothing if caching is unavailable or any error occurs.
pub(crate) fn report_cache_store(sha256: &str, options: &AnalysisOptions, report: &AnalysisReport) {
    let opts_hash = options_hash(options);
    let Some(traits_ts) = traits_timestamp_secs() else {
        return;
    };
    with_conn(|conn| {
        report_cache_store_conn(conn, sha256, &opts_hash, traits_ts, report);
        maybe_evict_report_cache(conn);
    });
}

/// Look up a cached `FileAnalysis` for the given file hash and options.
///
/// Returns `Some(fa)` on cache hit, `None` on miss or if caching is unavailable.
pub(crate) fn file_analysis_cache_lookup(
    sha256: &str,
    options: &AnalysisOptions,
) -> Option<FileAnalysis> {
    let opts_hash = options_hash(options);
    let traits_ts = traits_timestamp_secs()?;
    with_conn(|conn| file_analysis_cache_lookup_conn(conn, sha256, &opts_hash, traits_ts)).flatten()
}

/// Store a `FileAnalysis` in the file analysis cache.
///
/// Silently does nothing if caching is unavailable or any error occurs.
pub(crate) fn file_analysis_cache_store(
    sha256: &str,
    options: &AnalysisOptions,
    fa: &FileAnalysis,
) {
    let opts_hash = options_hash(options);
    let Some(traits_ts) = traits_timestamp_secs() else {
        return;
    };
    with_conn(|conn| {
        file_analysis_cache_store_conn(conn, sha256, &opts_hash, traits_ts, fa);
        maybe_evict_file_analysis_cache(conn);
    });
}

/// Look up a FileAnalysis in `conn`. Returns `None` on miss.
fn file_analysis_cache_lookup_conn(
    conn: &Connection,
    sha256: &str,
    opts_hash: &str,
    traits_ts: i64,
) -> Option<FileAnalysis> {
    let compressed: Vec<u8> = conn
        .prepare_cached(
            "SELECT file_analysis FROM file_analysis_cache
             WHERE sha256 = ?1 AND options_hash = ?2 AND traits_timestamp = ?3",
        )
        .ok()?
        .query_row(rusqlite::params![sha256, opts_hash, traits_ts], |row| {
            row.get(0)
        })
        .ok()?;

    let now = unix_timestamp();
    let _ = conn.execute(
        "UPDATE file_analysis_cache SET last_accessed = ?1
         WHERE sha256 = ?2 AND options_hash = ?3 AND traits_timestamp = ?4",
        rusqlite::params![now, sha256, opts_hash, traits_ts],
    );

    let json = zstd::decode_all(compressed.as_slice()).ok()?;
    serde_json::from_slice(&json).ok()
}

/// Store a FileAnalysis in `conn`. Silently ignores errors.
fn file_analysis_cache_store_conn(
    conn: &Connection,
    sha256: &str,
    opts_hash: &str,
    traits_ts: i64,
    fa: &FileAnalysis,
) {
    let Ok(json) = serde_json::to_vec(fa) else {
        return;
    };
    let Ok(compressed) = zstd::encode_all(json.as_slice(), 3) else {
        return;
    };
    let now = unix_timestamp();
    let _ = conn.execute(
        "INSERT OR REPLACE INTO file_analysis_cache
         (sha256, options_hash, traits_timestamp, file_analysis, created_at, last_accessed)
         VALUES (?1, ?2, ?3, ?4, ?5, ?5)",
        rusqlite::params![sha256, opts_hash, traits_ts, compressed, now],
    );
}

/// Evict the oldest 10% of file analysis cache entries if over `MAX_FILE_ANALYSIS_ENTRIES`.
fn maybe_evict_file_analysis_cache(conn: &Connection) {
    let count = FILE_ANALYSIS_STORE_COUNT.fetch_add(1, Ordering::Relaxed);
    if !count.is_multiple_of(EVICTION_CHECK_INTERVAL) {
        return;
    }

    let total: i64 = conn
        .query_row("SELECT COUNT(*) FROM file_analysis_cache", [], |row| {
            row.get(0)
        })
        .unwrap_or(0);

    if total > MAX_FILE_ANALYSIS_ENTRIES {
        let to_delete = total / 10;
        if let Ok(n) = conn.execute(
            "DELETE FROM file_analysis_cache WHERE rowid IN
             (SELECT rowid FROM file_analysis_cache ORDER BY last_accessed ASC LIMIT ?1)",
            rusqlite::params![to_delete],
        ) {
            tracing::info!(
                deleted = n,
                remaining = total - n as i64,
                "Evicted old file cache entries"
            );
        }
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use crate::types::core::{AnalysisReport, TargetInfo};
    use crate::types::FileAnalysis;

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
        let conn = Connection::open_in_memory().expect("in-memory SQLite must succeed in test");
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS toplevel_report_cache (
                sha256 TEXT NOT NULL,
                options_hash TEXT NOT NULL,
                traits_timestamp INTEGER NOT NULL,
                report BLOB NOT NULL,
                created_at INTEGER NOT NULL,
                last_accessed INTEGER NOT NULL,
                PRIMARY KEY (sha256, options_hash, traits_timestamp)
            );
            CREATE INDEX IF NOT EXISTS idx_toplevel_report_last_accessed
                ON toplevel_report_cache(last_accessed);",
        )
        .expect("table creation must succeed in test");
        conn
    }

    /// In-memory connection with the file_cache table (for testing file_cache_*_conn).
    fn file_analysis_test_conn() -> Connection {
        let conn = Connection::open_in_memory().expect("in-memory SQLite must succeed in test");
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS file_analysis_cache (
                sha256 TEXT NOT NULL,
                options_hash TEXT NOT NULL,
                traits_timestamp INTEGER NOT NULL,
                file_analysis BLOB NOT NULL,
                created_at INTEGER NOT NULL,
                last_accessed INTEGER NOT NULL,
                PRIMARY KEY (sha256, options_hash, traits_timestamp)
            );
            CREATE INDEX IF NOT EXISTS idx_file_analysis_last_accessed
                ON file_analysis_cache(last_accessed);",
        )
        .expect("file_cache table creation must succeed in test");
        conn
    }

    fn test_file_analysis(sha256: &str, file_type: &str) -> FileAnalysis {
        FileAnalysis::new(
            0,
            String::new(), // normalized: no path
            file_type.to_string(),
            sha256.to_string(),
            512,
        )
    }

    #[test]
    fn test_roundtrip() {
        let conn = test_conn();
        let sha = "abc123def456";
        let opts = "test_opts";
        let ts = 1700000000_i64;
        let report = test_report(sha);

        report_cache_store_conn(&conn, sha, opts, ts, &report);
        let cached = report_cache_lookup_conn(&conn, sha, opts, ts);

        assert!(cached.is_some());
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

        report_cache_store_conn(&conn, "abc123", opts, ts, &test_report("abc123"));
        assert!(report_cache_lookup_conn(&conn, "different_sha", opts, ts).is_none());
    }

    #[test]
    fn test_cache_miss_wrong_timestamp() {
        let conn = test_conn();
        let sha = "abc123";
        let opts = "test_opts";

        report_cache_store_conn(&conn, sha, opts, 1700000000, &test_report(sha));
        assert!(report_cache_lookup_conn(&conn, sha, opts, 1700000001).is_none());
    }

    #[test]
    fn test_cache_miss_wrong_options() {
        let conn = test_conn();
        let sha = "abc123";
        let ts = 1700000000_i64;

        report_cache_store_conn(&conn, sha, "opts_a", ts, &test_report(sha));
        assert!(report_cache_lookup_conn(&conn, sha, "opts_b", ts).is_none());
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

        report_cache_store_conn(&conn, sha, opts, ts, &test_report(sha));

        let mut report2 = test_report(sha);
        report2.target.file_type = "pe".to_string();
        report_cache_store_conn(&conn, sha, opts, ts, &report2);

        let cached = report_cache_lookup_conn(&conn, sha, opts, ts).expect("cache hit expected");
        assert_eq!(cached.target.file_type, "pe");
    }

    // ── file_cache tests ──────────────────────────────────────────────────────

    #[test]
    fn test_file_cache_roundtrip() {
        let conn = file_analysis_test_conn();
        let sha = "deadbeef01234567";
        let opts = "opts_hash";
        let ts = 1700000000_i64;
        let fa = test_file_analysis(sha, "javascript");

        file_analysis_cache_store_conn(&conn, sha, opts, ts, &fa);
        let cached = file_analysis_cache_lookup_conn(&conn, sha, opts, ts);

        assert!(cached.is_some());
        let cached = cached.expect("file cache hit expected");
        assert_eq!(cached.sha256, sha);
        assert_eq!(cached.file_type, "javascript");
        assert_eq!(cached.size, 512);
        // path is empty (normalized)
        assert_eq!(cached.path, "");
    }

    #[test]
    fn test_file_cache_miss_wrong_sha256() {
        let conn = file_analysis_test_conn();
        let opts = "opts_hash";
        let ts = 1700000000_i64;

        file_analysis_cache_store_conn(
            &conn,
            "aaa",
            opts,
            ts,
            &test_file_analysis("aaa", "python"),
        );
        assert!(file_analysis_cache_lookup_conn(&conn, "bbb", opts, ts).is_none());
    }

    #[test]
    fn test_file_cache_miss_wrong_timestamp() {
        let conn = file_analysis_test_conn();
        let sha = "aabbcc";
        let opts = "opts_hash";

        file_analysis_cache_store_conn(
            &conn,
            sha,
            opts,
            1700000000,
            &test_file_analysis(sha, "elf"),
        );
        assert!(file_analysis_cache_lookup_conn(&conn, sha, opts, 1700000001).is_none());
    }

    #[test]
    fn test_file_cache_miss_wrong_options() {
        let conn = file_analysis_test_conn();
        let sha = "aabbcc";
        let ts = 1700000000_i64;

        file_analysis_cache_store_conn(&conn, sha, "opts_a", ts, &test_file_analysis(sha, "elf"));
        assert!(file_analysis_cache_lookup_conn(&conn, sha, "opts_b", ts).is_none());
    }

    #[test]
    fn test_file_cache_replaces_existing() {
        let conn = file_analysis_test_conn();
        let sha = "aabbcc";
        let opts = "opts_hash";
        let ts = 1700000000_i64;

        file_analysis_cache_store_conn(&conn, sha, opts, ts, &test_file_analysis(sha, "elf"));

        let mut fa2 = test_file_analysis(sha, "pe");
        fa2.size = 9999;
        file_analysis_cache_store_conn(&conn, sha, opts, ts, &fa2);

        let cached = file_analysis_cache_lookup_conn(&conn, sha, opts, ts).expect("hit expected");
        assert_eq!(cached.file_type, "pe");
        assert_eq!(cached.size, 9999);
    }

    #[test]
    fn test_file_cache_preserves_findings() {
        use crate::types::traits_findings::Finding;
        use crate::types::Criticality;

        let conn = file_analysis_test_conn();
        let sha = "cafebabe";
        let opts = "opts_hash";
        let ts = 1700000000_i64;

        let mut fa = test_file_analysis(sha, "javascript");
        fa.findings.push(
            Finding::capability("exec/shell".to_string(), "Shell execution".to_string(), 0.9)
                .with_criticality(Criticality::Hostile),
        );
        fa.compute_summary();

        file_analysis_cache_store_conn(&conn, sha, opts, ts, &fa);
        let cached = file_analysis_cache_lookup_conn(&conn, sha, opts, ts).expect("hit expected");

        assert_eq!(cached.findings.len(), 1);
        assert_eq!(cached.findings[0].id, "exec/shell");
        // ceil(hostile(120) * conf(0.9)) = 108
        assert_eq!(cached.score, 108);
    }

    #[test]
    fn test_file_cache_independent_of_report_cache() {
        // Storing in file_cache should not affect analysis_cache and vice versa.
        let conn = file_analysis_test_conn();
        let sha = "deadbeef";
        let opts = "opts";
        let ts = 1700000000_i64;

        // Nothing in file_cache yet — lookup should miss
        assert!(file_analysis_cache_lookup_conn(&conn, sha, opts, ts).is_none());

        // Storing a FileAnalysis only populates file_cache
        file_analysis_cache_store_conn(&conn, sha, opts, ts, &test_file_analysis(sha, "python"));
        assert!(file_analysis_cache_lookup_conn(&conn, sha, opts, ts).is_some());

        // The separate analysis_cache table is unaffected (would fail if tables were shared)
        let report_conn = test_conn();
        assert!(report_cache_lookup_conn(&report_conn, sha, opts, ts).is_none());
    }

    #[test]
    fn test_file_cache_options_hash_excludes_cancellation() {
        // The cancellation flag must not affect the cache key — same content should
        // hit regardless of whether the caller has a cancellation token set.
        use std::sync::{atomic::AtomicBool, Arc};

        let opts_without = AnalysisOptions::default();
        let opts_with = AnalysisOptions {
            cancellation: Some(Arc::new(AtomicBool::new(false))),
            ..AnalysisOptions::default()
        };

        assert_eq!(options_hash(&opts_without), options_hash(&opts_with));
    }
}
