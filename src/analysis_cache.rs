//! SQLite-based analysis result cache.
//!
//! Caches `AnalysisReport` results keyed by `(file SHA256, options hash, traits revision)`.
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
//! - Trait definitions are modified (different `cache_revision()`)
//! - The cleave binary is updated (different binary mtime in production mode)
//! - Analysis options change (different options hash)
//!
//! # Eviction
//!
//! When the cache exceeds its entry cap, eviction runs down to 90% of the cap
//! (sorted by last-access time). A store samples the eviction point 1-in-100
//! and, when it fires, hands the work to a background thread with its own
//! connection — the `SELECT COUNT(*)` gate and `DELETE` never block the
//! storing thread. A per-table guard keeps at most one eviction in flight, so
//! the cache stays close to the ceiling on long-running scans (10M+ files over
//! multiple days) without ever stalling the hot path.

use crate::AnalysisOptions;
use crate::cache::{cache_dir, cache_revision};
use crate::types::AnalysisReport;
use crate::types::FileAnalysis;
use rusqlite::Connection;
use std::cell::RefCell;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, OnceLock, Weak};
use std::time::SystemTime;

/// Maximum number of toplevel report cache entries before eviction triggers.
const MAX_REPORT_ENTRIES: i64 = 100_000;

/// Maximum number of file analysis cache entries before eviction triggers.
const MAX_FILE_ANALYSIS_ENTRIES: i64 = 500_000;

/// Reciprocal probability of running eviction on each store (1-in-N).
///
/// With cache caps in the 100k-entry range and a few dozen concurrent writers,
/// `interval = 100` keeps overshoot under ~2.5 % of cap (at most
/// `threads * (interval-1)` entries between checks). The eviction itself is
/// cheap — an indexed range scan — but the `SELECT COUNT(*)` that gates it is
/// O(n) on the table; running it once per 100 stores instead of once per 10
/// cuts that gate cost by 10× on the cache-store hot path.
const EVICTION_CHECK_INTERVAL: u64 = 100;

/// After eviction, target this fraction of the cap. Bringing the cache down to
/// 90% avoids oscillation where each eviction only shaves 10% of *current*
/// size (which, when current > cap, leaves us still above cap).
const EVICTION_TARGET_NUMERATOR: i64 = 9;
const EVICTION_TARGET_DENOMINATOR: i64 = 10;

/// Evict entries idle longer than this regardless of the count cap, so nothing
/// lingers indefinitely. Keyed on `last_accessed`, so a still-used entry is
/// never dropped for age alone. 30 days.
const MAX_IDLE_SECS: i64 = 30 * 24 * 60 * 60;

/// Byte ceiling for the cache DB's live data. Enforced by evicting the
/// least-recently-used rows once a table's blobs exceed its share — not by
/// VACUUM (which can't delete live rows, and stalls concurrent writers while it
/// rewrites a multi-GB WAL DB). SQLite reuses the pages freed by eviction, so
/// the file stops growing even though it isn't shrunk back on disk. 2 GiB.
const MAX_DB_BYTES: i64 = 2 * 1024 * 1024 * 1024;

/// Each of the two cache tables is bounded to half of [`MAX_DB_BYTES`], so their
/// combined live data stays within the ceiling.
const MAX_TABLE_BYTES: i64 = MAX_DB_BYTES / 2;

/// Global store counter for report cache eviction scheduling, shared across all threads.
static REPORT_STORE_COUNT: AtomicU64 = AtomicU64::new(0);

/// Global store counter for file analysis cache eviction scheduling.
static FILE_ANALYSIS_STORE_COUNT: AtomicU64 = AtomicU64::new(0);

/// Database path, resolved once at first use. `None` means caching is disabled.
static DB_PATH: OnceLock<Option<PathBuf>> = OnceLock::new();

/// A report analysis can be expensive enough that two sides of a diff reach
/// the persistent cache miss at the same time. Keep those callers in one
/// in-process "single flight": one runs the pipeline, the others wait for
/// its report instead of analyzing identical bytes a second time.
///
/// Weak values are intentional. Completed flights remain discoverable while a
/// waiter is still holding the result, but the map does not retain reports or
/// flight state after the last caller releases it.
#[derive(Clone, Hash, PartialEq, Eq)]
struct FlightKey {
    kind: String,
    sha256: String,
    options_hash: String,
    traits_revision: i64,
}

struct FlightResult {
    done: bool,
    report: Option<Arc<AnalysisReport>>,
}

struct FlightState {
    result: Mutex<FlightResult>,
    wake: Condvar,
    /// Diagnostics for a wait that overruns: who owns this flight.
    owner_thread: Option<usize>,
    owner_label: Mutex<String>,
}

static IN_FLIGHT: OnceLock<Mutex<HashMap<FlightKey, Weak<FlightState>>>> = OnceLock::new();

/// The role a caller holds while analyzing one content hash.
pub(crate) struct ReportFlight {
    key: FlightKey,
    state: Arc<FlightState>,
    owner: bool,
    completed: bool,
}

impl ReportFlight {
    pub(crate) fn is_owner(&self) -> bool {
        self.owner
    }

    /// Wait for the owner and clone its report. Returns `None` when this
    /// caller is the owner, when the owner failed, or when waiting would block
    /// a Rayon worker. In the latter case the caller must analyze independently
    /// so nested work in the same pool can always make progress.
    pub(crate) fn wait(&self) -> Option<AnalysisReport> {
        if self.owner {
            return None;
        }

        // A follower may be running inside the same Rayon pool as its owner,
        // and archive/member/trait analysis all create nested Rayon work.
        // Neither parking nor `rayon::yield_now` is safe here: parking can
        // exhaust the pool, while yielding can recursively execute more
        // followers of this same flight and never unwind to the owner. Do not
        // wait on a Rayon worker. Callers fall back to independent analysis;
        // archive diffs avoid that work in the common case by collecting the
        // old archive first and serving unchanged new members from SHA cache.
        if rayon::current_thread_index().is_some() {
            let result = self
                .state
                .result
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            return result
                .done
                .then(|| result.report.as_deref().cloned())
                .flatten();
        }

        let mut result = self
            .state
            .result
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        while !result.done {
            result = self
                .state
                .wake
                .wait(result)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
        }
        result.report.as_deref().cloned()
    }

    /// [`Self::wait`] for a rayon worker: while the owner works, run this
    /// worker's *own* pending jobs (its archive's other members) instead of
    /// parking or re-analyzing.
    ///
    /// A worker that re-analyzes the bytes itself (the previous behaviour)
    /// doubles the work — measured on an npm corpus where seven archives
    /// carrying one identical 10 MB bundle all began in the same scheduling
    /// wave and each paid the full ~33 CPU-seconds. Only the local deque is
    /// drained (`rayon::yield_local`), never stolen work: a waiter that
    /// steals a foreign job can nest into another wait, or hold a half of
    /// the very join the owner is blocked in — both observed as multi-minute
    /// stalls. Owners themselves never wait (see `owns_any_flight`), and a
    /// waiter holds nothing another thread's join depends on, so the owner
    /// always makes progress and the wait resolves.
    ///
    /// Returns `None` when `deadline` passes first: the caller then analyzes
    /// on its own, so any wait cycle this design has not foreseen degrades
    /// into duplicated work rather than a wedged scan.
    pub(crate) fn wait_yielding(
        &self,
        deadline: std::time::Duration,
    ) -> Option<Option<AnalysisReport>> {
        if self.owner {
            return Some(self.wait());
        }
        let started = std::time::Instant::now();
        loop {
            {
                let result = self
                    .state
                    .result
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                if result.done {
                    return Some(result.report.as_deref().cloned());
                }
            }
            if started.elapsed() > deadline {
                tracing::warn!(
                    waited_s = started.elapsed().as_secs(),
                    sha256 = %self.key.sha256,
                    owner_thread = ?self.state.owner_thread,
                    owner = %self.owner_label(),
                    "single-flight wait exceeded its deadline; analyzing independently"
                );
                return None;
            }
            if started.elapsed().as_secs() >= 30 && started.elapsed().as_millis() % 30_000 < 3 {
                tracing::info!(
                    waited_s = started.elapsed().as_secs(),
                    sha256 = %self.key.sha256,
                    owner_thread = ?self.state.owner_thread,
                    owner = %self.owner_label(),
                    "single-flight wait still pending"
                );
            }
            match rayon::yield_local() {
                Some(rayon::Yield::Executed) => {}
                _ => {
                    let result = self
                        .state
                        .result
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    if !result.done {
                        let _ = self
                            .state
                            .wake
                            .wait_timeout(result, std::time::Duration::from_millis(2))
                            .unwrap_or_else(std::sync::PoisonError::into_inner);
                    }
                }
            }
        }
    }

    /// Name the analysis this flight stands for (the owner's member path),
    /// for wait diagnostics.
    pub(crate) fn set_label(&self, label: &str) {
        if self.owner
            && let Ok(mut l) = self.state.owner_label.lock()
        {
            *l = label.to_string();
        }
    }

    fn owner_label(&self) -> String {
        self.state
            .owner_label
            .lock()
            .map(|l| l.clone())
            .unwrap_or_default()
    }

    /// Publish the completed report to waiters and release the flight. The
    /// report is copied once into an Arc; waiters then clone the cheap Arc
    /// payload into their path-restamped result.
    pub(crate) fn complete(mut self, report: Option<&AnalysisReport>) {
        if !self.owner || self.completed {
            return;
        }
        {
            let mut result = self
                .state
                .result
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            result.report = report.map(|r| Arc::new(r.clone()));
            result.done = true;
            drop(result);
            self.state.wake.notify_all();
        }
        remove_flight(&self.key, &self.state);
        self.completed = true;
        release_owned(&self.key);
    }
}

fn release_owned(key: &FlightKey) {
    if key.kind == "member" {
        OWNED_FLIGHTS.with(|c| c.set(c.get().saturating_sub(1)));
    }
}

impl Drop for ReportFlight {
    fn drop(&mut self) {
        if !self.owner || self.completed {
            return;
        }
        let mut result = self
            .state
            .result
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        result.done = true;
        self.state.wake.notify_all();
        drop(result);
        remove_flight(&self.key, &self.state);
        release_owned(&self.key);
    }
}

fn remove_flight(key: &FlightKey, state: &Arc<FlightState>) {
    let flights = IN_FLIGHT.get_or_init(|| Mutex::new(HashMap::new()));
    let mut flights = flights
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if flights
        .get(key)
        .and_then(Weak::upgrade)
        .is_some_and(|current| Arc::ptr_eq(&current, state))
    {
        flights.remove(key);
    }
}

/// Acquire the in-process single-flight slot for a content hash.
pub(crate) fn acquire_report_flight(
    sha256: &str,
    file_type: &str,
    options: &AnalysisOptions,
) -> ReportFlight {
    acquire_flight("report", sha256, file_type, options)
}

/// Acquire a single-flight slot for an archive member. Identical bytes share
/// analysis only when they have the same detected type: a path-derived type is
/// part of the analyzer input, so sharing across types can change both trait
/// evaluation and whether an archive member is analyzed at all.
pub(crate) fn acquire_member_flight(
    sha256: &str,
    file_type: &str,
    options: &AnalysisOptions,
) -> ReportFlight {
    acquire_flight("member", sha256, file_type, options)
}

thread_local! {
    /// Flights this thread currently owns (nested: an archive member whose
    /// analysis is in progress on this stack). See [`ReportFlight::owns_any`].
    static OWNED_FLIGHTS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// Whether the calling thread is inside an analysis it owns a flight for.
///
/// Such a thread must never block on another flight: rayon lets an owner
/// stuck in a `join` steal arbitrary pending jobs, including a duplicate
/// of the very member it owns, and a wait there — or a longer cycle through
/// two owners each stealing the other's duplicate — can never complete
/// because completion needs the owner's stack to unwind. Threads that own
/// nothing may wait: the owner they wait on never blocks, so it finishes.
pub(crate) fn owns_any_flight() -> bool {
    OWNED_FLIGHTS.with(|c| c.get() > 0)
}

fn acquire_flight(
    kind: &str,
    sha256: &str,
    file_type: &str,
    options: &AnalysisOptions,
) -> ReportFlight {
    let key = FlightKey {
        kind: kind.to_string(),
        sha256: sha256.to_string(),
        options_hash: typed_options_hash(options, file_type),
        traits_revision: traits_revision_key().unwrap_or_default(),
    };
    let flights = IN_FLIGHT.get_or_init(|| Mutex::new(HashMap::new()));
    let mut flights = flights
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Some(state) = flights.get(&key).and_then(Weak::upgrade) {
        return ReportFlight {
            key,
            state,
            owner: false,
            completed: false,
        };
    }
    let state = Arc::new(FlightState {
        result: Mutex::new(FlightResult {
            done: false,
            report: None,
        }),
        wake: Condvar::new(),
        owner_thread: rayon::current_thread_index(),
        owner_label: Mutex::new(String::new()),
    });
    flights.insert(key.clone(), Arc::downgrade(&state));
    drop(flights);
    // Only member flights count: every top-level path owns its report
    // flight for the whole analysis, which would otherwise mark all of its
    // member waits as "owning" and disable waiting entirely.
    if key.kind == "member" {
        OWNED_FLIGHTS.with(|c| c.set(c.get() + 1));
    }
    ReportFlight {
        key,
        state,
        owner: true,
        completed: false,
    }
}

// Per-thread SQLite connection. Initialized lazily on first use.
thread_local! {
    static CONN: RefCell<Option<Connection>> = const { RefCell::new(None) };
}

/// Resolve the database path, or `None` if caching is disabled or unavailable.
fn db_path() -> Option<&'static Path> {
    DB_PATH
        .get_or_init(|| {
            if crate::cache::skip_cache() {
                tracing::info!("Analysis cache disabled (CLEAVE_SKIP_CACHE or override)");
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
                    if let Err(e) = std::fs::remove_file(path) {
                        tracing::debug!("Failed to remove corrupt cache db: {}", e);
                    }
                    if let Err(e) = std::fs::remove_file(path.with_extension("db-wal")) {
                        tracing::debug!("Failed to remove corrupt cache WAL: {}", e);
                    }
                    if let Err(e) = std::fs::remove_file(path.with_extension("db-shm")) {
                        tracing::debug!("Failed to remove corrupt cache SHM: {}", e);
                    }
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

/// Guards so at most one background eviction per table runs at a time; a
/// store that samples the eviction point while one is in flight skips it.
static REPORT_EVICTING: AtomicBool = AtomicBool::new(false);
static FILE_ANALYSIS_EVICTING: AtomicBool = AtomicBool::new(false);

/// Run a table eviction on a background thread with its own connection, so
/// the `SELECT COUNT(*)` gate and `DELETE` never block the storing thread.
/// No-op if an eviction for this table is already running, caching is
/// disabled, or the thread/connection cannot be created.
fn spawn_eviction(guard: &'static AtomicBool, evict: fn(&Connection)) {
    if guard
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        return;
    }
    let Some(path) = db_path().map(Path::to_path_buf) else {
        guard.store(false, Ordering::Release);
        return;
    };
    let spawned = std::thread::Builder::new()
        .name("cleave-cache-evict".into())
        .spawn(move || {
            if let Ok(conn) = open_connection(&path) {
                evict(&conn);
            }
            guard.store(false, Ordering::Release);
        });
    if spawned.is_err() {
        guard.store(false, Ordering::Release);
    }
}

/// Delete entries in `table` not accessed within [`MAX_IDLE_SECS`] (the 30-day
/// TTL). Best-effort; `table` is a trusted literal from this module, never user
/// input, so the interpolation is safe.
fn evict_idle(conn: &Connection, table: &str) {
    let cutoff = unix_timestamp() - MAX_IDLE_SECS;
    if let Ok(n) = conn.execute(
        &format!("DELETE FROM {table} WHERE last_accessed < ?1"),
        rusqlite::params![cutoff],
    ) && n > 0
    {
        tracing::info!(deleted = n, table, "Evicted cache entries past 30d TTL");
    }
}

/// Keep `table`'s live data within its byte share ([`MAX_TABLE_BYTES`]) by
/// deleting the least-recently-used rows (by `last_accessed`). The row count to
/// delete is estimated from the mean entry size — approximate, but eviction is
/// sampled repeatedly and converges. `blob` is the size-bearing column;
/// `table`/`blob` are trusted module literals, never user input. Best-effort.
fn enforce_table_bytes(conn: &Connection, table: &str, blob: &str, max_bytes: i64) {
    let used: i64 = conn
        .query_row(
            &format!("SELECT COALESCE(SUM(LENGTH({blob})), 0) FROM {table}"),
            [],
            |r| r.get(0),
        )
        .unwrap_or(0);
    let target = max_bytes / 10 * 9;
    if used <= target {
        return;
    }
    let count: i64 = conn
        .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |r| r.get(0))
        .unwrap_or(0);
    let avg = used.checked_div(count).unwrap_or(0).max(1);
    let to_delete = (used - target) / avg;
    if to_delete <= 0 {
        return;
    }
    if let Ok(n) = conn.execute(
        &format!(
            "DELETE FROM {table} WHERE rowid IN
             (SELECT rowid FROM {table} ORDER BY last_accessed ASC LIMIT ?1)"
        ),
        rusqlite::params![to_delete],
    ) && n > 0
    {
        tracing::info!(
            deleted = n,
            table,
            "Evicted cache entries over the byte cap"
        );
    }
}

/// Evict oldest entries from the toplevel report cache when over
/// `MAX_REPORT_ENTRIES`, down to 90% of the cap so the cache doesn't
/// re-trigger eviction immediately. Runs on a background thread.
fn evict_report_cache(conn: &Connection) {
    evict_idle(conn, "toplevel_report_cache");

    let total: i64 = conn
        .query_row("SELECT COUNT(*) FROM toplevel_report_cache", [], |row| {
            row.get(0)
        })
        .unwrap_or(0);

    if total > MAX_REPORT_ENTRIES {
        let target = MAX_REPORT_ENTRIES * EVICTION_TARGET_NUMERATOR / EVICTION_TARGET_DENOMINATOR;
        let to_delete = total - target;
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

    enforce_table_bytes(conn, "toplevel_report_cache", "report", MAX_TABLE_BYTES);
}

/// Compute a short deterministic hash of the result-affecting analysis options.
fn options_hash(options: &AnalysisOptions) -> String {
    use sha2::{Digest, Sha256};

    // Sort so the key is independent of the order platforms were supplied on the
    // command line: `--platforms linux,macos` and `macos,linux` share cache entries.
    let mut platform_names: Vec<String> =
        options.platforms.iter().map(|p| format!("{p:?}")).collect();
    platform_names.sort_unstable();
    let platforms_str = platform_names.join(",");
    // Cache version bumped v=5 → v=6 for the filefacts v6 schema cut
    // (Symbol enum collapse, Text/Literals split). Cached reports from
    // older binaries deserialize via `serde_json::Value` flexibility,
    // but the underlying field semantics differ — force re-analysis.
    //
    // `rizin=` folds in filefacts' rizin fingerprint (tool presence /
    // version / native-arch slicing). This lookup short-circuits *before*
    // filefacts runs, so without it a report built when rizin was absent
    // (or on an older rizin) would be served to a run that now has it,
    // hiding the recovered symbols. filefacts' own cache uses the same
    // fingerprint; this keeps the report layer in step.
    // v=6 → v=7: the raw report now serializes the transient fields the cache
    // round-trip needs — context-line `notes`, finding `evidence` (compact
    // `spans`), and `composite_sources` (compact `from`). Older entries lack
    // them and would render anchorless, so force a re-analysis.
    // v=7 → v=8: `ContextLine` is now uniformly byte-addressed — `loc` is always a
    // byte offset (never a line number), `addr` is gone, and textual chunks carry
    // derived `line`/`col`. Older entries encode `loc` as a line number, which the
    // new renderer would misread as an offset, so force a re-analysis.
    // `cm=` separates compact-member-retention entries: the two modes fold
    // members with different retained fields (`kv`, `filefacts.values`), so
    // an entry written in one mode would change the other mode's output.
    let key = format!(
        "v=8,cm={},3p={},yara={},r2={},upx={},plat={},hp={},sp={},ps={},fv={},rizin={}",
        crate::shared_resources::compact_member_retention(),
        options.enable_third_party_yara,
        !options.disable_yara,
        !options.disable_radare2,
        !options.disable_upx,
        platforms_str,
        options.min_hostile_precision,
        options.min_suspicious_precision,
        options.enable_precision_scoring,
        options.enable_full_validation,
        filefacts::rizin::cache_fingerprint(),
    );
    let hash = Sha256::digest(key.as_bytes());
    // First 16 hex chars is plenty for a small option space
    hex::encode(hash)[..16].to_string()
}

/// Add the detected file type to the analysis key. Detection may depend on a
/// member's logical path when content is ambiguous, so SHA equality alone does
/// not guarantee that two paths have the same analysis semantics.
fn typed_options_hash(options: &AnalysisOptions, file_type: &str) -> String {
    use sha2::{Digest, Sha256};

    let key = format!("{},type={file_type}", options_hash(options));
    let hash = Sha256::digest(key.as_bytes());
    hex::encode(hash)[..16].to_string()
}

/// Get the active analysis-cache revision fingerprint, or `None` if unavailable.
///
/// Mixes the trait-files fingerprint with the cleave binary's package version
/// and mtime so that recompiling cleave invalidates the analysis cache even
/// when the trait YAMLs are unchanged. Analyzer logic, file type detection,
/// and capability evaluation all live in the binary — when they change, the
/// cached `AnalysisReport` for the same SHA can be stale.
///
/// (`cache_revision()` alone — used by the YARA and capability-mapper caches —
/// is deterministic from trait inputs and should not depend on the binary.)
fn traits_revision_key() -> Option<i64> {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let traits_fingerprint = cache_revision()
        .ok()
        .map(super::cache::RuleFilesRevision::cache_i64)?;

    let mut hasher = DefaultHasher::new();
    traits_fingerprint.hash(&mut hasher);
    env!("CARGO_PKG_VERSION").hash(&mut hasher);
    if let Ok(mtime) = super::cache::binary_mtime()
        && let Ok(d) = mtime.duration_since(SystemTime::UNIX_EPOCH)
    {
        d.as_nanos().hash(&mut hasher);
    }
    Some(i64::from_ne_bytes(hasher.finish().to_ne_bytes()))
}

/// Current time as Unix seconds.
fn unix_timestamp() -> i64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// In-process memo in front of the SQLite caches.
///
/// Identical bytes recur constantly within one run — a corpus of npm packages
/// carrying the same worm payload, a vsix shipping per-language copies of every
/// DLL — and each copy re-ran the full analysis whenever the persistent cache
/// was disabled (`CLEAVE_SKIP_CACHE=1`, every benchmark and the worker) or
/// simply not yet written by a concurrent sibling on another thread. Measured
/// on a 510-package npm corpus: seven byte-identical 10 MB `bun_environment.js`
/// members cost ~33 CPU-seconds each, a quarter of the whole scan.
///
/// The memo mirrors the persistent cache exactly — same keys (sha256, typed
/// options hash, traits revision), same serialized `FileAnalysis`/report
/// values, same path guards applied by the callers — so a memo hit is
/// indistinguishable from a warm-cache hit. It lives and dies with the process,
/// so it never reuses a previous run's results. Byte-budgeted LRU
/// (`CLEAVE_ANALYSIS_MEMO_MB`, default 256; `0` disables).
mod memo {
    use std::sync::{Arc, Mutex, OnceLock};

    #[derive(Clone, Copy, PartialEq, Eq, Hash)]
    pub(super) enum Kind {
        Report,
        FileAnalysis,
    }

    struct Memo {
        entries: lru::LruCache<(Kind, String), Arc<[u8]>>,
        bytes: usize,
        budget: usize,
        hits: u64,
        misses: u64,
    }

    static MEMO: OnceLock<Option<Mutex<Memo>>> = OnceLock::new();

    fn memo() -> Option<&'static Mutex<Memo>> {
        MEMO.get_or_init(|| {
            let mb = std::env::var("CLEAVE_ANALYSIS_MEMO_MB")
                .ok()
                .and_then(|v| v.parse::<usize>().ok())
                .unwrap_or(256);
            (mb > 0).then(|| {
                Mutex::new(Memo {
                    entries: lru::LruCache::unbounded(),
                    bytes: 0,
                    budget: mb * 1024 * 1024,
                    hits: 0,
                    misses: 0,
                })
            })
        })
        .as_ref()
    }

    pub(super) fn get(kind: Kind, key: &str) -> Option<Arc<[u8]>> {
        let m = memo()?;
        let mut m = m.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let hit = m.entries.get(&(kind, key.to_string())).cloned();
        if hit.is_some() {
            m.hits += 1;
        } else {
            m.misses += 1;
        }
        hit
    }

    // The whole body is one read-modify-evict sequence against the memo: the
    // budget check, the insert and the LRU drain have to see the same state,
    // so the guard is held to the end by design. Clippy's suggestion here is
    // to drop it inside the eviction loop, which would not compile.
    #[allow(clippy::significant_drop_tightening)]
    pub(super) fn put(kind: Kind, key: String, value: Vec<u8>) {
        let Some(m) = memo() else { return };
        let len = value.len();
        let mut m = m.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        if len > m.budget / 4 {
            return;
        }
        if let Some(old) = m.entries.push((kind, key), Arc::from(value)) {
            m.bytes = m.bytes.saturating_sub(old.1.len());
        }
        m.bytes += len;
        while m.bytes > m.budget {
            let Some((_, evicted)) = m.entries.pop_lru() else {
                break;
            };
            m.bytes = m.bytes.saturating_sub(evicted.len());
        }
    }

    /// `(entries, bytes, hits, misses)` for end-of-scan logging.
    pub(crate) fn stats() -> (usize, usize, u64, u64) {
        memo().map_or((0, 0, 0, 0), |m| {
            let m = m.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            (m.entries.len(), m.bytes, m.hits, m.misses)
        })
    }
}

/// Log the in-process analysis memo's occupancy and hit rate at `info`.
pub(crate) fn log_analysis_memo_stats() {
    let (entries, bytes, hits, misses) = memo::stats();
    if hits + misses == 0 {
        return;
    }
    tracing::info!(
        entries,
        mb = bytes / (1024 * 1024),
        hits,
        misses,
        "analysis memo stats"
    );
}

fn memo_key(sha256: &str, opts_hash: &str) -> String {
    format!(
        "{sha256}:{opts_hash}:{}",
        traits_revision_key().unwrap_or_default()
    )
}

/// Look up a cached toplevel analysis report for the given file hash and options.
///
/// Returns `Some(report)` on cache hit, `None` on miss or if caching is unavailable.
pub(crate) fn report_cache_lookup(
    sha256: &str,
    file_type: &str,
    options: &AnalysisOptions,
) -> Option<AnalysisReport> {
    let opts_hash = typed_options_hash(options, file_type);
    let key = memo_key(sha256, &opts_hash);
    if let Some(bytes) = memo::get(memo::Kind::Report, &key)
        && let Ok(report) = serde_json::from_slice::<AnalysisReport>(&bytes)
    {
        return Some(report);
    }
    let traits_ts = traits_revision_key()?;
    let hit =
        with_conn(|conn| report_cache_lookup_conn(conn, sha256, &opts_hash, traits_ts)).flatten();
    if let Some(report) = &hit
        && let Ok(bytes) = serde_json::to_vec(report)
    {
        memo::put(memo::Kind::Report, key, bytes);
    }
    hit
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
pub(crate) fn report_cache_store(
    sha256: &str,
    file_type: &str,
    options: &AnalysisOptions,
    report: &AnalysisReport,
) {
    let opts_hash = typed_options_hash(options, file_type);
    if let Ok(bytes) = serde_json::to_vec(report) {
        memo::put(memo::Kind::Report, memo_key(sha256, &opts_hash), bytes);
    }
    let Some(traits_ts) = traits_revision_key() else {
        return;
    };
    with_conn(|conn| {
        report_cache_store_conn(conn, sha256, &opts_hash, traits_ts, report);
        // Sample across all threads and evict in the background.
        let count = REPORT_STORE_COUNT.fetch_add(1, Ordering::Relaxed);
        if count.is_multiple_of(EVICTION_CHECK_INTERVAL) {
            spawn_eviction(&REPORT_EVICTING, evict_report_cache);
        }
    });
}

/// Look up a cached `FileAnalysis` for the given file hash and options.
///
/// Returns `Some(fa)` on cache hit, `None` on miss or if caching is unavailable.
pub(crate) fn file_analysis_cache_lookup(
    sha256: &str,
    file_type: &str,
    options: &AnalysisOptions,
) -> Option<FileAnalysis> {
    let opts_hash = typed_options_hash(options, file_type);
    let key = memo_key(sha256, &opts_hash);
    if let Some(bytes) = memo::get(memo::Kind::FileAnalysis, &key)
        && let Ok(fa) = serde_json::from_slice::<FileAnalysis>(&bytes)
    {
        return Some(fa);
    }
    let traits_ts = traits_revision_key()?;
    let hit =
        with_conn(|conn| file_analysis_cache_lookup_conn(conn, sha256, &opts_hash, traits_ts))
            .flatten();
    if let Some(fa) = &hit
        && let Ok(bytes) = serde_json::to_vec(fa)
    {
        memo::put(memo::Kind::FileAnalysis, key, bytes);
    }
    hit
}

/// Store a `FileAnalysis` in the file analysis cache.
///
/// Silently does nothing if caching is unavailable or any error occurs.
pub(crate) fn file_analysis_cache_store(
    sha256: &str,
    file_type: &str,
    options: &AnalysisOptions,
    fa: &FileAnalysis,
) {
    let opts_hash = typed_options_hash(options, file_type);
    if let Ok(bytes) = serde_json::to_vec(fa) {
        memo::put(
            memo::Kind::FileAnalysis,
            memo_key(sha256, &opts_hash),
            bytes,
        );
    }
    let Some(traits_ts) = traits_revision_key() else {
        return;
    };
    with_conn(|conn| {
        file_analysis_cache_store_conn(conn, sha256, &opts_hash, traits_ts, fa);
        let count = FILE_ANALYSIS_STORE_COUNT.fetch_add(1, Ordering::Relaxed);
        if count.is_multiple_of(EVICTION_CHECK_INTERVAL) {
            spawn_eviction(&FILE_ANALYSIS_EVICTING, evict_file_analysis_cache);
        }
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

/// Evict oldest entries from the file analysis cache when over
/// `MAX_FILE_ANALYSIS_ENTRIES`, down to 90% of the cap. Runs on a
/// background thread.
fn evict_file_analysis_cache(conn: &Connection) {
    evict_idle(conn, "file_analysis_cache");

    let total: i64 = conn
        .query_row("SELECT COUNT(*) FROM file_analysis_cache", [], |row| {
            row.get(0)
        })
        .unwrap_or(0);

    if total > MAX_FILE_ANALYSIS_ENTRIES {
        let target =
            MAX_FILE_ANALYSIS_ENTRIES * EVICTION_TARGET_NUMERATOR / EVICTION_TARGET_DENOMINATOR;
        let to_delete = total - target;
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

    enforce_table_bytes(
        conn,
        "file_analysis_cache",
        "file_analysis",
        MAX_TABLE_BYTES,
    );
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::types::FileAnalysis;
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
    fn report_flight_shares_one_completed_report() {
        let sha = "single-flight-regression-unique";
        let options = AnalysisOptions::default();
        let owner = acquire_report_flight(sha, "python", &options);
        assert!(owner.is_owner());

        let follower = acquire_report_flight(sha, "python", &options);
        assert!(!follower.is_owner());

        let report = test_report(sha);
        owner.complete(Some(&report));

        let shared = follower.wait().expect("follower should receive report");
        assert_eq!(shared.target.sha256, sha);
        assert_eq!(shared.target.file_type, "elf");
    }

    #[test]
    fn report_flights_deduplicate_members_without_merging_hashes() {
        let options = AnalysisOptions::default();
        let first = acquire_member_flight("member-sha-a", "python", &options);
        let second = acquire_member_flight("member-sha-b", "python", &options);
        let archive_peer = acquire_member_flight("member-sha-a", "python", &options);

        assert!(first.is_owner(), "first member hash owns its analysis");
        assert!(
            second.is_owner(),
            "a different member hash analyzes independently"
        );
        assert!(
            !archive_peer.is_owner(),
            "same member hash joins the flight"
        );

        let report_a = test_report("member-sha-a");
        let report_b = test_report("member-sha-b");
        first.complete(Some(&report_a));
        second.complete(Some(&report_b));

        assert_eq!(archive_peer.wait().unwrap().target.sha256, "member-sha-a");
    }

    #[test]
    fn member_flights_do_not_merge_different_detected_types() {
        let options = AnalysisOptions::default();
        let html = acquire_member_flight("same-member-sha", "html", &options);
        let unknown = acquire_member_flight("same-member-sha", "unknown", &options);

        assert!(html.is_owner());
        assert!(
            unknown.is_owner(),
            "path-dependent file types require independent analysis"
        );
    }

    #[test]
    fn report_flight_shares_member_analysis_between_concurrent_archives() {
        use std::sync::{Arc, Barrier, mpsc};
        use std::thread;

        let options = AnalysisOptions::default();
        let owner = acquire_member_flight("shared-member-sha", "python", &options);
        assert!(owner.is_owner());

        let barrier = Arc::new(Barrier::new(2));
        let (tx, rx) = mpsc::channel();
        thread::scope(|scope| {
            let barrier_for_archive = Arc::clone(&barrier);
            let options_for_archive = options.clone();
            scope.spawn(move || {
                let archive_peer =
                    acquire_member_flight("shared-member-sha", "python", &options_for_archive);
                assert!(!archive_peer.is_owner());
                barrier_for_archive.wait();
                tx.send(archive_peer.wait().map(|report| report.target.sha256))
                    .unwrap();
            });

            barrier.wait();
            owner.complete(Some(&test_report("shared-member-sha")));
            assert_eq!(rx.recv().unwrap().as_deref(), Some("shared-member-sha"));
        });
    }

    #[test]
    fn report_flight_wait_never_blocks_nested_rayon_work() {
        use std::sync::{Arc, Barrier};

        // Reproduce the diff/archive cycle that hung node-ipc:
        //
        // * one pool worker owns analysis of a shared member and enters a
        //   nested Rayon join;
        // * the other worker reaches the same SHA and waits as a follower;
        // * the owner's second nested job cannot run if the follower parks.
        //
        // A blocking Condvar wait deadlocks this two-thread pool. The follower
        // instead receives None immediately and leaves the worker available,
        // allowing the owner's nested join to finish.
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(2)
            .build()
            .expect("build two-thread regression pool");
        let ready = Arc::new(Barrier::new(2));
        let nested = Arc::new(Barrier::new(2));
        let options = AnalysisOptions::default();
        let sha = "member-flight-nested-rayon-regression";

        let avoided_wait = pool.install(|| {
            let ((), avoided_wait) = rayon::join(
                || {
                    let owner = acquire_member_flight(sha, "python", &options);
                    assert!(owner.is_owner());
                    ready.wait();

                    let nested_left = Arc::clone(&nested);
                    let nested_right = Arc::clone(&nested);
                    rayon::join(|| nested_left.wait(), || nested_right.wait());

                    owner.complete(Some(&test_report(sha)));
                },
                || {
                    ready.wait();
                    let follower = acquire_member_flight(sha, "python", &options);
                    assert!(!follower.is_owner());
                    follower.wait().map(|report| report.target.sha256)
                },
            );
            avoided_wait
        });

        assert_eq!(avoided_wait, None);
    }

    #[test]
    fn evict_idle_drops_only_entries_past_ttl() {
        let conn = test_conn();
        let now = unix_timestamp();
        // One entry last accessed just past the 30-day TTL, one accessed now.
        conn.execute(
            "INSERT INTO toplevel_report_cache
             (sha256, options_hash, traits_timestamp, report, created_at, last_accessed)
             VALUES ('stale', 'h', 0, x'00', 0, ?1), ('fresh', 'h', 0, x'00', 0, ?2)",
            rusqlite::params![now - MAX_IDLE_SECS - 1, now],
        )
        .expect("insert");

        evict_idle(&conn, "toplevel_report_cache");

        let remaining: Vec<String> = conn
            .prepare("SELECT sha256 FROM toplevel_report_cache")
            .unwrap()
            .query_map([], |r| r.get(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(
            remaining,
            vec!["fresh".to_string()],
            "the entry idle past 30d is evicted; the fresh one is kept"
        );
    }

    #[test]
    fn enforce_table_bytes_evicts_least_recently_used_over_cap() {
        let conn = test_conn();
        let now = unix_timestamp();
        // Five 400-byte reports (2000 bytes total), last_accessed oldest→newest.
        for (i, age_days) in [5i64, 4, 3, 2, 1].into_iter().enumerate() {
            conn.execute(
                "INSERT INTO toplevel_report_cache
                 (sha256, options_hash, traits_timestamp, report, created_at, last_accessed)
                 VALUES (?1, 'h', 0, ?2, 0, ?3)",
                rusqlite::params![
                    format!("s{i}"),
                    vec![0u8; 400],
                    now - age_days * 24 * 60 * 60
                ],
            )
            .expect("insert");
        }

        // Cap 1000 → target 900; the mean-size estimate sheds the oldest rows.
        enforce_table_bytes(&conn, "toplevel_report_cache", "report", 1000);

        let remaining: Vec<String> = conn
            .prepare("SELECT sha256 FROM toplevel_report_cache ORDER BY last_accessed")
            .unwrap()
            .query_map([], |r| r.get(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(
            remaining,
            vec!["s2".to_string(), "s3".to_string(), "s4".to_string()],
            "the least-recently-used entries are evicted first, newest kept"
        );
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
        assert_eq!(cached.version, "3.0");
    }

    /// A cache hit must reproduce the *outputs* a fresh analysis would — not just
    /// the report's top-level fields. Several things the outputs are built from
    /// are transient and rebuilt only during analysis (which a cache hit skips):
    /// context-line `notes` (render anchoring), finding `evidence` (compact
    /// `spans`), and `composite_sources` (compact `from`). If any such field is
    /// dropped by serialization, a cached report renders structurally anchorless.
    ///
    /// This guards the whole class generically: a fixture exercising every such
    /// field is round-tripped through the *real* cache store/load, and both the
    /// tiny render and the compact JSON must come out byte-identical. A new
    /// output-feeding field marked `#[serde(skip)]` will fail this test.
    #[test]
    fn cache_roundtrip_preserves_rendered_outputs() {
        use crate::types::file_analysis::CompositeSource;
        use crate::types::{ContextLine, Criticality, Evidence, Finding, Note};

        let sha = "feedface00";
        let mut report = test_report(sha);

        let mut fa = test_file_analysis(sha, "python");
        fa.path = "pkg/x.py".to_string();

        // An atomic finding with evidence offsets → compact `spans`.
        let mut atom = Finding::capability("micro/exec".to_string(), "exec call".to_string(), 0.9)
            .with_criticality(Criticality::Suspicious);
        atom.evidence = vec![Evidence {
            method: "raw".to_string(),
            value: "exec(payload)".to_string(),
            offsets: vec![17],
            match_len: Some(13),
            ..Default::default()
        }];

        // A composite → its provenance lives in `composite_sources` (compact `from`).
        let composite = Finding::capability(
            "obj/dropper".to_string(),
            "decode→exec dropper".to_string(),
            0.95,
        )
        .with_criticality(Criticality::Hostile);

        fa.findings = vec![atom, composite];
        // Context lines with a note → render anchoring.
        fa.context = vec![
            ContextLine {
                loc: 0,
                line: Some(1),
                col: Some(1),
                data: b"data = b64decode(BLOB)".to_vec(),
                notes: vec![],
            },
            ContextLine {
                loc: 17,
                line: Some(2),
                col: Some(1),
                data: b"exec(payload)".to_vec(),
                notes: vec![Note {
                    crit: Criticality::Suspicious,
                    id: "micro/exec".to_string().into(),
                    desc: "exec call".to_string().into(),
                    off: 17,
                    len: 13,
                    conf: 0.9,
                }],
            },
        ];
        fa.composite_sources.insert(
            "obj/dropper".to_string(),
            vec![CompositeSource {
                file: 0,
                line: Some(2),
                offset: Some(17),
            }],
        );
        report.files = vec![fa];

        let compact = |r: &AnalysisReport| {
            serde_json::to_string(&crate::types::compact::compact_from_files(&r.files))
                .expect("compact serialization")
        };
        let tiny_before = crate::output::format_tiny(&report);
        let compact_before = compact(&report);

        // The fixture must actually exercise the transient fields, else the test
        // is vacuous — a cache that drops them would still pass on empty data.
        assert!(
            compact_before.contains("spans"),
            "fixture must produce compact spans (from finding evidence): {compact_before}"
        );
        assert!(
            compact_before.contains("\"from\""),
            "fixture must produce compact `from` (from composite_sources): {compact_before}"
        );
        assert!(
            tiny_before.contains("# S 2:1 exec call"),
            "fixture must anchor a note in the render: {tiny_before:?}"
        );

        // Round-trip through the real cache store/load (zstd + serde, both layers).
        let conn = test_conn();
        report_cache_store_conn(&conn, sha, "opts", 1700000000, &report);
        let restored =
            report_cache_lookup_conn(&conn, sha, "opts", 1700000000).expect("cache hit expected");

        assert_eq!(
            tiny_before,
            crate::output::format_tiny(&restored),
            "render anchoring (context notes) lost across cache round-trip"
        );
        assert_eq!(
            compact_before,
            compact(&restored),
            "compact spans/from lost across cache round-trip"
        );

        // The per-file cache layer serializes the same FileAnalysis the same way.
        let fconn = file_analysis_test_conn();
        file_analysis_cache_store_conn(&fconn, sha, "opts", 1700000000, &report.files[0]);
        let rfa = file_analysis_cache_lookup_conn(&fconn, sha, "opts", 1700000000)
            .expect("file cache hit expected");
        let mut file_restored = test_report(sha);
        file_restored.files = vec![rfa];
        assert_eq!(
            compact_before,
            compact(&file_restored),
            "file-analysis cache layer dropped a rendered-output field"
        );
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
    fn typed_options_hash_separates_path_dependent_file_types() {
        let opts = AnalysisOptions::default();
        assert_ne!(
            typed_options_hash(&opts, "html"),
            typed_options_hash(&opts, "unknown")
        );
        assert_eq!(
            typed_options_hash(&opts, "php"),
            typed_options_hash(&opts, "php")
        );
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
        use crate::types::Criticality;
        use crate::types::traits_findings::Finding;

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
        use std::sync::{Arc, atomic::AtomicBool};

        let opts_without = AnalysisOptions::default();
        let opts_with = AnalysisOptions {
            cancellation: Some(Arc::new(AtomicBool::new(false))),
            ..AnalysisOptions::default()
        };

        assert_eq!(options_hash(&opts_without), options_hash(&opts_with));
    }
}
