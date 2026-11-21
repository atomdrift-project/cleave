//! Bounded optional persistence. Contended cache writes never park analysis.
use super::{
    Arc, Connection, OnceLock, Ordering, Path, PathBuf, memo, open_connection, table_sql,
    unix_timestamp,
};
use std::sync::atomic::AtomicUsize;
use std::sync::mpsc::{self, SyncSender};

/// Compressed bytes the writer may have queued before further stores are
/// dropped. Checked before an item is compressed, so the backlog overshoots
/// it by at most the items being compressed at that moment.
const MAX_BYTES: usize = 32 * 1024 * 1024;
/// Entries the writer may have queued. Each is already compressed, so the
/// byte bound above is what limits memory; this only keeps a burst of small
/// members from being dropped while one transaction commits.
const MAX_ENTRIES: usize = 4096;
/// The largest analysis kept. The reports that cost the most to recompute are
/// the largest ones: a native binary's runs to tens of megabytes of JSON and a
/// whole archive's to hundreds, and both compress about tenfold.
const MAX_ITEM_BYTES: usize = 512 * 1024 * 1024;
static WRITER: OnceLock<Option<Writer>> = OnceLock::new();

struct Entry {
    kind: memo::Kind,
    sha: String,
    options: String,
    revision: i64,
    /// The analysis as zstd-compressed JSON.
    payload: Vec<u8>,
}
struct Writer {
    tx: SyncSender<Entry>,
    pending_bytes: Arc<AtomicUsize>,
}
impl Writer {
    fn start(path: PathBuf) -> Option<Self> {
        let (tx, rx) = mpsc::sync_channel::<Entry>(MAX_ENTRIES);
        let pending_bytes = Arc::new(AtomicUsize::new(0));
        let pending = Arc::clone(&pending_bytes);
        std::thread::Builder::new()
            .name("cleave-cache-write".into())
            .spawn(move || {
                let mut conn = None;
                while let Ok(first) = rx.recv() {
                    let mut entries = vec![first];
                    entries.extend(rx.try_iter().take(31));
                    let bytes: usize = entries.iter().map(|e| e.payload.len()).sum();
                    if conn.is_none() {
                        conn = open_connection(&path).ok();
                        if let Some(c) = &conn {
                            let _ = c.busy_timeout(std::time::Duration::from_millis(50));
                        }
                    }
                    if let Some(c) = &conn {
                        persist(c, &entries);
                    }
                    pending.fetch_sub(bytes, Ordering::Release);
                }
            })
            .ok()?;
        Some(Self { tx, pending_bytes })
    }

    /// Queue `json` to be stored. It is compressed here, on the thread that
    /// produced it: one writer thread compressing for a dozen analysis
    /// threads fell behind, and what it could not take was dropped, so the
    /// next scan of the same bytes analyzed them again.
    fn enqueue(&self, kind: memo::Kind, sha: &str, options: &str, revision: i64, json: &[u8]) {
        if json.len() > MAX_ITEM_BYTES {
            tracing::debug!(sha256 = %sha, bytes = json.len(), limit = MAX_ITEM_BYTES, "analysis too large to cache");
            return;
        }
        let pending = self.pending_bytes.load(Ordering::Acquire);
        if pending > MAX_BYTES {
            tracing::debug!(sha256 = %sha, bytes = json.len(), pending, limit = MAX_BYTES, "cache writer backlogged; analysis not cached");
            return;
        }
        let Ok(payload) = zstd::encode_all(json, 3) else {
            return;
        };
        let bytes = payload.len();
        self.pending_bytes.fetch_add(bytes, Ordering::AcqRel);
        let entry = Entry {
            kind,
            sha: sha.into(),
            options: options.into(),
            revision,
            payload,
        };
        if self.tx.try_send(entry).is_err() {
            self.pending_bytes.fetch_sub(bytes, Ordering::Release);
            tracing::debug!(sha256 = %sha, bytes, "cache writer queue full; analysis not cached");
        }
    }
}

// Called only at command shutdown, after all analysis has joined. Disk caching
// remains best effort: a busy disk cannot keep a completed scan alive forever.
pub(super) fn flush() {
    if let Some(Some(writer)) = WRITER.get() {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(1);
        while writer.pending_bytes.load(Ordering::Acquire) != 0 {
            if std::time::Instant::now() >= deadline {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
    }
}

fn persist(conn: &Connection, entries: &[Entry]) {
    let Ok(tx) = conn.unchecked_transaction() else {
        return;
    };
    let now = unix_timestamp();
    for entry in entries {
        let [_, _, sql] = table_sql(entry.kind);
        if tx
            .prepare_cached(sql)
            .and_then(|mut stmt| {
                stmt.execute(rusqlite::params![
                    entry.sha,
                    entry.options,
                    entry.revision,
                    entry.payload,
                    now
                ])
            })
            .is_err()
        {
            return; // Roll back this optional batch; the memo still holds results.
        }
    }
    let _ = tx.commit();
}

pub(super) fn store(
    path: &Path,
    kind: memo::Kind,
    sha: &str,
    options: &str,
    revision: i64,
    json: &[u8],
) {
    if let Some(writer) = WRITER.get_or_init(|| Writer::start(path.to_owned())) {
        writer.enqueue(kind, sha, options, revision, json);
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::analysis_cache::{cache_lookup_conn, cache_store_conn};

    #[test]
    fn cache_writer_never_blocks_analysis_and_persists_both_tables() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cache.db");
        let lock = open_connection(&path).unwrap();
        cache_store_conn(&lock, memo::Kind::Report, "old", "opts", 42, b"{}");
        lock.execute("UPDATE toplevel_report_cache SET last_accessed=0", [])
            .unwrap();
        lock.execute_batch("BEGIN IMMEDIATE").unwrap();
        let writer = Writer::start(path.clone()).unwrap();
        let start = std::time::Instant::now();
        for kind in [memo::Kind::Report, memo::Kind::FileAnalysis] {
            writer.enqueue(kind, "sample", "opts", 42, b"{}");
        }
        assert!(start.elapsed() < std::time::Duration::from_millis(100));
        let reader = open_connection(&path).unwrap();
        let read_start = std::time::Instant::now();
        assert_eq!(
            cache_lookup_conn(&reader, memo::Kind::Report, "old", "opts", 42).unwrap(),
            b"{}"
        );
        assert!(read_start.elapsed() < std::time::Duration::from_millis(100));
        lock.execute_batch("COMMIT").unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
        while writer.pending_bytes.load(Ordering::Acquire) != 0 {
            assert!(std::time::Instant::now() < deadline);
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        for kind in [memo::Kind::Report, memo::Kind::FileAnalysis] {
            assert_eq!(
                cache_lookup_conn(&reader, kind, "sample", "opts", 42).unwrap(),
                b"{}"
            );
        }
    }
    #[test]
    fn a_report_larger_than_the_backlog_bound_is_kept() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cache.db");
        let writer = Writer::start(path.clone()).unwrap();
        let json = vec![b' '; MAX_BYTES + 1];
        writer.enqueue(memo::Kind::Report, "whole-archive", "opts", 1, &json);
        // Behind it the backlog is over its bound, so the next store is dropped
        // rather than queued; once it drains, stores are admitted again.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
        while writer.pending_bytes.load(Ordering::Acquire) != 0 {
            assert!(std::time::Instant::now() < deadline, "writer never drained");
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        let reader = open_connection(&path).unwrap();
        let stored =
            cache_lookup_conn(&reader, memo::Kind::Report, "whole-archive", "opts", 1).unwrap();
        assert_eq!(stored.len(), json.len());
    }

    #[test]
    fn oversized_entries_do_not_consume_the_queue_budget() {
        let dir = tempfile::tempdir().unwrap();
        let writer = Writer::start(dir.path().join("cache.db")).unwrap();
        writer.enqueue(
            memo::Kind::Report,
            "large",
            "opts",
            1,
            &vec![0; MAX_ITEM_BYTES + 1],
        );
        assert_eq!(writer.pending_bytes.load(Ordering::Acquire), 0);
    }

    /// A dozen analysis threads finish members faster than one thread could
    /// compress them: what the writer could not take was dropped, and a
    /// second copy of the same archive was analyzed again. A burst several
    /// times the old bounds (128 entries, 32 MiB of JSON) is all kept.
    #[test]
    fn a_burst_of_analyses_is_all_kept() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cache.db");
        let writer = Writer::start(path.clone()).unwrap();
        let json = format!(
            "{{\"strings\":[{}\"end\"]}}",
            "\"import os\",".repeat(10_000)
        );
        let count = 1_000;
        assert!(json.len() * count > 3 * MAX_BYTES);
        for i in 0..count {
            writer.enqueue(
                memo::Kind::FileAnalysis,
                &format!("member-{i}"),
                "opts",
                1,
                json.as_bytes(),
            );
        }
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
        while writer.pending_bytes.load(Ordering::Acquire) != 0 {
            assert!(std::time::Instant::now() < deadline, "writer never drained");
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        let reader = open_connection(&path).unwrap();
        for i in 0..count {
            let stored = cache_lookup_conn(
                &reader,
                memo::Kind::FileAnalysis,
                &format!("member-{i}"),
                "opts",
                1,
            );
            assert_eq!(stored.as_deref(), Some(json.as_bytes()), "member {i}");
        }
    }
}
