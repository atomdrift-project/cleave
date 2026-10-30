//! Bounded optional persistence. Contended cache writes never park analysis.
use super::*;
use std::sync::atomic::AtomicUsize;
use std::sync::mpsc::{self, SyncSender};

const MAX_BYTES: usize = 32 * 1024 * 1024;
const MAX_ITEM_BYTES: usize = 8 * 1024 * 1024;
static WRITER: OnceLock<Option<Writer>> = OnceLock::new();

struct Entry {
    kind: memo::Kind,
    sha: String,
    options: String,
    revision: i64,
    json: Vec<u8>,
}
struct Writer {
    tx: SyncSender<Entry>,
    pending_bytes: Arc<AtomicUsize>,
}
impl Writer {
    fn start(path: PathBuf) -> Option<Self> {
        let (tx, rx) = mpsc::sync_channel::<Entry>(128);
        let pending_bytes = Arc::new(AtomicUsize::new(0));
        let pending = Arc::clone(&pending_bytes);
        std::thread::Builder::new()
            .name("cleave-cache-write".into())
            .spawn(move || {
                let mut conn = None;
                while let Ok(first) = rx.recv() {
                    let mut entries = vec![first];
                    entries.extend(rx.try_iter().take(31));
                    let bytes: usize = entries.iter().map(|e| e.json.len()).sum();
                    // Compress before acquiring SQLite's single writer lock.
                    let compressed: Vec<_> = entries
                        .into_iter()
                        .filter_map(|entry| {
                            let payload = zstd::encode_all(entry.json.as_slice(), 3).ok()?;
                            Some((entry, payload))
                        })
                        .collect();
                    if conn.is_none() {
                        conn = open_connection(&path).ok();
                        if let Some(c) = &conn {
                            let _ = c.busy_timeout(std::time::Duration::from_millis(50));
                        }
                    }
                    if let Some(c) = &conn {
                        persist(c, &compressed);
                    }
                    pending.fetch_sub(bytes, Ordering::Release);
                }
            })
            .ok()?;
        Some(Self { tx, pending_bytes })
    }

    fn enqueue(&self, entry: Entry) {
        let bytes = entry.json.len();
        if bytes > MAX_ITEM_BYTES {
            return;
        }
        let mut pending = self.pending_bytes.load(Ordering::Acquire);
        loop {
            let Some(next) = pending.checked_add(bytes).filter(|&n| n <= MAX_BYTES) else {
                return;
            };
            match self.pending_bytes.compare_exchange_weak(
                pending,
                next,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => break,
                Err(current) => pending = current,
            }
        }
        if self.tx.try_send(entry).is_err() {
            self.pending_bytes.fetch_sub(bytes, Ordering::Release);
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

fn persist(conn: &Connection, entries: &[(Entry, Vec<u8>)]) {
    let Ok(tx) = conn.unchecked_transaction() else {
        return;
    };
    let now = unix_timestamp();
    for (entry, payload) in entries {
        let [_, _, sql] = table_sql(entry.kind);
        if tx
            .prepare_cached(sql)
            .and_then(|mut stmt| {
                stmt.execute(rusqlite::params![
                    entry.sha,
                    entry.options,
                    entry.revision,
                    payload,
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
    json: Vec<u8>,
) {
    if let Some(writer) = WRITER.get_or_init(|| Writer::start(path.to_owned())) {
        writer.enqueue(Entry {
            kind,
            sha: sha.into(),
            options: options.into(),
            revision,
            json,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
            writer.enqueue(Entry {
                kind,
                sha: "sample".into(),
                options: "opts".into(),
                revision: 42,
                json: b"{}".to_vec(),
            });
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
    fn oversized_entries_do_not_consume_the_queue_budget() {
        let dir = tempfile::tempdir().unwrap();
        let writer = Writer::start(dir.path().join("cache.db")).unwrap();
        writer.enqueue(Entry {
            kind: memo::Kind::Report,
            sha: "large".into(),
            options: "opts".into(),
            revision: 1,
            json: vec![0; MAX_ITEM_BYTES + 1],
        });
        assert_eq!(writer.pending_bytes.load(Ordering::Acquire), 0);
    }
}
