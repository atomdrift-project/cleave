//! Content-keyed facts that `cleave validate` derives from patterns, kept
//! across runs.
//!
//! A full validation derives the same per-pattern facts on every run -- how
//! large a regex's NFA grows, what its lazy DFA does on a bundle-shaped
//! haystack, whether a regex matches a phrase -- and between two runs most of
//! the tree has not changed. Each fact is stored under a SHA-256 of what it is
//! (a kind tag) and of everything it is a function of (pattern text, flags,
//! phrase, engine parameters). Nothing trusts an mtime or a size: a fact is
//! found only by the exact content it was computed from, so a one-byte or
//! one-flag edit is a different key and is recomputed.
//!
//! The facts are properties of this build's engines, so the file records the
//! build that wrote it and a different build starts empty. The file carries a
//! SHA-256 of its body and is replaced atomically; a missing, corrupt,
//! truncated or foreign file reads as empty. Entries a run did not use are
//! dropped when it saves, so the file holds the current tree's working set
//! rather than every tree it has seen.

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, RwLock};

use serde::Serialize;
use serde::de::DeserializeOwned;
use sha2::{Digest, Sha256};

/// A fact's identity: the first 16 bytes of a SHA-256 over its kind and inputs.
pub(crate) type FactKey = [u8; 16];

const MAGIC: &[u8; 8] = b"CLVFACT1";
const FILE_NAME: &str = "validate-facts.bin";
/// Largest file read back: far above a full tree's working set, and a bound on
/// what a damaged or foreign file can make a load allocate.
const MAX_FILE_BYTES: u64 = 512 << 20;

/// The key for a fact of `kind` derived from `parts`. Every part is
/// length-prefixed, so no two different inputs share an encoding.
pub(crate) fn key(kind: &str, parts: &[&[u8]]) -> FactKey {
    let mut hasher = Sha256::new();
    for part in std::iter::once(kind.as_bytes()).chain(parts.iter().copied()) {
        hasher.update((part.len() as u64).to_le_bytes());
        hasher.update(part);
    }
    let digest = hasher.finalize();
    let mut key = [0u8; 16];
    key.copy_from_slice(&digest[..16]);
    key
}

struct Stored {
    value: Vec<u8>,
    used: AtomicBool,
}

/// Facts derived by this run land in one of these shards, chosen by key, so
/// the checks that derive them in parallel do not queue on one lock.
const FRESH_SHARDS: usize = 64;

/// The facts of one validation run: those read back from the last run, and
/// those derived by this one.
pub(crate) struct FactsCache {
    path: PathBuf,
    identity: Vec<u8>,
    stored: HashMap<FactKey, Stored>,
    fresh: Vec<Mutex<HashMap<FactKey, Vec<u8>>>>,
    /// The validation ran to its end, so what it did not use is not part of
    /// the tree's working set. A run that stopped at an error keeps everything.
    completed: AtomicBool,
}

impl FactsCache {
    /// The fact stored under `key`, if an earlier run derived it.
    pub(crate) fn get<T: DeserializeOwned>(&self, key: &FactKey) -> Option<T> {
        let stored = self.stored.get(key)?;
        let (value, _) =
            bincode::serde::decode_from_slice(&stored.value, bincode::config::standard()).ok()?;
        stored.used.store(true, Ordering::Relaxed);
        Some(value)
    }

    /// Record a fact this run derived.
    pub(crate) fn put<T: Serialize>(&self, key: FactKey, value: &T) {
        let Ok(bytes) = bincode::serde::encode_to_vec(value, bincode::config::standard()) else {
            return;
        };
        if let Some(Ok(mut fresh)) = self
            .fresh
            .get(usize::from(key[0]) % FRESH_SHARDS)
            .map(Mutex::lock)
        {
            fresh.insert(key, bytes);
        }
    }

    /// The stored fact, or `compute` it and record the result.
    pub(crate) fn get_or_compute<T: Serialize + DeserializeOwned>(
        &self,
        key: FactKey,
        compute: impl FnOnce() -> T,
    ) -> T {
        if let Some(value) = self.get(&key) {
            return value;
        }
        let value = compute();
        self.put(key, &value);
        value
    }

    /// Write the facts back when they changed. After a completed validation
    /// that is its working set -- what it used or derived; after one that
    /// stopped early, everything, since it never reached most of its checks.
    fn save(&self) {
        let fresh: Vec<(FactKey, Vec<u8>)> = self
            .fresh
            .iter()
            .filter_map(|shard| {
                shard
                    .lock()
                    .ok()
                    .map(|mut shard| std::mem::take(&mut *shard))
            })
            .flatten()
            .collect();
        let prune = self.completed.load(Ordering::Relaxed);
        let unused = prune
            && self
                .stored
                .values()
                .any(|stored| !stored.used.load(Ordering::Relaxed));
        if fresh.is_empty() && !unused {
            return;
        }
        let mut entries: Vec<(FactKey, Vec<u8>)> = self
            .stored
            .iter()
            .filter(|(_, stored)| !prune || stored.used.load(Ordering::Relaxed))
            .map(|(key, stored)| (*key, stored.value.clone()))
            .chain(fresh)
            .collect();
        entries.sort_unstable_by_key(|entry| entry.0);
        let Ok(body) =
            bincode::serde::encode_to_vec((&self.identity, &entries), bincode::config::standard())
        else {
            return;
        };
        let mut file = Vec::with_capacity(MAGIC.len() + 32 + body.len());
        file.extend_from_slice(MAGIC);
        file.extend_from_slice(&Sha256::digest(&body));
        file.extend_from_slice(&body);
        if let Err(error) = write_atomically(&self.path, &file) {
            tracing::debug!(
                "validate facts: not saved to {}: {error}",
                self.path.display()
            );
        } else {
            tracing::debug!(
                "validate facts: saved {} entries to {}",
                entries.len(),
                self.path.display()
            );
        }
    }
}

fn write_atomically(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let tmp = path.with_extension(format!("tmp.{}", std::process::id()));
    fs::write(&tmp, bytes)?;
    fs::rename(&tmp, path).inspect_err(|_| {
        let _ = fs::remove_file(&tmp);
    })
}

/// The stored facts in `path`, if it holds an intact file written by this build.
fn read_stored(path: &Path, identity: &[u8]) -> Option<HashMap<FactKey, Stored>> {
    if fs::metadata(path).ok()?.len() > MAX_FILE_BYTES {
        return None;
    }
    let bytes = fs::read(path).ok()?;
    let rest = bytes.strip_prefix(MAGIC.as_slice())?;
    if rest.len() < 32 {
        return None;
    }
    let (digest, body) = rest.split_at(32);
    if Sha256::digest(body).as_slice() != digest {
        return None;
    }
    let ((file_identity, entries), _): ((Vec<u8>, Vec<(FactKey, Vec<u8>)>), usize) =
        bincode::serde::decode_from_slice(body, bincode::config::standard()).ok()?;
    if file_identity != identity {
        return None;
    }
    Some(
        entries
            .into_iter()
            .map(|(key, value)| {
                (
                    key,
                    Stored {
                        value,
                        used: AtomicBool::new(false),
                    },
                )
            })
            .collect(),
    )
}

static ACTIVE: RwLock<Option<Arc<FactsCache>>> = RwLock::new(None);

/// The facts of the full validation running now, if any.
pub(crate) fn active() -> Option<Arc<FactsCache>> {
    ACTIVE.read().ok()?.clone()
}

/// An open validation's facts; saved when it drops, whether the validation
/// finished or stopped at an error -- a fact is true of its inputs either way.
pub(crate) struct Session(());

impl Drop for Session {
    fn drop(&mut self) {
        let cache = ACTIVE.write().ok().and_then(|mut active| active.take());
        if let Some(cache) = cache {
            cache.save();
        }
    }
}

/// Mark the running validation as having reached its end (see `save`).
pub(crate) fn completed() {
    if let Some(cache) = active() {
        cache.completed.store(true, Ordering::Relaxed);
    }
}

/// Open the facts for a full validation run. `CLEAVE_VALIDATE_FACTS=0` runs
/// without them.
pub(crate) fn begin() -> Option<Session> {
    if std::env::var("CLEAVE_VALIDATE_FACTS").is_ok_and(|v| v == "0") {
        return None;
    }
    let dir = crate::cache::cache_dir().ok()?;
    let identity = build_identity();
    let path = dir.join(FILE_NAME);
    let stored = read_stored(&path, &identity).unwrap_or_default();
    tracing::debug!(
        "validate facts: {} entries from {}",
        stored.len(),
        path.display()
    );
    let cache = FactsCache {
        path,
        identity,
        stored,
        fresh: (0..FRESH_SHARDS)
            .map(|_| Mutex::new(HashMap::new()))
            .collect(),
        completed: AtomicBool::new(false),
    };
    *ACTIVE.write().ok()? = Some(Arc::new(cache));
    Some(Session(()))
}

/// Serializes the tests that install a validation's facts: there is one
/// process-wide slot.
#[cfg(test)]
pub(crate) static TEST_SLOT: Mutex<()> = Mutex::new(());

/// Open facts stored at `path`, for tests.
#[cfg(test)]
pub(crate) fn begin_at(path: &Path) -> Session {
    let identity = build_identity();
    let cache = FactsCache {
        path: path.to_path_buf(),
        stored: read_stored(path, &identity).unwrap_or_default(),
        identity,
        fresh: (0..FRESH_SHARDS)
            .map(|_| Mutex::new(HashMap::new()))
            .collect(),
        completed: AtomicBool::new(true),
    };
    if let Ok(mut active) = ACTIVE.write() {
        *active = Some(Arc::new(cache));
    }
    Session(())
}

/// How many facts the file at `path` holds for this build, for tests.
#[cfg(test)]
pub(crate) fn stored_entries(path: &Path) -> usize {
    read_stored(path, &build_identity()).map_or(0, |stored| stored.len())
}

/// This build's identity: the crate version and the executable's identity
/// (its GNU build-id; see [`crate::traits_fingerprint::binary_identity`]).
/// Facts written by one build are never read by another.
pub(crate) fn build_identity() -> Vec<u8> {
    let mut identity = env!("CARGO_PKG_VERSION").as_bytes().to_vec();
    identity.push(0);
    identity.extend_from_slice(crate::traits_fingerprint::binary_identity().as_bytes());
    identity
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;

    fn cache_at(path: &Path, identity: &[u8]) -> FactsCache {
        FactsCache {
            path: path.to_path_buf(),
            identity: identity.to_vec(),
            stored: read_stored(path, identity).unwrap_or_default(),
            fresh: (0..FRESH_SHARDS)
                .map(|_| Mutex::new(HashMap::new()))
                .collect(),
            completed: AtomicBool::new(true),
        }
    }

    /// A key names its inputs exactly: one byte of a pattern, a flag, or
    /// either side of a pair changes it, and parts cannot run together.
    #[test]
    fn keys_separate_every_input() {
        let base = key("literal-coverage", &[b"foo.*", b"\nfoo\n"]);
        assert_eq!(base, key("literal-coverage", &[b"foo.*", b"\nfoo\n"]));
        for other in [
            key("literal-coverage", &[b"fop.*", b"\nfoo\n"]),
            key("literal-coverage", &[b"foo.*", b"\nfop\n"]),
            key("literal-coverage", &[b"foo.*\n", b"foo\n"]),
            key("regex-memory", &[b"foo.*", b"\nfoo\n"]),
            key("literal-coverage", &[b"foo.*", b"\nfoo\n", &[1]]),
        ] {
            assert_ne!(base, other);
        }
    }

    /// Facts survive a save and reload by the same build, are dropped by a
    /// different build, and only the facts a run used or derived are kept.
    #[test]
    fn saved_facts_reload_for_the_same_build_only() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(FILE_NAME);
        let (kept, dropped, derived) = (
            key("t", &[b"kept"]),
            key("t", &[b"dropped"]),
            key("t", &[b"new"]),
        );

        let first = cache_at(&path, b"build-a");
        first.put(kept, &true);
        first.put(dropped, &7u32);
        first.save();

        let second = cache_at(&path, b"build-a");
        assert_eq!(second.get::<bool>(&kept), Some(true));
        second.put(derived, &String::from("x"));
        second.save();

        let third = cache_at(&path, b"build-a");
        assert_eq!(third.get::<bool>(&kept), Some(true));
        assert_eq!(third.get::<String>(&derived).as_deref(), Some("x"));
        assert_eq!(third.get::<u32>(&dropped), None);

        assert!(cache_at(&path, b"build-b").get::<bool>(&kept).is_none());
    }

    /// A run that stopped at an error keeps what it did not reach.
    #[test]
    fn an_incomplete_run_prunes_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(FILE_NAME);
        let (a, b) = (key("t", &[b"a"]), key("t", &[b"b"]));
        let first = cache_at(&path, b"build");
        first.put(a, &1u8);
        first.put(b, &2u8);
        first.save();

        let aborted = cache_at(&path, b"build");
        aborted.completed.store(false, Ordering::Relaxed);
        assert_eq!(aborted.get::<u8>(&a), Some(1));
        aborted.put(key("t", &[b"c"]), &3u8);
        aborted.save();

        let after = cache_at(&path, b"build");
        assert_eq!(after.get::<u8>(&b), Some(2));
        assert_eq!(after.get::<u8>(&key("t", &[b"c"])), Some(3));
    }

    /// A damaged file is read as empty, never as facts.
    #[test]
    fn corrupt_files_read_as_empty() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(FILE_NAME);
        let cache = cache_at(&path, b"build");
        cache.put(key("t", &[b"k"]), &true);
        cache.save();
        let mut bytes = fs::read(&path).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 1;
        fs::write(&path, &bytes).unwrap();
        assert!(read_stored(&path, b"build").is_none());
        fs::write(&path, &bytes[..bytes.len() / 2]).unwrap();
        assert!(read_stored(&path, b"build").is_none());
    }

    /// The running test binary is a linker-built ELF with a build-id.
    #[test]
    fn this_binary_has_an_identity() {
        let identity = build_identity();
        assert!(identity.starts_with(env!("CARGO_PKG_VERSION").as_bytes()));
        assert!(identity.len() > env!("CARGO_PKG_VERSION").len() + 1);
    }
}
