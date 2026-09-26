//! The running build's identity, and "validated clean" marks keyed on it and
//! on a traits tree's contents.
//!
//! Tree contents come from [`crate::cache::traits_content_for`], the same
//! per-process scan every cache key reads, so a mark costs no hashing of its
//! own.

use sha2::{Digest, Sha256};
use std::ffi::OsString;
use std::fs;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

/// Most marks kept per directory. Each is a few bytes; the bound only keeps
/// the directory from growing with every tree a long-running host sees.
const MAX_MARKS: usize = 256;

/// `CLEAVE_*` variables that cannot change what full validation of a tree
/// reports. Every other one is part of a [`CleanMark`] key: most tune
/// loading or matching, and a knob added later is safer as a miss than as a
/// validation wrongly skipped.
const NOT_VALIDATION_INPUTS: &[&str] = &[
    "CLEAVE_VALIDATE",
    "CLEAVE_VALIDATE_SOFT",
    "CLEAVE_TRAITS_DIR",
    "CLEAVE_CACHE_DIR",
    "CLEAVE_RAYON_THREADS",
    "CLEAVE_MAX_RSS_GB",
    "CLEAVE_FORMAT",
    "CLEAVE_LOG_LEVEL",
    "CLEAVE_LOGS_DIR",
    "CLEAVE_NO_UPDATE_CHECK",
    "CLEAVE_SKIP_CLEAN_MARK",
    "CLEAVE_VALIDATE_FACTS",
    "CLEAVE_PHASE_STATS",
    "CLEAVE_PROFILE",
    "CLEAVE_TRAIT_TIMING",
    "CLEAVE_TRAIT_TIMING_TOP",
    "CLEAVE_SKIP_MAPPER_CACHE",
    "CLEAVE_UPDATE_URL",
];

/// Whether clean marks are switched off: `CLEAVE_SKIP_CLEAN_MARK=1`, or
/// `CLEAVE_SKIP_CACHE=1`, which already asks for fresh results.
fn marks_disabled() -> bool {
    ["CLEAVE_SKIP_CLEAN_MARK", "CLEAVE_SKIP_CACHE"]
        .iter()
        .any(|name| std::env::var(name).is_ok_and(|v| v == "1" || v.eq_ignore_ascii_case("true")))
}

/// Proof that this build fully validated this exact traits tree and found
/// nothing to report.
///
/// Full validation is a gate on the tree, not on each scan: cyclotron runs
/// every agent tool with `CLEAVE_VALIDATE=1`, so a tree an agent broke refuses
/// to load until it is fixed. Re-proving an unchanged tree on every one of
/// those loads cost minutes and gigabytes per scan -- 399 s and 7.2 GiB peak
/// against 41 s and 4.5 GiB for an 80 KB npm package. A tree whose content key
/// carries a mark skips the checks and loads like any other scan; any changed
/// byte is a new key, so an edited tree still validates in full.
pub(crate) struct CleanMark {
    key: String,
    path: PathBuf,
    precision: Option<(f32, f32)>,
}

impl CleanMark {
    /// The mark slot for `traits_dir` under this build and configuration, or
    /// `None` when marks are switched off.
    ///
    /// `precision` is the load's precision scoring: its hostile and suspicious
    /// thresholds when enabled. Its findings are part of what full validation
    /// rejects, so a tree clean without it is not vouched for with it.
    #[must_use]
    pub(crate) fn for_traits(traits_dir: &Path, precision: Option<(f32, f32)>) -> Option<Self> {
        if marks_disabled() {
            return None;
        }
        Self::slot(traits_dir, precision)
    }

    /// The mark slot for `traits_dir`, whether or not marks are switched on.
    fn slot(traits_dir: &Path, precision: Option<(f32, f32)>) -> Option<Self> {
        let key = mark_key(crate::cache::traits_content_for(traits_dir), precision);
        let path = crate::cache::cache_dir()
            .ok()?
            .join("validated-clean")
            .join(&key);
        Some(Self {
            key,
            path,
            precision,
        })
    }

    /// Whether `traits_dir`, read again now, still has this mark's key.
    fn still_matches(&self, traits_dir: &Path) -> bool {
        mark_key(
            crate::cache::traits_content_uncached(traits_dir),
            self.precision,
        ) == self.key
    }

    /// Whether this tree already validated clean.
    #[must_use]
    pub(crate) fn is_set(&self) -> bool {
        let set = fs::read(&self.path).is_ok_and(|bytes| bytes == self.key.as_bytes());
        tracing::info!(key = %self.key, set, "validated-clean mark");
        set
    }

    /// Record that `traits_dir` validated clean, provided it still hashes to
    /// this mark's key. A tree edited while it loaded was validated from bytes
    /// that match neither key, so it earns no mark.
    pub(crate) fn set_if_unchanged(&self, traits_dir: &Path) {
        if self.still_matches(traits_dir) {
            self.set();
        } else {
            tracing::info!(key = %self.key, "traits changed while loading; no validated-clean mark");
        }
    }

    /// Record that this tree validated clean. Best-effort: a mark that cannot
    /// be written only costs the next load a full validation.
    fn set(&self) {
        if let Err(e) = write_entry(&self.path, self.key.as_bytes(), MAX_MARKS) {
            tracing::warn!(key = %self.key, error = %e, "validated-clean mark not stored");
            return;
        }
        tracing::info!(key = %self.key, "validated-clean mark stored");
    }
}

/// A mark's key: the tree's rule contents and directory layout, the build,
/// and everything else that decides what full validation reports.
fn mark_key(content: crate::cache::TraitsContent, precision: Option<(f32, f32)>) -> String {
    let mut key = KeyHasher::new("cleave-validated-clean 2");
    key.field("version", env!("CARGO_PKG_VERSION").as_bytes());
    key.field("binary", binary_identity().as_bytes());
    let scoring = precision.map_or_else(Vec::new, |(hostile, suspicious)| {
        [hostile.to_bits(), suspicious.to_bits()]
            .iter()
            .flat_map(|bits| bits.to_le_bytes())
            .collect()
    });
    key.field("precision-scoring", &scoring);
    // `--exclude` drops whole validators, so "clean" under an exclusion says
    // nothing about the tree without it.
    let disabled = format!(
        "{:?}",
        crate::validation_controls::disabled_validators_by_category()
    );
    key.field("disabled-validators", disabled.as_bytes());
    for (name, value) in keyed_env(NOT_VALIDATION_INPUTS) {
        key.field(&name, value.as_encoded_bytes());
    }
    key.field("rules", &content.rules);
    key.field("layout", &content.layout);
    key.finish()
}

/// Write one entry atomically into its directory, then keep only the newest
/// `keep` entries there.
fn write_entry(path: &Path, bytes: &[u8], keep: usize) -> std::io::Result<()> {
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(dir)?;
    crate::cache::atomic_write(path, bytes)?;
    prune(dir, keep);
    Ok(())
}

/// Keep only the newest `keep` entries of `dir`. Best-effort.
fn prune(dir: &Path, keep: usize) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    let mut entries: Vec<(std::time::SystemTime, PathBuf)> = entries
        .filter_map(Result::ok)
        .filter_map(|e| Some((e.metadata().ok()?.modified().ok()?, e.path())))
        .collect();
    if entries.len() <= keep {
        return;
    }
    entries.sort_by_key(|entry| std::cmp::Reverse(entry.0));
    for (_, path) in entries.into_iter().skip(keep) {
        let _ = fs::remove_file(path);
    }
}

/// Builds a key from length-prefixed named fields, so no two field lists can
/// hash alike by shifting bytes between neighbours.
struct KeyHasher(Sha256);

impl KeyHasher {
    fn new(domain: &str) -> Self {
        let mut key = Self(Sha256::new());
        key.field("domain", domain.as_bytes());
        key
    }

    fn field(&mut self, name: &str, value: &[u8]) {
        self.0.update((name.len() as u64).to_le_bytes());
        self.0.update(name.as_bytes());
        self.0.update((value.len() as u64).to_le_bytes());
        self.0.update(value);
    }

    /// The key, hex-encoded.
    fn finish(self) -> String {
        hex::encode(self.0.finalize().as_slice())
    }
}

/// The `CLEAVE_*` environment minus `excluded`, sorted by name.
fn keyed_env(excluded: &[&str]) -> Vec<(String, OsString)> {
    let mut env: Vec<(String, OsString)> = std::env::vars_os()
        .filter_map(|(name, value)| {
            let name = name.into_string().ok()?;
            (name.starts_with("CLEAVE_") && !excluded.contains(&name.as_str()))
                .then_some((name, value))
        })
        .collect();
    env.sort();
    env
}

/// Which build is running: its GNU build-id, a hash of the linked output that
/// changes exactly when the code does, else its size and mtime. Every cache
/// key reads it, so it is computed once per process.
///
/// Linux reads `/proc/self/exe`, which is the running image even after a
/// deploy replaces the file on disk.
#[must_use]
pub(crate) fn binary_identity() -> &'static str {
    static IDENTITY: OnceLock<String> = OnceLock::new();
    IDENTITY.get_or_init(|| {
        let exe = if cfg!(target_os = "linux") {
            Some(PathBuf::from("/proc/self/exe"))
        } else {
            std::env::current_exe().ok()
        };
        exe.and_then(|exe| {
            build_id(&exe)
                .map(|id| format!("build-id:{id}"))
                .or_else(|| stat_identity(&exe).map(|id| format!("stat:{id}")))
        })
        .unwrap_or_else(|| "unknown".to_owned())
    })
}

/// A file's size and mtime, for identities with no content fingerprint.
fn stat_identity(path: &Path) -> Option<String> {
    let meta = fs::metadata(path).ok()?;
    let mtime = meta
        .modified()
        .ok()?
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?;
    Some(format!("{}:{}", meta.len(), mtime.as_nanos()))
}

/// The hex `NT_GNU_BUILD_ID` note of a 64-bit little-endian ELF file, or
/// `None` for anything else, including a binary linked without `--build-id`.
fn build_id(path: &Path) -> Option<String> {
    const PT_NOTE: u32 = 4;
    const NT_GNU_BUILD_ID: u32 = 3;
    const MAX_NOTES: u64 = 1 << 20;

    let mut file = fs::File::open(path).ok()?;
    let mut header = [0u8; 64];
    file.read_exact(&mut header).ok()?;
    // ELF magic, ELFCLASS64, ELFDATA2LSB.
    if header[..6] != *b"\x7fELF\x02\x01" {
        return None;
    }
    let phoff = le_u64(&header, 32)?;
    let phentsize = u64::from(le_u16(&header, 54)?);
    let phnum = u64::from(le_u16(&header, 56)?);
    if phentsize < 56 {
        return None;
    }
    let mut table = vec![0u8; usize::try_from(phentsize.checked_mul(phnum)?).ok()?];
    file.seek(SeekFrom::Start(phoff)).ok()?;
    file.read_exact(&mut table).ok()?;
    for entry in table.chunks_exact(usize::try_from(phentsize).ok()?) {
        if le_u32(entry, 0)? != PT_NOTE {
            continue;
        }
        let (offset, size, align) = (le_u64(entry, 8)?, le_u64(entry, 32)?, le_u64(entry, 48)?);
        if size > MAX_NOTES {
            continue;
        }
        let mut notes = vec![0u8; usize::try_from(size).ok()?];
        file.seek(SeekFrom::Start(offset)).ok()?;
        file.read_exact(&mut notes).ok()?;
        let align = if align == 8 { 8 } else { 4 };
        if let Some(id) = find_note(&notes, align, b"GNU\0", NT_GNU_BUILD_ID) {
            return Some(hex::encode(id));
        }
    }
    None
}

/// The descriptor of the first note named `name` with type `kind`.
fn find_note<'a>(mut notes: &'a [u8], align: usize, name: &[u8], kind: u32) -> Option<&'a [u8]> {
    let padded = |n: usize| n.div_ceil(align) * align;
    while notes.len() >= 12 {
        let namesz = usize::try_from(le_u32(notes, 0)?).ok()?;
        let descsz = usize::try_from(le_u32(notes, 4)?).ok()?;
        let note_kind = le_u32(notes, 8)?;
        let desc_start = 12usize.checked_add(padded(namesz))?;
        let desc_end = desc_start.checked_add(descsz)?;
        let note_name = notes.get(12..12usize.checked_add(namesz)?)?;
        let desc = notes.get(desc_start..desc_end)?;
        if note_kind == kind && note_name == name {
            return Some(desc);
        }
        notes = notes.get(desc_start.checked_add(padded(descsz))?..)?;
    }
    None
}

fn le_u16(bytes: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes(bytes.get(at..at + 2)?.try_into().ok()?))
}

fn le_u32(bytes: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(bytes.get(at..at + 4)?.try_into().ok()?))
}

fn le_u64(bytes: &[u8], at: usize) -> Option<u64> {
    Some(u64::from_le_bytes(bytes.get(at..at + 8)?.try_into().ok()?))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn tree() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir_all(dir.path().join("objectives/c2")).unwrap();
        fs::write(dir.path().join("objectives/c2/irc.yaml"), "traits: [a]\n").unwrap();
        dir
    }

    #[test]
    fn key_fields_are_length_prefixed() {
        let key = |fields: &[(&str, &[u8])]| {
            let mut k = KeyHasher::new("t");
            for (name, value) in fields {
                k.field(name, value);
            }
            k.finish()
        };
        assert_ne!(key(&[("a", b"bc")]), key(&[("ab", b"c")]));
        assert_eq!(key(&[("a", b"bc")]), key(&[("a", b"bc")]));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn build_id_reads_this_binary() {
        let id = build_id(Path::new("/proc/self/exe")).expect("test binary carries a build-id");
        assert!(
            id.len() >= 16 && id.chars().all(|c| c.is_ascii_hexdigit()),
            "{id}"
        );
        assert!(build_id(Path::new("/etc/hostname")).is_none());
        assert_eq!(binary_identity(), format!("build-id:{id}"));
    }

    #[test]
    fn find_note_skips_other_notes() {
        let mut notes = Vec::new();
        // A GNU property note first (type 5), then the build-id (type 3).
        for (kind, desc) in [(5u32, &[9u8; 8][..]), (3, &[0xab, 0xcd, 0xef, 0x01][..])] {
            notes.extend_from_slice(&4u32.to_le_bytes());
            notes.extend_from_slice(&u32::try_from(desc.len()).unwrap().to_le_bytes());
            notes.extend_from_slice(&kind.to_le_bytes());
            notes.extend_from_slice(b"GNU\0");
            notes.extend_from_slice(desc);
        }
        assert_eq!(
            find_note(&notes, 4, b"GNU\0", 3),
            Some(&[0xab, 0xcd, 0xef, 0x01][..])
        );
        assert_eq!(find_note(&notes, 4, b"GNU\0", 7), None);
    }

    // The case a stat key misses: same path, same length, same mtime.
    #[test]
    fn same_length_edit_with_mtime_restored_changes_the_mark() {
        let dir = tree();
        let content = crate::cache::traits_content_uncached(dir.path());
        let before = mark_key(content, None);

        let path = dir.path().join("objectives/c2/irc.yaml");
        let mtime = fs::metadata(&path).unwrap().modified().unwrap();
        fs::write(&path, "traits: [b]\n").unwrap();
        fs::File::options()
            .write(true)
            .open(&path)
            .unwrap()
            .set_modified(mtime)
            .unwrap();
        assert_eq!(fs::metadata(&path).unwrap().modified().unwrap(), mtime);

        let after = mark_key(crate::cache::traits_content_uncached(dir.path()), None);
        assert_ne!(after, before);
    }

    // Validation judges directory names, so a new directory holding no rule
    // file is still a different tree to a mark.
    #[test]
    fn new_directory_changes_the_mark() {
        let dir = tree();
        let before = mark_key(crate::cache::traits_content_uncached(dir.path()), None);
        fs::create_dir_all(dir.path().join("objectives/not-a-real-objective")).unwrap();
        let after = mark_key(crate::cache::traits_content_uncached(dir.path()), None);
        assert_ne!(after, before);
    }

    #[test]
    fn precision_scoring_is_part_of_the_mark() {
        let content = crate::cache::traits_content_uncached(tree().path());
        let none = mark_key(content, None);
        let scored = mark_key(content, Some((0.8, 0.5)));
        assert_ne!(scored, none);
        assert_ne!(mark_key(content, Some((0.9, 0.5))), scored);
    }

    #[test]
    fn clean_mark_round_trips_and_is_per_tree() {
        let a = tree();
        let b = tree();
        fs::write(b.path().join("objectives/c2/irc.yaml"), "traits: [z]\n").unwrap();

        // `slot`, not `for_traits`: `make test` sets CLEAVE_SKIP_CACHE=1.
        let mark_a = CleanMark::slot(a.path(), None).unwrap();
        let mark_b = CleanMark::slot(b.path(), None).unwrap();
        assert_ne!(mark_a.key, mark_b.key);
        // Keys live in a shared test cache dir; start from a clean slate.
        let _ = fs::remove_file(&mark_a.path);
        let _ = fs::remove_file(&mark_b.path);

        assert!(!mark_a.is_set());
        mark_a.set_if_unchanged(a.path());
        assert!(mark_a.is_set());
        assert!(!mark_b.is_set(), "a mark never vouches for another tree");

        // A tree edited between hashing and marking earns no mark.
        fs::write(b.path().join("objectives/c2/irc.yaml"), "traits: [y]\n").unwrap();
        mark_b.set_if_unchanged(b.path());
        assert!(!mark_b.is_set(), "tree changed while loading");

        // A mark whose contents do not match its key is not a mark.
        fs::write(&mark_b.path, b"not the key").unwrap();
        assert!(!mark_b.is_set());
    }
}
