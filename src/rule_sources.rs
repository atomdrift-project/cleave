//! Immutable source bytes shared by hashing, trait parsing and YARA loading.
//! Packed rule files have virtual paths without `.zst` so all consumers see
//! the same rule names and fingerprints as an unpacked traits checkout.
//! A fresh snapshot reads every byte again. It also records a [`TreeStamp`],
//! which lets a later process prove the tree unchanged from metadata alone.
use anyhow::{Context, Result};
use parking_lot::RwLock;
use rayon::prelude::*;
use rustc_hash::FxHashMap;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::SystemTime;

/// Concurrent readers for a snapshot. Reading 34k rule files on a 16-core Mac
/// took 1.40 s with 16 readers, 0.70 s with 12, 0.38 s with 6, and 0.67 s
/// with 2: past a handful, readers contend in the kernel's file-open path.
const SNAPSHOT_READERS: usize = 6;

/// One source file from an immutable rule tree snapshot.
#[derive(Clone, Debug)]
pub(crate) struct SourceFile {
    /// Path relative to the snapshot root.
    pub relative_path: PathBuf,
    /// Exact bytes read for both fingerprinting and compilation.
    pub bytes: Arc<[u8]>,
    /// Modification time for diagnostics; never used to validate contents.
    pub modified: Option<SystemTime>,
    symlink_directories: Vec<PathBuf>,
}

impl SourceFile {
    pub(crate) fn follows_directory_symlink(&self) -> bool {
        !self.symlink_directories.is_empty()
    }
}

/// Frozen source contents and directory layout for one loading cycle.
#[derive(Debug)]
pub(crate) struct RuleSources {
    root: PathBuf,
    files: Vec<SourceFile>,
    directories: Vec<PathBuf>,
    lookup: FxHashMap<PathBuf, usize>,
    stamp: Option<TreeStamp>,
}

/// How long after a snapshot begins a change may still share a timestamp
/// with what the snapshot recorded. Timestamps are only as fine as the
/// filesystem keeps them: nanoseconds on APFS, a scheduler tick on Linux,
/// one second on HFS+, two on FAT.
const TIMESTAMP_GRANULARITY: std::time::Duration = std::time::Duration::from_secs(2);

/// One entry's metadata as identity: device, inode, mode, size, and mtime and
/// ctime to the nanosecond. Checkouts, archives and `touch -r` set mtimes;
/// the kernel sets the ctime itself on every change to the inode, and none
/// of them can put it back. So an unchanged stamp means unchanged contents,
/// and for a directory unchanged entries, since adding, removing or renaming
/// one changes the directory. A changed device number (a remount, a reboot
/// that reorders disks) only costs a full read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Stamp([i64; 8]);

impl Stamp {
    /// `None` where the platform has no ctime.
    #[cfg(unix)]
    // Identity bits, compared, never ordered; `Option` for the non-unix twin.
    #[allow(clippy::cast_possible_wrap, clippy::unnecessary_wraps)]
    fn of(metadata: &fs::Metadata) -> Option<Self> {
        use std::os::unix::fs::MetadataExt;
        Some(Self([
            metadata.dev() as i64,
            metadata.ino() as i64,
            i64::from(metadata.mode()),
            metadata.size() as i64,
            metadata.mtime(),
            metadata.mtime_nsec(),
            metadata.ctime(),
            metadata.ctime_nsec(),
        ]))
    }

    #[cfg(not(unix))]
    fn of(_: &fs::Metadata) -> Option<Self> {
        None
    }

    /// Whether the entry changed so close to `begun` that a later change
    /// could carry the same timestamps.
    fn is_racy(&self, begun: SystemTime) -> bool {
        let Some(since_epoch) = begun
            .checked_sub(TIMESTAMP_GRANULARITY)
            .and_then(|horizon| horizon.duration_since(SystemTime::UNIX_EPOCH).ok())
        else {
            return true;
        };
        let horizon = i128::try_from(since_epoch.as_nanos()).unwrap_or(i128::MAX);
        let nanos = |secs: i64, nsec: i64| i128::from(secs) * 1_000_000_000 + i128::from(nsec);
        let [.., mtime, mtime_nsec, ctime, ctime_nsec] = self.0;
        nanos(mtime, mtime_nsec) >= horizon || nanos(ctime, ctime_nsec) >= horizon
    }
}

/// Proof that a tree is unchanged since a snapshot, checkable with a `stat`
/// per entry instead of a `readdir` per directory and a read per file:
/// the snapshot's directories and files, and a digest of their [`Stamp`]s.
///
/// Each stamp is taken before what it vouches for is read (a directory's
/// before its listing, a file's from the open descriptor before its bytes),
/// so a change during the snapshot shows as a different stamp later. A
/// snapshot that skipped an unreadable file, or saw an entry change within
/// [`TIMESTAMP_GRANULARITY`] of starting, has no stamp.
#[derive(Clone, Debug)]
pub(crate) struct TreeStamp {
    /// Root-relative paths as stored on disk, each NUL-terminated.
    listing: Vec<u8>,
    digest: [u8; 32],
}

impl TreeStamp {
    fn new<'a>(
        begun: SystemTime,
        entries: impl Iterator<Item = (&'a Path, Option<Stamp>)>,
    ) -> Option<Self> {
        let mut listing = Vec::new();
        let mut stamps = Vec::new();
        for (path, stamp) in entries {
            let stamp = stamp.filter(|s| !s.is_racy(begun))?;
            listing.extend_from_slice(path.as_os_str().as_encoded_bytes());
            listing.push(0);
            stamps.push(stamp);
        }
        let digest = Self::digest_of(&listing, &stamps);
        Some(Self { listing, digest })
    }

    fn digest_of(listing: &[u8], stamps: &[Stamp]) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(listing);
        for stamp in stamps {
            for field in stamp.0 {
                hasher.update(field.to_le_bytes());
            }
        }
        hasher.finalize().into()
    }

    /// The listed paths; `None` for one this platform cannot spell, which
    /// no stamp it took could have listed.
    fn entries(&self) -> Option<Vec<&Path>> {
        let listing = self.listing.strip_suffix(&[0]).unwrap_or(&self.listing);
        listing
            .split(|&b| b == 0)
            .map(|entry| {
                #[cfg(unix)]
                let path = Some(Path::new(
                    <std::ffi::OsStr as std::os::unix::ffi::OsStrExt>::from_bytes(entry),
                ));
                #[cfg(not(unix))]
                let path = std::str::from_utf8(entry).ok().map(Path::new);
                path
            })
            .collect()
    }

    /// Whether every entry under `root` still has the stamp it was recorded
    /// with. A file added or removed changes its directory's stamp, so the
    /// listing needs no readdir to stay complete.
    pub(crate) fn matches(&self, root: &Path) -> bool {
        let stat = |entry: &Path| {
            fs::metadata(root.join(entry))
                .ok()
                .as_ref()
                .and_then(Stamp::of)
        };
        let Some(entries) = self.entries() else {
            return false;
        };
        let stamps: Option<Vec<Stamp>> = if rayon::current_thread_index().is_some() {
            entries.into_iter().map(stat).collect()
        } else {
            let per_reader = entries.len().div_ceil(SNAPSHOT_READERS).max(1);
            entries
                .into_par_iter()
                .with_min_len(per_reader)
                .map(stat)
                .collect()
        };
        stamps.is_some_and(|stamps| Self::digest_of(&self.listing, &stamps) == self.digest)
    }

    /// The digest followed by the listing.
    pub(crate) fn encode(&self) -> Vec<u8> {
        [&self.digest[..], &self.listing].concat()
    }

    /// Reverse [`Self::encode`]; `None` for anything it could not have written.
    pub(crate) fn decode(bytes: &[u8]) -> Option<Self> {
        let (digest, listing) = bytes.split_first_chunk::<32>()?;
        listing.ends_with(&[0]).then(|| Self {
            listing: listing.to_vec(),
            digest: *digest,
        })
    }
}

impl RuleSources {
    /// Read a new snapshot, including directory layout and validation artifacts.
    ///
    /// A structural problem in the tree (a broken link, a symlink loop, an
    /// unreadable directory) fails the load. A single rule file that cannot be
    /// read is skipped with a warning instead: endpoint protection quarantines
    /// rules whose text resembles the malware they detect, and losing a few
    /// rules must not cost every other one. A tree in which no file could be
    /// read still fails, so a permissions problem never loads as an empty set.
    pub(crate) fn fresh(root: &Path) -> Result<Self> {
        Self::read(root, SystemTime::now())
    }

    /// [`Self::fresh`] for a snapshot taken as of `begun`, which decides what
    /// changed too recently to stamp. Tests pass a later time to model a tree
    /// whose last change is older than [`TIMESTAMP_GRANULARITY`].
    pub(crate) fn read(root: &Path, begun: SystemTime) -> Result<Self> {
        let started = std::time::Instant::now();
        let root =
            fs::canonicalize(root).with_context(|| format!("resolving {}", root.display()))?;
        let mut paths = Vec::new();
        let mut directories = Vec::new();
        let mut directory_stamps = Vec::new();
        let mut symlink_directories: Vec<(usize, PathBuf)> = Vec::new();
        for entry in walkdir::WalkDir::new(&root)
            .follow_links(true)
            .sort_by_file_name()
            .into_iter()
            .filter_entry(crate::traits_repo::is_rule_source_entry)
        {
            let entry = entry?;
            symlink_directories.retain(|(depth, _)| *depth < entry.depth());
            let relative = entry.path().strip_prefix(&root)?.to_path_buf();
            if entry.file_type().is_dir() {
                if entry.depth() > 0 && entry.path_is_symlink() {
                    symlink_directories.push((entry.depth(), relative.clone()));
                }
                // Before the walk lists it, which happens on the next step.
                directory_stamps.push(entry.metadata().ok().as_ref().and_then(Stamp::of));
                directories.push(relative);
            } else if entry.file_type().is_file() {
                let compressed = entry.path().extension().is_some_and(|e| e == "zst");
                let source_path = if compressed {
                    entry.path().with_extension("")
                } else {
                    entry.path().to_path_buf()
                };
                if matches!(
                    source_path.extension().and_then(|e| e.to_str()),
                    Some("yaml" | "yml" | "yar" | "yara" | "yrc")
                ) || !compressed && entry.file_name() == "manifest.json"
                {
                    paths.push((
                        relative,
                        source_path.strip_prefix(&root)?.to_path_buf(),
                        compressed,
                        symlink_directories
                            .iter()
                            .map(|(_, p)| p.clone())
                            .collect::<Vec<_>>(),
                    ));
                }
            }
        }
        let found = paths.len();
        let read_file = |(stored_path, relative_path, compressed, symlink_directories): (
            PathBuf,
            PathBuf,
            bool,
            Vec<PathBuf>,
        )|
         -> Option<(SourceFile, PathBuf, Option<Stamp>)> {
            let path = root.join(&stored_path);
            let read = || -> std::io::Result<(Vec<u8>, fs::Metadata)> {
                let mut file = fs::File::open(&path)?;
                let metadata = file.metadata()?;
                let mut bytes = Vec::with_capacity(usize::try_from(metadata.len()).unwrap_or(0));
                file.read_to_end(&mut bytes)?;
                if compressed {
                    bytes = zstd::decode_all(&bytes[..])?;
                }
                Ok((bytes, metadata))
            };
            match read() {
                Ok((bytes, metadata)) => Some((
                    SourceFile {
                        relative_path,
                        bytes: bytes.into(),
                        modified: metadata.modified().ok(),
                        symlink_directories,
                    },
                    stored_path,
                    Stamp::of(&metadata),
                )),
                Err(error) => {
                    tracing::warn!(path = %path.display(), %error,
                            "skipping unreadable or corrupt rule file; rules it defines are not loaded");
                    None
                }
            }
        };
        // Global YARA initialization may be entered by a Rayon worker while
        // its peers wait on the singleton. Do not enqueue work into that pool.
        let mut files: Vec<_> = if rayon::current_thread_index().is_some() {
            paths.into_iter().filter_map(read_file).collect()
        } else {
            // Bound concurrent reads; see SNAPSHOT_READERS.
            let per_reader = paths.len().div_ceil(SNAPSHOT_READERS).max(1);
            paths
                .into_par_iter()
                .with_min_len(per_reader)
                .filter_map(read_file)
                .collect()
        };
        files.sort_unstable_by(|a, b| a.0.relative_path.cmp(&b.0.relative_path));
        if files
            .windows(2)
            .any(|pair| pair[0].0.relative_path == pair[1].0.relative_path)
        {
            anyhow::bail!(
                "duplicate plain and compressed rule files under {}",
                root.display()
            );
        }
        if found > 0 && files.is_empty() {
            anyhow::bail!(
                "none of the {found} rule files under {} could be read",
                root.display()
            );
        }
        let skipped = found - files.len();
        if skipped > 0 {
            tracing::warn!(root = %root.display(), skipped, loaded = files.len(),
                "rule set loaded with unreadable files skipped; detection coverage is reduced");
        }
        let stamp = if skipped == 0 {
            let directories = directories
                .iter()
                .map(PathBuf::as_path)
                .zip(directory_stamps);
            let files = files
                .iter()
                .map(|(_, stored, stamp)| (stored.as_path(), *stamp));
            TreeStamp::new(begun, directories.chain(files))
        } else {
            None
        };
        let files: Vec<SourceFile> = files.into_iter().map(|(file, _, _)| file).collect();
        tracing::info!(root = %root.display(), files = files.len(),
            bytes = files.iter().map(|f| f.bytes.len()).sum::<usize>(),
            stamped = stamp.is_some(),
            read_ms = started.elapsed().as_millis(), "rule source snapshot read");
        Ok(Self::from_files(root, files, directories, stamp))
    }

    fn from_files(
        root: PathBuf,
        files: Vec<SourceFile>,
        directories: Vec<PathBuf>,
        stamp: Option<TreeStamp>,
    ) -> Self {
        let lookup = files
            .iter()
            .enumerate()
            .map(|(i, f)| (f.relative_path.clone(), i))
            .collect();
        Self {
            root,
            files,
            directories,
            lookup,
            stamp,
        }
    }

    /// Proof of this snapshot's tree, for a later process to check; `None`
    /// for a subtree view or a snapshot that could not take one.
    #[must_use]
    pub(crate) fn tree_stamp(&self) -> Option<&TreeStamp> {
        self.stamp.as_ref()
    }

    /// Source files in sorted walk order.
    #[must_use]
    pub(crate) fn files(&self) -> &[SourceFile] {
        &self.files
    }
    /// Directory layout, including the root as an empty relative path.
    #[must_use]
    pub(crate) fn directories(&self) -> &[PathBuf] {
        &self.directories
    }
    /// Look up a source by its root-relative path.
    #[must_use]
    pub(crate) fn file(&self, relative: &Path) -> Option<&SourceFile> {
        self.lookup.get(relative).map(|&i| &self.files[i])
    }

    pub(crate) fn subtree_relative(&self, prefix: &Path) -> Option<Self> {
        self.subtree(&self.root.join(prefix))
    }

    /// A subtree view reuses bytes from the same snapshot, including when YARA
    /// loads third-party sources through a path below the main traits root.
    pub(crate) fn subtree(&self, root: &Path) -> Option<Self> {
        let prefix = root.strip_prefix(&self.root).ok()?;
        if !self.directories.iter().any(|dir| dir == prefix) {
            return None;
        }
        let files = self
            .files
            .iter()
            .filter_map(|file| {
                Some(SourceFile {
                    relative_path: file.relative_path.strip_prefix(prefix).ok()?.to_path_buf(),
                    bytes: file.bytes.clone(),
                    modified: file.modified,
                    symlink_directories: file
                        .symlink_directories
                        .iter()
                        .filter_map(|dir| {
                            let relative = dir.strip_prefix(prefix).ok()?;
                            (!relative.as_os_str().is_empty()).then(|| relative.to_path_buf())
                        })
                        .collect(),
                })
            })
            .collect();
        let directories = self
            .directories
            .iter()
            .filter_map(|dir| dir.strip_prefix(prefix).ok().map(Path::to_path_buf))
            .collect();
        Some(Self::from_files(
            root.to_path_buf(),
            files,
            directories,
            None,
        ))
    }
}

static SOURCES: RwLock<Vec<Arc<RuleSources>>> = RwLock::new(Vec::new());
const MAX_SNAPSHOTS: usize = 8;

/// Reuse the snapshot for this load. Never hold a lock while doing parallel I/O:
/// nested Rayon work may re-enter this function.
pub(crate) fn shared(root: &Path) -> Result<Arc<RuleSources>> {
    let root = fs::canonicalize(root)?;
    {
        let snapshots = SOURCES.read();
        if let Some(snapshot) = snapshots.iter().find(|s| s.root == root) {
            return Ok(snapshot.clone());
        }
        if let Some(view) = snapshots.iter().find_map(|s| s.subtree(&root)) {
            return Ok(Arc::new(view));
        }
    }
    let snapshot = Arc::new(RuleSources::fresh(&root)?);
    let mut snapshots = SOURCES.write();
    if let Some(existing) = snapshots.iter().find(|s| s.root == root) {
        return Ok(existing.clone());
    }
    if snapshots.len() >= MAX_SNAPSHOTS {
        snapshots.remove(0);
    }
    snapshots.push(snapshot.clone());
    drop(snapshots);
    Ok(snapshot)
}

pub(crate) fn invalidate() {
    SOURCES.write().clear();
}

/// Whether `relative` (a path under the traits root) is a trait file the
/// loader reads: YAML outside `third-party/`, and not a README or EXAMPLE.
pub(crate) fn is_trait_file(relative: &std::path::Path) -> bool {
    let filename = relative.file_name().and_then(|f| f.to_str()).unwrap_or("");
    relative.extension().is_some_and(|e| e == "yaml")
        && !relative
            .components()
            .any(|c| c.as_os_str() == "third-party")
        && !filename.to_lowercase().contains("readme")
        && !filename.starts_with("EXAMPLE")
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn rule_sources_snapshot_freezes_bytes_and_fresh_detects_preserved_metadata_edits() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("rule.yaml");
        fs::write(&path, "rule-a").unwrap();
        let before = shared(dir.path()).unwrap();
        let mtime = fs::metadata(&path).unwrap().modified().unwrap();
        fs::write(&path, "rule-b").unwrap();
        fs::File::options()
            .write(true)
            .open(&path)
            .unwrap()
            .set_modified(mtime)
            .unwrap();
        fs::write(dir.path().join("added.yaml"), "new").unwrap();
        fs::create_dir(dir.path().join("new-directory")).unwrap();
        assert_eq!(
            &*before.file(Path::new("rule.yaml")).unwrap().bytes,
            b"rule-a"
        );
        assert!(before.file(Path::new("added.yaml")).is_none());
        let after = RuleSources::fresh(dir.path()).unwrap();
        assert_eq!(
            &*after.file(Path::new("rule.yaml")).unwrap().bytes,
            b"rule-b"
        );
        assert!(after.file(Path::new("added.yaml")).is_some());
        assert!(
            after
                .directories()
                .contains(&PathBuf::from("new-directory"))
        );
        fs::remove_file(&path).unwrap();
        assert!(
            RuleSources::fresh(dir.path())
                .unwrap()
                .file(Path::new("rule.yaml"))
                .is_none()
        );
    }

    /// A snapshot of `root` as if its last change were long past, after
    /// which later changes get timestamps of their own: Linux stamps inodes
    /// from a clock that ticks every few milliseconds.
    fn settled(root: &Path) -> RuleSources {
        let sources =
            RuleSources::read(root, SystemTime::now() + 2 * TIMESTAMP_GRANULARITY).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(30));
        sources
    }

    #[cfg(unix)]
    #[test]
    fn tree_stamp_proves_an_untouched_tree_and_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir(dir.path().join("objectives")).unwrap();
        fs::write(dir.path().join("objectives/a.yaml"), "a").unwrap();
        fs::write(dir.path().join("notes.txt"), "not a rule").unwrap();
        let stamp = settled(dir.path()).tree_stamp().unwrap().clone();
        let root = fs::canonicalize(dir.path()).unwrap();
        assert!(stamp.matches(&root));
        let decoded = TreeStamp::decode(&stamp.encode()).unwrap();
        assert!(decoded.matches(&root));
        assert!(TreeStamp::decode(&stamp.encode()[..40]).is_none_or(|s| !s.matches(&root)));
        assert!(TreeStamp::decode(&[0; 31]).is_none());
        // Files the snapshot does not read are not part of the proof.
        fs::write(dir.path().join("notes.txt"), "edited").unwrap();
        assert!(stamp.matches(&root));
    }

    #[cfg(unix)]
    #[test]
    fn tree_stamp_sees_every_kind_of_change() {
        type Change = fn(&Path);
        let changes: [(&str, Change); 6] = [
            ("same-length edit, mtime restored", |root| {
                let path = root.join("objectives/a.yaml");
                let mtime = fs::metadata(&path).unwrap().modified().unwrap();
                fs::write(&path, "b").unwrap();
                fs::File::options()
                    .write(true)
                    .open(&path)
                    .unwrap()
                    .set_modified(mtime)
                    .unwrap();
            }),
            ("file added", |root| {
                fs::write(root.join("objectives/new.yaml"), "n").unwrap()
            }),
            ("file removed", |root| {
                fs::remove_file(root.join("objectives/a.yaml")).unwrap()
            }),
            ("file replaced by rename", |root| {
                fs::write(root.join("tmp"), "a").unwrap();
                fs::rename(root.join("tmp"), root.join("objectives/a.yaml")).unwrap();
            }),
            ("directory added", |root| {
                fs::create_dir(root.join("objectives/sub")).unwrap()
            }),
            ("non-rule file added beside the rules", |root| {
                fs::write(root.join("objectives/README.md"), "x").unwrap();
            }),
        ];
        for (what, change) in changes {
            let dir = tempfile::tempdir().unwrap();
            let root = fs::canonicalize(dir.path()).unwrap();
            fs::create_dir(root.join("objectives")).unwrap();
            fs::write(root.join("objectives/a.yaml"), "a").unwrap();
            let stamp = settled(&root).tree_stamp().unwrap().clone();
            change(&root);
            assert!(!stamp.matches(&root), "{what} went unnoticed");
        }
    }

    #[test]
    fn a_tree_changed_within_the_timestamp_granularity_is_not_stamped() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("a.yaml"), "a").unwrap();
        assert!(
            RuleSources::fresh(dir.path())
                .unwrap()
                .tree_stamp()
                .is_none()
        );
        assert!(
            settled(dir.path())
                .subtree(&fs::canonicalize(dir.path()).unwrap())
                .unwrap()
                .tree_stamp()
                .is_none()
        );
    }

    #[test]
    fn rule_sources_subtree_shares_buffers_and_ignores_unrelated_files() {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir(dir.path().join("third-party")).unwrap();
        fs::write(dir.path().join("third-party/rule.yar"), "rule").unwrap();
        fs::write(dir.path().join("notes.txt"), "ignored").unwrap();
        let root = RuleSources::fresh(dir.path()).unwrap();
        let child = root.subtree_relative(Path::new("third-party")).unwrap();
        assert_eq!(root.files().len(), 1);
        assert!(Arc::ptr_eq(&root.files()[0].bytes, &child.files()[0].bytes));
        assert_eq!(child.files()[0].relative_path, Path::new("rule.yar"));
    }

    /// Endpoint protection denies reads of quarantined rules; an unreadable
    /// mode stands in for that.
    #[cfg(unix)]
    fn make_unreadable(path: &Path) {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o000)).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn rule_sources_skip_an_unreadable_file_and_keep_the_rest() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("kept.yaml"), "kept").unwrap();
        let blocked = dir.path().join("blocked.yrc");
        fs::write(&blocked, "blocked").unwrap();
        make_unreadable(&blocked);
        if fs::read(&blocked).is_ok() {
            return; // Running as root: permissions cannot deny the read.
        }
        let sources = RuleSources::fresh(dir.path()).unwrap();
        assert_eq!(
            &*sources.file(Path::new("kept.yaml")).unwrap().bytes,
            b"kept"
        );
        assert!(sources.file(Path::new("blocked.yrc")).is_none());
    }

    #[cfg(unix)]
    #[test]
    fn rule_sources_fail_when_no_file_is_readable() {
        let dir = tempfile::tempdir().unwrap();
        let only = dir.path().join("only.yaml");
        fs::write(&only, "rule").unwrap();
        make_unreadable(&only);
        if fs::read(&only).is_ok() {
            return; // Running as root: permissions cannot deny the read.
        }
        assert!(RuleSources::fresh(dir.path()).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn rule_sources_fresh_rejects_broken_links_and_loops() {
        let dir = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink("missing", dir.path().join("broken.yaml")).unwrap();
        assert!(RuleSources::fresh(dir.path()).is_err());
        fs::remove_file(dir.path().join("broken.yaml")).unwrap();
        std::os::unix::fs::symlink(dir.path(), dir.path().join("loop")).unwrap();
        assert!(RuleSources::fresh(dir.path()).is_err());
    }
}

#[cfg(unix)]
#[test]
#[allow(clippy::unwrap_used)]
fn rule_sources_preserves_yara_symlink_traversal() {
    let dir = tempfile::tempdir().unwrap();
    fs::create_dir(dir.path().join("real")).unwrap();
    fs::write(dir.path().join("real/rule.yar"), "rule").unwrap();
    std::os::unix::fs::symlink("real", dir.path().join("link")).unwrap();
    std::os::unix::fs::symlink("real/rule.yar", dir.path().join("file-link.yar")).unwrap();
    let sources = RuleSources::fresh(dir.path()).unwrap();
    assert!(
        sources
            .file(Path::new("link/rule.yar"))
            .unwrap()
            .follows_directory_symlink()
    );
    assert!(
        !sources
            .file(Path::new("real/rule.yar"))
            .unwrap()
            .follows_directory_symlink()
    );
    assert!(
        !sources
            .file(Path::new("file-link.yar"))
            .unwrap()
            .follows_directory_symlink()
    );
    assert!(
        !sources.subtree_relative(Path::new("link")).unwrap().files()[0]
            .follows_directory_symlink()
    );
}
