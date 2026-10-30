//! Immutable source bytes shared by hashing, trait parsing and YARA loading.
//! Packed rule files have virtual paths without `.zst` so all consumers see
//! the same rule names and fingerprints as an unpacked traits checkout.
//! A fresh snapshot reads every byte again; no stat-only cache is involved.
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
        let started = std::time::Instant::now();
        let root =
            fs::canonicalize(root).with_context(|| format!("resolving {}", root.display()))?;
        let mut paths = Vec::new();
        let mut directories = Vec::new();
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
         -> Option<SourceFile> {
            let path = root.join(&stored_path);
            let read = || -> std::io::Result<(Vec<u8>, Option<SystemTime>)> {
                let mut file = fs::File::open(&path)?;
                let metadata = file.metadata()?;
                let mut bytes = Vec::with_capacity(usize::try_from(metadata.len()).unwrap_or(0));
                file.read_to_end(&mut bytes)?;
                if compressed {
                    bytes = zstd::decode_all(&bytes[..])?;
                }
                Ok((bytes, metadata.modified().ok()))
            };
            match read() {
                Ok((bytes, modified)) => Some(SourceFile {
                    relative_path,
                    bytes: bytes.into(),
                    modified,
                    symlink_directories,
                }),
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
        files.sort_unstable_by(|a, b| a.relative_path.cmp(&b.relative_path));
        if files
            .windows(2)
            .any(|pair| pair[0].relative_path == pair[1].relative_path)
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
        tracing::info!(root = %root.display(), files = files.len(),
            bytes = files.iter().map(|f| f.bytes.len()).sum::<usize>(),
            read_ms = started.elapsed().as_millis(), "rule source snapshot read");
        Ok(Self::from_files(root, files, directories))
    }

    fn from_files(root: PathBuf, files: Vec<SourceFile>, directories: Vec<PathBuf>) -> Self {
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
        }
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
        Some(Self::from_files(root.to_path_buf(), files, directories))
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
