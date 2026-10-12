//! Immutable source bytes shared by hashing, trait parsing and YARA loading.
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

/// One source file from an immutable rule tree snapshot.
#[derive(Clone, Debug)]
pub struct SourceFile {
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
pub struct RuleSources {
    root: PathBuf,
    files: Vec<SourceFile>,
    directories: Vec<PathBuf>,
    lookup: FxHashMap<PathBuf, usize>,
}

impl RuleSources {
    /// Read a new snapshot, including directory layout and validation artifacts.
    /// Fail closed on unreadable inputs and symlink loops.
    pub fn fresh(root: &Path) -> Result<Self> {
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
            } else if entry.file_type().is_file()
                && (matches!(
                    entry.path().extension().and_then(|e| e.to_str()),
                    Some("yaml" | "yml" | "yar" | "yara" | "yrc")
                ) || entry.file_name() == "manifest.json")
            {
                paths.push((
                    relative,
                    symlink_directories
                        .iter()
                        .map(|(_, p)| p.clone())
                        .collect::<Vec<_>>(),
                ));
            }
        }
        let read_file =
            |(relative_path, symlink_directories): (PathBuf, Vec<PathBuf>)| -> Result<SourceFile> {
                let path = root.join(&relative_path);
                let mut file =
                    fs::File::open(&path).with_context(|| format!("reading {}", path.display()))?;
                let metadata = file.metadata()?;
                let mut bytes = Vec::with_capacity(usize::try_from(metadata.len()).unwrap_or(0));
                file.read_to_end(&mut bytes)
                    .with_context(|| format!("reading {}", path.display()))?;
                Ok(SourceFile {
                    relative_path,
                    bytes: bytes.into(),
                    modified: metadata.modified().ok(),
                    symlink_directories,
                })
            };
        // Global YARA initialization may be entered by a Rayon worker while
        // its peers wait on the singleton. Do not enqueue work into that pool.
        let files: Result<Vec<_>> = if rayon::current_thread_index().is_some() {
            paths.into_iter().map(read_file).collect()
        } else {
            paths.into_par_iter().map(read_file).collect()
        };
        let files = files?;
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
    pub fn files(&self) -> &[SourceFile] {
        &self.files
    }
    /// Directory layout, including the root as an empty relative path.
    pub fn directories(&self) -> &[PathBuf] {
        &self.directories
    }
    /// Look up a source by its root-relative path.
    pub fn file(&self, relative: &Path) -> Option<&SourceFile> {
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
pub fn shared(root: &Path) -> Result<Arc<RuleSources>> {
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
