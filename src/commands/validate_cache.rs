//! Full-validation outcomes.
//!
//! An outcome is published under a *content key*: a SHA-256 over every rule
//! source and fixture's bytes, the engine build, and every setting that can
//! change what validation reports. That key is the proof of reuse.
//!
//! Reading 200 MB of rule sources and fixtures to recompute it on every run
//! costs more than a second, so each entry also carries a *stamp*: a digest of
//! the directory walk's metadata (every path, size and modification time, plus
//! the executable's) taken when the content key was last verified. A run whose
//! walk reproduces the stamp reuses the outcome without opening a file; a run
//! whose walk differs falls back to the content key, and refreshes the stamp
//! when the contents turn out unchanged (a `touch`, a re-checkout). The stamp
//! is a shortcut to the content key, never a substitute for it: an edit that
//! keeps a file's size and preserves its modification time would hide from it,
//! which no editor, checkout or sync tool does by default. `CLEAVE_SKIP_CACHE=1`
//! bypasses both.
use super::{FixtureSummary, Target};
use anyhow::{Context, Result};
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

pub(super) struct ResultCache {
    path: PathBuf,
    traits_dir: PathBuf,
    fixtures: Vec<PathBuf>,
    expectations: &'static str,
    settings: Vec<u8>,
    /// The walk stamp of the inputs as this run found them.
    stamp: String,
    /// The content key, derived from the shared rule snapshot and the
    /// fixtures' bytes on first use. A stamp hit never needs it.
    key: OnceLock<Option<String>>,
}

#[derive(Serialize, Deserialize)]
struct Entry {
    key: String,
    outcome: Outcome,
    /// Walk stamp at the time `key` was verified by content.
    #[serde(default)]
    stamp: Option<String>,
    /// `traits_repo::version()` at that time; deriving it again would hash
    /// the whole tree.
    #[serde(default)]
    traits_version: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub(super) enum Outcome {
    Passed(FixtureSummary),
    /// A measured performance rejection is still a rejection on replay. Never
    /// cache operational errors or promote an incomplete analysis to a pass.
    PerformanceRejected(Vec<PerformanceIssue>),
}

/// A cached outcome and the traits version it was recorded under.
pub(super) struct Hit {
    pub(super) outcome: Outcome,
    pub(super) traits_version: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub(super) struct PerformanceIssue {
    message: String,
    file: Option<String>,
    line: Option<usize>,
    rule_id: Option<String>,
}

impl PerformanceIssue {
    pub(super) fn restore(self) -> crate::validation_controls::ValidationIssue {
        let mut issue =
            crate::validation_controls::ValidationIssue::new("rule-performance", self.message);
        issue.file = self.file;
        issue.line = self.line;
        issue.rule_id = self.rule_id;
        issue
    }
}

impl ResultCache {
    pub(super) fn new(
        traits_dir: &Path,
        rule_tree: Option<[u8; 32]>,
        targets: &[Target],
        expectations: &'static str,
        soft: bool,
        verbose: bool,
        slow_rule_ms: u64,
    ) -> Option<Self> {
        // These modes ask for work/diagnostics beyond a previously passed gate.
        if soft
            || verbose
            || crate::cache::skip_cache()
            || crate::cache::skip_mapper_cache()
            || [
                "CLEAVE_SKIP_CLEAN_MARK",
                "CLEAVE_TRAIT_TIMING",
                "CLEAVE_PHASE_STATS",
            ]
            .iter()
            .any(|k| std::env::var(k).is_ok_and(|v| v == "1" || v == "true"))
        {
            return None;
        }
        let traits_dir = std::fs::canonicalize(traits_dir).ok()?;
        // Every variable that can change a result: cleave's and filefacts' own
        // knobs, and PATH, which decides which external tools (7-Zip, UPX)
        // analysis can use.
        let mut env: Vec<_> = std::env::vars_os()
            .filter(|(k, _)| {
                k.to_str().is_some_and(|k| {
                    k == "PATH" || k.starts_with("CLEAVE_") || k.starts_with("FILEFACTS_")
                })
            })
            .collect();
        env.sort();
        let mut settings = Sha256::new();
        field(&mut settings, &slow_rule_ms.to_le_bytes());
        for (k, v) in env {
            field(&mut settings, k.as_encoded_bytes());
            field(&mut settings, v.as_encoded_bytes());
        }
        field(
            &mut settings,
            format!(
                "{:?}",
                crate::validation_controls::disabled_validators_by_category()
            )
            .as_bytes(),
        );
        field(
            &mut settings,
            format!("{:?}", crate::yara_engine::result_affecting_overrides()).as_bytes(),
        );
        field(
            &mut settings,
            &[u8::from(crate::shared_resources::skip_traits_requested())],
        );
        let settings = settings.finalize().to_vec();
        let fixtures: Vec<_> = targets.iter().map(|t| t.path().to_path_buf()).collect();
        let stamp = walk_stamp(&traits_dir, expectations, &settings, rule_tree?, targets)?;
        let tag = hex::encode(Sha256::digest(traits_dir.as_os_str().as_encoded_bytes()));
        let path = crate::cache::cache_dir()
            .ok()?
            .join(format!("validate-result-{}.json", &tag[..16]));
        Some(Self {
            path,
            traits_dir,
            fixtures,
            expectations,
            settings,
            stamp,
            key: OnceLock::new(),
        })
    }

    /// The digest of every setting that can change a result, for the
    /// per-fixture state to key on the same way.
    pub(super) fn settings(&self) -> &[u8] {
        &self.settings
    }

    /// The content key of the inputs this run validates: the shared rule
    /// snapshot (read once, then reused by the mapper load) and the fixtures.
    fn key(&self) -> Option<&str> {
        self.key
            .get_or_init(|| {
                let sources = crate::rule_sources::shared(&self.traits_dir).ok()?;
                let key = fingerprint_with_sources(
                    &sources,
                    &self.traits_dir,
                    &self.fixtures,
                    self.expectations,
                    &self.settings,
                    crate::traits_fingerprint::binary_identity(),
                )
                .ok()?;
                tracing::debug!(key = %key, settings = %hex::encode(&self.settings),
                    engine = crate::traits_fingerprint::binary_identity(), "validation cache fingerprint");
                Some(key)
            })
            .as_deref()
    }

    pub(super) fn load(&self) -> Option<Hit> {
        let bytes = std::fs::read(&self.path).ok()?;
        let entry: Entry = match serde_json::from_slice(&bytes) {
            Ok(entry) => entry,
            Err(error) => {
                tracing::debug!(%error, "validation cache entry could not be decoded");
                return None;
            }
        };
        if entry.stamp.as_deref() == Some(self.stamp.as_str()) {
            tracing::info!("full validation cache hit (walk stamp verified)");
            return Some(Hit {
                outcome: entry.outcome,
                traits_version: entry.traits_version,
            });
        }
        let key = self.key()?;
        if entry.key != key {
            tracing::debug!(cached = %entry.key, current = %key, "validation cache inputs differ");
            return None;
        }
        tracing::info!("full validation cache hit (content verified); walk stamp refreshed");
        // The contents are what passed; only metadata moved. Re-stamp so the
        // next run can stop at the walk.
        self.write(&Entry {
            key: key.to_owned(),
            outcome: entry.outcome,
            stamp: Some(self.stamp.clone()),
            traits_version: entry.traits_version,
        });
        let entry: Entry = serde_json::from_slice(&bytes).ok()?;
        Some(Hit {
            outcome: entry.outcome,
            traits_version: entry.traits_version,
        })
    }

    pub(super) fn store_if_unchanged(&self, fixtures: &FixtureSummary) {
        self.store_outcome_if_unchanged(&Outcome::Passed(fixtures.clone()));
    }

    pub(super) fn store_rejection_if_unchanged(
        &self,
        issues: &[crate::validation_controls::ValidationIssue],
    ) {
        self.store_outcome_if_unchanged(&Outcome::PerformanceRejected(
            issues
                .iter()
                .map(|issue| PerformanceIssue {
                    message: issue.message.clone(),
                    file: issue.file.clone(),
                    line: issue.line,
                    rule_id: issue.rule_id.clone(),
                })
                .collect(),
        ));
    }

    fn store_outcome_if_unchanged(&self, outcome: &Outcome) {
        let Some(key) = self.key() else {
            return;
        };
        // What was validated is the snapshot `key` digests. It is what is on
        // disk now if the walk stamps the same tree it did before the run:
        // the fixtures are discovered again (an added or removed one is a
        // different stamp) and every rule file's metadata is read again,
        // the same evidence that admits a hit. When the stamp moved, the
        // contents decide: read again and digested, they are either still
        // what was validated (a directory listing that had not yet caught up
        // with a write made just before the run, a `touch`), and the result
        // is stored under the stamp as it stands now, or they are not, and
        // the result is not stored.
        let Ok(targets) = super::collect_targets() else {
            return;
        };
        let stamp = stamp_rule_tree(&self.traits_dir).and_then(|rule_tree| {
            walk_stamp(
                &self.traits_dir,
                self.expectations,
                &self.settings,
                rule_tree,
                &targets,
            )
        });
        if stamp.as_deref() != Some(self.stamp.as_str()) {
            let paths: Vec<_> = targets.iter().map(|t| t.path().to_path_buf()).collect();
            let fresh = fingerprint(
                &self.traits_dir,
                &paths,
                self.expectations,
                &self.settings,
                crate::traits_fingerprint::binary_identity(),
            );
            if fresh.ok().as_deref() != Some(key) {
                tracing::info!("validation inputs changed during analysis; result not cached");
                return;
            }
            tracing::info!(
                "validation inputs moved but read the same; result cached under the new stamp"
            );
        }
        let entry = Entry {
            key: key.to_owned(),
            outcome: match outcome {
                Outcome::Passed(f) => Outcome::Passed(f.clone()),
                Outcome::PerformanceRejected(issues) => Outcome::PerformanceRejected(
                    issues
                        .iter()
                        .map(|i| PerformanceIssue {
                            message: i.message.clone(),
                            file: i.file.clone(),
                            line: i.line,
                            rule_id: i.rule_id.clone(),
                        })
                        .collect(),
                ),
            },
            stamp,
            traits_version: crate::traits_repo::version(),
        };
        self.write(&entry);
    }

    fn write(&self, entry: &Entry) {
        if let Ok(bytes) = serde_json::to_vec(entry) {
            if let Err(error) = crate::cache::atomic_write(&self.path, &bytes) {
                tracing::debug!(%error, "validation result cache write failed");
            } else {
                tracing::info!("full validation result cached");
            }
        }
    }
}

fn field(hash: &mut Sha256, bytes: &[u8]) {
    hash.update((bytes.len() as u64).to_le_bytes());
    hash.update(bytes);
}

/// Metadata of one walked entry, as the stamp records it.
fn stamp_entry(hash: &mut Sha256, relative: &Path, metadata: &std::fs::Metadata) {
    field(hash, relative.as_os_str().as_encoded_bytes());
    let kind: u8 = if metadata.is_dir() {
        b'd'
    } else if metadata.is_file() {
        b'f'
    } else {
        b'o'
    };
    hash.update([kind]);
    hash.update(metadata.len().to_le_bytes());
    let modified = metadata
        .modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map_or(u128::MAX, |d| d.as_nanos());
    hash.update(modified.to_le_bytes());
    // The inode tells a replaced file from a rewritten one. The
    // status-change time would too, but it also moves when a fixture is
    // hard-linked into its neutral stage, which every run does.
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        hash.update(metadata.ino().to_le_bytes());
        hash.update(metadata.dev().to_le_bytes());
    }
}

/// The rule tree's metadata digest: every entry under the rule source
/// directories that [`crate::rule_sources::RuleSources::fresh`] would read
/// (links followed), hashed by path and metadata. Each directory is read
/// once, its children in name order, and subdirectories are digested on the
/// pool and folded in that order, so the digest is a function of the tree
/// alone while the walk fans out at every level.
pub(super) fn stamp_rule_tree(root: &Path) -> Option<[u8; 32]> {
    let started = std::time::Instant::now();
    let root_has_traits = crate::traits_repo::has_traits(root);
    let mut hash = Sha256::new();
    stamp_dir(root, root, 0, root_has_traits, &mut hash)?;
    let digest: [u8; 32] = hash.finalize().into();
    tracing::info!(
        elapsed_ms = started.elapsed().as_millis(),
        "rule tree metadata digested"
    );
    Some(digest)
}

/// Deepest directory nesting followed, so a link cycle ends.
const MAX_WALK_DEPTH: usize = 64;

fn stamp_dir(
    root: &Path,
    dir: &Path,
    depth: usize,
    root_has_traits: bool,
    hash: &mut Sha256,
) -> Option<()> {
    let mut entries: Vec<(std::ffi::OsString, std::fs::DirEntry)> = std::fs::read_dir(dir)
        .ok()?
        .map(|entry| entry.map(|entry| (entry.file_name(), entry)))
        .collect::<std::io::Result<_>>()
        .ok()?;
    entries.sort_by(|a, b| a.0.cmp(&b.0));
    let mut subdirs = Vec::new();
    for (name, entry) in entries {
        let file_type = entry.file_type().ok()?;
        let path = entry.path();
        let (is_dir, metadata) = if file_type.is_symlink() {
            // Followed, as the source walk follows it; a dangling link is a
            // structural problem the source walk fails on too.
            let metadata = std::fs::metadata(&path).ok()?;
            (metadata.is_dir(), metadata)
        } else {
            (file_type.is_dir(), entry.metadata().ok()?)
        };
        if is_dir && !rule_directory_admitted(&name, depth + 1, root_has_traits) {
            continue;
        }
        stamp_entry(hash, path.strip_prefix(root).ok()?, &metadata);
        if is_dir && depth < MAX_WALK_DEPTH {
            subdirs.push(path);
        }
    }
    let digests: Vec<Option<[u8; 32]>> = subdirs
        .par_iter()
        .map(|subdir| {
            let mut hash = Sha256::new();
            stamp_dir(root, subdir, depth + 1, root_has_traits, &mut hash)?;
            Some(hash.finalize().into())
        })
        .collect();
    for digest in digests {
        hash.update(digest?);
    }
    Some(())
}

/// [`crate::traits_repo::is_rule_source_entry`] for a directory at `depth`
/// below the root: hidden, underscored and `testdata` directories are not
/// rule sources, and at the first level only the rule source directories are.
fn rule_directory_admitted(name: &std::ffi::OsStr, depth: usize, root_has_traits: bool) -> bool {
    let name = name.to_string_lossy();
    if name.starts_with('.') || name.starts_with('_') || name == "testdata" {
        return false;
    }
    if depth == 1 && root_has_traits {
        return crate::traits_repo::RULE_SOURCE_DIRS.contains(&name.as_ref());
    }
    true
}

/// The stamp of this run's inputs: the rule tree's metadata digest, the
/// fixtures with the metadata their discovery walk read, the executable, and
/// the settings.
fn walk_stamp(
    root: &Path,
    expectations: &str,
    settings: &[u8],
    rule_tree: [u8; 32],
    targets: &[Target],
) -> Option<String> {
    let mut hash = Sha256::new();
    field(&mut hash, b"cleave-validate-walk-stamp-v3");
    field(&mut hash, root.as_os_str().as_encoded_bytes());
    field(&mut hash, expectations.as_bytes());
    field(&mut hash, settings);
    // The build: the content key names it by build-id or by a digest of
    // the executable, which a stamp hit never has to compute.
    let exe = std::env::current_exe().ok()?;
    let exe_metadata = std::fs::metadata(&exe).ok()?;
    stamp_entry(&mut hash, &exe, &exe_metadata);
    hash.update(rule_tree);
    for target in targets {
        let relative = target.path().strip_prefix(root).unwrap_or(target.path());
        stamp_entry(&mut hash, relative, target.metadata.as_ref()?);
    }
    Some(hex::encode(hash.finalize()))
}

fn fingerprint(
    traits_dir: &Path,
    fixtures: &[PathBuf],
    expectations: &str,
    settings: &[u8],
    engine: &str,
) -> Result<String> {
    let sources = crate::rule_sources::RuleSources::fresh(traits_dir)?;
    fingerprint_with_sources(
        &sources,
        traits_dir,
        fixtures,
        expectations,
        settings,
        engine,
    )
}

fn fingerprint_with_sources(
    sources: &crate::rule_sources::RuleSources,
    traits_dir: &Path,
    fixtures: &[PathBuf],
    expectations: &str,
    settings: &[u8],
    engine: &str,
) -> Result<String> {
    let mut hash = Sha256::new();
    field(&mut hash, b"cleave-full-validation-v5");
    field(&mut hash, traits_dir.as_os_str().as_encoded_bytes());
    field(&mut hash, engine.as_bytes());
    field(&mut hash, settings);
    field(&mut hash, expectations.as_bytes());
    for dir in sources.directories() {
        field(&mut hash, dir.as_os_str().as_encoded_bytes());
    }
    let mut files: Vec<_> = sources
        .files()
        .iter()
        .map(|file| {
            (
                traits_dir.join(&file.relative_path),
                Some(file.bytes.clone()),
            )
        })
        .collect();
    let cwd = std::env::current_dir()?;
    files.extend(fixtures.iter().map(|p| {
        let path = if p.is_absolute() {
            p.clone()
        } else {
            cwd.join(p)
        };
        (path, None)
    }));
    files.sort_by(|a, b| a.0.cmp(&b.0));
    let digests: Result<Vec<_>> = files
        .par_iter()
        .map(|(path, bytes)| {
            let fresh;
            let bytes = match bytes {
                Some(bytes) => bytes.as_ref(),
                None => {
                    fresh = std::fs::read(path)
                        .with_context(|| format!("hashing {}", path.display()))?;
                    &fresh
                }
            };
            let mut file = Sha256::new();
            field(&mut file, path.as_os_str().as_encoded_bytes());
            field(&mut file, bytes);
            Ok(file.finalize())
        })
        .collect();
    for digest in digests? {
        field(&mut hash, &digest);
    }
    Ok(hex::encode(hash.finalize()))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn validation_snapshot_key_requires_fresh_publication_check() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let rule = root.join("rule.yaml");
        std::fs::write(&rule, "before").unwrap();
        let snapshot = crate::rule_sources::RuleSources::fresh(root).unwrap();
        let initial =
            fingerprint_with_sources(&snapshot, root, &[], "expected", b"settings", "engine")
                .unwrap();
        assert_eq!(
            initial,
            fingerprint(root, &[], "expected", b"settings", "engine").unwrap()
        );
        let mtime = std::fs::metadata(&rule).unwrap().modified().unwrap();
        std::fs::write(&rule, "edited").unwrap();
        std::fs::File::options()
            .write(true)
            .open(&rule)
            .unwrap()
            .set_modified(mtime)
            .unwrap();
        // Parsing still sees the initial bytes, but a successful validation
        // must never be published under that key after the on-disk edit.
        assert_eq!(
            initial,
            fingerprint_with_sources(&snapshot, root, &[], "expected", b"settings", "engine")
                .unwrap()
        );
        assert_ne!(
            initial,
            fingerprint(root, &[], "expected", b"settings", "engine").unwrap()
        );
    }

    #[test]
    fn validation_key_reads_contents_and_all_inputs() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::create_dir_all(root.join("objectives")).unwrap();
        std::fs::create_dir_all(root.join("testdata")).unwrap();
        let rule = root.join("objectives/rule.yaml");
        let fixture = root.join("testdata/sample.js");
        std::fs::write(&rule, b"rule: a").unwrap();
        std::fs::write(&fixture, b"data: a").unwrap();
        let key = |expectations: &str, settings: &[u8], engine: &str, fixtures: &[PathBuf]| {
            fingerprint(root, fixtures, expectations, settings, engine).unwrap()
        };
        let fixtures = vec![fixture.clone()];
        let before = key("expectations", b"strict", "engine-a", &fixtures);
        assert_eq!(
            before,
            key("expectations", b"strict", "engine-a", &fixtures)
        );
        let added = root.join("objectives/added.yaml");
        std::fs::write(&added, b"rule: new").unwrap();
        assert_ne!(
            before,
            key("expectations", b"strict", "engine-a", &fixtures)
        );
        std::fs::remove_file(added).unwrap();
        assert_eq!(
            before,
            key("expectations", b"strict", "engine-a", &fixtures)
        );
        assert_ne!(before, key("changed", b"strict", "engine-a", &fixtures));
        assert_ne!(before, key("expectations", b"soft", "engine-a", &fixtures));
        assert_ne!(
            before,
            key("expectations", b"strict", "engine-b", &fixtures)
        );
        for path in [&rule, &fixture] {
            let original = std::fs::read(path).unwrap();
            let mtime = std::fs::metadata(path).unwrap().modified().unwrap();
            let mut edited = original.clone();
            *edited.last_mut().unwrap() = b'b';
            std::fs::write(path, &edited).unwrap();
            std::fs::File::options()
                .write(true)
                .open(path)
                .unwrap()
                .set_modified(mtime)
                .unwrap();
            assert_ne!(
                before,
                key("expectations", b"strict", "engine-a", &fixtures)
            );
            std::fs::write(path, original).unwrap();
        }
        let renamed = root.join("testdata/other.js");
        std::fs::rename(&fixture, &renamed).unwrap();
        assert!(fingerprint(root, &fixtures, "expectations", b"strict", "engine-a").is_err());
        assert_ne!(
            before,
            key(
                "expectations",
                b"strict",
                "engine-a",
                std::slice::from_ref(&renamed)
            )
        );
        std::fs::rename(&renamed, &fixture).unwrap();
        std::fs::create_dir(root.join("objectives/new-directory")).unwrap();
        assert_ne!(
            before,
            key("expectations", b"strict", "engine-a", &fixtures)
        );
    }

    /// The walk stamp moves on every change the content key would see
    /// (contents, names, layout, settings) and holds across identical walks.
    #[test]
    fn walk_stamp_tracks_metadata_of_rules_fixtures_and_layout() {
        let dir = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(dir.path()).unwrap();
        std::fs::create_dir_all(root.join("objectives/a")).unwrap();
        std::fs::create_dir_all(root.join("testdata/hostile")).unwrap();
        let rule = root.join("objectives/a/rule.yaml");
        let fixture = root.join("testdata/hostile/sample.js");
        std::fs::write(&rule, b"rule: a").unwrap();
        std::fs::write(&fixture, b"data: a").unwrap();
        let stamp = |settings: &[u8]| {
            let targets = super::super::discover_targets(&root.join("testdata")).unwrap();
            let rule_tree = stamp_rule_tree(&root).unwrap();
            walk_stamp(&root, "expected", settings, rule_tree, &targets).unwrap()
        };
        let before = stamp(b"settings");
        assert_eq!(before, stamp(b"settings"));
        assert_ne!(before, stamp(b"other"));
        // A longer write: size and mtime both move.
        std::fs::write(&rule, b"rule: longer").unwrap();
        let after_rule = stamp(b"settings");
        assert_ne!(before, after_rule);
        std::fs::write(&fixture, b"data: longer").unwrap();
        let after_fixture = stamp(b"settings");
        assert_ne!(after_rule, after_fixture);
        // A modification time alone, contents and size untouched.
        let later = std::time::SystemTime::now() + std::time::Duration::from_secs(120);
        std::fs::File::options()
            .write(true)
            .open(&rule)
            .unwrap()
            .set_modified(later)
            .unwrap();
        let after_touch = stamp(b"settings");
        assert_ne!(after_fixture, after_touch);
        // Layout: an empty directory is an entry too.
        std::fs::create_dir(root.join("objectives/b")).unwrap();
        assert_ne!(after_touch, stamp(b"settings"));
        // Entries outside the rule and fixture trees are not inputs.
        let docs = stamp(b"settings");
        std::fs::create_dir(root.join("docs")).unwrap();
        std::fs::write(root.join("docs/notes.md"), b"x").unwrap();
        assert_eq!(docs, stamp(b"settings"));
    }
}
