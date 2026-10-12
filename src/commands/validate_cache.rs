//! Successful full-validation cache. Every lookup reads input contents; stat
//! metadata is never evidence that rules, fixtures or engine code are unchanged.
use super::{FixtureSummary, Target};
use anyhow::{Context, Result};
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

pub(super) struct ResultCache {
    key: String,
    path: PathBuf,
    traits_dir: PathBuf,
    settings: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
struct Entry {
    key: String,
    fixtures: FixtureSummary,
}

impl ResultCache {
    pub(super) fn new(
        traits_dir: &Path,
        targets: &[Target],
        expectations: &str,
        soft: bool,
        verbose: bool,
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
        // Include all environment inputs, conservatively. Changing an unknown
        // dependency knob must miss rather than reuse a possibly different run.
        let mut env: Vec<_> = std::env::vars_os().collect();
        env.retain(|(k, _)| k != "_" && k != "SHLVL");
        env.sort();
        let mut settings = Sha256::new();
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
        let paths: Vec<_> = targets.iter().map(|t| t.path().to_path_buf()).collect();
        let sources = crate::rule_sources::shared(&traits_dir).ok()?;
        let key = fingerprint_with_sources(
            &sources,
            &traits_dir,
            &paths,
            expectations,
            &settings,
            crate::traits_fingerprint::binary_identity(),
        )
        .ok()?;
        let tag = hex::encode(Sha256::digest(traits_dir.as_os_str().as_encoded_bytes()));
        let path = crate::cache::cache_dir()
            .ok()?
            .join(format!("validate-result-{}.json", &tag[..16]));
        Some(Self {
            key,
            path,
            traits_dir,
            settings,
        })
    }

    pub(super) fn load(&self) -> Option<FixtureSummary> {
        let entry: Entry = serde_json::from_slice(&std::fs::read(&self.path).ok()?).ok()?;
        if entry.key != self.key {
            return None;
        }
        tracing::info!("full validation cache hit (content verified)");
        Some(entry.fixtures)
    }

    pub(super) fn store_if_unchanged(&self, fixtures: &FixtureSummary) {
        // Recollect as well as rehash: additions/removals in walked corpora and
        // newly unlisted top-level fixtures must invalidate the completed run.
        let unchanged = (|| -> Result<bool> {
            let (targets, _, expectations) = super::collect_targets()?;
            let paths: Vec<_> = targets.iter().map(|t| t.path().to_path_buf()).collect();
            Ok(fingerprint(
                &self.traits_dir,
                &paths,
                &expectations,
                &self.settings,
                crate::traits_fingerprint::binary_identity(),
            )? == self.key)
        })();
        if !matches!(unchanged, Ok(true)) {
            tracing::info!("validation inputs changed during analysis; result not cached");
            return;
        }
        #[derive(Serialize)]
        struct BorrowedEntry<'a> {
            key: &'a str,
            fixtures: &'a FixtureSummary,
        }
        if let Ok(bytes) = serde_json::to_vec(&BorrowedEntry {
            key: &self.key,
            fixtures,
        }) {
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
    field(&mut hash, b"cleave-full-validation-v1");
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
            key("expectations", b"strict", "engine-a", &[renamed.clone()])
        );
        std::fs::rename(&renamed, &fixture).unwrap();
        std::fs::create_dir(root.join("objectives/new-directory")).unwrap();
        assert_ne!(
            before,
            key("expectations", b"strict", "engine-a", &fixtures)
        );
    }
}
