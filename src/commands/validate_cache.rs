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
        let key = fingerprint(
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
    let mut hash = Sha256::new();
    field(&mut hash, b"cleave-full-validation-v1");
    field(&mut hash, traits_dir.as_os_str().as_encoded_bytes());
    field(&mut hash, engine.as_bytes());
    field(&mut hash, settings);
    field(&mut hash, expectations.as_bytes());
    let mut files = Vec::new();
    for entry in walkdir::WalkDir::new(traits_dir)
        .follow_links(true)
        .sort_by_file_name()
        .into_iter()
        .filter_entry(crate::traits_repo::is_rule_source_entry)
    {
        // Unlike opportunistic caches, a validation proof must fail closed on
        // unreadable directories, symlink loops, or unreadable inputs.
        let entry = entry?;
        if entry.file_type().is_dir() {
            field(
                &mut hash,
                entry
                    .path()
                    .strip_prefix(traits_dir)?
                    .as_os_str()
                    .as_encoded_bytes(),
            );
        } else if entry.file_type().is_file()
            && (matches!(
                entry.path().extension().and_then(|s| s.to_str()),
                Some("yaml" | "yml" | "yar" | "yara" | "yrc")
            ) || entry.file_name() == "manifest.json")
        {
            files.push(entry.into_path());
        }
    }
    let cwd = std::env::current_dir()?;
    files.extend(fixtures.iter().map(|p| {
        if p.is_absolute() {
            p.clone()
        } else {
            // Preserve the caller's logical fixture basename and directory.
            cwd.join(p)
        }
    }));
    files.sort();
    let digests: Result<Vec<_>> = files
        .par_iter()
        .map(|path| {
            let bytes =
                std::fs::read(path).with_context(|| format!("hashing {}", path.display()))?;
            let mut file = Sha256::new();
            field(&mut file, path.as_os_str().as_encoded_bytes());
            field(&mut file, &bytes);
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
