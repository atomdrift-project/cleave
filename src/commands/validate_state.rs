//! What each fixture was last analyzed as, so an edit re-analyzes only the
//! fixtures it can have changed.
//!
//! A rule produces findings only on files whose type its `for:` admits (and
//! on the files of rules that depend on it, see
//! [`CapabilityMapper::rule_file_scopes`]). After a run, every fixture is
//! recorded with the types of the files its report held, every trait file
//! with a content digest and its scope. The next run digests the trait files
//! again, takes the scopes of those that changed, appeared or went away under
//! both the old and the new rule set, and re-analyzes a fixture only when its
//! types meet that scope, when its own bytes changed, or when it did not pass
//! last time. Everything the scope rule cannot follow (YARA sources, the
//! engine, settings, the fixture tree's expectations) is a full run.
//!
//! The state is advisory for scheduling and reuse only: every fixture's
//! verdict was produced by a full analysis of that fixture under a rule set
//! that, for its types, is the one in force.
use super::Target;
use crate::composite_rules::{FileType, TypeMask};
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

const FORMAT: &str = "cleave-validate-fixtures-v1";

#[derive(Serialize, Deserialize)]
pub(super) struct FixtureState {
    format: String,
    engine: String,
    settings: Vec<u8>,
    expectations: String,
    /// Digest of every rule source that is not a trait YAML file (YARA
    /// sources, manifests, files the trait loader skips): a change there
    /// cannot be scoped and widens to every fixture.
    other_sources: [u8; 32],
    /// Trait YAML files by root-relative path.
    rules: BTreeMap<String, RuleFile>,
    /// Fixtures by root-relative path.
    fixtures: BTreeMap<String, Fixture>,
}

#[derive(Serialize, Deserialize, Clone)]
pub(super) struct RuleFile {
    digest: [u8; 32],
    /// The types this file's rules and their dependents admit.
    scope: [u64; 4],
}

#[derive(Serialize, Deserialize, Clone)]
pub(super) struct Fixture {
    digest: [u8; 32],
    /// The types of every file in the fixture's report.
    types: [u64; 4],
    passed: bool,
    /// How long its last analysis took, for scheduling (see `Plan::whales`).
    pub(super) elapsed_ms: u64,
}

/// The trait YAML files and other sources of the current tree, digested.
pub(super) struct CurrentRules {
    rules: BTreeMap<String, [u8; 32]>,
    other_sources: [u8; 32],
}

impl CurrentRules {
    /// Digest the snapshot the mapper was loaded from. Trait files are the
    /// ones the loader reads (`.yaml`, outside `third-party/`, not a README
    /// or EXAMPLE); everything else in the snapshot is an "other" source.
    pub(super) fn of(sources: &crate::rule_sources::RuleSources) -> Self {
        let mut rules = BTreeMap::new();
        let mut other = Sha256::new();
        let digests: Vec<(String, bool, [u8; 32])> = sources
            .files()
            .par_iter()
            .map(|file| {
                let key = crate::capabilities::scope_key(&file.relative_path);
                let filename = file
                    .relative_path
                    .file_name()
                    .and_then(|f| f.to_str())
                    .unwrap_or("");
                let is_trait_file = file.relative_path.extension().is_some_and(|e| e == "yaml")
                    && !file
                        .relative_path
                        .components()
                        .any(|c| c.as_os_str() == "third-party")
                    && !filename.to_lowercase().contains("readme")
                    && !filename.starts_with("EXAMPLE");
                let mut hash = Sha256::new();
                hash.update(&file.bytes);
                (key, is_trait_file, hash.finalize().into())
            })
            .collect();
        for (key, is_trait_file, digest) in digests {
            if is_trait_file {
                rules.insert(key, digest);
            } else {
                other.update((key.len() as u64).to_le_bytes());
                other.update(key.as_bytes());
                other.update(digest);
            }
        }
        Self {
            rules,
            other_sources: other.finalize().into(),
        }
    }
}

/// Which fixtures the current run analyzes, and what it reuses.
pub(super) struct Plan {
    /// Per target, whether it is analyzed this run.
    pub(super) run: Vec<bool>,
    /// Per target, its record from the last run, where there is one.
    previous: Vec<Option<Fixture>>,
}

impl Plan {
    /// Analyze everything; nothing to reuse.
    pub(super) fn full(targets: usize) -> Self {
        Self {
            run: vec![true; targets],
            previous: vec![None; targets],
        }
    }

    pub(super) fn reused(&self) -> usize {
        self.run.iter().filter(|run| !**run).count()
    }

    /// The last run's duration of target `i`, when known.
    pub(super) fn previous_elapsed_ms(&self, i: usize) -> Option<u64> {
        self.previous[i].as_ref().map(|f| f.elapsed_ms)
    }
}

/// Root-relative key of a fixture.
fn fixture_key(root: &Path, target: &Target) -> String {
    let relative = target.path().strip_prefix(root).unwrap_or(target.path());
    relative.to_string_lossy().replace('\\', "/")
}

/// Content digests of every fixture, read in parallel.
pub(super) fn fixture_digests(targets: &[Target]) -> Vec<Option<[u8; 32]>> {
    targets
        .par_iter()
        .map(|t| {
            let bytes = std::fs::read(t.path()).ok()?;
            Some(Sha256::digest(&bytes).into())
        })
        .collect()
}

impl FixtureState {
    pub(super) fn path(traits_dir: &Path) -> Option<PathBuf> {
        let tag = hex::encode(Sha256::digest(traits_dir.as_os_str().as_encoded_bytes()));
        Some(
            crate::cache::cache_dir()
                .ok()?
                .join(format!("validate-fixtures-{}.bin", &tag[..16])),
        )
    }

    /// The last run's state, if it was recorded by this build under these
    /// settings and expectations.
    pub(super) fn load(
        path: &Path,
        engine: &str,
        settings: &[u8],
        expectations: &str,
    ) -> Option<Self> {
        let bytes = std::fs::read(path).ok()?;
        let (state, _): (Self, usize) =
            bincode::serde::decode_from_slice(&bytes, bincode::config::standard()).ok()?;
        (state.format == FORMAT
            && state.engine == engine
            && state.settings == settings
            && state.expectations == expectations)
            .then_some(state)
    }

    /// Decide what the current run must analyze.
    ///
    /// `scopes` is the current rule set's file scopes; a changed or removed
    /// file contributes its recorded scope, a changed or added file the
    /// current one, so a rule whose `for:` moved is followed on both sides.
    pub(super) fn plan(
        previous: Option<&Self>,
        root: &Path,
        targets: &[Target],
        digests: &[Option<[u8; 32]>],
        current: &CurrentRules,
        scopes: &BTreeMap<String, TypeMask>,
    ) -> Plan {
        let Some(previous) = previous else {
            return Plan::full(targets.len());
        };
        if previous.other_sources != current.other_sources {
            tracing::info!(
                "rule sources outside the trait files changed; every fixture is analyzed"
            );
            return Plan::full(targets.len());
        }
        let mut affected = TypeMask::EMPTY;
        let mut changed_files = 0usize;
        for (path, old) in &previous.rules {
            match current.rules.get(path) {
                Some(digest) if *digest == old.digest => {}
                Some(_) => {
                    changed_files += 1;
                    affected |= TypeMask::from_words(old.scope);
                    affected |= scopes.get(path).copied().unwrap_or(TypeMask::ALL);
                }
                None => {
                    changed_files += 1;
                    affected |= TypeMask::from_words(old.scope);
                }
            }
        }
        for path in current.rules.keys() {
            if !previous.rules.contains_key(path) {
                changed_files += 1;
                affected |= scopes.get(path).copied().unwrap_or(TypeMask::ALL);
            }
        }
        let mut run = Vec::with_capacity(targets.len());
        let mut previous_records = Vec::with_capacity(targets.len());
        for (target, digest) in targets.iter().zip(digests) {
            let record = previous.fixtures.get(&fixture_key(root, target)).cloned();
            let reuse = match (&record, digest) {
                (Some(record), Some(digest)) => {
                    record.passed
                        && record.digest == *digest
                        && !TypeMask::from_words(record.types).intersects(affected)
                }
                _ => false,
            };
            run.push(!reuse);
            previous_records.push(record);
        }
        let plan = Plan {
            run,
            previous: previous_records,
        };
        tracing::info!(
            changed_files,
            analyzed = targets.len() - plan.reused(),
            reused = plan.reused(),
            "fixtures an edit can have changed"
        );
        plan
    }

    /// Record this run: the current rule files with their scopes, each
    /// analyzed fixture from its report, each reused fixture as it was.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn record(
        root: &Path,
        engine: &str,
        settings: &[u8],
        expectations: &str,
        current: CurrentRules,
        scopes: &BTreeMap<String, TypeMask>,
        targets: &[Target],
        digests: &[Option<[u8; 32]>],
        plan: &Plan,
        outcomes: &[Option<FixtureOutcome>],
    ) -> Self {
        let rules = current
            .rules
            .into_iter()
            .map(|(path, digest)| {
                let scope = scopes.get(&path).copied().unwrap_or(TypeMask::ALL);
                (
                    path,
                    RuleFile {
                        digest,
                        scope: scope.words(),
                    },
                )
            })
            .collect();
        let mut fixtures = BTreeMap::new();
        for (i, target) in targets.iter().enumerate() {
            let Some(digest) = digests[i] else { continue };
            let record = if plan.run[i] {
                match &outcomes[i] {
                    Some(outcome) => Fixture {
                        digest,
                        types: outcome.types.words(),
                        passed: outcome.passed,
                        elapsed_ms: outcome.elapsed_ms,
                    },
                    None => continue,
                }
            } else {
                match &plan.previous[i] {
                    Some(previous) => previous.clone(),
                    None => continue,
                }
            };
            fixtures.insert(fixture_key(root, target), record);
        }
        Self {
            format: FORMAT.to_owned(),
            engine: engine.to_owned(),
            settings: settings.to_vec(),
            expectations: expectations.to_owned(),
            other_sources: current.other_sources,
            rules,
            fixtures,
        }
    }

    pub(super) fn store(&self, path: &Path) {
        match bincode::serde::encode_to_vec(self, bincode::config::standard()) {
            Ok(bytes) => {
                if let Err(error) = crate::cache::atomic_write(path, &bytes) {
                    tracing::debug!(%error, "fixture state not stored");
                }
            }
            Err(error) => tracing::debug!(%error, "fixture state not encoded"),
        }
    }
}

/// What a run learned about one analyzed fixture.
pub(super) struct FixtureOutcome {
    pub(super) types: TypeMask,
    pub(super) passed: bool,
    pub(super) elapsed_ms: u64,
}

/// The types of every file in `report`, as the rules see them.
pub(super) fn report_types(report: &crate::AnalysisReport) -> TypeMask {
    let mut mask = TypeMask::EMPTY;
    for name in std::iter::once(report.target.file_type.as_str())
        .chain(report.files.iter().map(|f| f.file_type.as_str()))
    {
        let file_type = FileType::from_str(name);
        mask |= file_type.type_bit();
        // A small unidentified `.com` is evaluated as DOS COM (see
        // `CapabilityMapper::evaluation_file_type`).
        if file_type == FileType::Unknown {
            mask |= FileType::DosCom.type_bit();
        }
    }
    mask
}
