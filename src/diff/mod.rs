//! Differential analysis — supply-chain attack detection.
//!
//! `diff_paths` compares two analysis trees (file-vs-file, dir-vs-dir) across
//! six scopes — traits, metrics, KV, symbols, strings, and binary sections —
//! and returns an [`AnalysisReport`] whose [`AnalysisReport::diff`] field
//! carries a [`DiffReportV1`] with per-scope and per-file change sets plus a
//! pooled rate-of-change summary.
//!
//! # Pipeline
//!
//! 1. Each side is walked into a flat [`DiffUnit`] list using the cached
//!    [`crate::analyze_file`] pipeline; archive members are flattened to
//!    units with `archive!!member` paths.
//! 2. Units are paired by relative path (rename detection deferred).
//! 3. [`scopes`] computes per-pair `ScopeDiff`s; results are pooled per scope
//!    and folded into the report summary.
//!
//! Performance comes from the SQLite-backed analysis cache: re-running a diff
//! after an analyze is essentially free per file.

mod scopes;

pub mod format;

use anyhow::{anyhow, Context, Result};
use rayon::prelude::*;
use rustc_hash::FxHashMap;
use serde_json::Value;
use std::path::{Path, PathBuf};

use crate::types::binary::{Export, Import, Section, StringInfo};
use crate::types::file_analysis::FileAnalysis;
use crate::types::scores::Metrics;
use crate::types::traits_findings::Finding;
use crate::types::{
    AnalysisReport, DiffReportV1, DiffSummary, FileDiffEntry, FileStatus, ScopeDiff, ScopeDiffs,
    ScopeRocs, TargetInfo,
};
use crate::AnalysisOptions;

/// Default limit for the size of each scope's `added` / `removed` / `changed`
/// list. Counts and ROCs are unaffected. `0` removes the cap.
pub const DEFAULT_LIMIT_CHANGES: usize = 100;

/// Selection of diff scopes to compute. All scopes are enabled by default.
#[derive(Debug, Clone, Copy)]
pub struct ScopeMask {
    /// Trait (Finding ID) diff.
    pub traits: bool,
    /// Flattened metric paths.
    pub metrics: bool,
    /// Flattened KV-tree paths.
    pub kv: bool,
    /// Imported and exported symbols.
    pub symbols: bool,
    /// String literals.
    pub strings: bool,
    /// Binary sections (ELF / Mach-O / PE).
    pub sections: bool,
}

impl ScopeMask {
    /// All six scopes enabled.
    #[must_use]
    pub const fn all() -> Self {
        Self {
            traits: true,
            metrics: true,
            kv: true,
            symbols: true,
            strings: true,
            sections: true,
        }
    }

    /// Parse a comma-separated scope list (`traits,kv` etc.). Accepts the
    /// alias `all` for [`Self::all`]. Empty string maps to `all`.
    pub fn parse(spec: &str) -> Result<Self> {
        let spec = spec.trim();
        if spec.is_empty() || spec.eq_ignore_ascii_case("all") {
            return Ok(Self::all());
        }
        let mut mask = Self {
            traits: false,
            metrics: false,
            kv: false,
            symbols: false,
            strings: false,
            sections: false,
        };
        for tok in spec.split(',') {
            match tok.trim().to_ascii_lowercase().as_str() {
                "traits" => mask.traits = true,
                "metrics" => mask.metrics = true,
                "kv" => mask.kv = true,
                "symbols" => mask.symbols = true,
                "strings" => mask.strings = true,
                "sections" => mask.sections = true,
                "all" => return Ok(Self::all()),
                "" => continue,
                other => {
                    return Err(anyhow!(
                        "unknown scope '{other}'; expected one of: traits, metrics, kv, symbols, strings, sections, all"
                    ));
                }
            }
        }
        Ok(mask)
    }
}

impl Default for ScopeMask {
    fn default() -> Self {
        Self::all()
    }
}

/// All inputs to a per-pair diff for a single logical file. Bundles the
/// fields each scope needs so scope functions take a single argument.
pub(crate) struct DiffUnit {
    pub(crate) path: String,
    pub(crate) findings: Vec<Finding>,
    pub(crate) metrics: Option<Metrics>,
    pub(crate) kv_tree: Option<Value>,
    pub(crate) imports: Vec<Import>,
    pub(crate) exports: Vec<Export>,
    pub(crate) strings: Vec<StringInfo>,
    pub(crate) sections: Vec<Section>,
}

impl DiffUnit {
    fn empty(path: String) -> Self {
        Self {
            path,
            findings: Vec::new(),
            metrics: None,
            kv_tree: None,
            imports: Vec::new(),
            exports: Vec::new(),
            strings: Vec::new(),
            sections: Vec::new(),
        }
    }
}

/// Compare two paths and return an [`AnalysisReport`] (v3 envelope) whose
/// `diff` field carries the differential analysis.
///
/// Both inputs may be files or directories; archives are decomposed into
/// their members. Relative paths under the input root are used for pairing.
///
/// `scope_mask` selects which of the six scopes to compute; excluded scopes
/// are absent from the report. `limit_changes` caps the per-scope item lists
/// for output legibility — the underlying counts and ROCs are unaffected.
///
/// # Errors
///
/// Returns an error if either path does not exist or analysis fails for a
/// reason the cache cannot mask (I/O, malformed input).
pub fn diff_paths(
    old: &Path,
    new: &Path,
    options: &AnalysisOptions,
    scope_mask: ScopeMask,
    limit_changes: usize,
) -> Result<AnalysisReport> {
    if !old.exists() {
        return Err(anyhow!("old path does not exist: {}", old.display()));
    }
    if !new.exists() {
        return Err(anyhow!("new path does not exist: {}", new.display()));
    }

    // Single-file vs single-file: pair the two roots regardless of filename.
    // Real supply-chain diffs ship as version-stamped filenames (xz 5.4.5
    // vs 5.6.0, openssl 3.0.13.tar.gz vs 3.0.14.tar.gz), so pairing by name
    // would flag everything as add+remove and bury the actual change.
    // Using a canonical root key collapses both sides onto the same logical
    // file. Directories still pair by relative path.
    let canonical_root = old.is_file() && new.is_file();
    let (old_units, new_units) = rayon::join(
        || collect_units(old, options, canonical_root),
        || collect_units(new, options, canonical_root),
    );
    let old_units = old_units?;
    let new_units = new_units?;

    let pairs = pair_units(old_units, new_units);

    let file_diffs: Vec<FileDiffEntry> = pairs
        .into_par_iter()
        .map(|pair| diff_pair(pair, scope_mask, limit_changes))
        .collect();

    let mut summary = DiffSummary::default();
    for entry in &file_diffs {
        match entry.status {
            FileStatus::Added => summary.files_added += 1,
            FileStatus::Removed => summary.files_removed += 1,
            FileStatus::Changed => summary.files_changed += 1,
            FileStatus::Unchanged => summary.files_unchanged += 1,
        }
    }

    let scopes = aggregate_scopes(&file_diffs, scope_mask, limit_changes);
    summary.scope_roc = ScopeRocs {
        traits: scopes.traits.as_ref().map_or(0.0, ScopeDiff::roc),
        metrics: scopes.metrics.as_ref().map_or(0.0, ScopeDiff::roc),
        kv: scopes.kv.as_ref().map_or(0.0, ScopeDiff::roc),
        symbols: scopes.symbols.as_ref().map_or(0.0, ScopeDiff::roc),
        strings: scopes.strings.as_ref().map_or(0.0, ScopeDiff::roc),
        sections: scopes.sections.as_ref().map_or(0.0, ScopeDiff::roc),
    };
    summary.overall_roc = mean_nonempty_rocs(&summary.scope_roc, &scopes);

    let visible_files: Vec<FileDiffEntry> = file_diffs
        .into_iter()
        .filter(|f| f.status != FileStatus::Unchanged)
        .collect();

    let old_root = old.display().to_string();
    let new_root = new.display().to_string();
    let report = build_envelope(
        &old_root,
        &new_root,
        DiffReportV1 {
            old_root: old_root.clone(),
            new_root: new_root.clone(),
            summary,
            scopes,
            files: visible_files,
        },
    );
    Ok(report)
}

/// Walk an input path and return one [`DiffUnit`] per analyzable file
/// (including archive members), with paths normalized relative to `root`.
///
/// `canonical_root` collapses the root file's name to a fixed `<root>` key
/// so two single-file inputs with different filenames still pair. Directory
/// inputs always use the side-relative path.
fn collect_units(
    root: &Path,
    options: &AnalysisOptions,
    canonical_root: bool,
) -> Result<Vec<DiffUnit>> {
    if root.is_file() {
        let root_rel = if canonical_root {
            "<root>".to_string()
        } else {
            file_name_string(root)
        };
        let report = crate::analyze_file(root, options)
            .with_context(|| format!("failed to analyze {}", root.display()))?;
        Ok(units_from_report(&report, &root_rel))
    } else if root.is_dir() {
        let files = walk_files(root)?;
        let mut units = files
            .par_iter()
            .map(|(path, rel)| -> Result<Vec<DiffUnit>> {
                let report = crate::analyze_file(path, options)
                    .with_context(|| format!("failed to analyze {}", path.display()))?;
                Ok(units_from_report(&report, rel))
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(units.drain(..).flatten().collect())
    } else {
        Err(anyhow!(
            "path is neither a file nor a directory: {}",
            root.display()
        ))
    }
}

/// Recognized analyzable files under `root`, paired with their relative path.
fn walk_files(root: &Path) -> Result<Vec<(PathBuf, String)>> {
    use walkdir::WalkDir;
    let mut out = Vec::new();
    for entry in WalkDir::new(root)
        .follow_links(true)
        .into_iter()
        .filter_entry(|e| !e.file_name().to_string_lossy().starts_with(".git"))
    {
        let entry = entry.context("failed to read directory entry")?;
        if !entry.file_type().is_file() {
            continue;
        }
        let path = entry.path().to_path_buf();
        let rel = path
            .strip_prefix(root)
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_else(|_| file_name_string(&path));
        out.push((path, rel));
    }
    Ok(out)
}

/// Build per-file [`DiffUnit`]s from one analyze report. Returns one unit for
/// the root (carrying top-level findings/metrics/kv/etc.) plus one per
/// archive member found in `report.files`.
fn units_from_report(report: &AnalysisReport, root_rel: &str) -> Vec<DiffUnit> {
    use crate::types::file_analysis::ARCHIVE_DELIMITER;

    let mut out = Vec::with_capacity(1 + report.files.len());
    out.push(DiffUnit {
        path: root_rel.to_string(),
        findings: report.findings.clone(),
        metrics: report.metrics.clone(),
        kv_tree: report.kv_tree.as_deref().cloned(),
        imports: report.imports.clone(),
        exports: report.exports.clone(),
        strings: report.strings.clone(),
        sections: report.sections.clone(),
    });
    for fa in &report.files {
        out.push(unit_from_member(fa, root_rel, ARCHIVE_DELIMITER));
    }
    out
}

fn unit_from_member(fa: &FileAnalysis, root_rel: &str, delim: &str) -> DiffUnit {
    // Pre-finalize FileAnalysis paths inside `report.files` may be either the
    // bare member name (`inner.so`) or already nested (`a.zip!!b.so`).
    // Either way, prepending `{root_rel}!!` produces a consistent path that
    // pairs cleanly across the two diff sides.
    let path = if fa.path.starts_with(root_rel) {
        fa.path.clone()
    } else {
        format!("{root_rel}{delim}{}", fa.path)
    };
    DiffUnit {
        path,
        findings: fa.findings.clone(),
        metrics: fa.metrics.clone(),
        kv_tree: None,
        imports: fa.imports.clone(),
        exports: fa.exports.clone(),
        strings: fa.strings.clone(),
        sections: fa.sections.clone(),
    }
}

fn file_name_string(p: &Path) -> String {
    p.file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| p.display().to_string())
}

/// Pairing result: every path that appears on either side, with the unit from
/// each side. `None` on a side means "absent there".
struct UnitPair {
    path: String,
    old: Option<DiffUnit>,
    new: Option<DiffUnit>,
}

/// Pair units from each side by their normalized path. Order is stable
/// (sorted by path) so the resulting `files[]` array is deterministic.
fn pair_units(old: Vec<DiffUnit>, new: Vec<DiffUnit>) -> Vec<UnitPair> {
    let mut by_path: FxHashMap<String, (Option<DiffUnit>, Option<DiffUnit>)> = FxHashMap::default();
    for u in old {
        let path = u.path.clone();
        by_path.entry(path).or_default().0 = Some(u);
    }
    for u in new {
        let path = u.path.clone();
        by_path.entry(path).or_default().1 = Some(u);
    }
    let mut pairs: Vec<UnitPair> = by_path
        .into_iter()
        .map(|(path, (old, new))| UnitPair { path, old, new })
        .collect();
    pairs.sort_by(|a, b| a.path.cmp(&b.path));
    pairs
}

/// Diff one paired unit. Adds, removes, and changes are fully populated when
/// a side is missing — the missing side contributes an empty unit, so every
/// item on the other side becomes an "added" or "removed" entry.
fn diff_pair(pair: UnitPair, mask: ScopeMask, limit: usize) -> FileDiffEntry {
    let UnitPair { path, old, new } = pair;
    // pair_units guarantees at least one side is present.
    let initial_status = match (old.is_some(), new.is_some()) {
        (true, false) => FileStatus::Removed,
        (false, true) => FileStatus::Added,
        _ => FileStatus::Changed, // refined below for (true, true); (false, false) cannot occur
    };
    let old = old.unwrap_or_else(|| DiffUnit::empty(path.clone()));
    let new = new.unwrap_or_else(|| DiffUnit::empty(path.clone()));

    let scopes = ScopeDiffs {
        traits: mask.traits.then(|| scopes::diff_traits(&old, &new, limit)),
        metrics: mask
            .metrics
            .then(|| scopes::diff_metrics(&old, &new, limit)),
        kv: mask.kv.then(|| scopes::diff_kv(&old, &new, limit)),
        symbols: mask
            .symbols
            .then(|| scopes::diff_symbols(&old, &new, limit)),
        strings: mask
            .strings
            .then(|| scopes::diff_strings(&old, &new, limit)),
        sections: mask
            .sections
            .then(|| scopes::diff_sections(&old, &new, limit)),
    };

    let resolved = match initial_status {
        FileStatus::Added | FileStatus::Removed => initial_status,
        _ if any_scope_changed(&scopes) => FileStatus::Changed,
        _ => FileStatus::Unchanged,
    };

    FileDiffEntry {
        path,
        status: resolved,
        scopes,
    }
}

fn any_scope_changed(s: &ScopeDiffs) -> bool {
    fn changed<T>(d: &Option<ScopeDiff<T>>) -> bool {
        d.as_ref().is_some_and(ScopeDiff::has_changes)
    }
    changed(&s.traits)
        || changed(&s.metrics)
        || changed(&s.kv)
        || changed(&s.symbols)
        || changed(&s.strings)
        || changed(&s.sections)
}

/// Pool per-file diffs into program-level `ScopeDiff`s. Counts and items are
/// summed; the resulting ROC is honest across mixed-size files.
///
/// The aggregated lists are re-truncated to `limit` so output size stays
/// bounded even when many files each contribute a few changes.
fn aggregate_scopes(files: &[FileDiffEntry], mask: ScopeMask, limit: usize) -> ScopeDiffs {
    fn pool<T: Clone>(
        files: &[FileDiffEntry],
        get: impl Fn(&ScopeDiffs) -> Option<&ScopeDiff<T>>,
        limit: usize,
    ) -> Option<ScopeDiff<T>> {
        let mut out = ScopeDiff::<T>::default();
        let mut any = false;
        for f in files {
            if let Some(s) = get(&f.scopes) {
                any = true;
                out.added.extend(s.added.iter().cloned());
                out.removed.extend(s.removed.iter().cloned());
                out.changed.extend(s.changed.iter().cloned());
                out.old_count += s.old_count;
                out.new_count += s.new_count;
                out.truncated |= s.truncated;
            }
        }
        if !any {
            return None;
        }
        scopes::truncate(&mut out, limit);
        Some(out)
    }

    ScopeDiffs {
        traits: mask
            .traits
            .then(|| pool(files, |s| s.traits.as_ref(), limit))
            .flatten(),
        metrics: mask
            .metrics
            .then(|| pool(files, |s| s.metrics.as_ref(), limit))
            .flatten(),
        kv: mask
            .kv
            .then(|| pool(files, |s| s.kv.as_ref(), limit))
            .flatten(),
        symbols: mask
            .symbols
            .then(|| pool(files, |s| s.symbols.as_ref(), limit))
            .flatten(),
        strings: mask
            .strings
            .then(|| pool(files, |s| s.strings.as_ref(), limit))
            .flatten(),
        sections: mask
            .sections
            .then(|| pool(files, |s| s.sections.as_ref(), limit))
            .flatten(),
    }
}

/// Mean of per-scope ROCs over scopes that have data on at least one side.
/// Empty-on-both scopes are excluded from the denominator so they do not
/// drag the overall ROC toward zero.
fn mean_nonempty_rocs(rocs: &ScopeRocs, scopes: &ScopeDiffs) -> f32 {
    let mut sum = 0.0;
    let mut n = 0u32;
    for (roc, present) in [
        (
            rocs.traits,
            scopes.traits.as_ref().is_some_and(|s| !s.is_empty()),
        ),
        (
            rocs.metrics,
            scopes.metrics.as_ref().is_some_and(|s| !s.is_empty()),
        ),
        (rocs.kv, scopes.kv.as_ref().is_some_and(|s| !s.is_empty())),
        (
            rocs.symbols,
            scopes.symbols.as_ref().is_some_and(|s| !s.is_empty()),
        ),
        (
            rocs.strings,
            scopes.strings.as_ref().is_some_and(|s| !s.is_empty()),
        ),
        (
            rocs.sections,
            scopes.sections.as_ref().is_some_and(|s| !s.is_empty()),
        ),
    ] {
        if present {
            sum += roc;
            n += 1;
        }
    }
    if n == 0 {
        0.0
    } else {
        sum / n as f32
    }
}

/// Build the v3-envelope `AnalysisReport` carrying the diff. The envelope is
/// minimal: the diff command does not emit per-file analyses (use
/// `cleave analyze` for those), so `files` is empty and the envelope exists
/// only to host `diff` and a small `summary` for tooling that reads both
/// `analyze` and `diff` output through the same parser.
fn build_envelope(old_path: &str, new_path: &str, diff: DiffReportV1) -> AnalysisReport {
    let mut report = AnalysisReport::new(TargetInfo {
        path: format!("{old_path} → {new_path}"),
        file_type: "diff".to_string(),
        size_bytes: 0,
        sha256: String::new(),
        architectures: None,
    });
    report.version = "3".to_string();
    report.target = TargetInfo::default(); // hidden via skip_serializing_if
    report.analysis_timestamp = None;
    report.diff = Some(diff);
    report
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn scope_mask_parse_default() {
        assert!(ScopeMask::parse("").unwrap().traits);
        assert!(ScopeMask::parse("all").unwrap().sections);
    }

    #[test]
    fn scope_mask_parse_subset() {
        let m = ScopeMask::parse("traits,kv").unwrap();
        assert!(m.traits);
        assert!(m.kv);
        assert!(!m.metrics);
        assert!(!m.symbols);
        assert!(!m.strings);
        assert!(!m.sections);
    }

    #[test]
    fn scope_mask_parse_unknown() {
        assert!(ScopeMask::parse("traits,bogus").is_err());
    }

    #[test]
    fn pair_units_orders_by_path() {
        let old = vec![DiffUnit::empty("b".into()), DiffUnit::empty("a".into())];
        let new = vec![DiffUnit::empty("c".into())];
        let pairs = pair_units(old, new);
        assert_eq!(
            pairs.iter().map(|p| p.path.as_str()).collect::<Vec<_>>(),
            vec!["a", "b", "c"]
        );
    }
}
