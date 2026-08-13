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
//! 1. Each side is walked into a flat `DiffUnit` list using the cached
//!    [`crate::analyze_file`] pipeline; archive members are flattened to
//!    units with `archive!!member` paths.
//! 2. Units are paired by relative path (rename detection deferred).
//! 3. `scopes` computes per-pair `ScopeDiff`s; results are pooled per scope
//!    and folded into the report summary.
//!
//! Performance comes from the SQLite-backed analysis cache: re-running a diff
//! after an analyze is essentially free per file.

mod scopes;

pub mod format;

use anyhow::{Context, Result, anyhow};
use rayon::prelude::*;
use rustc_hash::FxHashMap;
use serde_json::Value;
use std::path::{Path, PathBuf};

use crate::AnalysisOptions;
use crate::types::binary::{Export, Import, Section, StringInfo};
use crate::types::file_analysis::FileAnalysis;
use crate::types::traits_findings::Finding;
use crate::types::{
    AnalysisReport, DiffReportV1, DiffSummary, FileDiffEntry, FileStatus, Scope, ScopeDiff,
    ScopeDiffs, ScopeRocs, TargetInfo,
};

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

    /// True if the mask requests this scope. Pairs with [`Scope::ALL`]
    /// for "for each scope in the mask, do X" loops.
    #[must_use]
    pub fn contains(self, scope: Scope) -> bool {
        match scope {
            Scope::Traits => self.traits,
            Scope::Metrics => self.metrics,
            Scope::Kv => self.kv,
            Scope::Symbols => self.symbols,
            Scope::Strings => self.strings,
            Scope::Sections => self.sections,
        }
    }

    fn set(&mut self, scope: Scope, on: bool) {
        match scope {
            Scope::Traits => self.traits = on,
            Scope::Metrics => self.metrics = on,
            Scope::Kv => self.kv = on,
            Scope::Symbols => self.symbols = on,
            Scope::Strings => self.strings = on,
            Scope::Sections => self.sections = on,
        }
    }

    /// Parse a comma-separated scope list (`traits,value` etc.). Accepts the
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
            let token = tok.trim();
            if token.is_empty() {
                continue;
            }
            if token.eq_ignore_ascii_case("all") {
                return Ok(Self::all());
            }
            let lower = token.to_ascii_lowercase();
            match lower.parse::<Scope>() {
                Ok(scope) => mask.set(scope, true),
                Err(()) => {
                    return Err(anyhow!(
                        "unknown scope '{token}'; expected one of: traits, metrics, value, symbols, strings, sections, all"
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

/// Whether an archive diff analyzes members that are byte-identical on both
/// sides.
///
/// [`Skip`](Self::Skip) is the fast default: an unchanged member cannot change
/// the diff, so it is hashed but not analyzed. On a large package with a small
/// delta — a release where two of several hundred members moved — this is the
/// difference between analyzing every member and analyzing only the few that
/// changed. [`Analyze`](Self::Analyze) restores full analysis of unchanged
/// members; it is slower, but lets an unchanged-but-hostile member (a persistent
/// loader beside a refreshed payload carrier) still surface its behavioral
/// formula as differential context.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnchangedMembers {
    /// Skip analysis of members identical on both sides (fast; the default).
    Skip,
    /// Analyze every member, including unchanged ones (slower; thorough).
    Analyze,
}

/// All inputs to a per-pair diff for a single logical file. Bundles the
/// fields each scope needs so scope functions take a single argument.
///
/// File size is not stored here separately — the analyze pipeline writes
/// it to `metrics.file.size`, so it flows through with the rest of the
/// metrics scope.
pub(crate) struct DiffUnit {
    pub(crate) path: String,
    pub(crate) findings: Vec<Finding>,
    /// Flat numeric metric map (dotted-path keys). Sole surface
    /// after typed `*Metrics` projections retired.
    pub(crate) filefacts_metrics: Option<std::collections::BTreeMap<String, f64>>,
    /// kv tree pre-flattened with diff-friendly path encoding
    /// (membership / identity-keyed for arrays). Built once at unit
    /// construction so `diff_kv` can hash directly without re-walking
    /// the JSON. See [`scopes::flatten_kv_for_diff`].
    pub(crate) kv_flat: Vec<(String, Value)>,
    pub(crate) imports: Vec<Import>,
    pub(crate) exports: Vec<Export>,
    pub(crate) strings: Vec<StringInfo>,
    pub(crate) sections: Vec<Section>,
    /// Normalized identity claims for this side, when present. Compared
    /// whole to produce the file's identity headline/diff.
    pub(crate) identity: Option<filefacts::Identity>,
}

impl DiffUnit {
    fn empty(path: String) -> Self {
        Self {
            path,
            findings: Vec::new(),
            filefacts_metrics: None,
            kv_flat: Vec::new(),
            imports: Vec::new(),
            exports: Vec::new(),
            strings: Vec::new(),
            sections: Vec::new(),
            identity: None,
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
/// `unchanged` selects whether members identical on both sides of an archive
/// diff are analyzed (see [`UnchangedMembers`]).
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
    unchanged: UnchangedMembers,
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
    // Archive diffs are deliberately collected old-first. Their member cache
    // is keyed by SHA-256, so finishing the baseline populates all unchanged
    // members before the new archive starts. Besides avoiding duplicate work
    // for the common "mostly identical package" case, this avoids making
    // archive-member single-flight followers block the same Rayon pool as the
    // owner's nested trait work. Non-archive files keep the parallel path.
    let archive_pair = canonical_root
        && crate::analyzers::detect_file_type(old).is_ok_and(|kind| kind.is_archive())
        && crate::analyzers::detect_file_type(new).is_ok_and(|kind| kind.is_archive());
    let (old_units, new_units) = if archive_pair {
        // Members byte-identical on both sides cannot affect the diff, yet
        // analyzing them dominates runtime when a large package carries a tiny
        // delta. In `Skip` mode, a cheap pass hashes every member on each side
        // without analyzing it (`member_shas`); the real pass below then skips
        // members whose sha appears on both sides. Skipped members still surface
        // as empty units, pair up, and resolve to `Unchanged` — the report is
        // identical to `Analyze`'s minus the unchanged-hostile visibility case.
        let skip_opts;
        let options = match unchanged {
            UnchangedMembers::Analyze => options,
            UnchangedMembers::Skip => {
                let old_shas = member_shas(old, options)?;
                let new_shas = member_shas(new, options)?;
                let unchanged: std::collections::HashSet<String> =
                    old_shas.intersection(&new_shas).cloned().collect();
                skip_opts = with_member_skip(options, unchanged);
                &skip_opts
            }
        };
        (
            collect_units(old, options, canonical_root)?,
            collect_units(new, options, canonical_root)?,
        )
    } else {
        let (old_units, new_units) = rayon::join(
            || collect_units(old, options, canonical_root),
            || collect_units(new, options, canonical_root),
        );
        (old_units?, new_units?)
    };

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
    for scope in Scope::ALL {
        summary.scope_roc.set(scope, scopes.view(scope).roc);
    }
    summary.overall_roc = mean_nonempty_rocs(&summary.scope_roc, &scopes);

    let visible_files: Vec<FileDiffEntry> = file_diffs
        .into_iter()
        // Normally unchanged files are pure noise. Preserve the narrow case
        // where both sides carry a hostile behavioral formula: persistent
        // attack infrastructure is important differential context (for
        // example, an unchanged loader beside a refreshed payload carrier).
        .filter(visible_diff_file)
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

/// The sha256 of every member of an archive, computed without analyzing them.
///
/// Uses the same extraction path the real analysis uses — so the member set and
/// hashes match exactly — but installs a `skip_predicate` that spares only the
/// archive root (whose members must still be enumerated) and short-circuits
/// every member to a hash-only minimal report. The archive's own report is not
/// cached (a skip_predicate makes it non-canonical; see `analyze_file`), so this
/// enumeration cannot poison the real pass that follows.
fn member_shas(
    archive: &Path,
    options: &AnalysisOptions,
) -> Result<std::collections::HashSet<String>> {
    let root = archive.to_path_buf();
    let mut opts = options.clone();
    // Spare only the root: `analyze_file` consults the predicate with the
    // archive's own path, while members are consulted with their in-archive
    // relative path. Skipping the root would stop extraction before a single
    // member was enumerated; skipping every member is exactly the hash-only
    // pass we want. Discriminating by path avoids hashing the whole archive
    // just to recognize its root.
    opts.skip_predicate = Some(crate::SkipPredicate(std::sync::Arc::new(
        move |_sha: &str, path: &Path| path != root,
    )));
    let report = crate::analyze_file(archive, &opts)?;
    Ok(report.files.iter().map(|f| f.sha256.clone()).collect())
}

/// Clone `options` with a `skip_predicate` that skips any member whose sha is in
/// `unchanged`, composed with (OR-ed onto) any predicate the caller already set.
fn with_member_skip(
    options: &AnalysisOptions,
    unchanged: std::collections::HashSet<String>,
) -> AnalysisOptions {
    let existing = options.skip_predicate.clone();
    let mut opts = options.clone();
    opts.skip_predicate = Some(crate::SkipPredicate(std::sync::Arc::new(
        move |sha: &str, path: &Path| {
            unchanged.contains(sha) || existing.as_ref().is_some_and(|p| (p.0)(sha, path))
        },
    )));
    opts
}

/// Recognized analyzable files under `root`, paired with their relative path.
fn walk_files(root: &Path) -> Result<Vec<(PathBuf, String)>> {
    use walkdir::WalkDir;
    let mut out = Vec::new();
    for entry in WalkDir::new(root)
        .follow_links(true)
        .into_iter()
        // Skip the object store itself — thousands of entries, no analyzable
        // content. Match the name exactly: a `starts_with(".git")` prefix also
        // swallowed `.github`, hiding every workflow file from the diff, along
        // with `.gitignore` and `.gitattributes`. Nothing else hidden is
        // excluded; a dot in front of a name is not a reason to stop looking
        // at it, and `.github/workflows` is where a supply-chain change to CI
        // lands.
        .filter_entry(|e| !(e.file_type().is_dir() && e.file_name() == ".git"))
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
        filefacts_metrics: report.filefacts_metrics.clone(),
        kv_flat: report
            .values_tree
            .as_deref()
            .map(scopes::flatten_kv_for_diff)
            .unwrap_or_default(),
        imports: report.imports.clone(),
        exports: report.exports.clone(),
        strings: report.strings.clone(),
        sections: report.sections.clone(),
        identity: report.identity.clone(),
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
        filefacts_metrics: fa.filefacts_metrics.clone(),
        // Members contribute their own kv paths (a `.class` inside a `.jar`
        // still surfaces its `class.*` keys) from the already-flattened
        // `FileAnalysis.kv` — the per-file nested values tree is no longer
        // retained.
        kv_flat: scopes::kv_flat_from_map(&fa.kv),
        imports: fa.imports.clone(),
        exports: fa.exports.clone(),
        strings: fa.strings.clone(),
        sections: fa.sections.clone(),
        identity: fa.identity.clone(),
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

    // Identity is compared whole. A drift here (signer, trust tier,
    // publisher, build user, …) is the highest-signal change a file can
    // carry, so it forces `Changed` on its own — even if no scope moved.
    let identity = identity_diff(&old, &new);
    let identity_changed = identity.as_ref().is_some_and(|d| d.changed);

    let resolved = match initial_status {
        FileStatus::Added | FileStatus::Removed => initial_status,
        _ if identity_changed || any_scope_changed(&scopes) => FileStatus::Changed,
        _ => FileStatus::Unchanged,
    };

    // Snapshot each side's formula. Computing here keeps the formula in the
    // same canonical form as the analyze CLI/JSON output (see
    // `output::filter_findings_for_formula`) and the renderer doesn't need
    // access to the raw findings.
    let unchanged_hostile = matches!(resolved, FileStatus::Unchanged)
        && old
            .findings
            .iter()
            .chain(&new.findings)
            .any(|finding| finding.crit == crate::types::Criticality::Hostile);
    let old_formula = side_formula(&old.findings);
    let new_formula = match resolved {
        FileStatus::Added | FileStatus::Changed => side_formula(&new.findings),
        FileStatus::Unchanged if unchanged_hostile => side_formula(&new.findings),
        // Removed and ordinary unchanged files carry no new-side formula.
        _ => None,
    };
    let old_formula = match resolved {
        FileStatus::Removed | FileStatus::Changed => old_formula,
        FileStatus::Unchanged if unchanged_hostile => old_formula,
        _ => None,
    };

    FileDiffEntry {
        path,
        status: resolved,
        identity,
        scopes,
        old_formula,
        new_formula,
    }
}

/// Build the identity headline for a diffed pair. Returns `None` only
/// when neither side carried an identity. When one side has it and the
/// other doesn't (added/removed signing, a manifest gained/lost), that
/// is itself a change.
fn identity_diff(old: &DiffUnit, new: &DiffUnit) -> Option<crate::types::IdentityDiff> {
    if old.identity.is_none() && new.identity.is_none() {
        return None;
    }
    let changed = old.identity != new.identity;
    Some(crate::types::IdentityDiff {
        old: old.identity.clone(),
        new: new.identity.clone(),
        changed,
    })
}

fn side_formula(findings: &[Finding]) -> Option<String> {
    let filtered = crate::output::filter_findings_for_formula(findings);
    let f = crate::malecule_bridge::formula_from_findings(&filtered);
    (!f.is_empty()).then_some(f)
}

fn visible_diff_file(file: &FileDiffEntry) -> bool {
    file.status != FileStatus::Unchanged
        || (file.old_formula.is_some() && file.new_formula.is_some())
}

fn any_scope_changed(s: &ScopeDiffs) -> bool {
    Scope::ALL.iter().any(|scope| s.view(*scope).has_changes)
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
                // Weights pool linearly across files; ROC is recomputed below
                // from the program-level totals (honest pooling, not an
                // average of per-file ROCs).
                out.old_weight += s.old_weight;
                out.new_weight += s.new_weight;
                out.change_weight += s.change_weight;
                out.truncated |= s.truncated;
            }
        }
        if !any {
            return None;
        }
        out.recompute_roc();
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
    let (sum, n) = Scope::ALL
        .iter()
        .filter(|&&scope| {
            let view = scopes.view(scope);
            view.present && !view.is_empty
        })
        .map(|&scope| rocs.get(scope))
        .fold((0.0_f32, 0_u32), |(s, n), r| (s + r, n + 1));
    if n == 0 { 0.0 } else { sum / n as f32 }
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

    /// `.git` is skipped because it is thousands of files of object store, not
    /// because it starts with a dot. The distinction is load-bearing: a prefix
    /// match on `.git` also swallowed `.github`, so every CI workflow — where a
    /// supply-chain change to the build lands — was invisible to a directory
    /// diff, along with `.gitignore` and `.gitattributes`.
    #[test]
    fn walk_skips_the_git_store_but_not_dot_files() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        for (path, body) in [
            (".github/workflows/ci.yml", "uses: actions/checkout@v4\n"),
            (".git/objects/ab/cdef", "object store\n"),
            (".git/config", "[core]\n"),
            (".gitignore", "target/\n"),
            (".config/tool.toml", "k = 1\n"),
            ("src/main.rs", "fn main() {}\n"),
        ] {
            let full = root.join(path);
            std::fs::create_dir_all(full.parent().unwrap()).unwrap();
            std::fs::write(&full, body).unwrap();
        }

        let found: Vec<String> = walk_files(root)
            .unwrap()
            .into_iter()
            .map(|(_, rel)| rel.replace('\\', "/"))
            .collect();

        assert!(
            !found.iter().any(|p| p.starts_with(".git/")),
            "the object store must stay out of the diff: {found:?}"
        );
        for expected in [
            ".github/workflows/ci.yml",
            ".gitignore",
            ".config/tool.toml",
            "src/main.rs",
        ] {
            assert!(
                found.iter().any(|p| p == expected),
                "{expected} must be analyzed, got {found:?}"
            );
        }
    }

    #[test]
    fn scope_mask_parse_default() {
        assert!(ScopeMask::parse("").unwrap().traits);
        assert!(ScopeMask::parse("all").unwrap().sections);
    }

    #[test]
    fn scope_mask_parse_subset() {
        let m = ScopeMask::parse("traits,value").unwrap();
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

    #[test]
    fn unchanged_hostile_file_retains_formula_and_visibility() {
        let hostile = Finding {
            id: "objectives/supply-chain/install-hook/build/autotools::loader".into(),
            desc: "Persistent hostile loader".into(),
            conf: 0.99,
            crit: crate::types::Criticality::Hostile,
            ..Finding::default()
        };
        let mut old = DiffUnit::empty("m4/loader.m4".into());
        old.findings.push(hostile.clone());
        let mut new = DiffUnit::empty("m4/loader.m4".into());
        new.findings.push(hostile);

        let entry = diff_pair(
            UnitPair {
                path: "m4/loader.m4".into(),
                old: Some(old),
                new: Some(new),
            },
            ScopeMask::all(),
            DEFAULT_LIMIT_CHANGES,
        );

        assert_eq!(entry.status, FileStatus::Unchanged);
        assert!(entry.old_formula.is_some());
        assert_eq!(entry.old_formula, entry.new_formula);
        assert!(visible_diff_file(&entry));
    }

    #[test]
    fn ordinary_unchanged_file_stays_hidden() {
        let entry = diff_pair(
            UnitPair {
                path: "README".into(),
                old: Some(DiffUnit::empty("README".into())),
                new: Some(DiffUnit::empty("README".into())),
            },
            ScopeMask::all(),
            DEFAULT_LIMIT_CHANGES,
        );
        assert_eq!(entry.status, FileStatus::Unchanged);
        assert!(!visible_diff_file(&entry));
    }
}
