//! Core CapabilityMapper implementation.
//!
//! This module provides the main `CapabilityMapper` struct which:
//! - Loads capability definitions from YAML files
//! - Maps symbols to capability IDs
//! - Evaluates trait definitions and composite rules against analysis reports
//! - Provides platform and file type detection
//!
//! ## Module Organization
//!
//! The mapper is organized into focused submodules:
//!
//! - **builder**: Constructor methods (empty, new, with_platforms)
//! - **loader_directory**: Loading capabilities from directory of YAML files
//! - **loader_yaml**: Loading capabilities from single YAML file
//! - **lookup**: Query methods for finding traits and getting counts
//! - **evaluate_traits**: Atomic trait evaluation against analysis reports
//! - **evaluate_composites**: Composite rule evaluation
//! - **evaluate_merged**: Unified evaluation API combining traits + composites
//! - **imports**: Import finding generation and ecosystem detection
//! - **filters**: Low-value rule filtering
//! - **helpers**: Utility functions (file type detection, validation helpers)
//! - **builder**: Constructor methods (empty, new, with_platforms)

use std::sync::{Arc, OnceLock};

use crate::capabilities::indexes::{
    RawContentRegexIndex, StringMatchIndex, SymbolMatchIndex, TraitIndex,
};
use crate::composite_rules::{
    CompositeTrait, Condition, FileType as RuleFileType, Platform, TraitDefinition,
};

/// The four match indexes, built together as a pure function of the mapper's
/// `trait_definitions` and `platforms`. Held behind a [`OnceLock`] so they are
/// built lazily on the first analysis that needs to match traits — see
/// [`CapabilityMapper::match_indexes`]. Building them recompiles thousands of
/// trait regexes (the dominant cold-start cost), so a scan that only evaluates
/// package composites or reads rule counts — e.g. a warm `pkg:`/`url` scan whose
/// analyses all hit the report cache — never pays for them.
#[derive(Debug)]
pub(super) struct MatchIndexes {
    pub(super) trait_index: TraitIndex,
    pub(super) string_match_index: StringMatchIndex,
    pub(super) symbol_match_index: SymbolMatchIndex,
    pub(super) raw_content_regex_index: RawContentRegexIndex,
}

impl MatchIndexes {
    /// Build all four indexes for `traits` filtered to `platforms`. `[Platform::All]`
    /// filters nothing, so this reproduces the previous eager construction exactly.
    fn build(traits: &[TraitDefinition], platforms: &[Platform]) -> Self {
        let t0 = std::time::Instant::now();
        let raw_content_regex_index = RawContentRegexIndex::build_filtered(traits, platforms);
        let t_raw = t0.elapsed();
        let t1 = std::time::Instant::now();
        let trait_index = TraitIndex::build_filtered(traits, platforms);
        let t_trait = t1.elapsed();
        let t2 = std::time::Instant::now();
        let string_match_index = StringMatchIndex::build_filtered(traits, platforms);
        let t_string = t2.elapsed();
        let t3 = std::time::Instant::now();
        let symbol_match_index = SymbolMatchIndex::build_filtered(traits, platforms);
        let t_symbol = t3.elapsed();
        tracing::debug!(
            raw_regex_ms = t_raw.as_millis() as u64,
            trait_ms = t_trait.as_millis() as u64,
            string_ms = t_string.as_millis() as u64,
            symbol_ms = t_symbol.as_millis() as u64,
            "match indexes built"
        );
        // Index builds are the only computers of pattern derivations; flush any
        // new ones so the next process starts warm.
        super::derivation_memo::persist();
        Self {
            trait_index,
            string_match_index,
            symbol_match_index,
            raw_content_regex_index,
        }
    }
}

/// Where an `unless:`-bearing definition lives, by position — a compact
/// stand-in for its condition list that avoids a self-referential borrow in
/// [`UnlessIndex`]. Positions stay valid for the mapper's lifetime: the
/// definition lists are never mutated after construction (clones copy them
/// wholesale, and `with_platforms` only filters at index-build time).
#[derive(Clone, Copy, Debug)]
pub(super) enum UnlessSource {
    Trait(usize),
    Composite(usize),
}

/// Lookup tables for retroactive `unless:` suppression, a pure function of
/// the definition lists (platforms don't apply here — the old linear build
/// ignored them too). See `evaluate_merged.rs` for how findings resolve
/// through these. `by_id` maps a qualified definition ID to its
/// `unless:`-bearing definition; `by_hook_leaf` maps a `builtin-*` ID leaf
/// (e.g. `builtin-macho-fat-binary`) to the first such definition in
/// traits-then-composites order. Replaces per-finding scans over every
/// definition that dominated large-archive scans.
#[derive(Debug, Default)]
pub(super) struct UnlessIndex {
    pub(super) by_id: rustc_hash::FxHashMap<String, UnlessSource>,
    pub(super) by_hook_leaf: rustc_hash::FxHashMap<String, UnlessSource>,
}

impl UnlessIndex {
    pub(super) fn is_empty(&self) -> bool {
        self.by_id.is_empty() && self.by_hook_leaf.is_empty()
    }
}

/// Composite-rule indices that pass the static (platform, file-type) gates
/// for one file type, split by `has_negative_conditions`.
#[derive(Debug, Default)]
pub(super) struct CompositeTypeLists {
    pub(super) positive: Vec<u32>,
    pub(super) negative: Vec<u32>,
}

/// Maps symbols (function names, library calls) to capability IDs
/// Also supports trait definitions and composite rules that combine traits
#[derive(Clone, Debug)]
pub struct CapabilityMapper {
    pub(super) trait_definitions: Vec<TraitDefinition>,
    pub(crate) composite_rules: Vec<CompositeTrait>,
    /// The four trait match indexes, built lazily on the first analysis (see
    /// [`Self::match_indexes`]). `Arc` so a cloned mapper — the analyzers clone
    /// it per file — shares a single build rather than repeating it.
    pub(super) indexes: Arc<OnceLock<MatchIndexes>>,
    /// Retroactive `unless:` suppression tables, built lazily on first use
    /// and, like `indexes`, shared across per-file mapper clones.
    pub(super) unless_index: Arc<OnceLock<UnlessIndex>>,
    /// Lowercased `<filename>::` sibling basenames referenced by any loaded
    /// rule's kv paths, computed once on first use. The member-retention
    /// gate reads this to decide which members must keep their flattened
    /// `kv` after folding (see `shared_resources`).
    pub(super) kv_sibling_basenames: Arc<OnceLock<std::collections::BTreeSet<String>>>,
    /// Index of every trait id the loaded rules can reference (exact,
    /// short-suffix, or directory-prefix — mirroring `eval_trait`), computed
    /// once on first use. The member-fold early strip keeps any finding this
    /// index can reach.
    pub(super) trait_ref_index: Arc<OnceLock<TraitRefIndex>>,
    /// Ids of every trait and composite whose findings depend on the file's
    /// path (`Condition::depends_on_path`, closed over `trait:` references),
    /// computed once on first use. The content-keyed `FileAnalysis` cache
    /// keeps the evaluation path on a report that carries any of these, and
    /// only serves it back under that same path.
    pub(super) path_dependent_ids: Arc<OnceLock<rustc_hash::FxHashSet<String>>>,
    /// Like `trait_ref_index`, but restricted to rules that can evaluate at
    /// container (archive) scope — `for:` containing `all` or any
    /// archive-family type. Container-scope evaluation is the only rule pass
    /// that runs AFTER the member fold, over the folded member findings; a
    /// folded member finding this index can reach must keep its evidence
    /// (offsets feed `near_bytes`, values/counts feed conditions). Everything
    /// else is safe to slim at fold.
    pub(super) container_ref_index: Arc<OnceLock<TraitRefIndex>>,
    /// Skip `eval_raw` for a component/baseline whose every file-scope
    /// consumer composite is already unsatisfiable on this file.
    pub(super) doomed_skip: Arc<OnceLock<doomed_skip::DoomedSkipIndex>>,
    /// Composite-rule id → index into `composite_rules`, built once on first
    /// downgrade re-evaluation and shared across per-file mapper clones. The
    /// reeval paths run once per file (and once per archive member in the
    /// container phase), so rebuilding this map there dominated small-member
    /// corpora.
    pub(super) composite_id_index: Arc<OnceLock<rustc_hash::FxHashMap<String, usize>>>,
    /// Per-trait static evaluation flags (index-aligned bitmask; see
    /// `trait_eval_flags`): the per-(trait x member) closure previously
    /// re-derived these with deep `matches!` walks and five hash-set probes
    /// per trait per member.
    pub(super) trait_eval_flags: Arc<OnceLock<Vec<u16>>>,
    /// Atomic-trait work lists per (file type, dependent) pass: applicable
    /// indices additionally filtered by `Condition::can_match_file_type` and
    /// `has_trait_dependency` — all static per (mapper, file type), but
    /// previously recomputed per member per pass, with `has_trait_dependency`
    /// walking each trait's unless/downgrade lists every time.
    pub(super) trait_worklists:
        Arc<parking_lot::RwLock<rustc_hash::FxHashMap<(RuleFileType, bool), Arc<Vec<usize>>>>>,
    /// `trait_ref_ids()` per trait definition (index-aligned), computed once:
    /// the per-call version allocates a Vec per (trait x member x rescan).
    pub(super) trait_ref_ids_memo: Arc<OnceLock<Vec<Vec<String>>>>,
    /// Composite-rule work lists per file type: indices of rules whose
    /// platform and file-type gates can pass, split positive/negative
    /// (`has_negative_conditions`). Those three gates are static per
    /// (mapper, file type); testing them per (rule x member) was a measured
    /// leaf on many-member archives. Memoized here and shared across the
    /// per-file mapper clones, like the other lazy indexes.
    pub(super) composite_worklists:
        Arc<parking_lot::RwLock<rustc_hash::FxHashMap<RuleFileType, Arc<CompositeTypeLists>>>>,
    /// Maps trait ID -> index in trait_definitions
    #[allow(dead_code)]
    pub(super) trait_id_map: std::collections::HashMap<String, usize>,
    /// Platform filter(s) for rule evaluation (default: [All])
    pub(super) platforms: Vec<Platform>,
    /// Warn threshold for slow rule evaluation in milliseconds (default: 4000)
    pub(super) slow_rule_ms: u64,
}

/// Every trait id the loaded rule set can reference through a
/// `type: trait` condition, split by `eval_trait`'s three match modes:
/// exact ids, short names (matched against a finding id's final segment),
/// and directory prefixes (matched against a finding id's `/`-and-`::`
/// boundary prefixes). `possibly_referenced` answers "could any rule ever
/// match this finding id" in a handful of hash probes — a conservative
/// superset of what actually fires, which is exactly what the early strip
/// needs to be output-identical.
#[derive(Debug, Default)]
pub(crate) struct TraitRefIndex {
    exact: rustc_hash::FxHashSet<String>,
    short: rustc_hash::FxHashSet<String>,
    dirs: rustc_hash::FxHashSet<String>,
}

impl TraitRefIndex {
    fn build(raw: std::collections::BTreeSet<String>) -> Self {
        let mut idx = Self::default();
        for id in raw {
            if id.contains("::") {
                idx.exact.insert(id);
            } else if id.contains('/') {
                // Directory refs also match exactly (legacy flat ids).
                idx.dirs.insert(id.clone());
                idx.exact.insert(id);
            } else {
                idx.short.insert(id);
            }
        }
        idx
    }

    /// Whether any loaded rule's trait reference can match `id`.
    pub(crate) fn possibly_referenced(&self, id: &str) -> bool {
        if self.exact.contains(id) {
            return true;
        }
        // Short refs match the final segment (after the last `::`, else the
        // last `/`).
        let last = id
            .rsplit_once("::")
            .map_or(id, |(_, v)| v)
            .rsplit('/')
            .next()
            .unwrap_or(id);
        if self.short.contains(last) {
            return true;
        }
        // Directory refs match any boundary prefix: `a/b` reaches `a/b::x`
        // and `a/b/x`.
        if let Some((base, _)) = id.split_once("::")
            && self.dirs.contains(base)
        {
            return true;
        }
        let mut pos = 0;
        while let Some(off) = id[pos..].find('/') {
            let boundary = pos + off;
            if self.dirs.contains(&id[..boundary]) {
                return true;
            }
            pos = boundary + 1;
        }
        false
    }
}

impl CapabilityMapper {
    /// The match indexes, built on first use from `trait_definitions`+`platforms`.
    ///
    /// Only the trait-matching (analysis) path calls this; composite evaluation
    /// and rule-count queries do not, so a scan whose analyses all hit the report
    /// cache never builds them.
    ///
    /// The build deliberately runs *before* the `OnceLock` is touched.
    /// [`MatchIndexes::build`] fans out across the global rayon pool, and every
    /// rayon worker that reaches trait matching calls this function — so holding
    /// the cell across the build parks the whole pool on it and starves the very
    /// workers the build is waiting for.
    ///
    /// Forcing the first build off the rayon pool is *not* sufficient on its own:
    /// an off-pool winner still needs a free worker to finish, and a pool already
    /// parked on this cell can never provide one. That is the production deadlock
    /// this shape prevents — a traits reload republishes an unwarmed mapper
    /// mid-scan, so the first build routinely lands mid-flight rather than at
    /// startup, with the pool already saturated.
    ///
    /// Cost: callers racing the first build each build their own copy and all but
    /// one discards it — redundant CPU in a narrow window, in exchange for a shape
    /// in which no thread ever waits on another thread's build. `warm_indexes`
    /// collapses that window for callers that know they are about to fan out.
    pub(super) fn match_indexes(&self) -> &MatchIndexes {
        // Fast path: already built.
        if let Some(built) = self.indexes.get() {
            return built;
        }
        let built = MatchIndexes::build(&self.trait_definitions, &self.platforms);
        // The closure only moves an already-built value, so a racing caller
        // blocks for a move rather than for a multi-second parallel build.
        self.indexes.get_or_init(|| built)
    }

    /// Index-aligned static per-trait evaluation flags. Bits mirror the
    /// predicates in `evaluate_traits_filtered_with_cache`'s per-trait
    /// closure exactly — keep the two in lockstep.
    pub(super) fn trait_eval_flags(&self) -> &[u16] {
        self.trait_eval_flags.get_or_init(|| {
            use crate::composite_rules::{Condition, RawQuery, TextQuery};
            let indexes = self.match_indexes();
            self.trait_definitions
                .iter()
                .enumerate()
                .map(|(idx, t)| {
                    let mut bits: u16 = 0;
                    let counts_plain = t.count_min.unwrap_or(1) == 1
                        && t.count_max.is_none()
                        && t.per_kb_min.is_none()
                        && t.per_kb_max.is_none();
                    let no_location = |q: &TextQuery| {
                        q.section.is_none()
                            && q.offset.is_none()
                            && q.offset_range.is_none()
                            && q.section_offset.is_none()
                            && q.section_offset_range.is_none()
                    };
                    if t.downgrade.is_none()
                        && counts_plain
                        && matches!(&t.r#if, Condition::Text(q) if q.exact.is_some() && no_location(q))
                    {
                        bits |= flags::SIMPLE_EXACT;
                    }
                    if t.downgrade.is_none()
                        && counts_plain
                        && matches!(&t.r#if, Condition::Text(q) if q.substr.is_some() && no_location(q))
                    {
                        bits |= flags::SIMPLE_SUBSTR;
                    }
                    if indexes.string_match_index.is_exact_trait(idx) {
                        bits |= flags::IDX_EXACT;
                    }
                    if indexes.string_match_index.is_substr_trait(idx) {
                        bits |= flags::IDX_SUBSTR;
                    }
                    if indexes.string_match_index.is_regex_trait(idx) {
                        bits |= flags::IDX_REGEX;
                    }
                    if indexes.symbol_match_index.is_symbol_trait(idx) {
                        bits |= flags::IDX_SYMBOL;
                    }
                    match &t.r#if {
                        Condition::Raw(RawQuery { regex: Some(_), .. })
                        | Condition::Raw(RawQuery { word: Some(_), .. }) => {
                            bits |= flags::CONTENT_RAW;
                        }
                        Condition::Text(TextQuery { regex: Some(_), .. })
                        | Condition::Text(TextQuery { word: Some(_), .. }) => {
                            bits |= flags::CONTENT_TEXT;
                        }
                        _ => {}
                    }
                    if indexes.raw_content_regex_index.is_indexed_trait(idx) {
                        bits |= flags::RAW_INDEXED;
                    }
                    if t.count_min.is_some()
                        || t.count_max.is_some()
                        || t.per_kb_min.is_some()
                        || t.per_kb_max.is_some()
                    {
                        bits |= flags::NEEDS_COUNT;
                    }
                    bits
                })
                .collect()
        })
    }

    /// Atomic-trait work list for `(file_type, dependent_only)`: applicable
    /// indices whose `if:` can match the file type and whose dependency class
    /// matches the pass. Mirrors the filter at the top of
    /// `evaluate_traits_filtered_with_cache`, which must stay in lockstep.
    pub(super) fn trait_worklist(
        &self,
        file_type: RuleFileType,
        dependent_only: bool,
    ) -> Arc<Vec<usize>> {
        let key = (file_type, dependent_only);
        if let Some(hit) = self.trait_worklists.read().get(&key) {
            return Arc::clone(hit);
        }
        let applicable: Vec<usize> = self
            .match_indexes()
            .trait_index
            .get_applicable(&file_type)
            .into_indices_static()
            .collect();
        let list: Vec<usize> = applicable
            .into_iter()
            .filter(|&idx| {
                let t = &self.trait_definitions[idx];
                t.r#if.can_match_file_type(&file_type)
                    && t.has_trait_dependency() == dependent_only
                    // Platform gate folded here too: the evaluation context's
                    // platforms are always this mapper's `self.platforms`, so
                    // the per-evaluation `platforms_intersect` check in
                    // `TraitDefinition::evaluate` is static per trait.
                    && crate::composite_rules::platforms_intersect(
                        &t.platforms,
                        &self.platforms,
                    )
            })
            .collect();
        let arc = Arc::new(list);
        self.trait_worklists.write().insert(key, Arc::clone(&arc));
        arc
    }

    /// Index-aligned `trait_ref_ids()` for every trait definition, built once.
    pub(super) fn trait_ref_ids_for(&self, idx: usize) -> &[String] {
        let memo = self.trait_ref_ids_memo.get_or_init(|| {
            self.trait_definitions
                .iter()
                .map(|t| t.trait_ref_ids().into_iter().map(str::to_string).collect())
                .collect()
        });
        memo.get(idx).map_or(&[], Vec::as_slice)
    }

    /// Composite-rule work lists for `file_type`. Folds the gates that are
    /// static per (mapper, file type) — platform intersection, the `for:`
    /// file-type check (including the archive-family / cross-archive-scope
    /// carve-outs), and the positive/negative partition — so per-member
    /// evaluation only walks rules that can actually apply. Arch and size
    /// gates stay dynamic in `CompositeTrait::evaluate`. Must mirror the
    /// gates at the top of `CompositeTrait::evaluate` exactly.
    pub(super) fn composite_worklists(&self, file_type: RuleFileType) -> Arc<CompositeTypeLists> {
        use crate::composite_rules::Scope;
        if let Some(hit) = self.composite_worklists.read().get(&file_type) {
            return Arc::clone(hit);
        }
        let mut lists = CompositeTypeLists::default();
        for (i, rule) in self.composite_rules.iter().enumerate() {
            if !crate::composite_rules::platforms_intersect(&rule.platforms, &self.platforms) {
                continue;
            }
            let wants_archive_family = rule.r#for.iter().any(RuleFileType::is_archive);
            let pools_across_archive = matches!(
                rule.scope,
                Some(Scope::Outer | Scope::Archive | Scope::Package)
            );
            let file_type_match = rule.r#for.contains(&RuleFileType::All)
                || rule.r#for.contains(&file_type)
                || ((file_type == RuleFileType::All || file_type.is_archive())
                    && (wants_archive_family || pools_across_archive));
            if !file_type_match {
                continue;
            }
            #[allow(clippy::cast_possible_truncation)]
            let idx = i as u32;
            if rule.has_negative_conditions() {
                lists.negative.push(idx);
            } else {
                lists.positive.push(idx);
            }
        }
        let arc = Arc::new(lists);
        self.composite_worklists
            .write()
            .insert(file_type, Arc::clone(&arc));
        arc
    }

    pub(super) fn doomed_skip_index(&self) -> &doomed_skip::DoomedSkipIndex {
        self.doomed_skip.get_or_init(|| {
            doomed_skip::DoomedSkipIndex::build(
                &self.trait_definitions,
                &self.composite_rules,
                &self.trait_id_map,
            )
        })
    }

    /// Composite-rule id → index into `composite_rules`, built once on first
    /// use (see the field doc).
    pub(super) fn composite_id_index(&self) -> &rustc_hash::FxHashMap<String, usize> {
        self.composite_id_index.get_or_init(|| {
            self.composite_rules
                .iter()
                .enumerate()
                .map(|(i, r)| (r.id.clone(), i))
                .collect()
        })
    }

    /// The lowercased sibling basenames the loaded rule set can read via
    /// `<filename>::` kv paths — the only member basenames whose flattened
    /// `kv` is consulted after the member folds into its container.
    pub(crate) fn kv_sibling_basenames(&self) -> &std::collections::BTreeSet<String> {
        self.kv_sibling_basenames.get_or_init(|| {
            let mut out = std::collections::BTreeSet::new();
            for t in &self.trait_definitions {
                t.r#if.collect_kv_sibling_basenames(&mut out);
                for c in t.unless.iter().flatten() {
                    c.collect_kv_sibling_basenames(&mut out);
                }
                if let Some(d) = &t.downgrade {
                    d.collect_kv_sibling_basenames(&mut out);
                }
            }
            for r in &self.composite_rules {
                for c in r
                    .all
                    .iter()
                    .flatten()
                    .chain(r.any.iter().flatten())
                    .chain(r.unless.iter().flatten())
                {
                    c.collect_kv_sibling_basenames(&mut out);
                }
                if let Some(d) = &r.downgrade {
                    d.collect_kv_sibling_basenames(&mut out);
                }
            }
            if !out.is_empty() {
                tracing::debug!(basenames = ?out, "kv sibling basenames referenced by loaded rules");
            }
            out
        })
    }

    /// The referenced-trait index for the member-fold early strip. See
    /// [`TraitRefIndex`].
    pub(crate) fn trait_ref_index(&self) -> &TraitRefIndex {
        self.trait_ref_index.get_or_init(|| {
            let mut raw = std::collections::BTreeSet::new();
            for t in &self.trait_definitions {
                t.r#if.collect_trait_refs(&mut raw);
                for c in t.unless.iter().flatten() {
                    c.collect_trait_refs(&mut raw);
                }
                if let Some(d) = &t.downgrade {
                    d.collect_trait_refs(&mut raw);
                }
            }
            for r in &self.composite_rules {
                for c in r
                    .all
                    .iter()
                    .flatten()
                    .chain(r.any.iter().flatten())
                    .chain(r.unless.iter().flatten())
                {
                    c.collect_trait_refs(&mut raw);
                }
                if let Some(d) = &r.downgrade {
                    d.collect_trait_refs(&mut raw);
                }
            }
            TraitRefIndex::build(raw)
        })
    }

    /// The referenced-trait index restricted to container-scope-capable rules.
    /// See the `container_ref_index` field doc.
    /// See the `path_dependent_ids` field.
    pub(crate) fn path_dependent_ids(&self) -> &rustc_hash::FxHashSet<String> {
        self.path_dependent_ids.get_or_init(|| {
            fn conds_depend_on_path<'a>(conds: impl Iterator<Item = &'a Condition>) -> bool {
                let mut conds = conds;
                conds.any(Condition::depends_on_path)
            }
            fn downgrade_conds(
                d: &crate::composite_rules::DowngradeConditions,
            ) -> impl Iterator<Item = &Condition> {
                d.any
                    .iter()
                    .flatten()
                    .chain(d.all.iter().flatten())
                    .chain(d.none.iter().flatten())
            }
            let mut index = PathRefIndex::default();
            for t in &self.trait_definitions {
                let direct = t.r#if.depends_on_path()
                    || conds_depend_on_path(t.unless.iter().flatten())
                    || t.downgrade
                        .as_ref()
                        .is_some_and(|d| conds_depend_on_path(downgrade_conds(d)));
                if direct {
                    index.insert(t.id.as_str());
                }
            }
            for r in &self.composite_rules {
                if conds_depend_on_path(r.all.iter().flatten().chain(r.any.iter().flatten())) {
                    index.insert(r.id.as_str());
                }
            }
            // Close over `trait:` references: a rule built on a path-dependent
            // finding is itself path-dependent. Each pass is one linear scan
            // over the rules with O(1) reference probes; it runs until no rule
            // is added, bounded by the reference-chain depth (a handful).
            let mut refs = std::collections::BTreeSet::new();
            loop {
                let mut grew = false;
                for t in &self.trait_definitions {
                    if index.ids.contains(t.id.as_str()) {
                        continue;
                    }
                    refs.clear();
                    t.r#if.collect_trait_refs(&mut refs);
                    for c in t.unless.iter().flatten() {
                        c.collect_trait_refs(&mut refs);
                    }
                    if refs.iter().any(|r| index.hits(r)) {
                        index.insert(t.id.as_str());
                        grew = true;
                    }
                }
                for r in &self.composite_rules {
                    if index.ids.contains(r.id.as_str()) {
                        continue;
                    }
                    refs.clear();
                    for c in r.all.iter().flatten().chain(r.any.iter().flatten()) {
                        c.collect_trait_refs(&mut refs);
                    }
                    if refs.iter().any(|x| index.hits(x)) {
                        index.insert(r.id.as_str());
                        grew = true;
                    }
                }
                if !grew {
                    break;
                }
            }
            index.ids
        })
    }

    /// Whether any finding on `report` comes from a path-dependent rule.
    pub(crate) fn report_has_path_dependent_findings(
        &self,
        report: &crate::types::core::AnalysisReport,
    ) -> bool {
        let ids = self.path_dependent_ids();
        !ids.is_empty() && report.findings.iter().any(|f| ids.contains(f.id.as_str()))
    }

    pub(crate) fn container_ref_index(&self) -> &TraitRefIndex {
        self.container_ref_index.get_or_init(|| {
            use crate::composite_rules::FileType;
            let container_capable = |r#for: &[FileType]| {
                r#for.contains(&FileType::All) || r#for.iter().any(FileType::is_archive)
            };
            let mut raw = std::collections::BTreeSet::new();
            for t in &self.trait_definitions {
                if !container_capable(&t.r#for) {
                    continue;
                }
                t.r#if.collect_trait_refs(&mut raw);
                for c in t.unless.iter().flatten() {
                    c.collect_trait_refs(&mut raw);
                }
                if let Some(d) = &t.downgrade {
                    d.collect_trait_refs(&mut raw);
                }
            }
            for r in &self.composite_rules {
                if !container_capable(&r.r#for) {
                    continue;
                }
                for c in r
                    .all
                    .iter()
                    .flatten()
                    .chain(r.any.iter().flatten())
                    .chain(r.unless.iter().flatten())
                {
                    c.collect_trait_refs(&mut raw);
                }
                if let Some(d) = &r.downgrade {
                    d.collect_trait_refs(&mut raw);
                }
            }
            TraitRefIndex::build(raw)
        })
    }

    /// Force the lazy match indexes to build now, on the calling thread.
    ///
    /// Callers about to fan a scan out across the rayon pool warm them here so the
    /// pool does not perform redundant concurrent builds. Correctness no longer
    /// depends on this — see `Self::match_indexes`. Idempotent and cheap once built.
    pub fn warm_indexes(&self) {
        let _ = self.match_indexes();
        // The doomed-skip index is also lazily built on the first analysis;
        // left out of the warm-up it lands inside the first job while that
        // job holds the worker's cleave gate and everything else queues.
        let _ = self.doomed_skip_index();
        // The trait-reference index (end-strip / member-fold `retain`) is
        // also lazy; cold it costs ~70 ms inside the first archive's member
        // fold, which holds the fold lock while every other member waits.
        let _ = self.trait_ref_index();
        // Same story for the path-dependence index the content-keyed cache
        // consults on every member store.
        let _ = self.path_dependent_ids();
    }
}

/// Path-dependent ids plus the two derived forms a `trait:` reference can
/// use to reach them — every directory prefix (`a/b/` reaches `a/b/c::x`)
/// and the bare name after `::` — so a reference resolves in O(1). Mirrors
/// the forms `eval_trait` accepts; over-matching only widens what the cache
/// refuses to share, under-matching would leak path findings across paths.
#[derive(Default)]
struct PathRefIndex {
    ids: rustc_hash::FxHashSet<String>,
    prefixes: rustc_hash::FxHashSet<String>,
    names: rustc_hash::FxHashSet<String>,
}

impl PathRefIndex {
    fn insert(&mut self, id: &str) {
        if !self.ids.insert(id.to_string()) {
            return;
        }
        let path = id.split("::").next().unwrap_or(id);
        let mut acc = String::new();
        for seg in path.split('/') {
            if !acc.is_empty() {
                acc.push('/');
            }
            acc.push_str(seg);
            self.prefixes.insert(acc.clone());
        }
        if let Some(name) = id.rsplit("::").next() {
            self.names.insert(name.to_string());
        }
    }

    fn hits(&self, r: &str) -> bool {
        self.ids.contains(r)
            || self.prefixes.contains(r.trim_end_matches('/'))
            || self.names.contains(r)
    }
}

#[cfg(test)]
mod path_ref_tests {
    use super::PathRefIndex;

    #[test]
    fn exact_prefix_and_bare_name_references_reach_path_dependent_ids() {
        let mut idx = PathRefIndex::default();
        idx.insert("well-known/lib/crypto/better-auth::core-path");
        assert!(idx.hits("well-known/lib/crypto/better-auth::core-path"));
        assert!(idx.hits("well-known/lib/crypto/"));
        assert!(idx.hits("well-known/lib/crypto/better-auth"));
        assert!(idx.hits("core-path"));
        assert!(!idx.hits("well-known/lib/cryptoX/"));
        assert!(!idx.hits("path"));
    }
}

impl Default for CapabilityMapper {
    fn default() -> Self {
        Self::new()
    }
}

/// Extract relative path from full path (relative to traits directory)
/// Returns None if path conversion fails
pub(super) fn get_relative_source_file(path: &std::path::Path) -> Option<String> {
    // Try to find "traits/" in the path and return everything after it
    let path_str = path.to_string_lossy();
    if let Some(pos) = path_str.find("traits/") {
        let relative = &path_str[pos + 7..]; // Skip "traits/" prefix
        return Some(relative.to_string());
    }
    // Fallback: return the file name only if we can't find "traits/"
    path.file_name()
        .and_then(|n| n.to_str())
        .map(std::string::ToString::to_string)
}

/// Build the combined string vector from report strings, imports, and exports.
/// Used by both `evaluate_and_merge_findings` (cached path) and `evaluate_traits_filtered` (standalone).
/// Build the synthetic `StringInfo` entries for the string-match haystack —
/// import and export symbol names surfaced as strings so `type: text`/`string`
/// traits can match them. The caller chains these (cheap, bounded by symbol
/// count) after `report.strings`, which is borrowed by reference rather than
/// deep-copied into the haystack.
pub(super) fn build_string_pseudo_entries(
    report: &crate::types::AnalysisReport,
) -> Vec<crate::types::StringInfo> {
    let mut all_strings = Vec::with_capacity(report.imports.len() + report.exports.len());
    for imp in &report.imports {
        let offset = imp.offset.as_ref().and_then(|s| {
            let s = s.trim().trim_start_matches("0x").trim_start_matches("0X");
            u64::from_str_radix(s, 16).ok()
        });
        all_strings.push(crate::types::StringInfo {
            value: imp.symbol.clone().into(),
            offset,
            encoding: "symbol".to_string(),
            string_type: Some(crate::types::StringType::Import),
            section: None,
            encoding_chain: Vec::new(),
            fragments: None,
        });
    }
    for exp in &report.exports {
        let offset = exp.offset.as_ref().and_then(|s| {
            let s = s.trim().trim_start_matches("0x").trim_start_matches("0X");
            u64::from_str_radix(s, 16).ok()
        });
        all_strings.push(crate::types::StringInfo {
            value: exp.symbol.clone().into(),
            offset,
            encoding: "symbol".to_string(),
            string_type: Some(crate::types::StringType::Export),
            section: None,
            encoding_chain: Vec::new(),
            fragments: None,
        });
    }
    all_strings
}

/// String-index skip sets for one file.
///
/// On source (`uses_raw_text_search`), `source_text_prefiltered` is set only
/// when the raw file was scanned as one haystack. Exact/substr/regex-prefix
/// skips are then sound because `eval_text` searches those same bytes.
/// Cached evidence stays empty on that path — do not take the PE fast path
/// that would emit extracted-string evidence in place of `eval_raw`.
pub(super) struct StringPrefilter {
    pub matched: rustc_hash::FxHashSet<usize>,
    pub evidence: rustc_hash::FxHashMap<usize, Vec<crate::types::Evidence>>,
    pub regex_candidates: rustc_hash::FxHashSet<usize>,
    pub source_text_prefiltered: bool,
}

pub(super) fn build_string_prefilter(
    index: &StringMatchIndex,
    file_type: &RuleFileType,
    binary_data: &[u8],
    report: &crate::types::AnalysisReport,
) -> StringPrefilter {
    if file_type.uses_raw_text_search() {
        if let Some((mut matched, regex_candidates)) = index.find_matches_in_raw_source(binary_data)
        {
            let decoded: Vec<&crate::types::StringInfo> = report
                .strings
                .iter()
                .filter(|s| !s.encoding_chain.is_empty())
                .collect();
            if !decoded.is_empty() {
                let (decoded_matched, _) = index.find_matches_with_evidence(&decoded);
                matched.extend(decoded_matched);
            }
            return StringPrefilter {
                matched,
                evidence: rustc_hash::FxHashMap::default(),
                regex_candidates,
                source_text_prefiltered: true,
            };
        }
        return StringPrefilter {
            matched: rustc_hash::FxHashSet::default(),
            evidence: rustc_hash::FxHashMap::default(),
            regex_candidates: rustc_hash::FxHashSet::default(),
            source_text_prefiltered: false,
        };
    }

    if report.strings.is_empty() && report.imports.is_empty() && report.exports.is_empty() {
        return StringPrefilter {
            matched: rustc_hash::FxHashSet::default(),
            evidence: rustc_hash::FxHashMap::default(),
            regex_candidates: rustc_hash::FxHashSet::default(),
            source_text_prefiltered: false,
        };
    }

    let pseudo_strings = build_string_pseudo_entries(report);
    let all_strings: Vec<&crate::types::StringInfo> =
        report.strings.iter().chain(pseudo_strings.iter()).collect();
    let (matched, evidence) = if index.has_patterns() {
        index.find_matches_with_evidence(&all_strings)
    } else {
        (
            rustc_hash::FxHashSet::default(),
            rustc_hash::FxHashMap::default(),
        )
    };
    let regex_candidates = index.find_regex_candidates(&all_strings);
    StringPrefilter {
        matched,
        evidence,
        regex_candidates,
        source_text_prefiltered: false,
    }
}

/// Build the symbol-prefilter haystack the `SymbolMatchIndex` runs over to
/// decide which `type: symbol` traits are candidates for evaluation.
///
/// Includes import/export symbol names (binary symbol tables) *and* every
/// source-AST projection filefacts extracted — call targets, member-access
/// chains, bind targets, and identifiers (`Symbol::name()` yields the
/// matchable name for each kind). Without the filefacts names a
/// `kind: member`/`bind`/`identifier` trait could never become a candidate
/// (its literal would never appear in the haystack) and would be silently
/// skipped — the prefilter must see the same facts the evaluators do.
pub(super) fn build_all_symbols(report: &crate::types::AnalysisReport) -> Vec<&str> {
    let filefacts_len = report.filefacts.as_ref().map_or(0, |v| v.symbols.len());
    let mut all = Vec::with_capacity(
        report.imports.len() + report.exports.len() + report.functions.len() + filefacts_len,
    );
    all.extend(report.imports.iter().map(|i| i.symbol.as_str()));
    all.extend(report.exports.iter().map(|e| e.symbol.as_str()));
    // Binary function names come from the typed `report.functions` (the view
    // only mirrors source-AST kinds); source-AST names come from the view.
    all.extend(report.functions.iter().map(|f| f.name.as_str()));
    if let Some(view) = report.filefacts.as_ref() {
        all.extend(view.symbols.iter().filter_map(|s| s.name()));
    }
    all
}

/// Map a symbol name to its file-offset (hex string such as `"0x1234"`),
/// drawn from the report's imports and exports. The symbol-match index works
/// on names alone, so its evidence is anchored back to the symbol's real
/// location via this map (an import's offset is its `.dynstr` name offset; an
/// export's is its `st_value`). Used by `fill_symbol_evidence_locations`.
pub(super) fn build_symbol_offset_map(
    report: &crate::types::AnalysisReport,
) -> rustc_hash::FxHashMap<&str, String> {
    let mut map: rustc_hash::FxHashMap<&str, String> = rustc_hash::FxHashMap::default();
    for i in &report.imports {
        if let Some(off) = i.offset.as_ref() {
            map.entry(i.symbol.as_str()).or_insert_with(|| off.clone());
        }
    }
    for e in &report.exports {
        if let Some(off) = e.offset.as_ref() {
            map.entry(e.symbol.as_str()).or_insert_with(|| off.clone());
        }
    }
    // Function offsets come from the typed `report.functions` — the view no
    // longer mirrors `Function` symbols (see `FilefactsView::retained_symbols`).
    for f in &report.functions {
        if let Some(off) = f.offset.as_ref() {
            map.entry(f.name.as_str()).or_insert_with(|| off.clone());
        }
    }
    if let Some(view) = report.filefacts.as_ref() {
        for symbol in &view.symbols {
            let Some(name) = symbol.name() else {
                continue;
            };
            let offset = match symbol {
                filefacts::Symbol::Import { offset, .. }
                | filefacts::Symbol::Export { offset, .. }
                | filefacts::Symbol::Function { offset, .. }
                | filefacts::Symbol::Call { offset, .. }
                | filefacts::Symbol::Member { offset, .. }
                | filefacts::Symbol::Identifier { offset, .. } => *offset,
                filefacts::Symbol::Bind { offset, .. } => Some(*offset),
            };
            if let Some(offset) = offset {
                map.entry(name).or_insert_with(|| format!("{:#x}", offset));
            }
        }
    }
    map
}

/// Anchor symbol-index evidence at the matched symbol's file offset.
///
/// The symbol-match index emits evidence whose `value` is the symbol name but
/// with no `location` (it sees names, not offsets). Fill each such item from
/// `offsets`. Callers discard any item that remains unanchored so cached
/// symbol evidence never fabricates a file-start location.
pub(super) fn fill_symbol_evidence_locations(
    evidence: &mut [crate::types::Evidence],
    offsets: &rustc_hash::FxHashMap<&str, String>,
) {
    for ev in evidence.iter_mut() {
        if ev.location.is_none() {
            ev.location = offsets.get(ev.value.as_str()).cloned();
        }
    }
}

// Extracted modules
pub(crate) mod builder;
pub(crate) mod doomed_skip;
pub(crate) mod evaluate_composites;
pub(crate) mod evaluate_merged;
pub(crate) mod evaluate_traits;
pub(crate) use evaluate_merged::AnalysisBorrow;
pub(crate) mod filters;
pub(crate) mod helpers;
pub(crate) mod loader_directory;
pub(crate) mod loader_yaml;
pub(crate) mod lookup;

/// Bit names for [`CapabilityMapper::trait_eval_flags`].
pub(super) mod flags {
    pub(super) const SIMPLE_EXACT: u16 = 1 << 0;
    pub(super) const SIMPLE_SUBSTR: u16 = 1 << 1;
    pub(super) const IDX_EXACT: u16 = 1 << 2;
    pub(super) const IDX_SUBSTR: u16 = 1 << 3;
    pub(super) const IDX_REGEX: u16 = 1 << 4;
    pub(super) const IDX_SYMBOL: u16 = 1 << 5;
    pub(super) const CONTENT_RAW: u16 = 1 << 6;
    pub(super) const CONTENT_TEXT: u16 = 1 << 7;
    pub(super) const RAW_INDEXED: u16 = 1 << 8;
    pub(super) const NEEDS_COUNT: u16 = 1 << 9;
}
