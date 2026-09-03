//! Atomic trait evaluation against analysis reports.
//!
//! This module handles the evaluation of atomic trait definitions, which are the building
//! blocks of the capability detection system. It includes optimizations like:
//! - Index-based filtering by file type
//! - Batched Aho-Corasick string matching with evidence caching
//! - Parallel evaluation of applicable traits
//! - Early termination for empty files

use crate::composite_rules::TreeSitterQuery;
use crate::composite_rules::ast_kinds::map_kind_to_node_types;
use crate::composite_rules::{Arch, Condition, EvaluationContext, SectionMap};
use crate::types::{AnalysisReport, Criticality, Evidence, Finding, FindingKind};
use rayon::prelude::*;
use rustc_hash::{FxHashMap, FxHashSet};
use std::collections::HashMap;
use std::path::Path;
use std::sync::OnceLock;

/// Pre-computed caches passed to trait evaluation to avoid redundant work.
pub(crate) struct TraitEvalCache<'a> {
    pub raw_regex_matches: Option<&'a FxHashSet<usize>>,
    pub raw_atom_offsets: Option<&'a FxHashMap<usize, Vec<u32>>>,
    /// Indexed traits whose atoms occur in the member's decoded string
    /// layers; see `RawGateHits::decoded_candidates`.
    pub decoded_candidates: Option<&'a FxHashSet<usize>>,
    pub section_map: &'a SectionMap,
    pub string_matched_traits: &'a FxHashSet<usize>,
    pub symbol_matched_traits: &'a FxHashSet<usize>,
    pub cached_evidence: &'a FxHashMap<usize, Vec<Evidence>>,
    pub regex_candidates: &'a FxHashSet<usize>,
    pub arch_ranges: Option<&'a [(Arch, std::ops::Range<usize>)]>,
    pub ast_kind_cache: Option<&'a FxHashMap<String, Vec<Evidence>>>,
    /// Raw-file string-index scan ran for this source member. Enables
    /// skip-if-absent for exact/substr/regex-prefix `type: text` without
    /// taking the extracted-string evidence fast path.
    pub source_text_prefiltered: bool,
    /// Batched `query:` results for this file. Missing → per-trait QueryCursor.
    pub ast_query_cache:
        Option<&'a FxHashMap<String, crate::composite_rules::context::ConditionResult>>,
}

/// Which half of the trait set one filtered pass evaluates, plus any findings
/// that are not in the report yet but must be visible to `trait:` conditions.
///
/// The two travel together because they are the same question asked twice: the
/// dependent pass exists to react to what the independent pass just found, so
/// it needs those findings in scope. Carrying them here — rather than handing
/// evaluation a report clone with the findings spliced in — matters at
/// container scope, where cloning an archive report copies every member's
/// `FileAnalysis` and strings (2026-07-24: gigabytes per call on a
/// 63k-member archive, and a top single-threaded finalize cost).
#[derive(Clone, Copy)]
pub(crate) struct TraitPass<'a> {
    /// `false` evaluates traits WITHOUT `trait:` dependencies, `true` those WITH.
    pub dependent_only: bool,
    /// Findings the report does not carry yet; `EvaluationContext` folds these
    /// into its finding-id index, so `trait:` conditions see them exactly as if
    /// they had been appended to `report.findings`.
    pub extra_findings: Option<&'a [Finding]>,
    /// Worklist narrowing for fixed-point iterations ≥ 2: the finding ids the
    /// PREVIOUS iteration added. When set, only traits with a `trait:` ref
    /// those ids could satisfy are re-evaluated — an unchanged input can't
    /// change an unmatched trait's result. `None` (the first pass) evaluates
    /// every dependent trait.
    pub changed_ids: Option<&'a [crate::types::Istr]>,
    /// Trait ids that already produced a finding. Paired with `changed_ids`:
    /// re-evaluating them is pure waste, because the fixed-point loops dedup
    /// by id and would discard whatever they return.
    pub settled_ids: Option<&'a rustc_hash::FxHashSet<crate::types::Istr>>,
    /// Where this pass records the `unless:`/`downgrade:` legs that withheld or
    /// demoted a notable-or-above trait. Threaded on the pass rather than as a
    /// parameter so every constructor below carries it to the one context the
    /// pass builds.
    pub suppressions: Option<&'a crate::types::SuppressionSink>,
}

impl<'a> TraitPass<'a> {
    /// Traits with no `trait:` dependency — nothing earlier to observe.
    pub(crate) fn independent() -> Self {
        Self {
            dependent_only: false,
            extra_findings: None,
            changed_ids: None,
            settled_ids: None,
            suppressions: None,
        }
    }

    /// Traits with a `trait:` dependency, observing `extra` on top of the report.
    pub(crate) fn dependent(extra: Option<&'a [Finding]>) -> Self {
        Self {
            dependent_only: true,
            extra_findings: extra,
            changed_ids: None,
            settled_ids: None,
            suppressions: None,
        }
    }

    /// A fixed-point re-iteration: like [`Self::dependent`], but narrowed to
    /// traits affected by `changed` and not already settled.
    pub(crate) fn dependent_rescan(
        extra: Option<&'a [Finding]>,
        changed: &'a [crate::types::Istr],
        settled: &'a rustc_hash::FxHashSet<crate::types::Istr>,
    ) -> Self {
        Self {
            dependent_only: true,
            extra_findings: extra,
            changed_ids: Some(changed),
            settled_ids: Some(settled),
            suppressions: None,
        }
    }

    /// Record this pass's suppressions into `sink`.
    #[must_use]
    pub(crate) fn recording(mut self, sink: Option<&'a crate::types::SuppressionSink>) -> Self {
        self.suppressions = sink;
        self
    }
}

/// Raw-content gate telemetry (logged by `log_raw_gate_stats` at end of scan):
/// how many trait evaluations had a gateable content regex, how many of those
/// were actually covered by the raw index, and how many were skipped.
pub(crate) static RAW_GATE_ELIGIBLE: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);
pub(crate) static RAW_GATE_INDEXED: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);
pub(crate) static RAW_GATE_SKIPPED: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

/// Gate telemetry is opt-in (`CLEAVE_PHASE_STATS=1`): the counters below sit
/// in the per-trait loop (13M+ increments on a large archive), and a shared
/// atomic RMW per evaluation is cache-line ping-pong across every worker.
fn gate_stats_enabled() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| std::env::var("CLEAVE_PHASE_STATS").is_ok_and(|v| v == "1"))
}

/// Traits evaluated serially per Rayon job before that job's mutable context
/// is dropped. The override exists for reproducible scheduler tuning on large
/// workers; zero and invalid values retain the measured default.
fn parallel_trait_chunk() -> usize {
    static CHUNK: OnceLock<usize> = OnceLock::new();
    *CHUNK.get_or_init(|| {
        std::env::var("CLEAVE_PAR_TRAIT_CHUNK")
            .ok()
            .and_then(|value| value.parse::<usize>().ok())
            .filter(|&value| value > 0)
            .unwrap_or(64)
    })
}

/// Log the raw-content gate counters at `info`.
pub(crate) fn log_raw_gate_stats() {
    if !gate_stats_enabled() {
        return;
    }
    tracing::info!(
        eligible = RAW_GATE_ELIGIBLE.load(std::sync::atomic::Ordering::Relaxed),
        indexed = RAW_GATE_INDEXED.load(std::sync::atomic::Ordering::Relaxed),
        skipped = RAW_GATE_SKIPPED.load(std::sync::atomic::Ordering::Relaxed),
        "raw-content gate stats"
    );
}

/// Whether newly-added finding id `f` could satisfy the `trait:` reference `r`
/// — mirrors `eval_trait`'s exact/suffix/prefix semantics (the
/// Exception-criticality narrowing is deliberately ignored: erring toward
/// re-evaluation is always safe).
fn finding_could_affect_ref(r: &str, f: &str) -> bool {
    let r = r.trim_end_matches('/');
    if f == r {
        return true;
    }
    // Specific references (`dir::id`) match exactly only.
    if r.contains("::") {
        return false;
    }
    if !r.contains('/') {
        // Short name: same-directory suffix reference.
        return f.len() > r.len()
            && f.ends_with(r)
            && matches!(f.as_bytes()[f.len() - r.len() - 1], b':' | b'/');
    }
    // Directory path: any trait under it.
    f.len() > r.len() && f.starts_with(r) && matches!(f.as_bytes()[r.len()], b':' | b'/')
}

use super::get_relative_source_file;

/// Record one AST node into the kind cache if a `kind:`/`node:` trait needs it.
/// Shared by the source-analyzer fact walk and `build_ast_kind_cache` so a
/// second cursor pass is not required for bag-identical `kind: call` matches.
pub(crate) fn record_ast_kind_node(
    kind: &str,
    node: &tree_sitter::Node<'_>,
    source: &[u8],
    required_node_types: &FxHashSet<&str>,
    call_node_types: &FxHashSet<&'static str>,
    cache: &mut FxHashMap<String, Vec<Evidence>>,
) {
    if !required_node_types.contains(kind) {
        return;
    }
    let Ok(text) = node.utf8_text(source) else {
        return;
    };
    let alt_value = if call_node_types.contains(kind) {
        crate::analyzers::symbol_extraction::extract_function_name(node, source)
    } else {
        None
    };
    cache.entry(kind.to_string()).or_default().push(Evidence {
        method: "ast".to_string(),
        source: "tree-sitter".to_string(),
        value: crate::composite_rules::evaluators::truncate_evidence(text, 100),
        location: Some(format!(
            "{}:{}",
            node.start_position().row + 1,
            node.start_position().column + 1
        )),
        offsets: vec![node.start_byte() as u64],
        alt_value,
        ..Default::default()
    });
}

impl super::CapabilityMapper {
    /// Node kinds `kind:`/`node:` traits need for this file type, plus the
    /// call-expression kinds whose function name goes in `Evidence.alt_value`.
    /// Empty `required` means the kind-cache walk can be skipped.
    pub(crate) fn ast_kind_cache_plan(
        &self,
        file_type: crate::composite_rules::FileType,
    ) -> (FxHashSet<&str>, FxHashSet<&'static str>) {
        let applicable_indices: Vec<usize> = self
            .match_indexes()
            .trait_index
            .get_applicable(&file_type)
            .into_indices_static()
            .collect();
        self.ast_kind_cache_plan_for(&applicable_indices, file_type)
    }

    fn ast_kind_cache_plan_for<'a>(
        &'a self,
        applicable_indices: &[usize],
        file_type: crate::composite_rules::FileType,
    ) -> (FxHashSet<&'a str>, FxHashSet<&'static str>) {
        let mut required_node_types = FxHashSet::default();
        for &idx in applicable_indices {
            if let Condition::TreeSitter(TreeSitterQuery { kind, node, .. }) =
                &self.trait_definitions[idx].r#if
            {
                if let Some(k) = kind {
                    for nt in map_kind_to_node_types(k, file_type) {
                        required_node_types.insert(nt);
                    }
                } else if let Some(n) = node {
                    required_node_types.insert(n.as_str());
                }
            }
        }
        let call_node_types = map_kind_to_node_types("call", file_type)
            .into_iter()
            .collect();
        (required_node_types, call_node_types)
    }

    /// Pre-walk the cached AST once, collecting every node whose kind some
    /// applicable `kind:`/`node:` trait needs into a `kind → evidence` map (Idea
    /// 9). Call-expression nodes also carry the extracted function name in
    /// `alt_value` so `kind: call, exact: <name>` rules match `name(args)`.
    ///
    /// Returns `None` when there's no tree, the bytes aren't UTF-8, or no
    /// applicable trait asks for an AST node — the same conditions under which
    /// the per-trait path falls back to walking the tree itself. Shared by
    /// `evaluate_traits_with_ast` and the merged evaluation path so the two can't
    /// drift (a drift here silently drops `kind: call` matches on one path).
    pub(crate) fn build_ast_kind_cache(
        &self,
        cached_ast: Option<&tree_sitter::Tree>,
        binary_data: &[u8],
        applicable_indices: &[usize],
        file_type: crate::composite_rules::FileType,
    ) -> Option<FxHashMap<String, Vec<Evidence>>> {
        let tree = cached_ast?;
        let source = std::str::from_utf8(binary_data).ok()?;
        let (required_node_types, call_node_types) =
            self.ast_kind_cache_plan_for(applicable_indices, file_type);
        if required_node_types.is_empty() {
            return None;
        }

        let mut cache: FxHashMap<String, Vec<Evidence>> = FxHashMap::default();
        let mut cursor = tree.walk();
        crate::analyzers::ast_walker::walk_tree_with_stats(&mut cursor, None, |node, _| {
            record_ast_kind_node(
                node.kind(),
                &node,
                source.as_bytes(),
                &required_node_types,
                &call_node_types,
                &mut cache,
            );
            true
        });
        Some(cache)
    }

    fn collect_ast_query_strings<'a>(&'a self, indices: &[usize]) -> Vec<&'a str> {
        let mut seen = FxHashSet::default();
        let mut out = Vec::new();
        let mut push = |c: &'a Condition| {
            if let Some(q) = c.ast_query_text()
                && seen.insert(q)
            {
                out.push(q);
            }
        };
        for &idx in indices {
            let t = &self.trait_definitions[idx];
            push(&t.r#if);
            if let Some(unless) = &t.unless {
                for c in unless {
                    push(c);
                }
            }
            if let Some(d) = &t.downgrade {
                for c in d
                    .any
                    .iter()
                    .flatten()
                    .chain(d.all.iter().flatten())
                    .chain(d.none.iter().flatten())
                {
                    push(c);
                }
            }
        }
        out.sort_unstable();
        out
    }

    /// One trait evaluation step for `evaluate_traits_filtered_with_cache`'s
    /// loop: static-flag gates, then the actual `TraitDefinition::evaluate`.
    /// Split out so the loop can reuse one mutable context per worker (the
    /// closure form could not name the context lifetime).
    #[allow(clippy::too_many_arguments)]
    fn eval_one_trait<'a>(
        &self,
        trait_ctx: &mut EvaluationContext<'a>,
        idx: usize,
        cache: &TraitEvalCache<'_>,
        eval_flags: &[u16],
        dependent_only: bool,
        use_string_prefilters: bool,
        is_raw_text: bool,
        raw_regex_prefilter_enabled: bool,
        base_cached_evidence: Option<&'a rustc_hash::FxHashMap<usize, Vec<Evidence>>>,
    ) -> Option<Finding> {
        // Check cancellation before each trait — this is the innermost
        // loop that processes ~9000 traits per file, and is the main reason
        // analysis can't be interrupted once it enters trait evaluation.
        if trait_ctx.is_cancelled() {
            return None;
        }

        let trait_def = &self.trait_definitions[idx];
        let tf = eval_flags[idx];
        // For dependent traits, skip string-based optimizations since
        // we're matching on trait: conditions, not strings.
        //
        // Extracted-string skips stay off for raw-text source unless
        // `source_text_prefiltered`: `type: text` searches the file bytes,
        // and extracted literals miss span-syntax (`require('./prebuilt/…')`).
        // When the raw file was scanned as one haystack, skip-if-absent is
        // sound. The evidence fast path below is PE-only — it would replace
        // `eval_raw` evidence with extracted-string hits.
        if !dependent_only && use_string_prefilters {
            if !is_raw_text
                && (tf & (super::flags::SIMPLE_EXACT | super::flags::SIMPLE_SUBSTR)) != 0
            {
                // Simple exact/substr string trait: cached evidence is the
                // whole answer (hit -> synthesized finding, miss -> None).
                if let Some(evidence) = cache.cached_evidence.get(&idx)
                    && !evidence.is_empty()
                {
                    return Some(Finding {
                        precomputed_spans: None,
                        src: None,
                        id: trait_def.shared_id(),
                        desc: trait_def.shared_desc(),
                        conf: trait_def.conf,
                        crit: trait_def.crit,
                        mbc: trait_def.mbc.as_deref().map(Into::into),
                        attack: trait_def.attack.as_deref().map(Into::into),
                        evidence: evidence.clone(),
                        match_count: 0,
                        kind: FindingKind::Capability,
                        trait_refs: vec![],
                        source_file: get_relative_source_file(&trait_def.defined_in),
                    });
                }
                return None;
            }

            // Skip indexed exact traits that weren't matched
            if tf & super::flags::IDX_EXACT != 0 && !cache.string_matched_traits.contains(&idx) {
                return None;
            }

            // Source raw-haystack prefilter is exact-only. Substr/regex
            // skips stay PE-only (extracted-string haystack).
            if !is_raw_text {
                if tf & super::flags::IDX_SUBSTR != 0 && !cache.string_matched_traits.contains(&idx)
                {
                    return None;
                }

                if tf & super::flags::IDX_REGEX != 0 && !cache.regex_candidates.contains(&idx) {
                    return None;
                }
            }
        }

        // `type: symbol` searches imports/exports/functions plus the
        // filefacts names `build_all_symbols` already fed the index (see
        // the flag builder for why this skip is sound on all file types).
        if !dependent_only
            && tf & super::flags::IDX_SYMBOL != 0
            && !cache.symbol_matched_traits.contains(&idx)
        {
            return None;
        }

        // Raw-content atom gate: `type: raw` always; `type: text` only on
        // raw-text files. Sound on every file type and in the dependent
        // pass (an absent mandatory atom can't match regardless of other
        // findings).
        let has_content_regex = tf & super::flags::CONTENT_RAW != 0
            || (tf & super::flags::CONTENT_TEXT != 0 && is_raw_text);
        if has_content_regex && gate_stats_enabled() {
            RAW_GATE_ELIGIBLE.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            if tf & super::flags::RAW_INDEXED != 0 {
                RAW_GATE_INDEXED.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
        }
        if has_content_regex
            && raw_regex_prefilter_enabled
            && tf & super::flags::RAW_INDEXED != 0
            && cache.raw_regex_matches.is_some_and(|s| !s.contains(&idx))
        {
            if gate_stats_enabled() {
                RAW_GATE_SKIPPED.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
            return None;
        }

        trait_ctx.current_trait_idx = Some(idx);
        trait_ctx.cached_evidence = if tf & super::flags::NEEDS_COUNT != 0 {
            None
        } else {
            base_cached_evidence
        };

        // Both index sources (the work list, and the tiny-DOS bypass
        // above) apply the platform gate before an index reaches here.
        trait_def.evaluate_pregated(trait_ctx)
    }

    /// One QueryCursor walk for every applicable `query:` on this file.
    /// `None` leaves `eval_ast_query` on the per-trait path.
    pub(crate) fn build_ast_query_batch(
        &self,
        cached_ast: Option<&tree_sitter::Tree>,
        binary_data: &[u8],
        file_type: crate::composite_rules::FileType,
        indices: &[usize],
        cancellation: Option<&std::sync::atomic::AtomicBool>,
    ) -> Option<FxHashMap<String, crate::composite_rules::context::ConditionResult>> {
        let tree = cached_ast?;
        if !file_type.supports_ast_queries() {
            return None;
        }
        let source = std::str::from_utf8(binary_data).ok()?;
        let queries = self.collect_ast_query_strings(indices);
        crate::composite_rules::evaluators::batch_ast_queries(
            tree,
            source,
            file_type,
            &queries,
            Some(std::time::Instant::now() + std::time::Duration::from_secs(180)),
            cancellation,
        )
    }

    /// Evaluate trait definitions against an analysis report with optional cached AST.
    /// `inline_yara` supplies pre-scanned results from the combined YARA engine, keyed by
    /// namespace (`"inline.{trait_id}"`), enabling fast lookup in `eval_yara_inline`.
    ///
    /// Platform filtering is controlled by the `platform` field set via `with_platform()`.
    #[must_use]
    pub(crate) fn evaluate_traits_with_ast(
        &self,
        report: &AnalysisReport,
        binary_data: &[u8],
        cached_ast: Option<&tree_sitter::Tree>,
        inline_yara: Option<&HashMap<String, Vec<Evidence>>>,
    ) -> Vec<Finding> {
        // Determine file type from report (platform comes from self.platform)
        let file_type = self.detect_file_type(&report.target.file_type);

        // Build section map for location-constrained matching from the report's
        // already-populated sections. Standalone trait evaluation should not
        // parse file bytes just to rebuild data the analyzer already owns.
        let section_map = if file_type.has_sections() && !report.sections.is_empty() {
            SectionMap::from_report_sections(&report.sections, binary_data.len() as u64)
        } else {
            SectionMap::empty(binary_data.len() as u64)
        };

        // Use trait index to only evaluate applicable traits
        let applicable_indices: Vec<usize> = self
            .match_indexes()
            .trait_index
            .get_applicable(&file_type)
            .into_indices_static()
            .collect();

        // Idea 9: Batch AST node collection
        let ast_kind_cache =
            self.build_ast_kind_cache(cached_ast, binary_data, &applicable_indices, file_type);
        let ast_query_cache = self.build_ast_query_batch(
            cached_ast,
            binary_data,
            file_type,
            &applicable_indices,
            None,
        );

        // Pre-filter using batched Aho-Corasick string matching WITH evidence
        // caching. Source files scan the raw bytes; PE still uses extracted
        // strings plus import/export pseudo-entries.
        let string_prefilter = super::build_string_prefilter(
            &self.match_indexes().string_match_index,
            &file_type,
            binary_data,
            report,
        );
        let string_matched_traits = string_prefilter.matched;
        let mut cached_evidence = string_prefilter.evidence;
        let regex_candidates = string_prefilter.regex_candidates;
        let source_text_prefiltered = string_prefilter.source_text_prefiltered;

        // Run symbol matching ONCE across exact, substr, and regex patterns.
        // Evidence flows into cached_evidence so eval_symbol's FAST PATH 0 can
        // skip the per-symbol iteration on repeat trait evaluation. The
        // haystack spans imports/exports plus filefacts call/member/bind/
        // identifier names (see `build_all_symbols`).
        let all_symbols = super::build_all_symbols(report);
        let (symbol_matched_traits, symbol_evidence) = self
            .match_indexes()
            .symbol_match_index
            .find_matches_with_evidence(&all_symbols);
        let symbol_offsets = super::build_symbol_offset_map(report);
        for (trait_idx, mut ev) in symbol_evidence {
            super::fill_symbol_evidence_locations(&mut ev, &symbol_offsets);
            ev.retain(|item| item.location.is_some());
            if !ev.is_empty() {
                cached_evidence
                    .entry(trait_idx)
                    .or_default()
                    .append(&mut ev);
            }
        }

        // Pre-filter using batched regex matching for Content conditions
        let raw_regex_hits = self
            .match_indexes()
            .raw_content_regex_index
            .find_matches_detailed(binary_data, &file_type, file_type.uses_raw_text_search());

        let cache = TraitEvalCache {
            raw_regex_matches: Some(&raw_regex_hits.traits),
            raw_atom_offsets: Some(&raw_regex_hits.atom_offsets),
            decoded_candidates: None,
            section_map: &section_map,
            string_matched_traits: &string_matched_traits,
            symbol_matched_traits: &symbol_matched_traits,
            cached_evidence: &cached_evidence,
            regex_candidates: &regex_candidates,
            arch_ranges: None,
            ast_kind_cache: ast_kind_cache.as_ref(),
            source_text_prefiltered,
            ast_query_cache: ast_query_cache.as_ref(),
        };

        // Pass 1: Evaluate independent traits
        let mut findings = self.evaluate_traits_filtered_with_cache(
            report,
            binary_data,
            cached_ast,
            inline_yara,
            TraitPass::independent(),
            &cache,
            None,
        );

        // Pass 2: Evaluate dependent traits (iteratively until fixed point).
        // `findings` doubles as the extra-findings scope: it holds pass 1's
        // results plus everything later iterations add, which is exactly what
        // the previous report clone spliced into `report.findings`.
        const MAX_ITERATIONS: usize = 10;
        // Dedup scope for the loop below: everything the report already
        // carried plus everything this call accumulates. Doubles as the
        // settled set for re-iterations — a settled trait's re-evaluation
        // would be deduped away, so it's skipped at the filter.
        let mut settled: rustc_hash::FxHashSet<crate::types::Istr> = report
            .findings
            .iter()
            .map(|f| f.id.clone())
            .chain(findings.iter().map(|f| f.id.clone()))
            .collect();
        let mut changed: Vec<crate::types::Istr> = Vec::new();
        for iteration in 0..MAX_ITERATIONS {
            let pass = if iteration == 0 {
                TraitPass::dependent(Some(&findings))
            } else {
                // Re-iterations only re-run traits the previous round's new
                // findings could affect; everything else is provably unchanged.
                TraitPass::dependent_rescan(Some(&findings), &changed, &settled)
            };
            let dep_findings = self.evaluate_traits_filtered_with_cache(
                report,
                binary_data,
                cached_ast,
                inline_yara,
                pass,
                &cache,
                None,
            );

            if dep_findings.is_empty() {
                break;
            }

            let mut new_ids = Vec::new();
            for f in dep_findings {
                if !settled.contains(f.id.as_str()) {
                    settled.insert(f.id.clone().to_string().into());
                    new_ids.push(f.id.clone());
                    findings.push(f);
                }
            }

            if new_ids.is_empty() {
                break;
            }
            changed = new_ids;
        }

        findings
    }

    /// Evaluate trait definitions against an analysis report (without cached AST)
    /// Wrapper for evaluate_traits_with_ast
    #[allow(dead_code)] // Used by binary target
    #[must_use]
    pub(crate) fn evaluate_traits(
        &self,
        report: &AnalysisReport,
        binary_data: &[u8],
    ) -> Vec<Finding> {
        self.evaluate_traits_with_ast(report, binary_data, None, None)
    }

    /// Evaluate traits filtered by dependency status.
    /// When `dependent_only` is false, evaluates only traits WITHOUT trait: dependencies.
    /// When `dependent_only` is true, evaluates only traits WITH trait: dependencies.
    ///
    /// This enables proper ordering: independent traits are evaluated first, then
    /// dependent traits can see their results via `report.findings`.
    #[must_use]
    #[allow(dead_code)] // May be used by tests or binary
    pub(crate) fn evaluate_traits_filtered(
        &self,
        report: &AnalysisReport,
        binary_data: &[u8],
        cached_ast: Option<&tree_sitter::Tree>,
        inline_yara: Option<&HashMap<String, Vec<Evidence>>>,
        dependent_only: bool,
    ) -> Vec<Finding> {
        // Compute raw regex matches (this is expensive but necessary if no cache provided)
        let file_type = self.detect_file_type(&report.target.file_type);
        let raw_regex_hits = if self.match_indexes().raw_content_regex_index.has_patterns() {
            self.match_indexes()
                .raw_content_regex_index
                .find_matches_detailed(binary_data, &file_type, file_type.uses_raw_text_search())
        } else {
            crate::capabilities::indexes::RawGateHits::default()
        };
        // Build section map from existing report sections. This keeps the
        // standalone API parse-free; callers that need section constraints must
        // provide a report populated by the structural analyzer.
        let section_map = if file_type.has_sections() && !report.sections.is_empty() {
            SectionMap::from_report_sections(&report.sections, binary_data.len() as u64)
        } else {
            SectionMap::empty(binary_data.len() as u64)
        };

        let string_prefilter = super::build_string_prefilter(
            &self.match_indexes().string_match_index,
            &file_type,
            binary_data,
            report,
        );
        let string_matched_traits = string_prefilter.matched;
        let mut cached_evidence = string_prefilter.evidence;
        let regex_candidates = string_prefilter.regex_candidates;
        let source_text_prefiltered = string_prefilter.source_text_prefiltered;
        // Run symbol matching ONCE across exact, substr, and regex patterns.
        // Haystack spans imports/exports plus filefacts call/member/bind/
        // identifier names (see `build_all_symbols`).
        let all_symbols = super::build_all_symbols(report);
        let (symbol_matched_traits, symbol_evidence) = self
            .match_indexes()
            .symbol_match_index
            .find_matches_with_evidence(&all_symbols);
        let symbol_offsets = super::build_symbol_offset_map(report);
        for (trait_idx, mut ev) in symbol_evidence {
            super::fill_symbol_evidence_locations(&mut ev, &symbol_offsets);
            ev.retain(|item| item.location.is_some());
            if !ev.is_empty() {
                cached_evidence
                    .entry(trait_idx)
                    .or_default()
                    .append(&mut ev);
            }
        }

        self.evaluate_traits_filtered_with_cache(
            report,
            binary_data,
            cached_ast,
            inline_yara,
            TraitPass {
                dependent_only,
                extra_findings: None,
                changed_ids: None,
                settled_ids: None,
                suppressions: None,
            },
            &TraitEvalCache {
                raw_regex_matches: Some(&raw_regex_hits.traits),
                raw_atom_offsets: Some(&raw_regex_hits.atom_offsets),
                decoded_candidates: None,
                section_map: &section_map,
                string_matched_traits: &string_matched_traits,
                symbol_matched_traits: &symbol_matched_traits,
                cached_evidence: &cached_evidence,
                regex_candidates: &regex_candidates,
                arch_ranges: None,
                ast_kind_cache: None,
                source_text_prefiltered,
                ast_query_cache: None,
            },
            None,
        )
    }

    /// Evaluate traits filtered by dependency status, with pre-computed raw regex matches.
    /// This is the optimized version that avoids recomputing regex matches on each call.
    #[must_use]
    pub(crate) fn evaluate_traits_filtered_with_cache(
        &self,
        report: &AnalysisReport,
        binary_data: &[u8],
        cached_ast: Option<&tree_sitter::Tree>,
        inline_yara: Option<&HashMap<String, Vec<Evidence>>>,
        pass: TraitPass<'_>,
        cache: &TraitEvalCache<'_>,
        cancellation: Option<&std::sync::atomic::AtomicBool>,
    ) -> Vec<Finding> {
        let TraitPass {
            dependent_only,
            extra_findings,
            changed_ids,
            settled_ids,
            suppressions,
        } = pass;
        // Determine file type from report
        let file_type = self.detect_file_type(&report.target.file_type);
        let use_string_prefilters =
            !file_type.uses_raw_text_search() || cache.source_text_prefiltered;

        let mut ctx = EvaluationContext::new(
            report,
            binary_data,
            file_type,
            &self.platforms,
            extra_findings,
            cached_ast,
        )
        .with_suppressions(suppressions)
        .with_section_map(cache.section_map)
        .with_cached_evidence(Some(cache.cached_evidence))
        .with_deadline(std::time::Instant::now() + std::time::Duration::from_secs(180))
        .with_slow_rule_ms(self.slow_rule_ms);

        if let Some(flag) = cancellation {
            ctx = ctx.with_cancellation(flag);
        }

        if let Some(ast_cache) = cache.ast_kind_cache {
            ctx = ctx.with_ast_kind_cache(ast_cache);
        }
        if let Some(qcache) = cache.ast_query_cache {
            ctx = ctx.with_ast_query_cache(qcache);
        }

        if let Some(results) = inline_yara {
            ctx = ctx.with_inline_yara(results);
        }
        if let Some(ranges) = cache.arch_ranges {
            ctx = ctx.with_arch_ranges(ranges);
        }
        if file_type.uses_raw_text_search() {
            ctx = ctx.with_raw_atom_offsets(cache.raw_atom_offsets);
        }

        // Use trait index to only evaluate applicable traits
        // This dramatically reduces work for specific file types
        let mut applicable_indices: Vec<usize> = self
            .match_indexes()
            .trait_index
            .get_applicable(&file_type)
            .into_indices_static()
            .collect();

        let is_tiny_dos_com_candidate = file_type == crate::composite_rules::FileType::Unknown
            && binary_data.len() <= 4096
            && Path::new(&report.target.path)
                .extension()
                .is_some_and(|ext| ext.eq_ignore_ascii_case("com"));

        if is_tiny_dos_com_candidate {
            applicable_indices.retain(|&idx| {
                let trait_def = &self.trait_definitions[idx];
                let source = trait_def.defined_in.to_string_lossy();
                source.ends_with("/metadata/binary/layout/msdos.yaml")
                    || source.ends_with("/micro-behaviors/os/msdos/internal/signatures.yaml")
                    || source.ends_with("/micro-behaviors/os/msdos/interrupt/file_management.yaml")
                    || source.ends_with("/micro-behaviors/time/schedule/calendar/msdos.yaml")
                    || source.ends_with("/well-known/malware/virus/friday_the_13th/msdos.yaml")
            });
        }

        // Further filter by dependency status; on fixed-point re-iterations,
        // additionally to the worklist — traits already settled, or whose
        // `trait:` refs none of the newly-added ids could satisfy, cannot
        // produce a new deduped finding, so re-running them is pure waste.
        // Static half of the filter — applicability, `can_match_file_type`,
        // dependency class — comes from the per-(file type, pass) memo
        // (`trait_worklist`); only the fixed-point rescan narrowing is
        // dynamic. The rare tiny-DOS-`.com` candidate keeps the old inline
        // path because its `retain` above shrank `applicable_indices`.
        let rescan_keep = |idx: usize| -> bool {
            let trait_def = &self.trait_definitions[idx];
            let Some(changed) = changed_ids else {
                return true;
            };
            if settled_ids.is_some_and(|s| s.contains(trait_def.id.as_str())) {
                return false;
            }
            self.trait_ref_ids_for(idx)
                .iter()
                .any(|r| changed.iter().any(|f| finding_could_affect_ref(r, f)))
        };
        let filtered_indices: Vec<usize> = if is_tiny_dos_com_candidate {
            applicable_indices
                .into_iter()
                .filter(|&idx| {
                    let trait_def = &self.trait_definitions[idx];
                    trait_def.r#if.can_match_file_type(&file_type)
                        && trait_def.has_trait_dependency() == dependent_only
                        // The work-list path folds the platform gate; this
                        // bypass must apply it explicitly for pregated
                        // evaluation to stay sound.
                        && crate::composite_rules::platforms_intersect(
                            &trait_def.platforms,
                            &self.platforms,
                        )
                        && rescan_keep(idx)
                })
                .collect()
        } else if changed_ids.is_some() {
            self.trait_worklist(file_type, dependent_only)
                .iter()
                .copied()
                .filter(|&idx| rescan_keep(idx))
                .collect()
        } else {
            self.trait_worklist(file_type, dependent_only).to_vec()
        };

        if filtered_indices.is_empty() {
            return vec![];
        }

        // Use pre-computed raw regex matches (passed in from caller)
        let raw_regex_prefilter_enabled = cache.raw_regex_matches.is_some();

        // Deliberately excludes `raw_regex_matches`: it is a skip-set for the
        // per-trait gate below, not a signal survey. Counting it here made
        // enabling the raw prefilter defeat the tiny-file short-circuit (a
        // sub-100-byte `export {};` stub suddenly grew 12 metadata findings),
        // changing detections as a side effect of a performance switch.
        let has_any_matches =
            !cache.string_matched_traits.is_empty() || !cache.regex_candidates.is_empty();

        // For dependent traits, we can't skip based on string matches alone
        // because the trait: condition might match even if strings don't.
        // Source-AST facts (calls/members/binds/identifiers) also count: a
        // tiny source file like `process.env` carries no extracted strings or
        // imports but does carry member facts that `kind: member` traits match.
        let has_strings = !report.strings.is_empty()
            || !report.imports.is_empty()
            || !report.exports.is_empty()
            || report
                .filefacts
                .as_ref()
                .is_some_and(|v| !v.symbols.is_empty());
        // Structured manifests carry their signal as parsed KV fields, not
        // extracted strings: a 94-byte skeleton `package.json`
        // (`{"name","version","license"}`) has zero strings yet `value:`/kv
        // traits match its fields by reparsing the content. Skipping it would
        // blind us to sub-100-byte namespace-squatting manifests — exactly the
        // supply-chain shape worth flagging — so never short-circuit them.
        let is_structured_manifest =
            crate::composite_rules::evaluators::kv::structured_format_from_file_type(&file_type)
                != crate::composite_rules::evaluators::kv::StructuredFormat::Unknown;
        if !dependent_only
            && !has_any_matches
            && !has_strings
            && !is_structured_manifest
            && binary_data.len() < 100
        {
            return vec![];
        }

        let doomed_index = self.doomed_skip_index();
        let indexes = self.match_indexes();
        let (doomed_indices, rest_indices): (Vec<usize>, Vec<usize>) =
            filtered_indices.into_iter().partition(|&idx| {
                doomed_index.should_skip(
                    idx,
                    &self.trait_definitions,
                    &self.composite_rules,
                    &self.platforms,
                    file_type,
                    indexes,
                    cache,
                )
            });

        // Static per-trait classification comes from the precomputed flag
        // vector (`trait_eval_flags`) — one indexed load replaces the deep
        // `matches!` walks and five hash-set probes this closure used to run
        // per (trait x member). Only `current_trait_idx` / `cached_evidence`
        // vary per trait, so one mutable context serves a bounded trait chunk.
        //
        // Do not use `par_iter().map_init(|| ctx.clone(), ...)` here. Rayon
        // initializes that state per split job, not once per durable worker;
        // member-heavy archives consequently spent most of their CPU cloning
        // and dropping the context's Arc-backed lazy caches. Explicit chunks
        // bound clones to ceil(traits / chunk) while preserving fine-grained
        // load balancing. `CLEAVE_PAR_TRAIT_CHUNK` is the benchmark override.
        let eval_flags = self.trait_eval_flags();
        let base_cached_evidence = ctx.cached_evidence;
        let is_raw_text = file_type.uses_raw_text_search();
        let trait_chunk = parallel_trait_chunk();

        // Decoded-layer skip map for `eval_text`: indexed `type: text` traits
        // (regex/word `if:`) whose atoms are absent from every decoded
        // string value. Keyed by trait index and carrying the `if:` pattern
        // text, so only that pattern's evaluation skips — an `unless:` or
        // extra regex sharing the trait index still sweeps the layers.
        let decoded_skip: Option<FxHashMap<usize, &str>> = match cache.decoded_candidates {
            Some(cands)
                if is_raw_text && report.strings.iter().any(|s| !s.encoding_chain.is_empty()) =>
            {
                use crate::composite_rules::{Condition, TextQuery};
                let map: FxHashMap<usize, &str> = rest_indices
                    .iter()
                    .copied()
                    .filter(|&idx| {
                        let tf = eval_flags[idx];
                        tf & super::flags::RAW_INDEXED != 0
                            && tf & super::flags::CONTENT_TEXT != 0
                            && !cands.contains(&idx)
                    })
                    .filter_map(|idx| match &self.trait_definitions[idx].r#if {
                        Condition::Text(TextQuery { regex: Some(r), .. }) => {
                            Some((idx, r.as_str()))
                        }
                        Condition::Text(TextQuery { word: Some(w), .. }) => Some((idx, w.as_str())),
                        _ => None,
                    })
                    .collect();
                Some(map)
            }
            _ => None,
        };
        if let Some(map) = decoded_skip.as_ref() {
            ctx = ctx.with_decoded_skip(Some(map));
        }

        let eval_indices = |indices: &[usize]| -> Vec<Finding> {
            if crate::rayon_nest::inner_work_parallel() {
                indices
                    .par_chunks(trait_chunk)
                    .flat_map_iter(|chunk| {
                        let mut trait_ctx = ctx.clone();
                        chunk
                            .iter()
                            .filter_map(|&idx| {
                                self.eval_one_trait(
                                    &mut trait_ctx,
                                    idx,
                                    cache,
                                    eval_flags,
                                    dependent_only,
                                    use_string_prefilters,
                                    is_raw_text,
                                    raw_regex_prefilter_enabled,
                                    base_cached_evidence,
                                )
                            })
                            .collect::<Vec<_>>()
                    })
                    .collect()
            } else {
                let mut trait_ctx = ctx.clone();
                indices
                    .iter()
                    .filter_map(|&idx| {
                        self.eval_one_trait(
                            &mut trait_ctx,
                            idx,
                            cache,
                            eval_flags,
                            dependent_only,
                            use_string_prefilters,
                            is_raw_text,
                            raw_regex_prefilter_enabled,
                            base_cached_evidence,
                        )
                    })
                    .collect()
            }
        };

        let mut all_findings = eval_indices(&rest_indices);
        let has_notable_plus = all_findings.iter().any(|f| f.crit >= Criticality::Notable)
            || extra_findings.is_some_and(|xs| xs.iter().any(|f| f.crit >= Criticality::Notable))
            || report
                .findings
                .iter()
                .any(|f| f.crit >= Criticality::Notable);
        if !doomed_indices.is_empty() && !has_notable_plus {
            all_findings.extend(eval_indices(&doomed_indices));
        }

        // Deduplicate findings
        let mut seen = rustc_hash::FxHashSet::default();
        let mut unique_findings: Vec<Finding> = all_findings
            .into_iter()
            .filter(|f| seen.insert(f.id.clone()))
            .collect();

        unique_findings.shrink_to_fit();

        const MAX_FINDINGS_PER_FILE: usize = 500;
        if unique_findings.len() > MAX_FINDINGS_PER_FILE {
            unique_findings.sort_unstable_by(|a, b| {
                b.crit.cmp(&a.crit).then_with(|| {
                    let conf_a = (a.conf * 100.0) as i32;
                    let conf_b = (b.conf * 100.0) as i32;
                    conf_b.cmp(&conf_a)
                })
            });
            unique_findings.truncate(MAX_FINDINGS_PER_FILE);
            unique_findings.shrink_to_fit();
        }

        unique_findings
    }
}
