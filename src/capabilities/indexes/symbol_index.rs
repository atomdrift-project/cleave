//! Index over symbol patterns.

// Split out of the parent module for size; it shares the parent's namespace.
#[allow(clippy::wildcard_imports)]
use super::*;

/// Index for fast symbol matching.
///
/// Batches three pattern kinds across traits in a single pass per symbol:
/// - `exact`: hashmap lookup (O(1) per symbol per pattern).
/// - `substr`: Aho-Corasick automaton (O(symbol_len) per symbol, all patterns at once).
/// - `regex`: literal-prefix Aho-Corasick prefilter + full-regex verification on candidates.
///   Regexes with no extractable literal are batched into a single `RegexSet` so the
///   fallback path is O(symbol_len × set_cost) instead of O(symbols × patterns).
#[derive(Clone, Default, Debug)]
pub(crate) struct SymbolMatchIndex {
    /// Case-sensitive exact symbol -> trait indices
    pub(super) exact_symbols: FxHashMap<String, Vec<usize>>,
    /// Set of all trait indices with symbol patterns (for lookup)
    pub(super) symbol_trait_indices: FxHashSet<usize>,

    /// Aho-Corasick automaton for substr symbol patterns (normalized).
    pub(super) substr_automaton: Option<AhoCorasick>,
    /// Maps AC pattern index -> trait indices.
    pub(super) substr_to_traits: Vec<Vec<usize>>,

    /// Aho-Corasick automaton over regex literal prefixes (normalized).
    pub(super) regex_literal_automaton: Option<AhoCorasick>,
    /// Maps AC pattern index -> trait indices that share that literal.
    pub(super) regex_literal_to_traits: Vec<Vec<usize>>,
    /// Per-trait pattern and verifier regex, compiled on its first
    /// literal-prefilter hit by [`compile_once`]. Compiling all ~1.2k symbol
    /// regexes and ~0.5k fallbacks up front cost ~0.3 s, serially, in every
    /// process that built the match indexes, though most never see a
    /// candidate symbol and text files have no symbols at all.
    /// Dense Vec indexed by trait_idx (None = not a regex trait). Vec lookup is
    /// ~3× faster than a hashmap here because trait_idx is a dense usize range.
    pub(super) trait_regex: Vec<Option<(String, OnceLock<Option<Arc<TraitRegex>>>)>>,

    /// Regex traits with no extractable literal prefix, compiled individually
    /// (str-based, unlike the bytes-based raw-content regexes elsewhere in
    /// this module). A `RegexSet` here ran the PikeVM with every pattern live
    /// on every symbol; per-pattern `is_match` uses the lazy DFA and, looped
    /// pattern-major, reuses its cache across the whole symbol list.
    /// `regex_fallback_traits[i]` is the trait index for pattern `i`, whose
    /// regex compiles on the first symbol list to reach it; a pattern that
    /// fails to compile stays `None` (warned once).
    pub(super) regex_fallback_patterns: Vec<String>,
    pub(super) regex_fallback_regexes: Vec<OnceLock<Option<ScratchRegex>>>,
    pub(super) regex_fallback_traits: Vec<usize>,
    /// Any-of atom gate for the fallbacks (`mandatory_atom_set`: every match
    /// contains one of the pattern's atoms). Most fallbacks are literal
    /// alternations such as `^(exec|execSync)$`; with the gate they verify
    /// only the symbols one sweep nominated instead of every symbol.
    /// `[cs, ci]` automata map pattern -> fallback positions;
    /// `regex_fallback_gated[i]` marks fallbacks that run on candidates only.
    pub(super) fallback_atom_automata: [Option<AhoCorasick>; 2],
    pub(super) fallback_atom_to_fallbacks: [Vec<Vec<u32>>; 2],
    pub(super) regex_fallback_gated: Vec<bool>,
}

impl SymbolMatchIndex {
    /// Build index, keeping only traits whose platform set intersects `platforms`.
    /// Off-platform traits keep their absolute index slot but contribute no patterns.
    pub(crate) fn build_filtered(traits: &[TraitDefinition], platforms: &[Platform]) -> Self {
        let num_traits = traits.len();
        let mut exact_symbols: FxHashMap<String, Vec<usize>> = FxHashMap::default();
        let mut symbol_trait_indices: FxHashSet<usize> = FxHashSet::default();

        // Substr collection — de-dupe patterns so multiple traits sharing the
        // same substr share one AC slot.
        let mut substr_patterns: Vec<String> = Vec::new();
        let mut substr_pattern_map: FxHashMap<String, usize> = FxHashMap::default();
        let mut substr_to_traits: Vec<Vec<usize>> = Vec::new();

        // Regex-literal-prefix collection
        let mut regex_literals: Vec<String> = Vec::new();
        let mut regex_literal_map: FxHashMap<String, usize> = FxHashMap::default();
        let mut regex_literal_to_traits: Vec<Vec<usize>> = Vec::new();

        // Dense Vec for per-trait regex lookup.
        let mut trait_regex = vec![None; num_traits];

        let mut regex_fallback_traits: Vec<usize> = Vec::new();
        let mut regex_fallback_patterns: Vec<String> = Vec::new();

        for (trait_idx, trait_def) in traits.iter().enumerate() {
            if !platforms_intersect(&trait_def.platforms, platforms) {
                continue;
            }
            match &trait_def.r#if {
                Condition::Symbol(SymbolQuery {
                    exact: Some(exact_str),
                    substr: None,
                    regex: None,
                    ..
                }) => {
                    exact_symbols
                        .entry(normalize_symbol(exact_str))
                        .or_default()
                        .push(trait_idx);
                    symbol_trait_indices.insert(trait_idx);
                }
                Condition::Symbol(SymbolQuery {
                    exact: None,
                    substr: Some(substr_str),
                    regex: None,
                    ..
                }) => {
                    let normalized = normalize_symbol(substr_str);
                    if normalized.is_empty() {
                        continue;
                    }
                    symbol_trait_indices.insert(trait_idx);
                    if let Some(&idx) = substr_pattern_map.get(&normalized) {
                        substr_to_traits[idx].push(trait_idx);
                    } else {
                        let idx = substr_patterns.len();
                        substr_pattern_map.insert(normalized.clone(), idx);
                        substr_patterns.push(normalized);
                        substr_to_traits.push(vec![trait_idx]);
                    }
                }
                Condition::Symbol(SymbolQuery {
                    exact: None,
                    substr: None,
                    regex: Some(regex_str),
                    ..
                }) => {
                    symbol_trait_indices.insert(trait_idx);
                    trait_regex[trait_idx] = Some((regex_str.clone(), OnceLock::new()));
                    // Prefer the longest *mandatory* literal anywhere in the
                    // pattern (not just a prefix). A prefix-only extractor dumps
                    // most symbol regexes into the no-literal `RegexSet`, whose
                    // per-symbol PikeVM `which_overlapping` scan was the single
                    // biggest CPU hotspot (profiled). An inner-literal atom lets
                    // the cheap Aho-Corasick prefilter cover them instead.
                    let atom = super::super::derivation_memo::mandatory_atom_utf8(regex_str);
                    match atom {
                        Some(literal) => {
                            let normalized = normalize_symbol(&literal);
                            if normalized.len() >= 3 {
                                if let Some(&idx) = regex_literal_map.get(&normalized) {
                                    regex_literal_to_traits[idx].push(trait_idx);
                                } else {
                                    let idx = regex_literals.len();
                                    regex_literal_map.insert(normalized.clone(), idx);
                                    regex_literals.push(normalized);
                                    regex_literal_to_traits.push(vec![trait_idx]);
                                }
                            } else {
                                regex_fallback_traits.push(trait_idx);
                                regex_fallback_patterns.push(regex_str.clone());
                            }
                        }
                        None => {
                            regex_fallback_traits.push(trait_idx);
                            regex_fallback_patterns.push(regex_str.clone());
                        }
                    }
                }
                _ => {}
            }
        }

        let substr_automaton = (!substr_patterns.is_empty())
            .then(|| build_index_automaton(&substr_patterns, false))
            .flatten();

        let regex_literal_automaton = (!regex_literals.is_empty())
            .then(|| build_index_automaton(&regex_literals, false))
            .flatten();

        let regex_fallback_regexes = regex_fallback_patterns
            .iter()
            .map(|_| OnceLock::new())
            .collect();

        // Any-of atom gate for the fallbacks; a pattern without a guaranteed
        // set stays on the full sweep, and so does every fallback if either
        // automaton fails to build (a missing gate must never hide a match).
        let mut regex_fallback_gated = vec![false; regex_fallback_patterns.len()];
        let mut atom_patterns: [Vec<String>; 2] = [Vec::new(), Vec::new()];
        let mut atom_maps: [FxHashMap<String, usize>; 2] =
            [FxHashMap::default(), FxHashMap::default()];
        let mut fallback_atom_to_fallbacks: [Vec<Vec<u32>>; 2] = [Vec::new(), Vec::new()];
        for (fi, pattern) in regex_fallback_patterns.iter().enumerate() {
            let Some(atoms) = super::super::derivation_memo::mandatory_atom_set(pattern) else {
                continue;
            };
            if atoms.is_empty() || atoms.iter().any(|(a, _)| a.is_empty()) {
                continue;
            }
            regex_fallback_gated[fi] = true;
            for (atom, ci) in &atoms {
                let k = usize::from(*ci);
                let key = if *ci {
                    atom.to_ascii_lowercase()
                } else {
                    atom.clone()
                };
                let slot = match atom_maps[k].get(&key) {
                    Some(&slot) => slot,
                    None => {
                        let slot = atom_patterns[k].len();
                        atom_maps[k].insert(key.clone(), slot);
                        atom_patterns[k].push(key);
                        fallback_atom_to_fallbacks[k].push(Vec::new());
                        slot
                    }
                };
                fallback_atom_to_fallbacks[k][slot].push(fi as u32);
            }
        }
        let mut fallback_atom_automata = [
            build_index_automaton(&atom_patterns[0], false),
            build_index_automaton(&atom_patterns[1], true),
        ];
        if (0..2).any(|k| fallback_atom_automata[k].is_none() && !atom_patterns[k].is_empty()) {
            fallback_atom_automata = [None, None];
            fallback_atom_to_fallbacks = [Vec::new(), Vec::new()];
            regex_fallback_gated.iter_mut().for_each(|g| *g = false);
        }
        tracing::debug!(
            gated = regex_fallback_gated.iter().filter(|g| **g).count(),
            fallbacks = regex_fallback_gated.len(),
            "symbol fallback atom gate"
        );

        tracing::debug!(
            "Built SymbolMatchIndex: {} exact, {} substr, {} regex-literal, {} regex-fallback",
            exact_symbols.len(),
            substr_to_traits.len(),
            regex_literal_to_traits.len(),
            regex_fallback_traits.len(),
        );

        Self {
            exact_symbols,
            symbol_trait_indices,
            substr_automaton,
            substr_to_traits,
            regex_literal_automaton,
            regex_literal_to_traits,
            trait_regex,
            regex_fallback_patterns,
            regex_fallback_regexes,
            regex_fallback_traits,
            fallback_atom_automata,
            fallback_atom_to_fallbacks,
            regex_fallback_gated,
        }
    }

    /// Legacy entry point — returns only the matched trait indices.
    /// Prefer `find_matches_with_evidence`.
    pub(crate) fn find_matches(&self, symbols: &[&str]) -> FxHashSet<usize> {
        self.find_matches_with_evidence(symbols).0
    }

    /// Emit one Evidence for (trait_idx, symbol) into `evidence`, respecting the
    /// per-trait MAX cap. Pulls the entry once per (trait, symbol) pair — cheaper
    /// than `entry().or_default()` when a trait matches many symbols.
    #[inline(always)]
    pub(super) fn push_evidence(
        evidence: &mut FxHashMap<usize, Vec<Evidence>>,
        trait_idx: usize,
        symbol: &str,
    ) {
        let entry = evidence.entry(trait_idx).or_default();
        if entry.len() >= MAX_EVIDENCE_PER_TRAIT {
            return;
        }
        entry.push(Evidence {
            method: "symbol".to_string(),
            source: "symbol_index".to_string(),
            value: symbol.to_string(),
            location: None,
            ..Default::default()
        });
    }

    /// Single pass over `symbols`: simultaneously evaluates exact, substr-AC,
    /// regex-literal-prefilter, and regex fallback RegexSet. For each hit,
    /// records evidence so trait evaluation can reuse it via the
    /// `cached_evidence` fast path.
    pub(crate) fn find_matches_with_evidence(
        &self,
        symbols: &[&str],
    ) -> (FxHashSet<usize>, FxHashMap<usize, Vec<Evidence>>) {
        // Parallel path threshold matches StringMatchIndex.
        const PARALLEL_THRESHOLD: usize = 4096;
        if symbols.len() >= PARALLEL_THRESHOLD
            && crate::rayon_nest::inner_work_parallel()
            && (self.substr_automaton.is_some()
                || self.regex_literal_automaton.is_some()
                || !self.regex_fallback_regexes.is_empty())
        {
            return self.find_matches_parallel(symbols);
        }
        self.find_matches_sequential(symbols)
    }

    pub(super) fn find_matches_sequential(
        &self,
        symbols: &[&str],
    ) -> (FxHashSet<usize>, FxHashMap<usize, Vec<Evidence>>) {
        let mut matched: FxHashSet<usize> = FxHashSet::default();
        let mut evidence: FxHashMap<usize, Vec<Evidence>> = FxHashMap::default();
        // Reused across symbols to avoid per-symbol allocation.
        let mut seen_candidates: FxHashSet<usize> = FxHashSet::default();
        // (trait, symbol position) pairs the literal prefilter nominated,
        // verified pattern-major after the sweep: one scratch checkout per
        // regex instead of one per candidate. Per-candidate `is_match` thrashed
        // the thread's hot scratch slot (a different regex nearly every call)
        // and spent more in checkout/park bookkeeping than in the search —
        // ~45% of this function's time on the benign corpus. Each trait holds
        // exactly one pattern kind, so its evidence order (symbol order) is
        // unchanged.
        let mut regex_candidates: Vec<(usize, u32)> = Vec::new();
        // (fallback position, symbol position) pairs nominated by the
        // fallback atom gate; deduped per symbol by `seen_fallbacks`.
        let mut fallback_candidates: Vec<(u32, u32)> = Vec::new();
        let mut seen_fallbacks: FxHashSet<u32> = FxHashSet::default();

        // Rule loading strips up to two leading underscores. Report symbols
        // are normally pre-normalized, but normalize here for edge cases.
        // A named fn because the fallback pass below iterates pattern-major.
        fn normalize(symbol: &str) -> &str {
            let n = symbol.strip_prefix('_').unwrap_or(symbol);
            n.strip_prefix('_').unwrap_or(n)
        }

        for (pos, &symbol) in symbols.iter().enumerate() {
            let normalized = normalize(symbol);
            if normalized.is_empty() {
                continue;
            }

            // Exact: O(1) hashmap lookup.
            if let Some(trait_indices) = self.exact_symbols.get(normalized) {
                for &trait_idx in trait_indices {
                    matched.insert(trait_idx);
                    Self::push_evidence(&mut evidence, trait_idx, symbol);
                }
            }

            // Substr: one AC pass covers all substr patterns at once.
            if let Some(ref ac) = self.substr_automaton {
                for mat in ac.find_overlapping_iter(normalized) {
                    let idx = mat.pattern().as_usize();
                    // Safety: idx from AC always < substr_to_traits.len().
                    for &trait_idx in &self.substr_to_traits[idx] {
                        matched.insert(trait_idx);
                        Self::push_evidence(&mut evidence, trait_idx, symbol);
                    }
                }
            }

            // Regex literal prefilter; verification is deferred (see above).
            if let Some(ref ac) = self.regex_literal_automaton {
                seen_candidates.clear();
                for mat in ac.find_overlapping_iter(normalized) {
                    let idx = mat.pattern().as_usize();
                    for &trait_idx in &self.regex_literal_to_traits[idx] {
                        if !seen_candidates.insert(trait_idx) {
                            continue;
                        }
                        regex_candidates.push((trait_idx, pos as u32));
                    }
                }
            }

            if self.fallback_atom_automata.iter().any(Option::is_some) {
                seen_fallbacks.clear();
                for (k, ac) in self.fallback_atom_automata.iter().enumerate() {
                    let Some(ac) = ac else { continue };
                    for mat in ac.find_overlapping_iter(normalized) {
                        for &fi in &self.fallback_atom_to_fallbacks[k][mat.pattern().as_usize()] {
                            if seen_fallbacks.insert(fi) {
                                fallback_candidates.push((fi, pos as u32));
                            }
                        }
                    }
                }
            }
        }
        // Stable: each fallback's symbols stay in sweep order.
        fallback_candidates.sort_by_key(|&(fi, _)| fi);

        // Pattern-major verification of the nominated (trait, symbol) pairs.
        // Stable sort keeps each trait's symbols in sweep order.
        regex_candidates.sort_by_key(|&(trait_idx, _)| trait_idx);
        let mut i = 0;
        while i < regex_candidates.len() {
            let trait_idx = regex_candidates[i].0;
            let mut j = i;
            while j < regex_candidates.len() && regex_candidates[j].0 == trait_idx {
                j += 1;
            }
            if let Some(Some((pattern, slot))) = self.trait_regex.get(trait_idx)
                && let Some(re) = compile_once(slot, || cached_regex(pattern))
            {
                re.with_scratch(|cache| {
                    for &(_, pos) in &regex_candidates[i..j] {
                        let symbol = symbols[pos as usize];
                        if re.is_match_cached(normalize(symbol), cache) {
                            matched.insert(trait_idx);
                            Self::push_evidence(&mut evidence, trait_idx, symbol);
                        }
                    }
                });
            }
            i = j;
        }

        // Regex fallback (no-literal patterns), pattern-major: each regex's
        // lazy-DFA cache stays hot across the whole symbol list instead of
        // being re-entered per symbol.
        if !symbols.is_empty() {
            for (fi, ((slot, pattern), &trait_idx)) in self
                .regex_fallback_regexes
                .iter()
                .zip(&self.regex_fallback_patterns)
                .zip(&self.regex_fallback_traits)
                .enumerate()
            {
                let gated = self.regex_fallback_gated.get(fi).copied().unwrap_or(false);
                let nominated: &[(u32, u32)] = if gated {
                    let start = fallback_candidates.partition_point(|&(f, _)| (f as usize) < fi);
                    let end = fallback_candidates.partition_point(|&(f, _)| (f as usize) <= fi);
                    if start == end {
                        continue;
                    }
                    &fallback_candidates[start..end]
                } else {
                    &[]
                };
                let Some(re) = compile_once(slot, || {
                    ScratchRegex::new(pattern)
                        .inspect_err(|e| tracing::warn!(pattern, error = %e, "symbol fallback pattern failed to compile; skipping"))
                        .ok()
                }) else {
                    continue;
                };
                re.with_matcher(|is_match| {
                    let mut check = |symbol: &str| {
                        let normalized = normalize(symbol);
                        if !normalized.is_empty() && is_match(normalized) {
                            matched.insert(trait_idx);
                            Self::push_evidence(&mut evidence, trait_idx, symbol);
                        }
                    };
                    if gated {
                        for &(_, pos) in nominated {
                            check(symbols[pos as usize]);
                        }
                    } else {
                        for &symbol in symbols {
                            check(symbol);
                        }
                    }
                });
            }
        }

        let evidence: FxHashMap<usize, Vec<Evidence>> = evidence
            .into_iter()
            .map(|(k, v)| (k, deduplicate_evidence(v)))
            .collect();

        (matched, evidence)
    }

    /// Parallel scan: chunks the symbol list across rayon workers and merges
    /// per-chunk (matched, evidence) results. Only used when the symbol set is
    /// large enough to amortize the merge cost.
    pub(super) fn find_matches_parallel(
        &self,
        symbols: &[&str],
    ) -> (FxHashSet<usize>, FxHashMap<usize, Vec<Evidence>>) {
        let chunk_size = (symbols.len() / rayon::current_num_threads().max(1)).max(512);
        let results: Vec<(FxHashSet<usize>, FxHashMap<usize, Vec<Evidence>>)> = symbols
            .par_chunks(chunk_size)
            .map(|chunk| self.find_matches_sequential(chunk))
            .collect();

        let mut merged_matched: FxHashSet<usize> = FxHashSet::default();
        let mut merged_evidence: FxHashMap<usize, Vec<Evidence>> = FxHashMap::default();
        for (m, e) in results {
            merged_matched.extend(m);
            for (trait_idx, evs) in e {
                let entry = merged_evidence.entry(trait_idx).or_default();
                for ev in evs {
                    if entry.len() >= MAX_EVIDENCE_PER_TRAIT {
                        break;
                    }
                    entry.push(ev);
                }
            }
        }
        let merged_evidence: FxHashMap<usize, Vec<Evidence>> = merged_evidence
            .into_iter()
            .map(|(k, v)| (k, deduplicate_evidence(v)))
            .collect();
        (merged_matched, merged_evidence)
    }

    pub(crate) fn is_symbol_trait(&self, trait_idx: usize) -> bool {
        self.symbol_trait_indices.contains(&trait_idx)
    }
}
