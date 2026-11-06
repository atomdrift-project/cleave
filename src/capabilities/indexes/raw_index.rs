//! Raw-content regex index: per-file-type regex sets and the gate that runs them.

// Split out of the parent module for size; it shares the parent's namespace.
#[allow(clippy::wildcard_imports)]
use super::*;

/// Index for regex patterns from `type: raw` conditions.
/// Builds per-file-type RegexSets to avoid running irrelevant patterns.
#[derive(Clone, Default, Debug)]
pub(crate) struct RawContentRegexIndex {
    /// Per-file-type regex sets for targeted matching, each built on first
    /// use (see [`Self::set`])
    pub(super) by_file_type: FxHashMap<RuleFileType, LazyRegexSet>,
    /// Universal patterns that apply to all file types
    pub(super) universal: Option<FileTypeRegexSet>,
    /// Set of all trait indices that have content regex patterns (for quick lookup)
    pub(super) indexed_traits: FxHashSet<usize>,
}

/// One file type's patterns, and the set built from them on first use.
/// Building every type's set up front -- ~131 of them, mostly Aho-Corasick
/// DFAs -- cost ~0.6 CPU-s and ~0.1 s of wall in every process that
/// evaluated a trait, though a file only ever needs its own type's set and
/// its archive family's.
#[derive(Clone, Debug)]
pub(super) struct LazyRegexSet {
    pub(super) patterns: Vec<(String, usize)>,
    pub(super) words: Vec<WordPattern>,
    pub(super) substr: Vec<WordPattern>,
    pub(super) set: OnceLock<Option<FileTypeRegexSet>>,
}

/// Presence set plus reusable atom-hit offsets from one raw-content gate pass.
///
/// Offsets are complete for a trait only when that trait is in `atom_offsets`.
/// Overflowed / no-literal / unrecorded traits are absent — `eval_raw` must
/// full-scan those. Decoded-layer candidate unions must not write offsets
/// (those positions are not in the raw file).
#[derive(Clone, Debug, Default)]
pub(crate) struct RawGateHits {
    pub traits: FxHashSet<usize>,
    pub atom_offsets: FxHashMap<usize, Vec<u32>>,
    /// Indexed traits whose atoms occur in the member's decoded string
    /// layers (base64/xor/… values). `Some` once the decoded sweep ran, even
    /// when nothing decoded; `eval_text` skips its decoded-layer pass for an
    /// indexed trait absent from this set.
    pub decoded_candidates: Option<FxHashSet<usize>>,
}

/// First-N atom starts per trait during a gate scan. Hitting the cap drops
/// the trait (common atoms are cheaper as one full `eval_raw` than as
/// hundreds of windows).
/// 512, up from 64: on overflow the recorder DROPS the trait's offsets, which
/// forces `eval_raw` back to a full-content scan — and a common atom ("curl",
/// "http") overflows precisely in the large members where the full scan is
/// most expensive. Windows are merged after sorting, so a dense atom degrades toward one big
/// window — i.e. toward today's full scan — never past it.
pub(super) const MAX_ATOM_OFFSETS: usize = 512;

pub(super) struct OffsetRecorder {
    pub(super) map: FxHashMap<usize, Vec<u32>>,
    pub(super) overflowed: FxHashSet<usize>,
}

impl OffsetRecorder {
    pub(super) fn new() -> Self {
        Self {
            map: FxHashMap::default(),
            overflowed: FxHashSet::default(),
        }
    }

    pub(super) fn hit_traits(&mut self, traits: &[usize], offset: u32) {
        for &t in traits {
            self.hit(t, offset);
        }
    }

    pub(super) fn hit(&mut self, trait_idx: usize, offset: u32) {
        if self.overflowed.contains(&trait_idx) {
            return;
        }
        let entry = self.map.entry(trait_idx).or_default();
        if entry.last() == Some(&offset) {
            return;
        }
        if entry.len() >= MAX_ATOM_OFFSETS {
            self.map.remove(&trait_idx);
            self.overflowed.insert(trait_idx);
            return;
        }
        entry.push(offset);
    }

    pub(super) fn finish(mut self) -> FxHashMap<usize, Vec<u32>> {
        for v in self.map.values_mut() {
            v.sort_unstable();
            v.dedup();
        }
        self.map
    }
}

pub(super) fn record_mapped(
    rec: &mut OffsetRecorder,
    mapped: &[usize],
    via_patterns: Option<&[Vec<usize>]>,
    offset: u32,
) {
    if let Some(pattern_to_traits) = via_patterns {
        for &pattern_idx in mapped {
            if let Some(traits) = pattern_to_traits.get(pattern_idx) {
                rec.hit_traits(traits, offset);
            }
        }
    } else {
        rec.hit_traits(mapped, offset);
    }
}

/// Regex set for a specific file type
#[derive(Clone)]
pub(super) struct FileTypeRegexSet {
    pub(super) pattern_to_traits: Vec<Vec<usize>>,
    /// Original pattern strings for debugging/profiling
    pub(super) patterns: Vec<String>,
    /// Per-pattern verifier regexes, compiled on first atom hit. Eagerly
    /// compiling every raw pattern cost ~300 ms per process start; only
    /// patterns whose literal atoms actually appear in scanned content are
    /// ever needed. A pattern that fails to compile stays `None` (warned
    /// once) — strictly better than the old behavior, where one bad pattern
    /// discarded the whole index.
    pub(super) individual_regexes: Vec<OnceLock<Option<Arc<regex::bytes::Regex>>>>,
    /// Individually-compiled regexes for ONLY patterns without extractable
    /// literals (see `no_literal_pass` for why not one `RegexSet`). Parallel
    /// to `no_literal_to_original`; patterns that fail to compile are dropped
    /// from both (warned once at build).
    pub(super) no_literal_regexes: Vec<regex::bytes::Regex>,
    /// Maps no_literal_regexes index -> original pattern index
    pub(super) no_literal_to_original: Vec<usize>,
    /// Aho-Corasick automaton for CASE-SENSITIVE literal prefix pre-filtering
    pub(super) cs_literal_prefilter: Option<AhoCorasick>,
    /// Maps case-sensitive literal index -> pattern indices
    pub(super) cs_literal_to_patterns: Vec<Vec<usize>>,
    /// Aho-Corasick automaton for CASE-INSENSITIVE literal prefix pre-filtering
    pub(super) ci_literal_prefilter: Option<AhoCorasick>,
    /// Maps case-insensitive literal index -> pattern indices
    pub(super) ci_literal_to_patterns: Vec<Vec<usize>>,
    /// Pattern indices that have no extractable literal prefix
    pub(super) patterns_without_literals: Vec<usize>,
    /// Aho-Corasick automaton for case-sensitive word boundary patterns
    pub(super) cs_word_automaton: Option<AhoCorasick>,
    /// Maps case-sensitive word pattern index -> trait indices
    pub(super) cs_word_to_traits: Vec<Vec<usize>>,
    /// Aho-Corasick automaton for case-insensitive word boundary patterns
    pub(super) ci_word_automaton: Option<AhoCorasick>,
    /// Maps case-insensitive word pattern index -> trait indices
    pub(super) ci_word_to_traits: Vec<Vec<usize>>,
    /// Candidate-only substring atoms for `type: text`-on-source traits. Unlike
    /// `*_literal_*` (raw patterns, verified by `individual_regexes`), an atom hit
    /// here marks the trait a candidate **without** an in-index regex verify — the
    /// PikeVM in `eval_raw` is the authority. This gates text traits (so PikeVM
    /// runs only when the atom is present) without compiling a meta-engine per
    /// text pattern, which is what made `type: text` the RSS hog. No word-boundary
    /// check (text regex atoms aren't necessarily token-bounded).
    pub(super) cs_substr_automaton: Option<AhoCorasick>,
    /// Maps case-sensitive substring-atom index -> trait indices.
    pub(super) cs_substr_to_traits: Vec<Vec<usize>>,
    /// Aho-Corasick for case-insensitive substring atoms.
    pub(super) ci_substr_automaton: Option<AhoCorasick>,
    /// Maps case-insensitive substring-atom index -> trait indices.
    pub(super) ci_substr_to_traits: Vec<Vec<usize>>,
}

impl std::fmt::Debug for FileTypeRegexSet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FileTypeRegexSet")
            .field("pattern_count", &self.patterns.len())
            .field("patterns", &self.patterns)
            .finish()
    }
}

impl FileTypeRegexSet {
    /// Find matching traits using hybrid literal pre-filtering strategy:
    /// 1a. Run case-sensitive Aho-Corasick for case-sensitive literal patterns
    /// 1b. Run case-insensitive Aho-Corasick for case-insensitive literal patterns
    /// 1c. Run word boundary Aho-Corasick + byte boundary checks (replaces \b regex)
    /// 1d. Run substring-atom Aho-Corasick for `type: text` trait candidates
    /// 2. Run individual regexes for patterns with matching literals
    /// 3. Run smaller RegexSet for patterns without literals (unavoidable)
    ///
    /// Every sub-pass is an independent full scan over `content` whose results
    /// merge as set unions, so on large inputs (a container's raw bytes, a big
    /// binary) the passes run as parallel rayon tasks — each pass is
    /// byte-identical to its serial run; parallelism is across passes, never
    /// across content chunks, so match semantics cannot change. Small inputs
    /// keep the serial path: archive members already saturate the pool via the
    /// member fan-out, and fork/join overhead would dominate a small scan.
    /// Candidate-only counterpart of [`Self::find_matches`]: every atom pass
    /// plus the no-literal RegexSet, but literal-bucket candidates map to
    /// their traits without the full-content `verify_literal_candidates`
    /// step. Serves the gate's decoded-layer union, where over-approximation
    /// is sound and verification cost is not worth paying.
    pub(super) fn find_candidates(&self, content: &[u8]) -> FxHashSet<usize> {
        let mut out: FxHashSet<usize> = FxHashSet::default();
        let mut literal_candidates: FxHashSet<usize> = FxHashSet::default();
        literal_candidates.extend(Self::ac_first_occurrence_pass(
            self.cs_literal_prefilter.as_ref(),
            &self.cs_literal_to_patterns,
            content,
        ));
        literal_candidates.extend(Self::ac_first_occurrence_pass(
            self.ci_literal_prefilter.as_ref(),
            &self.ci_literal_to_patterns,
            content,
        ));
        for pattern_idx in literal_candidates {
            if let Some(trait_indices) = self.pattern_to_traits.get(pattern_idx) {
                out.extend(trait_indices.iter().copied());
            }
        }
        out.extend(Self::ac_word_boundary_pass(
            self.cs_word_automaton.as_ref(),
            &self.cs_word_to_traits,
            content,
        ));
        out.extend(Self::ac_word_boundary_pass(
            self.ci_word_automaton.as_ref(),
            &self.ci_word_to_traits,
            content,
        ));
        out.extend(Self::ac_first_occurrence_pass(
            self.cs_substr_automaton.as_ref(),
            &self.cs_substr_to_traits,
            content,
        ));
        out.extend(Self::ac_first_occurrence_pass(
            self.ci_substr_automaton.as_ref(),
            &self.ci_substr_to_traits,
            content,
        ));
        out.extend(self.no_literal_pass(content));
        out
    }

    /// Merge word / substr / type:raw verify / no-literal / type:text verify
    /// into `(traits, verified)`. Words and type:raw hits are already decided;
    /// substr atom hits are confirmed or dropped by `verify_text_regex_candidates`.
    pub(super) fn assemble_matches(
        &self,
        words: FxHashSet<usize>,
        substr: FxHashSet<usize>,
        literal_candidates: &FxHashSet<usize>,
        no_lit: &FxHashSet<usize>,
        content: &[u8],
    ) -> (FxHashSet<usize>, FxHashSet<usize>) {
        let verified = words;
        let mut traits = verified.clone();
        traits.extend(substr);

        let mut raw_hits = FxHashSet::default();
        self.verify_literal_candidates(literal_candidates, &mut raw_hits, content);
        traits.extend(&raw_hits);
        // type:raw verifiers use `compile_engine_mirrored`, not LeanRegex+(?m).
        // They stay candidates; marking them verified made `eval_raw` skip a
        // disagreeing second scan.

        traits.extend(no_lit);

        (traits, verified)
    }

    pub(super) fn find_matches_classified(
        &self,
        content: &[u8],
    ) -> (FxHashSet<usize>, FxHashSet<usize>) {
        const PARALLEL_MIN_BYTES: usize = 4 << 20;
        let mut literal_candidates: FxHashSet<usize> = FxHashSet::default();

        if content.len() >= PARALLEL_MIN_BYTES && crate::rayon_nest::inner_work_parallel() {
            let (((cand_cs, cand_ci), (word_cs, word_ci)), ((sub_cs, sub_ci), no_lit)) =
                rayon::join(
                    || {
                        rayon::join(
                            || {
                                rayon::join(
                                    || {
                                        Self::ac_first_occurrence_pass(
                                            self.cs_literal_prefilter.as_ref(),
                                            &self.cs_literal_to_patterns,
                                            content,
                                        )
                                    },
                                    || {
                                        Self::ac_first_occurrence_pass(
                                            self.ci_literal_prefilter.as_ref(),
                                            &self.ci_literal_to_patterns,
                                            content,
                                        )
                                    },
                                )
                            },
                            || {
                                rayon::join(
                                    || {
                                        Self::ac_word_boundary_pass(
                                            self.cs_word_automaton.as_ref(),
                                            &self.cs_word_to_traits,
                                            content,
                                        )
                                    },
                                    || {
                                        Self::ac_word_boundary_pass(
                                            self.ci_word_automaton.as_ref(),
                                            &self.ci_word_to_traits,
                                            content,
                                        )
                                    },
                                )
                            },
                        )
                    },
                    || {
                        rayon::join(
                            || {
                                rayon::join(
                                    || {
                                        Self::ac_first_occurrence_pass(
                                            self.cs_substr_automaton.as_ref(),
                                            &self.cs_substr_to_traits,
                                            content,
                                        )
                                    },
                                    || {
                                        Self::ac_first_occurrence_pass(
                                            self.ci_substr_automaton.as_ref(),
                                            &self.ci_substr_to_traits,
                                            content,
                                        )
                                    },
                                )
                            },
                            || self.no_literal_pass(content),
                        )
                    },
                );
            literal_candidates.extend(cand_cs);
            literal_candidates.extend(cand_ci);
            let mut words = word_cs;
            words.extend(word_ci);
            let mut substr = sub_cs;
            substr.extend(sub_ci);
            return self.assemble_matches(words, substr, &literal_candidates, &no_lit, content);
        }

        // Step 1a/1b: patterns with matching case-sensitive / case-insensitive
        // literals (the CI automaton was built with lowercased literals and
        // ascii_case_insensitive=true).
        literal_candidates.extend(Self::ac_first_occurrence_pass(
            self.cs_literal_prefilter.as_ref(),
            &self.cs_literal_to_patterns,
            content,
        ));
        literal_candidates.extend(Self::ac_first_occurrence_pass(
            self.ci_literal_prefilter.as_ref(),
            &self.ci_literal_to_patterns,
            content,
        ));

        // Step 1c: word boundary patterns via Aho-Corasick + cheap byte checks
        let mut words = Self::ac_word_boundary_pass(
            self.cs_word_automaton.as_ref(),
            &self.cs_word_to_traits,
            content,
        );
        words.extend(Self::ac_word_boundary_pass(
            self.ci_word_automaton.as_ref(),
            &self.ci_word_to_traits,
            content,
        ));

        // Step 1d: substring atoms for `type: text` traits. Atom hit is
        // candidate-only until `assemble_matches` verifies the real regex.
        let mut substr = Self::ac_first_occurrence_pass(
            self.cs_substr_automaton.as_ref(),
            &self.cs_substr_to_traits,
            content,
        );
        substr.extend(Self::ac_first_occurrence_pass(
            self.ci_substr_automaton.as_ref(),
            &self.ci_substr_to_traits,
            content,
        ));

        tracing::trace!(
            "Hybrid prefilter: {} literal candidates, {} no-literal patterns",
            literal_candidates.len(),
            self.patterns_without_literals.len()
        );

        self.assemble_matches(
            words,
            substr,
            &literal_candidates,
            &self.no_literal_pass(content),
            content,
        )
    }

    /// Same presence semantics as [`Self::find_matches`], but records every
    /// atom start (up to [`MAX_ATOM_OFFSETS`] per trait) for windowed
    /// `eval_raw`. Serial only — the gate's 3 MiB cap never hits the 4 MiB
    /// parallel join, and chunked AC would need offset rebasing.
    pub(super) fn find_matches_recording(
        &self,
        content: &[u8],
        rec: &mut OffsetRecorder,
    ) -> (FxHashSet<usize>, FxHashSet<usize>) {
        let mut words: FxHashSet<usize> = FxHashSet::default();
        let mut substr: FxHashSet<usize> = FxHashSet::default();
        let mut literal_candidates: FxHashSet<usize> = FxHashSet::default();

        if let Some(ac) = self.cs_literal_prefilter.as_ref() {
            literal_candidates.extend(Self::ac_record_offsets(
                ac,
                &self.cs_literal_to_patterns,
                content,
                rec,
                Some(&self.pattern_to_traits),
            ));
        }
        if let Some(ac) = self.ci_literal_prefilter.as_ref() {
            literal_candidates.extend(Self::ac_record_offsets(
                ac,
                &self.ci_literal_to_patterns,
                content,
                rec,
                Some(&self.pattern_to_traits),
            ));
        }
        if let Some(ac) = self.cs_word_automaton.as_ref() {
            words.extend(Self::ac_record_word_offsets(
                ac,
                &self.cs_word_to_traits,
                content,
                rec,
            ));
        }
        if let Some(ac) = self.ci_word_automaton.as_ref() {
            words.extend(Self::ac_record_word_offsets(
                ac,
                &self.ci_word_to_traits,
                content,
                rec,
            ));
        }
        if let Some(ac) = self.cs_substr_automaton.as_ref() {
            substr.extend(Self::ac_record_offsets(
                ac,
                &self.cs_substr_to_traits,
                content,
                rec,
                None,
            ));
        }
        if let Some(ac) = self.ci_substr_automaton.as_ref() {
            substr.extend(Self::ac_record_offsets(
                ac,
                &self.ci_substr_to_traits,
                content,
                rec,
                None,
            ));
        }

        self.assemble_matches(
            words,
            substr,
            &literal_candidates,
            &self.no_literal_pass(content),
            content,
        )
    }

    pub(super) fn ac_record_offsets(
        ac: &AhoCorasick,
        index_map: &[Vec<usize>],
        content: &[u8],
        rec: &mut OffsetRecorder,
        via_patterns: Option<&[Vec<usize>]>,
    ) -> FxHashSet<usize> {
        let mut out = FxHashSet::default();
        for mat in ac.find_overlapping_iter(content) {
            let idx = mat.pattern().as_usize();
            let Some(mapped) = index_map.get(idx) else {
                continue;
            };
            out.extend(mapped.iter().copied());
            record_mapped(rec, mapped, via_patterns, mat.start() as u32);
        }
        out
    }

    pub(super) fn ac_record_word_offsets(
        ac: &AhoCorasick,
        word_to_traits: &[Vec<usize>],
        content: &[u8],
        rec: &mut OffsetRecorder,
    ) -> FxHashSet<usize> {
        let mut out = FxHashSet::default();
        let content_len = content.len();
        for mat in ac.find_overlapping_iter(content) {
            let idx = mat.pattern().as_usize();
            let start = mat.start();
            let end = mat.end();
            let before_ok = start == 0
                || !content[start - 1].is_ascii_alphanumeric() && content[start - 1] != b'_';
            let after_ok =
                end == content_len || !content[end].is_ascii_alphanumeric() && content[end] != b'_';
            if before_ok
                && after_ok
                && let Some(trait_indices) = word_to_traits.get(idx)
            {
                out.extend(trait_indices.iter().copied());
                rec.hit_traits(trait_indices, start as u32);
            }
        }
        out
    }

    /// One Aho-Corasick pass collecting the mapped indices of every distinct
    /// automaton pattern that occurs in `content`, with early exit once all
    /// patterns have been seen. Serves steps 1a/1b (literal → candidate
    /// pattern indices) and 1d (substring atom → trait indices) — both only
    /// care about first occurrence.
    /// Minimum content size for chunk-parallel AC sweeps. Below this a single
    /// serial pass wins; above it the slowest pass otherwise runs alone at one
    /// core for the whole blob (container-scope sweeps over tens of MB were a
    /// measured 1-core wall window).
    pub(super) const AC_CHUNK_BYTES: usize = 8 << 20;

    /// Near-equal chunk ranges over `len` bytes, each extended by `overlap`
    /// (= longest pattern − 1): any match starting inside a chunk lies fully
    /// within that chunk's window, so a presence-only union over chunks is
    /// exact.
    pub(super) fn ac_chunk_ranges(len: usize, overlap: usize) -> Vec<(usize, usize)> {
        let chunks = len.div_ceil(Self::AC_CHUNK_BYTES);
        let base = len.div_ceil(chunks);
        (0..chunks)
            .map(|i| {
                let lo = i * base;
                (lo, ((i + 1) * base + overlap).min(len))
            })
            .collect()
    }

    pub(super) fn ac_first_occurrence_pass(
        ac: Option<&AhoCorasick>,
        index_map: &[Vec<usize>],
        content: &[u8],
    ) -> FxHashSet<usize> {
        let Some(ac) = ac else {
            return FxHashSet::default();
        };
        if content.len() >= 2 * Self::AC_CHUNK_BYTES && crate::rayon_nest::inner_work_parallel() {
            use rayon::prelude::*;
            return Self::ac_chunk_ranges(content.len(), ac.max_pattern_len().saturating_sub(1))
                .par_iter()
                .map(|&(lo, hi)| Self::ac_first_occurrence_serial(ac, index_map, &content[lo..hi]))
                .reduce(FxHashSet::default, |mut a, b| {
                    a.extend(b);
                    a
                });
        }
        Self::ac_first_occurrence_serial(ac, index_map, content)
    }

    pub(super) fn ac_first_occurrence_serial(
        ac: &AhoCorasick,
        index_map: &[Vec<usize>],
        content: &[u8],
    ) -> FxHashSet<usize> {
        let mut out = FxHashSet::default();
        let total = index_map.len();
        let mut seen: FxHashSet<usize> = FxHashSet::default();
        // Overlapping iteration is required for correctness: `find_iter` is
        // non-overlapping, so when one pattern's match spans another's (e.g.
        // atoms "fs.readdirSync" and ".readdirSync" from different traits),
        // the contained pattern is silently consumed and its traits never
        // marked — which turns the atom gate into a false-negative machine.
        // The per-pattern dedup plus the all-seen early exit keep the extra
        // match volume bounded.
        for mat in ac.find_overlapping_iter(content) {
            let idx = mat.pattern().as_usize();
            if seen.insert(idx) {
                if let Some(mapped) = index_map.get(idx) {
                    out.extend(mapped.iter().copied());
                }
                if seen.len() == total {
                    break;
                }
            }
        }
        out
    }

    /// Step 1c: word patterns via Aho-Corasick, keeping only occurrences with
    /// non-word bytes (or content edges) on both sides.
    pub(super) fn ac_word_boundary_pass(
        ac: Option<&AhoCorasick>,
        word_to_traits: &[Vec<usize>],
        content: &[u8],
    ) -> FxHashSet<usize> {
        let Some(ac) = ac else {
            return FxHashSet::default();
        };
        if content.len() >= 2 * Self::AC_CHUNK_BYTES && crate::rayon_nest::inner_work_parallel() {
            use rayon::prelude::*;
            return Self::ac_chunk_ranges(content.len(), ac.max_pattern_len().saturating_sub(1))
                .par_iter()
                .map(|&(lo, hi)| Self::ac_word_boundary_serial(ac, word_to_traits, content, lo, hi))
                .reduce(FxHashSet::default, |mut a, b| {
                    a.extend(b);
                    a
                });
        }
        Self::ac_word_boundary_serial(ac, word_to_traits, content, 0, content.len())
    }

    /// Serial word-boundary sweep over `content[lo..hi]`. Boundary bytes are
    /// read from the FULL content at the match's global offsets, so chunk
    /// edges cannot fabricate or lose a boundary.
    pub(super) fn ac_word_boundary_serial(
        ac: &AhoCorasick,
        word_to_traits: &[Vec<usize>],
        content: &[u8],
        lo: usize,
        hi: usize,
    ) -> FxHashSet<usize> {
        let mut out = FxHashSet::default();
        let content_len = content.len();
        let total = word_to_traits.len();
        // Overlapping iteration for the same reason as
        // `ac_first_occurrence_pass`: a word contained in a longer word's
        // match span must still get its own boundary check. `satisfied` skips
        // re-checking words that already passed, and exits once every word
        // has.
        let mut satisfied: FxHashSet<usize> = FxHashSet::default();
        for mat in ac.find_overlapping_iter(&content[lo..hi]) {
            let idx = mat.pattern().as_usize();
            if satisfied.contains(&idx) {
                continue;
            }
            let start = lo + mat.start();
            let end = lo + mat.end();
            let before_ok = start == 0
                || !content[start - 1].is_ascii_alphanumeric() && content[start - 1] != b'_';
            let after_ok =
                end == content_len || !content[end].is_ascii_alphanumeric() && content[end] != b'_';
            if before_ok
                && after_ok
                && let Some(trait_indices) = word_to_traits.get(idx)
            {
                out.extend(trait_indices.iter().copied());
                satisfied.insert(idx);
                if satisfied.len() == total {
                    break;
                }
            }
        }
        out
    }

    /// Step 2: run individual regexes for candidate patterns, folding their
    /// traits into `matched_traits`. Candidates whose traits are all already
    /// matched are skipped — a work-saving check only; the result is the same
    /// union either way.
    pub(super) fn verify_literal_candidates(
        &self,
        literal_candidates: &FxHashSet<usize>,
        matched_traits: &mut FxHashSet<usize>,
        content: &[u8],
    ) {
        // Each candidate verifies against the WHOLE content, so on a large
        // input every one is a full scan and they add up to a single-threaded
        // tail. They are independent — the already-matched skip below is a
        // work-saving check, not a dependency (the docstring's "same union
        // either way") — so a read-only snapshot of `matched_traits` is a
        // sound basis for it and the verifies can run concurrently.
        const PARALLEL_MIN_BYTES: usize = 1 << 20;
        let verify = |&pattern_idx: &usize| -> Option<&[usize]> {
            let trait_indices = self.pattern_to_traits.get(pattern_idx)?;
            if trait_indices.iter().all(|t| matched_traits.contains(t)) {
                return None;
            }
            // Race-don't-block: concurrent first users each compile and the
            // first `set` wins. `get_or_init` would serialize the pile-up of
            // rayon workers hitting a popular pattern during warmup — the
            // same idled-cores trap the bytes-regex cache documents (its
            // per-key OnceLock experiment raised wall ~35%).
            let pattern = &self.patterns[pattern_idx];
            let regex = compile_once(&self.individual_regexes[pattern_idx], || {
                compile_engine_mirrored(pattern)
                    .inspect_err(|e| tracing::warn!(pattern, error = %e, "raw content pattern failed to compile; skipping"))
                    .ok()
                    .map(Arc::new)
            });
            match regex {
                Some(regex) if regex.is_match(content) => Some(trait_indices),
                _ => None,
            }
        };

        if content.len() >= PARALLEL_MIN_BYTES
            && literal_candidates.len() > 1
            && crate::rayon_nest::inner_work_parallel()
        {
            use rayon::prelude::*;
            let hits: Vec<&[usize]> = literal_candidates.par_iter().filter_map(verify).collect();
            matched_traits.extend(hits.into_iter().flatten().copied());
        } else {
            let hits: Vec<&[usize]> = literal_candidates.iter().filter_map(verify).collect();
            matched_traits.extend(hits.into_iter().flatten().copied());
        }
    }

    /// Step 3: patterns without extractable literals (unavoidable full scans).
    ///
    /// Evaluated per pattern rather than as one multi-pattern `RegexSet`: the
    /// set's `matches()` runs the PikeVM over every byte with all patterns
    /// live (no prefilters, no early exit) and was the dominant leaf on
    /// many-member archives. Individual `Regex::is_match` gives each pattern
    /// the full meta-engine stack — lazy DFA, regex-automata's own inner
    /// literal prefilters (more permissive than our atom extractor) — plus
    /// first-match early exit, and large content fans the patterns across
    /// the pool. Presence-per-pattern semantics are identical.
    pub(super) fn no_literal_pass(&self, content: &[u8]) -> FxHashSet<usize> {
        const PARALLEL_MIN_BYTES: usize = 1 << 20;
        let mut out = FxHashSet::default();
        if self.no_literal_regexes.is_empty() {
            return out;
        }
        let matched: Vec<usize> = if content.len() >= PARALLEL_MIN_BYTES
            && self.no_literal_regexes.len() > 1
            && crate::rayon_nest::inner_work_parallel()
        {
            use rayon::prelude::*;
            self.no_literal_regexes
                .par_iter()
                .zip(self.no_literal_to_original.par_iter())
                .filter_map(|(re, &idx)| re.is_match(content).then_some(idx))
                .collect()
        } else {
            self.no_literal_regexes
                .iter()
                .zip(self.no_literal_to_original.iter())
                .filter_map(|(re, &idx)| re.is_match(content).then_some(idx))
                .collect()
        };
        for original_idx in matched {
            if let Some(trait_indices) = self.pattern_to_traits.get(original_idx) {
                out.extend(trait_indices.iter().copied());
            }
        }
        out
    }
}

/// The value in `slot`, compiling it with `compile` on first use; `None` is a
/// pattern that failed to compile. Race-don't-block: concurrent first users
/// each compile and the first `set` wins (see `verify_literal_candidates`).
pub(super) fn compile_once<T>(
    slot: &OnceLock<Option<T>>,
    compile: impl FnOnce() -> Option<T>,
) -> Option<&T> {
    if slot.get().is_none() {
        let _ = slot.set(compile());
    }
    slot.get().and_then(Option::as_ref)
}

/// Compile a raw-content pattern with the same parse mode the trait engines
/// use (`condition.rs::TraitRegex::compile`): byte-mode classes for ASCII
/// patterns with a codepoint fallback, codepoint mode for non-ASCII patterns.
/// The gate's verifiers must mirror the
/// engine's parse mode or the two diverge — Unicode-mode verifiers here were
/// also the reason gate sweeps ran the PikeVM (Unicode `\b` quits the lazy
/// DFA on non-ASCII bytes) instead of the DFA the engines use.
pub(super) fn compile_engine_mirrored(pattern: &str) -> Result<regex::bytes::Regex, regex::Error> {
    const SIZE_LIMIT: usize = 100 * 1024 * 1024;
    if pattern.is_ascii()
        && let Ok(re) = regex::bytes::RegexBuilder::new(pattern)
            .size_limit(SIZE_LIMIT)
            .unicode(false)
            .build()
    {
        return Ok(re);
    }
    // `\p{..}` classes are ASCII source but only parse in codepoint mode.
    regex::bytes::RegexBuilder::new(pattern)
        .size_limit(SIZE_LIMIT)
        .build()
}

/// A word pattern: the literal word and whether it's case-insensitive
#[derive(Clone, Debug)]
pub(super) struct WordPattern {
    pub(super) word: String,
    pub(super) case_insensitive: bool,
    pub(super) trait_idx: usize,
}

impl RawContentRegexIndex {
    /// Build index from trait definitions (all platforms).
    #[cfg(test)] // non-filtered convenience; production builds go through build_filtered
    pub(crate) fn build(traits: &[TraitDefinition]) -> Self {
        Self::build_filtered(traits, &[Platform::All])
    }

    /// Build index, keeping only traits whose platform set intersects `platforms`.
    /// Off-platform traits keep their absolute index slot but contribute no patterns.
    pub(crate) fn build_filtered(traits: &[TraitDefinition], platforms: &[Platform]) -> Self {
        // Group patterns by file type
        let mut by_file_type_patterns: FxHashMap<RuleFileType, Vec<(String, usize)>> =
            FxHashMap::default();
        let mut universal_patterns: Vec<(String, usize)> = Vec::new();
        // Word patterns separated for Aho-Corasick batch matching
        let mut by_file_type_words: FxHashMap<RuleFileType, Vec<WordPattern>> =
            FxHashMap::default();
        let mut universal_words: Vec<WordPattern> = Vec::new();
        // Candidate-only substring atoms from `type: text`-on-source regex traits.
        let mut by_file_type_substr: FxHashMap<RuleFileType, Vec<WordPattern>> =
            FxHashMap::default();
        let mut universal_substr: Vec<WordPattern> = Vec::new();

        for (trait_idx, trait_def) in traits.iter().enumerate() {
            if !platforms_intersect(&trait_def.platforms, platforms) {
                continue;
            }
            // Extract regex patterns from Content traits
            // Word patterns are routed to a dedicated Aho-Corasick automaton
            match &trait_def.r#if {
                Condition::Raw(RawQuery {
                    regex: Some(regex_str),
                    case_insensitive,
                    ..
                }) => {
                    let pattern = if *case_insensitive {
                        format!("(?i){}", regex_str)
                    } else {
                        regex_str.clone()
                    };
                    // Derived now although the per-type sets that use it are
                    // built lazily: `MatchIndexes::build` saves new derivations
                    // when it finishes, and one first derived later is never saved.
                    let _ = super::super::derivation_memo::prefix_literal(&pattern);
                    if trait_def.r#for.contains(&RuleFileType::All) {
                        universal_patterns.push((pattern, trait_idx));
                    } else {
                        for ft in &trait_def.r#for {
                            by_file_type_patterns
                                .entry(*ft)
                                .or_default()
                                .push((pattern.clone(), trait_idx));
                        }
                    }
                }
                Condition::Raw(RawQuery {
                    word: Some(word_str),
                    case_insensitive,
                    ..
                }) => {
                    let wp = WordPattern {
                        word: word_str.clone(),
                        case_insensitive: *case_insensitive,
                        trait_idx,
                    };
                    if trait_def.r#for.contains(&RuleFileType::All) {
                        universal_words.push(wp);
                    } else {
                        for ft in &trait_def.r#for {
                            by_file_type_words
                                .entry(*ft)
                                .or_default()
                                .push(WordPattern {
                                    word: word_str.clone(),
                                    case_insensitive: *case_insensitive,
                                    trait_idx,
                                });
                        }
                    }
                }
                // `type: text` on source delegates to `eval_raw` (raw content);
                // gate it via cheap atom prefilters so its PikeVM runs only when an
                // atom is present — but candidate-only, with no compiled verifier
                // (eval_raw verifies). `word:` reuses the boundary-checked word path;
                // `regex:` contributes its mandatory literal (if extractable) to the
                // substring path. A regex with no extractable literal stays unindexed
                // (ungated; eval_raw scans it as before — correctness over speed).
                Condition::Text(TextQuery {
                    word: Some(word_str),
                    case_insensitive,
                    ..
                }) => {
                    let make = || WordPattern {
                        word: word_str.clone(),
                        case_insensitive: *case_insensitive,
                        trait_idx,
                    };
                    if trait_def.r#for.contains(&RuleFileType::All) {
                        universal_words.push(make());
                    } else {
                        for ft in &trait_def.r#for {
                            by_file_type_words.entry(*ft).or_default().push(make());
                        }
                    }
                }
                Condition::Text(TextQuery {
                    regex: Some(regex_str),
                    case_insensitive,
                    ..
                }) => {
                    // Gate on a mandatory *any-of* atom set (alternation-aware,
                    // `(?i)`-aware — see `mandatory_atom_set`), not just a
                    // prefix — otherwise ~half of `type: text` patterns are
                    // ungated and re-scan every source file. Multiple entries
                    // sharing a trait_idx give any-of semantics for free: a hit
                    // on any atom marks the trait a candidate. Non-UTF-8 or
                    // inextractable sets stay ungated (eval_raw scans directly).
                    let atoms = super::super::derivation_memo::mandatory_atom_set(regex_str);
                    if let Some(atoms) = atoms {
                        for (literal, atom_ci) in &atoms {
                            let make = || WordPattern {
                                word: literal.clone(),
                                case_insensitive: *case_insensitive || *atom_ci,
                                trait_idx,
                            };
                            if trait_def.r#for.contains(&RuleFileType::All) {
                                universal_substr.push(make());
                            } else {
                                for ft in &trait_def.r#for {
                                    by_file_type_substr.entry(*ft).or_default().push(make());
                                }
                            }
                        }
                    }
                }
                _ => {}
            }
        }

        // Only the universal set is built here; each file type's is built on
        // first use (see `LazyRegexSet`). The indexed traits are exactly those
        // given a pattern, word or atom below, since a set keeps every one.
        let indexed_traits = by_file_type_patterns
            .values()
            .flatten()
            .chain(&universal_patterns)
            .map(|(_, trait_idx)| *trait_idx)
            .chain(
                by_file_type_words
                    .values()
                    .chain(by_file_type_substr.values())
                    .flatten()
                    .chain(&universal_words)
                    .chain(&universal_substr)
                    .map(|wp| wp.trait_idx),
            )
            .collect();
        let file_types: FxHashSet<RuleFileType> = by_file_type_patterns
            .keys()
            .chain(by_file_type_words.keys())
            .chain(by_file_type_substr.keys())
            .copied()
            .collect();
        let by_file_type: FxHashMap<RuleFileType, LazyRegexSet> = file_types
            .into_iter()
            .map(|ft| {
                let lazy = LazyRegexSet {
                    patterns: by_file_type_patterns.remove(&ft).unwrap_or_default(),
                    words: by_file_type_words.remove(&ft).unwrap_or_default(),
                    substr: by_file_type_substr.remove(&ft).unwrap_or_default(),
                    set: OnceLock::new(),
                };
                (ft, lazy)
            })
            .collect();
        let t_universal = std::time::Instant::now();
        let universal =
            Self::build_regex_set(&universal_patterns, &universal_words, &universal_substr);
        tracing::debug!(
            universal_ms = t_universal.elapsed().as_millis() as u64,
            file_types = by_file_type.len(),
            "raw-content regex index built"
        );

        Self {
            by_file_type,
            universal,
            indexed_traits,
        }
    }

    /// `file_type`'s set, built by its first caller. Race-don't-block, as in
    /// [`compile_once`]: concurrent first callers each build one and the first
    /// kept wins, so no thread waits on another's build.
    pub(super) fn set(&self, file_type: &RuleFileType) -> Option<&FileTypeRegexSet> {
        let lazy = self.by_file_type.get(file_type)?;
        compile_once(&lazy.set, || {
            let t = std::time::Instant::now();
            let set = Self::build_regex_set(&lazy.patterns, &lazy.words, &lazy.substr);
            tracing::debug!(
                ?file_type,
                patterns = lazy.patterns.len(),
                words = lazy.words.len(),
                atoms = lazy.substr.len(),
                elapsed_ms = t.elapsed().as_millis() as u64,
                "raw-content regex set built"
            );
            set
        })
    }

    /// Build every file type's set now, in parallel. For callers about to fan
    /// a scan out across the pool (see `CapabilityMapper::warm_indexes`): left
    /// lazy, every worker that meets a type before its set is kept builds its
    /// own copy, and after a trait edit `validate`'s fixtures did exactly that.
    pub(crate) fn warm(&self) {
        self.by_file_type.par_iter().for_each(|(file_type, _)| {
            let _ = self.set(file_type);
        });
    }

    pub(super) fn build_regex_set(
        patterns: &[(String, usize)],
        words: &[WordPattern],
        substr: &[WordPattern],
    ) -> Option<FileTypeRegexSet> {
        if patterns.is_empty() && words.is_empty() && substr.is_empty() {
            return None;
        }

        // Group traits by unique pattern to avoid redundancy
        let mut pattern_map: FxHashMap<String, Vec<usize>> = FxHashMap::default();
        for (pattern, trait_idx) in patterns {
            pattern_map
                .entry(pattern.clone())
                .or_default()
                .push(*trait_idx);
        }

        let pattern_strs: Vec<String> = pattern_map.keys().cloned().collect();
        let pattern_to_traits: Vec<Vec<usize>> = pattern_strs
            .iter()
            .filter_map(|p| pattern_map.get(p).cloned())
            .collect();

        // Extract literal prefixes for Aho-Corasick pre-filtering
        // Separate case-sensitive and case-insensitive patterns
        let mut cs_literal_prefixes: Vec<String> = Vec::new();
        let mut cs_literal_to_patterns: Vec<Vec<usize>> = Vec::new();
        let mut cs_literal_map: FxHashMap<String, usize> = FxHashMap::default();
        let mut ci_literal_prefixes: Vec<String> = Vec::new();
        let mut ci_literal_to_patterns: Vec<Vec<usize>> = Vec::new();
        let mut ci_literal_map: FxHashMap<String, usize> = FxHashMap::default();
        let mut patterns_without_literals: Vec<usize> = Vec::new();

        for (pattern_idx, pattern) in pattern_strs.iter().enumerate() {
            // Check if pattern is case-insensitive (starts with (?i))
            let is_case_insensitive = pattern.starts_with("(?i)");

            if let Some(literal) = super::super::derivation_memo::prefix_literal(pattern) {
                if is_case_insensitive {
                    // Case-insensitive: lowercase the literal for matching
                    let lower_literal = literal.to_lowercase();
                    if let Some(&literal_idx) = ci_literal_map.get(&lower_literal) {
                        ci_literal_to_patterns[literal_idx].push(pattern_idx);
                    } else {
                        let literal_idx = ci_literal_prefixes.len();
                        ci_literal_map.insert(lower_literal.clone(), literal_idx);
                        ci_literal_prefixes.push(lower_literal);
                        ci_literal_to_patterns.push(vec![pattern_idx]);
                    }
                } else {
                    // Case-sensitive: use literal as-is
                    if let Some(&literal_idx) = cs_literal_map.get(&literal) {
                        cs_literal_to_patterns[literal_idx].push(pattern_idx);
                    } else {
                        let literal_idx = cs_literal_prefixes.len();
                        cs_literal_map.insert(literal.clone(), literal_idx);
                        cs_literal_prefixes.push(literal);
                        cs_literal_to_patterns.push(vec![pattern_idx]);
                    }
                }
            } else {
                // No extractable literal - must always run this pattern
                patterns_without_literals.push(pattern_idx);
            }
        }

        // Build case-sensitive Aho-Corasick automaton
        let cs_literal_prefilter = if !cs_literal_prefixes.is_empty() {
            build_index_automaton(&cs_literal_prefixes, false)
        } else {
            None
        };

        // Build case-insensitive Aho-Corasick automaton
        let ci_literal_prefilter = if !ci_literal_prefixes.is_empty() {
            build_index_automaton(&ci_literal_prefixes, true)
        } else {
            None
        };

        // Verifier regexes compile lazily on first atom hit (see
        // `verify_literal_candidates`); allocate the empty slots.
        let individual_regexes: Vec<OnceLock<Option<Arc<regex::bytes::Regex>>>> =
            (0..pattern_strs.len()).map(|_| OnceLock::new()).collect();

        // Compile the no-extractable-literal patterns individually (see
        // `no_literal_pass`). A pattern that fails to compile is dropped with
        // a warning — strictly better than the old single-RegexSet build,
        // where one bad pattern discarded every no-literal pattern.
        let mut no_literal_regexes: Vec<regex::bytes::Regex> = Vec::new();
        let mut no_literal_to_original: Vec<usize> = Vec::new();
        for &idx in &patterns_without_literals {
            let Some(pattern) = pattern_strs.get(idx) else {
                continue;
            };
            match compile_engine_mirrored(pattern) {
                Ok(re) => {
                    no_literal_regexes.push(re);
                    no_literal_to_original.push(idx);
                }
                Err(e) => {
                    tracing::warn!(pattern, error = %e, "no-literal pattern failed to compile; skipping");
                }
            }
        }

        // Build word boundary Aho-Corasick automatons
        // Separate case-sensitive and case-insensitive words
        let mut cs_words: Vec<String> = Vec::new();
        let mut cs_word_to_traits: Vec<Vec<usize>> = Vec::new();
        let mut cs_word_map: FxHashMap<String, usize> = FxHashMap::default();
        let mut ci_words: Vec<String> = Vec::new();
        let mut ci_word_to_traits: Vec<Vec<usize>> = Vec::new();
        let mut ci_word_map: FxHashMap<String, usize> = FxHashMap::default();

        for wp in words {
            if wp.case_insensitive {
                let lower = wp.word.to_lowercase();
                if let Some(&idx) = ci_word_map.get(&lower) {
                    ci_word_to_traits[idx].push(wp.trait_idx);
                } else {
                    let idx = ci_words.len();
                    ci_word_map.insert(lower.clone(), idx);
                    ci_words.push(lower);
                    ci_word_to_traits.push(vec![wp.trait_idx]);
                }
            } else if let Some(&idx) = cs_word_map.get(&wp.word) {
                cs_word_to_traits[idx].push(wp.trait_idx);
            } else {
                let idx = cs_words.len();
                cs_word_map.insert(wp.word.clone(), idx);
                cs_words.push(wp.word.clone());
                cs_word_to_traits.push(vec![wp.trait_idx]);
            }
        }

        let cs_word_automaton = if !cs_words.is_empty() {
            build_index_automaton(&cs_words, false)
        } else {
            None
        };

        let ci_word_automaton = if !ci_words.is_empty() {
            build_index_automaton(&ci_words, true)
        } else {
            None
        };

        // Substring-atom automata (candidate-only, no boundary check) for text traits.
        let mut cs_substr: Vec<String> = Vec::new();
        let mut cs_substr_to_traits: Vec<Vec<usize>> = Vec::new();
        let mut cs_substr_map: FxHashMap<String, usize> = FxHashMap::default();
        let mut ci_substr: Vec<String> = Vec::new();
        let mut ci_substr_to_traits: Vec<Vec<usize>> = Vec::new();
        let mut ci_substr_map: FxHashMap<String, usize> = FxHashMap::default();
        for sp in substr {
            if sp.case_insensitive {
                let lower = sp.word.to_lowercase();
                if let Some(&idx) = ci_substr_map.get(&lower) {
                    ci_substr_to_traits[idx].push(sp.trait_idx);
                } else {
                    let idx = ci_substr.len();
                    ci_substr_map.insert(lower.clone(), idx);
                    ci_substr.push(lower);
                    ci_substr_to_traits.push(vec![sp.trait_idx]);
                }
            } else if let Some(&idx) = cs_substr_map.get(&sp.word) {
                cs_substr_to_traits[idx].push(sp.trait_idx);
            } else {
                let idx = cs_substr.len();
                cs_substr_map.insert(sp.word.clone(), idx);
                cs_substr.push(sp.word.clone());
                cs_substr_to_traits.push(vec![sp.trait_idx]);
            }
        }
        let cs_substr_automaton = if !cs_substr.is_empty() {
            build_index_automaton(&cs_substr, false)
        } else {
            None
        };
        let ci_substr_automaton = if !ci_substr.is_empty() {
            build_index_automaton(&ci_substr, true)
        } else {
            None
        };

        // If there are no regex patterns (only word/substr patterns), build a minimal set
        if pattern_strs.is_empty() {
            return Some(FileTypeRegexSet {
                pattern_to_traits: Vec::new(),
                patterns: Vec::new(),
                individual_regexes: Vec::new(),
                no_literal_regexes: Vec::new(),
                no_literal_to_original: Vec::new(),
                cs_literal_prefilter: None,
                cs_literal_to_patterns: Vec::new(),
                ci_literal_prefilter: None,
                ci_literal_to_patterns: Vec::new(),
                patterns_without_literals: Vec::new(),
                cs_word_automaton,
                cs_word_to_traits,
                ci_word_automaton,
                ci_word_to_traits,
                cs_substr_automaton,
                cs_substr_to_traits,
                ci_substr_automaton,
                ci_substr_to_traits,
            });
        }

        // Pattern validity is no longer checked here. Verifiers compile
        // lazily; an invalid pattern warns and skips itself at eval time
        // instead of (as before) failing this build and silently degrading
        // the ENTIRE raw-content index to empty. Author-grade validation
        // belongs to `cleave validate`.
        Some(FileTypeRegexSet {
            pattern_to_traits,
            patterns: pattern_strs,
            individual_regexes,
            no_literal_regexes,
            no_literal_to_original,
            cs_literal_prefilter,
            cs_literal_to_patterns,
            ci_literal_prefilter,
            ci_literal_to_patterns,
            patterns_without_literals,
            cs_word_automaton,
            cs_word_to_traits,
            ci_word_automaton,
            ci_word_to_traits,
            cs_substr_automaton,
            cs_substr_to_traits,
            ci_substr_automaton,
            ci_substr_to_traits,
        })
    }

    pub(crate) fn has_patterns(&self) -> bool {
        !self.indexed_traits.is_empty()
    }

    /// Check whether a trait is indexed in a compiled regex set.
    pub(crate) fn is_indexed_trait(&self, trait_idx: usize) -> bool {
        self.indexed_traits.contains(&trait_idx)
    }

    /// Find matches using only patterns applicable to the given file type.
    /// Uses Aho-Corasick literal prefix pre-filtering to skip RegexSet when possible.
    ///
    /// The universal set, the file-type set and the archive-family sets are
    /// independent scans over the same bytes whose results are unioned, so on
    /// large content they run concurrently. Each set already fans its own
    /// sub-passes out (see [`FileTypeRegexSet::find_matches`]), but those
    /// fan-outs were serialized behind one another: a container's raw bytes
    /// (hundreds of MB) paid every set's slowest pass end to end.
    #[cfg(test)]
    pub(crate) fn find_matches(
        &self,
        binary_data: &[u8],
        file_type: &RuleFileType,
    ) -> FxHashSet<usize> {
        self.find_matches_classified(binary_data, file_type).0
    }

    pub(super) fn find_matches_classified(
        &self,
        binary_data: &[u8],
        file_type: &RuleFileType,
    ) -> (FxHashSet<usize>, FxHashSet<usize>) {
        const PARALLEL_MIN_BYTES: usize = 4 << 20;

        let sets: Vec<&FileTypeRegexSet> = self
            .universal
            .iter()
            .chain(self.set(file_type))
            .chain(
                archive_family_types(file_type)
                    .iter()
                    .filter_map(|ft| self.set(ft)),
            )
            .collect();

        if binary_data.len() >= PARALLEL_MIN_BYTES
            && sets.len() > 1
            && crate::rayon_nest::inner_work_parallel()
        {
            use rayon::prelude::*;
            return sets
                .par_iter()
                .map(|set| set.find_matches_classified(binary_data))
                .reduce(
                    || (FxHashSet::default(), FxHashSet::default()),
                    |mut a, b| {
                        a.0.extend(b.0);
                        a.1.extend(b.1);
                        a
                    },
                );
        }

        let mut traits = FxHashSet::default();
        let mut verified = FxHashSet::default();
        for set in sets {
            let (t, v) = set.find_matches_classified(binary_data);
            traits.extend(t);
            verified.extend(v);
        }
        (traits, verified)
    }

    /// Like [`Self::find_matches`], optionally recording atom-hit offsets for
    /// source-only windowed `eval_raw`. Presence semantics are identical.
    pub(crate) fn find_matches_detailed(
        &self,
        binary_data: &[u8],
        file_type: &RuleFileType,
        record_offsets: bool,
    ) -> RawGateHits {
        // Windowing is disabled below [`MIN_HAYSTACK_TO_WINDOW`]. Recording
        // every atom occurrence on sub-floor stubs is extra gate work that
        // `eval_raw` would never use. The floor is 256 B so 256 B–1 KiB
        // source members can window bounded regexes.
        if !record_offsets || binary_data.len() < MIN_HAYSTACK_TO_WINDOW {
            let (traits, _) = self.find_matches_classified(binary_data, file_type);
            return RawGateHits {
                traits,
                atom_offsets: FxHashMap::default(),
                decoded_candidates: None,
            };
        }
        let sets: Vec<&FileTypeRegexSet> = self
            .universal
            .iter()
            .chain(self.set(file_type))
            .chain(
                archive_family_types(file_type)
                    .iter()
                    .filter_map(|ft| self.set(ft)),
            )
            .collect();
        let mut rec = OffsetRecorder::new();
        let mut traits = FxHashSet::default();
        for set in sets {
            let (t, _) = set.find_matches_recording(binary_data, &mut rec);
            traits.extend(t);
        }
        RawGateHits {
            traits,
            atom_offsets: rec.finish(),
            decoded_candidates: None,
        }
    }

    /// Candidate-only sweep for small secondary haystacks (the decoded string
    /// layers unioned into the gate). Unlike [`Self::find_matches`], the
    /// pattern-bucket literal candidates map straight to their traits without
    /// full-content regex verification — an over-approximation, which is
    /// exactly what a gate union wants (the trait evaluator verifies for
    /// real), and it keeps this pass cheap on decode-heavy members where the
    /// verify step measured as a wall regression.
    pub(crate) fn find_candidates(
        &self,
        content: &[u8],
        file_type: &RuleFileType,
    ) -> FxHashSet<usize> {
        let mut out = FxHashSet::default();
        for set in self.universal.iter().chain(self.set(file_type)).chain(
            archive_family_types(file_type)
                .iter()
                .filter_map(|ft| self.set(ft)),
        ) {
            out.extend(set.find_candidates(content));
        }
        out
    }
}
