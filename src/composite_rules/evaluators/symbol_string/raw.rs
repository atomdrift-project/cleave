//! Byte-level conditions: raw, numeric-literal and encoded matching.

// Split out of the parent module for size; it shares the parent's namespace.
#[allow(clippy::wildcard_imports)]
use super::*;

/// Maps byte offsets found in a case-folded search copy back to the text it
/// was folded from.
///
/// Case-insensitive Unicode search runs over `text.to_lowercase()`, and
/// lowercasing can change a char's UTF-8 length (`İ`, 2 bytes, lowers to the
/// 3-byte `i̇`), so an offset in the copy is not an offset in `text`: slicing
/// `text` with it can split a char (a panic) or select the wrong bytes.
/// Queries must be non-decreasing; each resumes where the last stopped, so
/// mapping every hit of one scan costs a single pass over `text`. Without case
/// folding the copy is `text` itself and offsets pass through unchanged.
pub(super) struct LoweredOffsets<'a> {
    pub(super) chars: Option<std::str::CharIndices<'a>>,
    pub(super) lowered: usize,
    pub(super) original: usize,
}

impl<'a> LoweredOffsets<'a> {
    pub(super) fn new(text: &'a str, case_folded: bool) -> Self {
        Self {
            chars: case_folded.then(|| text.char_indices()),
            lowered: 0,
            original: 0,
        }
    }

    /// The char boundary in `text` at or after the image of `lowered_offset`.
    pub(super) fn original(&mut self, lowered_offset: usize) -> usize {
        let Some(chars) = self.chars.as_mut() else {
            return lowered_offset;
        };
        while self.lowered < lowered_offset {
            let Some((at, c)) = chars.next() else { break };
            self.lowered += c.to_lowercase().map(char::len_utf8).sum::<usize>();
            self.original = at + c.len_utf8();
        }
        self.original
    }
}

/// Evaluate `type: literal, kind: number` — match against numeric
/// literals extracted by the AST walker into `ctx.report.strings` with
/// `section: Some("ast-number")`. The string row encodes:
///   - `value`    = decimal-rendered parsed integer (e.g., `"511"`)
///   - `encoding` = source-written radix as string (`"2" / "8" / "10" / "16"`)
///
/// When `want_value` is set, the literal's parsed value must equal it.
/// When `want_radix` is set, the source-written radix must match —
/// lets authors distinguish `0o777` from `511`.
#[must_use]
pub(crate) fn eval_numeric_literal<'a>(
    want_value: Option<i64>,
    want_radix: Option<u32>,
    ctx: &EvaluationContext<'a>,
) -> ConditionResult {
    let mut evidence = Vec::new();
    let mut match_count = 0usize;

    for string_info in &ctx.report.strings {
        if string_info.section.as_deref() != Some("ast-number") {
            continue;
        }
        let Ok(parsed_value) = string_info.value.parse::<i64>() else {
            continue;
        };
        let Ok(parsed_radix) = string_info.encoding.parse::<u32>() else {
            continue;
        };
        if let Some(v) = want_value
            && parsed_value != v
        {
            continue;
        }
        if let Some(r) = want_radix
            && parsed_radix != r
        {
            continue;
        }
        match_count += 1;
        if evidence.len() < MAX_EVIDENCE_PER_TRAIT {
            evidence.push(Evidence {
                method: "literal".to_string(),
                source: "ast-number".to_string(),
                value: format!("{} (radix {})", parsed_value, parsed_radix),
                location: Some(string_info_location(ctx.report, string_info)),
                ..Default::default()
            });
        }
    }

    ConditionResult {
        matched: match_count > 0,
        evidence,
        match_count,
        warnings: Vec::new(),
        // High precision — numeric literal matches are unambiguous.
        precision: 2.0,
        matched_trait_ids: Vec::new(),
    }
}

/// Windows around gate-supplied atom hits for source `eval_raw`. `None` means
/// full-scan: PE/extracted-string types, gate did not run, trait has no
/// recorded offsets, the pattern is cross-line unbounded (`(?s).*` /
/// `[\s\S]*`), or `\A`/`\z`. Line-local `.*` / `[^\n]*` and whitespace `\s*`
/// (capped at `UNBOUNDED_WS_CAP`) window.
pub(super) fn source_raw_windows(
    ctx: &EvaluationContext<'_>,
    pattern: &str,
    search_start: usize,
    search_end: usize,
) -> Option<Vec<(usize, usize)>> {
    use super::super::raw_window_stats as ws;
    if !ctx.file_type.uses_raw_text_search_for(ctx.binary_data) {
        ws::bump(&ws::NOT_SOURCE_TYPE);
        ws::LAST_REASON.with(|r| r.set(3));
        return None;
    }
    let Some(idx) = ctx.current_trait_idx else {
        ws::bump(&ws::NO_TRAIT_IDX);
        ws::LAST_REASON.with(|r| r.set(3));
        return None;
    };
    let Some(hits) = ctx.raw_atom_offsets.and_then(|m| m.get(&idx)) else {
        ws::bump(&ws::NO_ATOMS);
        ws::LAST_REASON.with(|r| r.set(1));
        return None;
    };
    // Offsets were recorded for this trait's *indexed* regex (usually `if:`).
    // `unless:` / extra `type: text` regexes share `current_trait_idx` but not
    // those atoms — windowing them around the `if` hits misses their matches
    // (`loopback-http-url-reference`, `bearer-token`).
    if !super::super::hits_are_pattern_atoms(ctx.binary_data, hits, pattern) {
        ws::bump(&ws::ATOM_MISMATCH);
        ws::LAST_REASON.with(|r| r.set(3));
        return None;
    }
    let windows = super::super::windows_from_atom_hits(
        ctx.binary_data,
        hits,
        pattern,
        search_start,
        search_end,
    );
    if windows.is_none() {
        ws::bump(&ws::UNBOUNDED);
        ws::LAST_REASON.with(|r| r.set(2));
    }
    windows
}

/// Used by `type: raw` conditions to search raw file content rather than extracted strings.
/// Use for cross-boundary patterns or when string extraction is insufficient.
#[must_use]
pub(crate) fn eval_raw<'a>(
    pattern: TextPattern<'_>,
    length_bounds: (Option<usize>, Option<usize>),
    is_check: Option<StringValidator>,
    not: Option<&Vec<NotException>>,
    location: &ContentLocationParams,
    ctx: &EvaluationContext<'a>,
    trait_id: Option<&str>,
) -> ConditionResult {
    let TextPattern {
        exact,
        substr,
        regex,
        word,
        case_insensitive,
    } = pattern;
    let _mp = crate::mem_profile::phase(crate::mem_profile::Phase::EvalRaw);
    // `word:` is a literal byte-boundary scan (no regex engine). Only `regex:`
    // resolves to a pattern string here, and even then the engine is chosen
    // from the string alone (ASCII → bytes engine, else unicode), so an ASCII
    // pattern never compiles the unicode `regex::Regex` it would only read
    // `.as_str()` off of — that wasted compile dominated peak RSS on archives.
    let raw_pattern = crate::composite_rules::condition::raw_regex_pattern(
        None,
        regex.map(String::as_str),
        case_insensitive,
    );
    if too_short_for_unbounded_scan(exact, substr, location) {
        return ConditionResult::no_match();
    }

    let t_start = PROFILE_TIMING_ENABLED.then(std::time::Instant::now);

    // Resolve effective range from location constraints, within the data.
    let (search_start, search_end) = resolve_effective_range(location, ctx);
    let search_start = search_start.min(ctx.binary_data.len());
    let search_end = search_end.min(ctx.binary_data.len());
    if search_start >= search_end {
        return ConditionResult::no_match();
    }
    let scan = RawScan {
        ctx,
        start: search_start,
        end: search_end,
        data: &ctx.binary_data[search_start..search_end],
        is_check,
        not,
        needs_count: match_count_needed(),
        needs_locations: super::match_locations_needed(),
    };

    let mut evidence = Vec::new();
    let match_count = if let Some(w) = word {
        scan.word(w, case_insensitive, &mut evidence)
    } else if let Some(pattern_str) = raw_pattern.as_deref() {
        scan.regex(
            pattern_str,
            case_insensitive,
            length_bounds,
            trait_id,
            &mut evidence,
        )
    } else if let Some(exact_str) = exact {
        scan.exact(exact_str, case_insensitive, &mut evidence)
    } else if let Some(substr_str) = substr {
        let Some(count) = scan.substr(substr_str, case_insensitive, &mut evidence) else {
            return ConditionResult::no_match();
        };
        count
    } else {
        0
    };

    if let Some(t) = t_start {
        eprintln!("[PROFILE]   eval_raw: {}ms", t.elapsed().as_millis());
    }

    // count/density constraints are checked and scored at trait level.
    ConditionResult {
        matched: match_count > 0,
        evidence,
        match_count,
        warnings: Vec::new(),
        precision: raw_precision(
            exact.is_some(),
            word.is_some() || raw_pattern.is_some(),
            substr.is_some(),
            case_insensitive,
            is_check.is_some(),
            location,
        ),
        matched_trait_ids: Vec::new(),
    }
}

/// Short raw patterns are rejected unless the search space is pinned to a
/// small range: an offset or offset range, or a section plus a section
/// offset. Density constraints (count_min, per_kb_min) are checked at trait
/// level, not here.
fn too_short_for_unbounded_scan(
    exact: Option<&String>,
    substr: Option<&String>,
    location: &ContentLocationParams,
) -> bool {
    const MIN_PATTERN_LEN: usize = 3;
    let pinned = location.offset.is_some()
        || location.offset_range.is_some()
        || (location.section.is_some()
            && (location.section_offset.is_some() || location.section_offset_range.is_some()));
    !pinned
        && [exact, substr]
            .into_iter()
            .flatten()
            .any(|s| s.len() < MIN_PATTERN_LEN)
}

/// How much a raw match says, by pattern kind and constraint.
fn raw_precision(
    exact: bool,
    pattern: bool,
    substr: bool,
    case_insensitive: bool,
    validated: bool,
    location: &ContentLocationParams,
) -> f32 {
    let mut precision = if exact {
        2.0
    } else if pattern {
        1.5
    } else if substr {
        1.0
    } else {
        0.0
    };
    if case_insensitive {
        precision *= 0.5;
    }
    // A high-fidelity validator narrows the match.
    if validated {
        precision += 0.5;
    }
    if location.section.is_some() {
        precision += 1.0;
    }
    if location.offset.is_some() {
        precision += 1.5;
    } else if location.offset_range.is_some()
        || location.section_offset.is_some()
        || location.section_offset_range.is_some()
    {
        precision += 1.0;
    }
    precision
}

/// The one evidence row a literal raw match (word, exact, substr) reports:
/// its first passing match, plus every later one when a proximity consumer
/// reads locations (see [`RawScan::keep_offset`]).
fn push_literal_match(
    evidence: &mut Vec<Evidence>,
    match_count: usize,
    value: String,
    offsets: Vec<u64>,
) {
    if match_count > 0 && evidence.len() < MAX_EVIDENCE_PER_TRAIT {
        evidence.push(Evidence {
            method: "raw".to_string(),
            source: "raw_content".to_string(),
            value,
            location: Some(format!("0x{:x}", offsets.first().copied().unwrap_or(0))),
            offsets,
            ..Default::default()
        });
    }
}

fn log_match_limit(trait_id: Option<&str>, pattern: &str) {
    if let Some(trait_id) = trait_id {
        tracing::info!(
            %trait_id,
            %pattern,
            limit = MAX_MATCHES_TO_PROCESS,
            "Hit regex-pattern match limit; stopping early"
        );
    } else {
        tracing::info!(
            %pattern,
            limit = MAX_MATCHES_TO_PROCESS,
            "Hit regex-pattern match limit; stopping early"
        );
    }
}

/// The compiled bytes regex for `pattern_str`, from the thread-local slot or
/// the shared bounded LRU, compiling it on a miss.
///
/// Read via `peek` under a read-lock — `LruCache::get` needs &mut and was
/// forcing every rayon worker to serialize through the cache's write lock even
/// on cache hit. That single bottleneck accounted for ~25 % of total CPU as
/// `parking_lot::lock_exclusive_slow` wait time on the slow dataset.
///
/// On a miss we compile outside the lock and `put`. Two workers can race to
/// compile the same pattern, but those compiles run in PARALLEL — measured
/// wall-faster than serializing on a per-key `OnceLock`, which idles cores
/// during the compile-heavy warmup (compile-once cut CPU but raised wall
/// ~35 %). Wall is the priority, so the parallel race stays.
fn cached_bytes_regex(
    pattern_str: &str,
    case_insensitive: bool,
    tls_hit: Option<std::sync::Arc<super::super::LeanRegex>>,
) -> Option<std::sync::Arc<super::super::LeanRegex>> {
    if tls_hit.is_some() {
        return tls_hit;
    }
    let key = (pattern_str.to_string(), case_insensitive);
    let cache = super::super::bytes_regex_cache();
    // Clone the `Arc`, never the `Regex`: a `Regex` clone gets a cold
    // lazy-DFA cache and rebuilds every DFA state on first search; the shared
    // `Arc` reuses the warm instance across members/threads. On a miss, claim
    // the key so racing workers pick up this compile instead of duplicating it
    // (see `compile_claim`); the bounded fallback still compiles independently
    // if the claimant is slow.
    static CLAIMS: crate::composite_rules::compile_claim::ClaimSet =
        crate::composite_rules::compile_claim::ClaimSet::new();
    let compile_and_put = |key: (String, bool)| {
        super::super::compile_bytes_regex(pattern_str, case_insensitive).map(|re| {
            let arc = std::sync::Arc::new(re);
            let size = arc.heap_bytes();
            cache.write().put(key, std::sync::Arc::clone(&arc), size);
            arc
        })
    };
    let cached = cache.read().peek(&key).cloned();
    let resolved = if cached.is_some() {
        cached
    } else {
        let kh = crate::composite_rules::compile_claim::ClaimSet::hash_key(&key);
        if let Some(_guard) = CLAIMS.try_claim(kh) {
            let hit = cache.read().peek(&key).cloned();
            hit.or_else(|| compile_and_put(key))
        } else if let Some(hit) = CLAIMS.wait_for(kh, || cache.read().peek(&key).cloned()) {
            Some(hit)
        } else {
            compile_and_put(key)
        }
    };
    if let Some(ref re) = resolved {
        super::super::bytes_regex_tls_put(pattern_str, case_insensitive, re);
    }
    resolved
}

/// What every raw scan of one condition shares: the bytes searched (`data`
/// is `ctx.binary_data[start..end]`) and the filters a match must pass.
struct RawScan<'s, 'c> {
    ctx: &'s EvaluationContext<'c>,
    start: usize,
    end: usize,
    data: &'s [u8],
    is_check: Option<StringValidator>,
    not: Option<&'s Vec<NotException>>,
    /// When the active trait has no count/density filter and no consumer
    /// reads the exact `match_count` (set per-trait via `MatchCountGuard`;
    /// default true = safe full count), a scan may stop at the first passing
    /// match instead of scanning the whole file. The full `find_iter` scan is
    /// the dominant RSS lever — it grows each `regex::bytes::Regex` lazy-DFA
    /// cache to ~778 KB (~7.7 GB at 10k patterns). Parity-exact on finding
    /// id+level + evidence (the first match is identical); only the unused
    /// `match_count` value is truncated.
    needs_count: bool,
    /// A `near_lines:`/`near_bytes:` consumer reads every match location, so
    /// literal scans keep each accepted offset, not just the first. Without
    /// them a word whose first occurrence lies outside the proximity window
    /// fails a rule its later occurrences satisfy.
    needs_locations: bool,
}

/// Most offsets one literal-match evidence row carries for proximity.
const MAX_LITERAL_LOCATION_OFFSETS: usize = 256;

impl RawScan<'_, '_> {
    /// Record `offset` when it is the first match, or when proximity needs
    /// every location (up to [`MAX_LITERAL_LOCATION_OFFSETS`]).
    fn keep_offset(&self, offsets: &mut Vec<u64>, offset: u64) {
        if offsets.is_empty()
            || (self.needs_locations && offsets.len() < MAX_LITERAL_LOCATION_OFFSETS)
        {
            offsets.push(offset);
        }
    }

    /// Whether matches need their text or context checked at all.
    fn filtered(&self) -> bool {
        self.is_check.is_some() || self.not.is_some()
    }

    /// Whether `text` passes the validator and no `not:` exception.
    fn accepts(&self, text: &str) -> bool {
        validate_match(text, self.is_check)
            && !self
                .not
                .is_some_and(|exceptions| exceptions.iter().any(|e| e.matches(text)))
    }

    /// The file's UTF-8 view over the searched range. Reuses the whole-file
    /// view built once at ctx construction (source types) or on first use
    /// (everything else); only re-validates for sub-ranges.
    fn utf8(&self) -> std::borrow::Cow<'_, str> {
        if self.start == 0 && self.end == self.ctx.binary_data.len() {
            std::borrow::Cow::Borrowed(self.ctx.full_utf8())
        } else {
            super::super::utf8_view(self.ctx.binary_data, (self.start, self.end))
        }
    }

    /// `word:` — literal byte-boundary scan over raw bytes, no regex engine.
    /// The boundary rule mirrors the `\bword\b` regex this used to compile
    /// (see `raw_word_match_offsets`); `\bword\b` matches can't overlap, so
    /// the offset set equals the regex's.
    fn word(&self, w: &str, case_insensitive: bool, evidence: &mut Vec<Evidence>) -> usize {
        let offsets = crate::composite_rules::condition::raw_word_match_offsets(
            self.data,
            w,
            case_insensitive,
            if self.needs_count || self.filtered() {
                MAX_MATCHES_TO_PROCESS
            } else {
                1
            },
        );
        let mut match_count = 0;
        let mut value = None;
        let mut kept = Vec::new();
        for start in offsets {
            let bytes = &self.data[start..start + w.len()];
            if self.filtered() && !self.accepts(&String::from_utf8_lossy(bytes)) {
                continue;
            }
            if value.is_none() {
                value = Some(String::from_utf8_lossy(bytes).into_owned());
            }
            self.keep_offset(&mut kept, (self.start + start) as u64);
            match_count += 1;
            if !self.needs_count {
                break;
            }
        }
        if let Some(value) = value {
            push_literal_match(evidence, match_count, value, kept);
        }
        match_count
    }

    /// `regex:` — the bytes engine for ASCII patterns, over the atom windows
    /// the raw-content gate already found when it has them; the unicode
    /// engine over the UTF-8 view otherwise.
    fn regex(
        &self,
        pattern_str: &str,
        case_insensitive: bool,
        length_bounds: (Option<usize>, Option<usize>),
        trait_id: Option<&str>,
        evidence: &mut Vec<Evidence>,
    ) -> usize {
        use super::super::raw_window_stats as ws;
        let mut match_count = 0;
        let mut considered = 0usize;
        // Gate one candidate of `len` bytes: `Err(keep_scanning)` when it is
        // out of bounds or past the budget. Short or long candidates cannot
        // satisfy this condition, so they must not exhaust the qualifying-match
        // budget; the budget prevents DoS on pattern-dense files.
        let mut admit = |len: usize| -> Result<(), bool> {
            if !span_length_ok(len, length_bounds) {
                return Err(true);
            }
            if considered >= MAX_MATCHES_TO_PROCESS {
                log_match_limit(trait_id, pattern_str);
                return Err(false);
            }
            considered += 1;
            Ok(())
        };

        // A thread-local hit implies the pattern already passed
        // `can_use_byte_matching` on the compile that filled the slot.
        let tls_hit = super::super::bytes_regex_tls_get(pattern_str, case_insensitive);
        if tls_hit.is_some() || can_use_byte_matching(pattern_str) {
            // FAST PATH: bytes::Regex on raw binary data, no UTF-8 conversion.
            let Some(lean) = cached_bytes_regex(pattern_str, case_insensitive, tls_hit) else {
                return 0;
            };
            let mut visit_bytes = |abs_start: usize, abs_end: usize| -> bool {
                if let Err(keep_scanning) = admit(abs_end - abs_start) {
                    return keep_scanning;
                }
                let bytes = &self.ctx.binary_data[abs_start..abs_end];
                let text = String::from_utf8_lossy(bytes);
                if !self.accepts(&text) {
                    return true;
                }
                record_raw_match(evidence, &text, abs_start, bytes.len());
                match_count += 1;
                // No density constraint and nobody needs later locations:
                // stop at the first passing match instead of scanning the
                // whole file.
                self.needs_count
            };
            // Reuse atom offsets the raw-content gate already paid for. No
            // second memmem. Missing offsets / unbounded / PE → full scan.
            if let Some(spans) = source_raw_windows(self.ctx, pattern_str, self.start, self.end) {
                ws::bump(&ws::WINDOWED);
                ws::add_bytes(
                    &ws::WINDOWED_BYTES,
                    spans.iter().map(|(a, b)| b - a).sum::<usize>(),
                );
                lean.for_each_match_spans(self.ctx.binary_data, &spans, visit_bytes);
            } else {
                ws::bump(&ws::FULL);
                ws::add_bytes(&ws::FULL_BYTES, self.data.len());
                match ws::LAST_REASON.with(std::cell::Cell::get) {
                    1 => ws::add_bytes(&ws::NO_ATOMS_BYTES, self.data.len()),
                    2 => ws::add_bytes(&ws::UNBOUNDED_BYTES, self.data.len()),
                    _ => ws::add_bytes(&ws::OTHER_FULL_BYTES, self.data.len()),
                }
                lean.for_each_match(self.data, |start, end| {
                    visit_bytes(self.start + start, self.start + end)
                });
            }
        } else {
            // UNICODE PATH: compile the unicode engine now — only non-ASCII
            // patterns reach here. A compile failure (unreachable for corpus
            // patterns, which compiled before) simply yields no matches.
            ws::bump(&ws::STR_ENGINE);
            ws::bump(&ws::FULL);
            ws::add_bytes(&ws::FULL_BYTES, self.end - self.start);
            if let Some(re) = crate::composite_rules::condition::cached_regex(pattern_str) {
                let content = self.utf8();
                re.for_each_find(&content, |start, text| {
                    if let Err(keep_scanning) = admit(text.len()) {
                        return keep_scanning;
                    }
                    if !self.accepts(text) {
                        return true;
                    }
                    record_raw_match(evidence, text, self.start + start, text.len());
                    match_count += 1;
                    self.needs_count
                });
            }
        }
        match_count
    }

    /// `exact:` — per-line equality: the pattern must equal some trimmed
    /// line in the searched bytes.
    ///
    /// This mirrors extracted-strings mode (where `exact` compares against a
    /// complete extracted string) by treating each line as the unit of
    /// equality for raw text. Pattern-as-substring within a line is
    /// `substr:`; pattern-as-token is regex. ASCII-only patterns compare
    /// byte-wise without UTF-8 conversion, and trimming stays allocation-free.
    fn exact(
        &self,
        exact_str: &str,
        case_insensitive: bool,
        evidence: &mut Vec<Evidence>,
    ) -> usize {
        let data = self.data;
        let ascii_path = can_use_byte_matching(exact_str);
        let pat_bytes = exact_str.as_bytes();
        let mut match_count = 0;
        let mut value: Option<String> = None;
        let mut kept = Vec::new();

        let mut line_start = 0usize;
        while line_start <= data.len() {
            let line_end =
                memchr::memchr(b'\n', &data[line_start..]).map_or(data.len(), |p| line_start + p);
            // Strip trailing \r (CRLF) and surrounding ASCII whitespace.
            let mut s = line_start;
            let mut e = line_end;
            if e > s && data[e - 1] == b'\r' {
                e -= 1;
            }
            while s < e && data[s].is_ascii_whitespace() {
                s += 1;
            }
            while e > s && data[e - 1].is_ascii_whitespace() {
                e -= 1;
            }
            let line = &data[s..e];
            let line_matches = if ascii_path {
                if case_insensitive {
                    line.eq_ignore_ascii_case(pat_bytes)
                } else {
                    line == pat_bytes
                }
            } else {
                // Unicode pattern: convert this line only.
                std::str::from_utf8(line).is_ok_and(|line| {
                    if case_insensitive {
                        line.eq_ignore_ascii_case(exact_str)
                    } else {
                        line == exact_str
                    }
                })
            };
            if line_matches {
                let line_value = String::from_utf8_lossy(line).into_owned();
                if self.accepts(&line_value) {
                    match_count += 1;
                    self.keep_offset(&mut kept, (self.start + s) as u64);
                    if value.is_none() {
                        value = Some(line_value);
                    }
                    if !self.needs_count {
                        break;
                    }
                }
            }
            if line_end == data.len() {
                break;
            }
            line_start = line_end + 1;
        }
        let value = value.unwrap_or_else(|| exact_str.to_string());
        push_literal_match(evidence, match_count, value, kept);
        match_count
    }

    /// `substr:` — byte-level search for ASCII patterns, the UTF-8 view for
    /// others. `None` when a case-sensitive Unicode literal is absent from
    /// the bytes outright (see [`Self::substr_unicode`]).
    fn substr(
        &self,
        substr_str: &str,
        case_insensitive: bool,
        evidence: &mut Vec<Evidence>,
    ) -> Option<usize> {
        let (match_count, kept) = if can_use_byte_matching(substr_str) {
            self.substr_ascii(substr_str, case_insensitive)
        } else {
            self.substr_unicode(substr_str, case_insensitive)?
        };
        push_literal_match(evidence, match_count, substr_str.to_string(), kept);
        Some(match_count)
    }

    /// ASCII `substr:` over raw bytes, without UTF-8 conversion. A validator
    /// or `not:` filter judges the 50 bytes on either side of each match.
    fn substr_ascii(&self, substr_str: &str, case_insensitive: bool) -> (usize, Vec<u64>) {
        let data = self.data;
        let mut match_count = 0;
        let mut kept = Vec::new();
        if !self.filtered() {
            // Simple count - just count byte occurrences (fastest path).
            if case_insensitive {
                for_each_ascii_ci_substr(data, substr_str, false, |abs_pos, _len| {
                    self.keep_offset(&mut kept, (self.start + abs_pos) as u64);
                    match_count += 1;
                    self.needs_count
                });
            } else {
                // Shared searcher per needle: building a memmem `Searcher`
                // per evaluation measured ~13 s of pool time per corpus.
                let finder = crate::composite_rules::condition::cached_finder(substr_str);
                let iter = finder.find_iter(data);
                if self.needs_locations {
                    for o in iter {
                        self.keep_offset(&mut kept, (self.start + o) as u64);
                        match_count += 1;
                    }
                } else {
                    kept.extend(iter.clone().next().map(|o| (self.start + o) as u64));
                    match_count = if self.needs_count {
                        iter.count()
                    } else {
                        kept.len()
                    };
                }
            }
            return (match_count, kept);
        }
        let accepts_at = |abs_pos: usize, needle_len: usize| {
            let ctx_start = abs_pos.saturating_sub(50);
            let ctx_end = (abs_pos + needle_len + 50).min(data.len());
            self.accepts(&String::from_utf8_lossy(&data[ctx_start..ctx_end]))
        };
        if case_insensitive {
            for_each_ascii_ci_substr(data, substr_str, true, |abs_pos, needle_len| {
                if accepts_at(abs_pos, needle_len) {
                    self.keep_offset(&mut kept, (self.start + abs_pos) as u64);
                    match_count += 1;
                }
                self.needs_count || match_count == 0
            });
        } else {
            let finder = crate::composite_rules::condition::cached_finder(substr_str);
            let mut pos = 0;
            while let Some(offset) = finder.find(&data[pos..]) {
                let abs_pos = pos + offset;
                if accepts_at(abs_pos, substr_str.len()) {
                    self.keep_offset(&mut kept, (self.start + abs_pos) as u64);
                    match_count += 1;
                }
                if !self.needs_count && match_count > 0 {
                    break;
                }
                pos = abs_pos + 1;
            }
        }
        (match_count, kept)
    }

    /// Unicode `substr:` over the UTF-8 view. Case-insensitive search folds
    /// both sides into owned copies and maps hits back (see
    /// [`LoweredOffsets`]). A validator judges the 50 characters on either
    /// side of a match; a `not:` filter alone judges [`match_window`].
    ///
    /// A case-sensitive Unicode literal without U+FFFD cannot appear only
    /// through lossy decoding: each matching UTF-8 byte must be present in
    /// the original input. `None` rejects absent literals before decoding a
    /// potentially huge binary/archive into text.
    fn substr_unicode(
        &self,
        substr_str: &str,
        case_insensitive: bool,
    ) -> Option<(usize, Vec<u64>)> {
        if !case_insensitive
            && !substr_str.contains('\u{fffd}')
            && memchr::memmem::find(self.data, substr_str.as_bytes()).is_none()
        {
            return None;
        }
        let content = self.utf8();
        // Case-sensitive borrows the cached UTF-8 view (no per-eval copy);
        // case-insensitive folds case into owned buffers.
        let (search_content, search_pattern): (
            std::borrow::Cow<'_, str>,
            std::borrow::Cow<'_, str>,
        ) = if case_insensitive {
            (
                std::borrow::Cow::Owned(content.to_lowercase()),
                std::borrow::Cow::Owned(substr_str.to_lowercase()),
            )
        } else {
            (
                std::borrow::Cow::Borrowed(content.as_ref()),
                std::borrow::Cow::Borrowed(substr_str),
            )
        };
        if !self.filtered() {
            // Simple count - no filter (fastest path).
            let mut kept = Vec::new();
            if self.needs_locations {
                let mut starts = LoweredOffsets::new(&content, case_insensitive);
                let mut match_count = 0;
                for (o, _) in search_content.match_indices(search_pattern.as_ref()) {
                    self.keep_offset(&mut kept, (self.start + starts.original(o)) as u64);
                    match_count += 1;
                }
                return Some((match_count, kept));
            }
            kept.extend(search_content.find(search_pattern.as_ref()).map(|o| {
                let o = LoweredOffsets::new(&content, case_insensitive).original(o);
                (self.start + o) as u64
            }));
            let match_count = if self.needs_count {
                search_content.matches(search_pattern.as_ref()).count()
            } else {
                kept.len()
            };
            return Some((match_count, kept));
        }
        // Hits are found in `search_content` but windows and offsets must be
        // in `content`'s coordinates (see `LoweredOffsets`).
        let mut starts = LoweredOffsets::new(&content, case_insensitive);
        let mut ends = LoweredOffsets::new(&content, case_insensitive);
        let mut match_count = 0;
        let mut kept = Vec::new();
        let mut start = 0;
        while let Some(pos) = search_content[start..].find(search_pattern.as_ref()) {
            let abs_pos = start + pos;
            let match_start = starts.original(abs_pos);
            let match_end = ends.original(abs_pos + search_pattern.len());
            let accepted = if self.is_check.is_some() {
                let context_start = content.floor_char_boundary(match_start.saturating_sub(50));
                let context_end = content.ceil_char_boundary((match_end + 50).min(content.len()));
                self.accepts(&content[context_start..context_end])
            } else {
                self.accepts(&match_window(&content, match_start, match_end, 50))
            };
            if accepted {
                self.keep_offset(&mut kept, (self.start + match_start) as u64);
                match_count += 1;
            }
            if !self.needs_count && match_count > 0 {
                break;
            }
            start = search_content[abs_pos..]
                .char_indices()
                .nth(1)
                .map_or(search_content.len(), |(next, _)| abs_pos + next);
        }
        Some((match_count, kept))
    }
}

/// Search encoded/decoded strings for patterns with optional encoding filter.
/// Unified replacement for eval_base64 and eval_xor with additional features.
///
/// # Encoding Filter
/// - `Some(Single("base64"))` - Only search base64-decoded strings
/// - `Some(Multiple(vec!["base64", "hex"]))` - Search base64 OR hex decoded strings
/// - `None` - Search ALL encoded strings (any non-empty encoding_chain)
///
/// # Pattern Matching
/// Supports exact, substr, regex, and word boundary matching
#[must_use]
pub(crate) fn eval_encoded<'a>(
    encoding: Option<&crate::composite_rules::condition::EncodingSpec>,
    pattern: TextPattern<'_>,
    location: &ContentLocationParams,
    is_check: Option<StringValidator>,
    not: Option<&Vec<crate::composite_rules::condition::NotException>>,
    ctx: &EvaluationContext<'a>,
) -> ConditionResult {
    let TextPattern {
        exact,
        substr,
        regex,
        word,
        case_insensitive,
    } = pattern;
    use crate::composite_rules::condition::EncodingSpec;

    // Resolve effective range for offset filtering
    let effective_range = resolve_effective_range_opt(location, ctx);

    let mut evidence = Vec::new();
    let mut match_count = 0;

    // Build regex if needed
    let regex_matcher = if let Some(pattern) = regex {
        match super::super::build_regex(pattern, case_insensitive) {
            Ok(re) => Some(re),
            Err(_) => return ConditionResult::no_match(),
        }
    } else if let Some(word_pattern) = word {
        // Build word boundary regex from word parameter
        let pattern = format!(r"\b{}\b", regex::escape(word_pattern));
        match super::super::build_regex(&pattern, case_insensitive) {
            Ok(re) => Some(re),
            Err(_) => return ConditionResult::no_match(),
        }
    } else {
        None
    };

    // Determine encoding filter function
    //
    // A spec containing `+` names a *chain* rather than one encoding:
    // `base64+base64` is the doubly-wrapped payload, `xor+base64` the XOR over
    // base64 form. It is matched as a contiguous run of links so it says
    // "these encodings, in this order", which is the property worth writing a
    // rule against — nothing legitimate wraps a payload twice. The spelling
    // matches how a chain is already rendered in evidence
    // (`encoding_chain:xor+base64`), so a rule reads the way the finding does.
    let chain_matches = |spec: &str, enc_chain: &[String]| -> bool {
        if !spec.contains('+') {
            return enc_chain.iter().any(|link| link == spec);
        }
        let want: Vec<&str> = spec.split('+').filter(|s| !s.is_empty()).collect();
        if want.is_empty() || want.len() > enc_chain.len() {
            return false;
        }
        enc_chain
            .windows(want.len())
            .any(|run| run.iter().zip(&want).all(|(link, w)| link == w))
    };
    let matches_encoding = |enc_chain: &[String]| -> bool {
        match encoding {
            None => {
                // No filter: match ANY encoded string (non-empty encoding_chain)
                !enc_chain.is_empty()
            }
            Some(EncodingSpec::Single(enc)) => chain_matches(enc, enc_chain),
            Some(EncodingSpec::Multiple(encodings)) => {
                // Multiple encodings: match if ANY entry matches (OR logic)
                encodings.iter().any(|enc| chain_matches(enc, enc_chain))
            }
        }
    };

    // Filter and match strings
    for string_info in &ctx.report.strings {
        // Apply encoding filter
        if !matches_encoding(&string_info.encoding_chain) {
            continue;
        }

        // Skip strings outside the effective range (if location constraints specified)
        if !offset_in_range(string_info.offset, effective_range) {
            continue;
        }

        let mut matches = false;
        // The span a `regex:`/`word:` matcher actually hit. `is:` validates
        // this rather than the whole decoded string, matching how the `text`
        // evaluator treats a regex match: a whole-string validator such as
        // `random_like` judges the most letter-dense token it can find, so
        // handing it the entire line lets unrelated text outvote the span the
        // rule selected (`--connect-timeout` outscoring a DGA hostname in the
        // same `curl` command). Falls back to the whole value when the match
        // came from `exact:`/`substr:`, where the span is the value or a
        // caller-supplied literal and there is nothing to narrow to.
        let mut matched_span: Option<&str> = None;

        // Check exact match (full string equality)
        if let Some(exact_str) = exact {
            matches = if case_insensitive {
                string_info.value.eq_ignore_ascii_case(exact_str)
            } else {
                string_info.value == *exact_str
            };
        }

        // Check substring match
        if !matches && let Some(substr_str) = substr {
            matches = if case_insensitive {
                string_info
                    .value
                    .to_lowercase()
                    .contains(&substr_str.to_lowercase())
            } else {
                string_info.value.contains(substr_str.as_str())
            };
        }

        // Check regex or word match
        if !matches
            && let Some(ref re) = regex_matcher
            && let Some(m) = re.find(&string_info.value)
        {
            matches = true;
            matched_span = Some(m.as_str());
        }

        if matches {
            // Apply not: exclusions
            let excluded_by_not = not
                .map(|exceptions| exceptions.iter().any(|exc| exc.matches(&string_info.value)))
                .unwrap_or(false);
            // Apply validator: filter
            let excluded_by_is =
                !validate_match(matched_span.unwrap_or(string_info.value.as_str()), is_check);

            if !excluded_by_not && !excluded_by_is {
                match_count += 1;
                if evidence.len() < MAX_EVIDENCE_PER_TRAIT {
                    let value_preview = if string_info.value.len() > 100 {
                        format!(
                            "{}...",
                            &string_info.value[..string_info.value.floor_char_boundary(100)]
                        )
                    } else {
                        string_info.value.as_str().to_string()
                    };

                    evidence.push(Evidence {
                        method: "encoded_string".to_string(),
                        source: format!("encoding_chain:{}", string_info.encoding_chain.join("+")),
                        value: value_preview,
                        location: Some(string_info_location(ctx.report, string_info)),
                        ..Default::default()
                    });
                }
            }
        }
    }

    // Calculate precision based on match type and constraints
    let mut precision = 0.0f32;

    if exact.is_some() {
        precision = 2.0;
    } else if regex.is_some() || word.is_some() {
        precision = 1.5;
    } else if substr.is_some() {
        precision = 1.0;
    }

    if case_insensitive {
        precision *= 0.5;
    }

    // Location constraints add precision
    if location.section.is_some() {
        precision += 1.0;
    }
    if location.offset.is_some() {
        precision += 1.5;
    } else if location.offset_range.is_some()
        || location.section_offset.is_some()
        || location.section_offset_range.is_some()
    {
        precision += 1.0;
    }

    // count/density constraints are now scored and checked at trait level
    let matched = match_count > 0;

    ConditionResult {
        matched,
        evidence,
        match_count,
        warnings: Vec::new(),
        precision,
        matched_trait_ids: Vec::new(),
    }
}
