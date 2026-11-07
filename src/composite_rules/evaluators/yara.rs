//! YARA and hex pattern condition evaluators.
//!
//! This module handles evaluation of YARA-based conditions:
//! - YARA rule matching against pre-scanned results
//! - Inline YARA rule compilation and scanning
//! - Hex pattern matching with wildcards and gaps
//! - Atom extraction for efficient pattern searching

use super::{inline_scanner, truncate_evidence};
use crate::composite_rules::condition::NotException;
use crate::composite_rules::context::{AnalysisWarning, ConditionResult, EvaluationContext};
use crate::types::{Evidence, MAX_EVIDENCE_PER_TRAIT};
use std::sync::Arc;

/// Collect evidence from YARA scan results (limited to MAX_EVIDENCE_PER_TRAIT items).
pub(crate) fn collect_yara_evidence<'a, 'b>(
    results: &yara_x::ScanResults<'a, 'b>,
    binary_data: &[u8],
) -> Vec<Evidence> {
    let mut evidence = Vec::new();
    'outer: for matched_rule in results.matching_rules() {
        // A condition satisfied without string hits is still a match.
        if matched_rule
            .patterns()
            .all(|p| p.matches().next().is_none())
        {
            if evidence.len() >= MAX_EVIDENCE_PER_TRAIT {
                break;
            }
            evidence.push(crate::yara_engine::rule_level_evidence(
                matched_rule.identifier(),
            ));
            continue;
        }
        for pattern in matched_rule.patterns() {
            for m in pattern.matches() {
                if evidence.len() >= MAX_EVIDENCE_PER_TRAIT {
                    break 'outer;
                }
                let match_bytes = binary_data.get(m.range());
                let evidence_value = match match_bytes {
                    Some(bytes) => {
                        let is_printable = bytes
                            .iter()
                            .all(|&b| (0x20..0x7f).contains(&b) || b == b'\n' || b == b'\t');
                        if is_printable {
                            if let Ok(s) = std::str::from_utf8(bytes) {
                                truncate_evidence(s, 50)
                            } else {
                                pattern.identifier().to_string()
                            }
                        } else {
                            pattern.identifier().to_string()
                        }
                    }
                    None => pattern.identifier().to_string(),
                };

                evidence.push(Evidence {
                    method: "yara".to_string(),
                    source: "yara-x".to_string(),
                    value: evidence_value,
                    location: Some(format!("offset:{}", m.range().start)),
                    ..Default::default()
                });
            }
        }
    }
    evidence
}

/// Evaluate inline YARA rule condition.
///
/// Evaluation priority:
/// 1. Combined-engine lookup: if `namespace` is set and `ctx.inline_yara_results` is present,
///    return the pre-scanned evidence. This is the fast path for atomic trait conditions.
/// 2. Per-condition compiled rules: if `compiled` is set (unless/composite conditions),
///    scan with the pre-compiled Rules object.
/// 3. Skip: if YARA is disabled (no inline results AND no pre-compiled rules), return no-match.
///    This prevents expensive on-the-fly compilation when --disable=yara is set.
#[must_use]
pub(crate) fn eval_yara_inline<'a>(
    source: &str,
    namespace: Option<&str>,
    compiled: Option<&Arc<yara_x::Rules>>,
    ctx: &EvaluationContext<'a>,
) -> ConditionResult {
    // Fast path: combined engine results are available for this namespace.
    if let (Some(ns), Some(inline_results)) = (namespace, ctx.inline_yara_results) {
        let evidence = inline_results.get(ns).cloned().unwrap_or_default();
        let match_count = evidence.len();
        return ConditionResult {
            matched: match_count > 0,
            evidence,
            match_count,
            warnings: Vec::new(),
            precision: 1.0,
            matched_trait_ids: Vec::new(),
        };
    }

    // Medium path: use per-condition pre-compiled rules (unless/composite conditions).
    if let Some(pre_compiled) = compiled {
        let scan_start = std::time::Instant::now();
        let mut scanner = inline_scanner(pre_compiled.as_ref());
        let evidence = match scanner.scan(ctx.binary_data) {
            Ok(results) => collect_yara_evidence(&results, ctx.binary_data),
            Err(e) => {
                // A timed-out scan leaves the condition undecided, not false;
                // the gap says so and keeps the report out of the cache.
                if matches!(e, yara_x::errors::ScanError::Timeout) {
                    ctx.report
                        .analysis_gaps
                        .record(crate::types::AnalysisGap::EvaluationDeadline);
                }
                tracing::warn!(
                    source_preview = source.lines().next().unwrap_or(""),
                    error = %e,
                    "inline YARA scan failed; treating the condition as unmatched"
                );
                Vec::new()
            }
        };

        let scan_duration = scan_start.elapsed();
        if scan_duration.as_millis() > 1000 {
            tracing::warn!(
                source_preview = source.lines().next().unwrap_or(""),
                file_kb = ctx.binary_data.len() / 1024,
                ms = scan_duration.as_millis(),
                "Inline YARA rule took {}ms ({}KB); consider moving to combined engine",
                scan_duration.as_millis(),
                ctx.binary_data.len() / 1024,
            );
        }

        let match_count = evidence.len();
        return ConditionResult {
            matched: match_count > 0,
            evidence,
            match_count,
            warnings: Vec::new(),
            precision: 1.0,
            matched_trait_ids: Vec::new(),
        };
    }

    // No inline results AND no pre-compiled rules: YARA is effectively disabled.
    // Return no-match instead of expensive on-the-fly compilation.
    // This is the expected path when --disable=yara is set.
    ConditionResult::no_match()
}

/// Hex pattern segment for matching
#[derive(Debug, Clone)]
enum HexSegment {
    /// Fixed bytes to match exactly
    Bytes(Vec<u8>),
    /// Single wildcard byte (??)
    Wildcard,
    /// Variable gap [N] or [N-M]
    Gap { min: usize, max: usize },
    /// Nibble mask: matches bytes where masked nibbles match
    /// high_mask: 0xF0 if high nibble fixed, 0x00 if wild
    /// low_mask: 0x0F if low nibble fixed, 0x00 if wild
    /// value: the expected value after masking
    NibbleMask {
        high_mask: u8,
        low_mask: u8,
        value: u8,
    },
    /// Negated byte (`~XX` in YARA hex syntax).
    NotByte { mask: u8, value: u8 },
    /// Byte alternation: matches any byte in the set
    ByteSet(Vec<u8>),
    /// Nibble-wildcard alternation, for example `(0?|1?)`.
    NibbleSet(Vec<(u8, u8)>),
    /// General YARA alternation. Each branch is a sequence, not necessarily
    /// a single byte (for example `(33 C0 | 31 C0)`).
    Alternative(Vec<Vec<HexSegment>>),
}

/// Parse one YARA hex byte into `(value, mask)`. A mask bit of one is
/// significant; a zero bit is a nibble wildcard.
fn parse_masked_byte(token: &str) -> Result<(u8, u8), String> {
    if token.len() != 2 {
        return Err(format!(
            "invalid alternation byte {token}: expected two hex digits"
        ));
    }
    let chars: Vec<char> = token.chars().collect();
    let mut value = 0;
    let mut mask = 0xFF;
    if chars[0] == '?' {
        mask &= 0x0F;
    } else {
        value |= (chars[0]
            .to_digit(16)
            .ok_or_else(|| format!("invalid alternation byte {token}: invalid hex digit"))?
            as u8)
            << 4;
    }
    if chars[1] == '?' {
        mask &= 0xF0;
    } else {
        value |= chars[1]
            .to_digit(16)
            .ok_or_else(|| format!("invalid alternation byte {token}: invalid hex digit"))?
            as u8;
    }
    Ok((value, mask))
}

/// Split a hex pattern into tokens while preserving whitespace inside YARA
/// alternations. `str::split_whitespace` alone would turn `(AA BB|CC DD)`
/// into invalid fragments.
fn tokenize_hex_pattern(pattern: &str) -> Result<Vec<String>, String> {
    let mut tokens = Vec::new();
    let mut group = None::<String>;
    for part in pattern.split_whitespace() {
        if let Some(current) = &mut group {
            current.push(' ');
            current.push_str(part);
            if part.ends_with(')') {
                tokens.push(std::mem::take(current));
                group = None;
            }
        } else if part.starts_with('(') && !part.ends_with(')') {
            group = Some(part.to_string());
        } else {
            tokens.push(part.to_string());
        }
    }
    if group.is_some() {
        return Err("unterminated hex alternation".to_string());
    }
    Ok(tokens)
}

fn single_byte_mask(segment: &HexSegment) -> Option<(u8, u8)> {
    match segment {
        HexSegment::Bytes(bytes) if bytes.len() == 1 => Some((bytes[0], 0xFF)),
        HexSegment::NibbleMask {
            high_mask,
            low_mask,
            value,
        } => Some((*value, high_mask | low_mask)),
        _ => None,
    }
}

fn parse_alternation(inner: &str) -> Result<HexSegment, String> {
    let branches: Result<Vec<Vec<HexSegment>>, String> = inner
        .split('|')
        .map(|branch| parse_hex_pattern(branch.trim()))
        .collect();
    let branches = branches?;
    if branches.is_empty() || branches.iter().any(Vec::is_empty) {
        return Err("empty hex alternation branch".to_string());
    }

    let byte_alternatives: Option<Vec<(u8, u8)>> = branches
        .iter()
        .map(|branch| {
            (branch.len() == 1)
                .then(|| single_byte_mask(&branch[0]))
                .flatten()
        })
        .collect();
    if let Some(alternatives) = byte_alternatives {
        if alternatives.iter().all(|(_, mask)| *mask == 0xFF) {
            return Ok(HexSegment::ByteSet(
                alternatives.into_iter().map(|(value, _)| value).collect(),
            ));
        }
        return Ok(HexSegment::NibbleSet(alternatives));
    }
    Ok(HexSegment::Alternative(branches))
}

/// Parse a hex pattern string into segments
/// Format: "7F 45 4C 46" or "31 ?? 48" or "00 [4] FF" or "00 [2-8] FF"
fn parse_hex_pattern(pattern: &str) -> Result<Vec<HexSegment>, String> {
    let mut segments: Vec<HexSegment> = Vec::new();
    let mut current_bytes: Vec<u8> = Vec::new();

    for token in tokenize_hex_pattern(pattern)? {
        if token == "??" {
            // Flush current bytes
            if !current_bytes.is_empty() {
                segments.push(HexSegment::Bytes(std::mem::take(&mut current_bytes)));
            }
            segments.push(HexSegment::Wildcard);
        } else if token.len() == 2 {
            // Check for nibble wildcards: X? or ?X (but not ??)
            let chars: Vec<char> = token.chars().collect();
            let high_wild = chars[0] == '?';
            let low_wild = chars[1] == '?';

            if high_wild && !low_wild {
                // ?X pattern: high nibble wild, low nibble fixed
                if !current_bytes.is_empty() {
                    segments.push(HexSegment::Bytes(std::mem::take(&mut current_bytes)));
                }
                let low_nibble = u8::from_str_radix(&token[1..2], 16)
                    .map_err(|e| format!("invalid nibble {token}: {e}"))?;
                segments.push(HexSegment::NibbleMask {
                    high_mask: 0x00,
                    low_mask: 0x0F,
                    value: low_nibble,
                });
                continue;
            } else if !high_wild && low_wild {
                // X? pattern: high nibble fixed, low nibble wild
                if !current_bytes.is_empty() {
                    segments.push(HexSegment::Bytes(std::mem::take(&mut current_bytes)));
                }
                let high_nibble = u8::from_str_radix(&token[0..1], 16)
                    .map_err(|e| format!("invalid nibble {token}: {e}"))?;
                segments.push(HexSegment::NibbleMask {
                    high_mask: 0xF0,
                    low_mask: 0x00,
                    value: high_nibble << 4,
                });
                continue;
            }
            // Fall through to regular hex byte parsing for non-wildcard 2-char tokens
            let byte = u8::from_str_radix(&token, 16)
                .map_err(|e| format!("invalid hex byte {token}: {e}"))?;
            current_bytes.push(byte);
        } else if token.starts_with('(') && token.ends_with(')') {
            // Byte/general alternation: `(XX|YY|ZZ)` or `(AA BB|CC DD)`.
            if !current_bytes.is_empty() {
                segments.push(HexSegment::Bytes(std::mem::take(&mut current_bytes)));
            }

            let inner = &token[1..token.len() - 1];
            segments.push(parse_alternation(inner)?);
        } else if token.contains('|') {
            // Retain compatibility with the legacy cleave spelling `AA|BB`.
            segments.push(parse_alternation(&token)?);
        } else if token.starts_with('~') && token.len() == 3 {
            if !current_bytes.is_empty() {
                segments.push(HexSegment::Bytes(std::mem::take(&mut current_bytes)));
            }
            let (value, mask) = parse_masked_byte(&token[1..])?;
            segments.push(HexSegment::NotByte { mask, value });
        } else if token.starts_with('[') && token.ends_with(']') {
            // Gap: [N] or [N-M]
            if !current_bytes.is_empty() {
                segments.push(HexSegment::Bytes(std::mem::take(&mut current_bytes)));
            }
            let inner = &token[1..token.len() - 1];
            if let Some(dash_pos) = inner.find('-') {
                let min: usize = inner[..dash_pos]
                    .parse()
                    .map_err(|e| format!("invalid gap min in {inner}: {e}"))?;
                let max: usize = inner[dash_pos + 1..]
                    .parse()
                    .map_err(|e| format!("invalid gap max in {inner}: {e}"))?;
                segments.push(HexSegment::Gap { min, max });
            } else {
                let n: usize = inner
                    .parse()
                    .map_err(|e| format!("invalid gap {inner}: {e}"))?;
                segments.push(HexSegment::Gap { min: n, max: n });
            }
        } else {
            return Err(format!(
                "invalid hex token {token}: expected a two-digit byte, wildcard, alternation, or gap"
            ));
        }
    }

    // Flush remaining bytes
    if !current_bytes.is_empty() {
        segments.push(HexSegment::Bytes(current_bytes));
    }

    Ok(segments)
}

/// Validate a cleave hex pattern without exposing the matcher representation.
#[cfg(feature = "lint")]
pub(crate) fn validate_hex_pattern(pattern: &str) -> Result<(), String> {
    parse_hex_pattern(pattern).map(|_| ())
}

fn segment_length_bounds(segment: &HexSegment) -> (usize, usize) {
    match segment {
        HexSegment::Bytes(bytes) => (bytes.len(), bytes.len()),
        HexSegment::Wildcard
        | HexSegment::NibbleMask { .. }
        | HexSegment::NotByte { .. }
        | HexSegment::ByteSet(_)
        | HexSegment::NibbleSet(_) => (1, 1),
        HexSegment::Gap { min, max } => (*min, *max),
        HexSegment::Alternative(branches) => {
            let mut lengths = branches.iter().map(|branch| {
                branch.iter().fold((0, 0), |(min, max), segment| {
                    let (segment_min, segment_max) = segment_length_bounds(segment);
                    (min + segment_min, max + segment_max)
                })
            });
            let Some(first) = lengths.next() else {
                return (0, 0);
            };
            lengths.fold(first, |(min, max), (branch_min, branch_max)| {
                (min.min(branch_min), max.max(branch_max))
            })
        }
    }
}

/// Check if pattern is simple (no wildcards or gaps)
fn is_simple_pattern(segments: &[HexSegment]) -> bool {
    segments.len() == 1 && matches!(segments.first(), Some(HexSegment::Bytes(_)))
}

/// Extract the longest fixed byte sequence (atom) for fast pre-filtering.
/// Allows single-byte atoms so that memmem degrades to SIMD memchr rather
/// than falling through to a byte-by-byte linear scan.
///
/// Returns the FIRST occurrence of the longest run. This must agree with the
/// `take_while` offset computation in `eval_hex`, which also stops at the
/// first segment whose content matches the chosen atom. Using `max_by_key`
/// (which returns the last maximum on ties) would cause a mismatch when the
/// same byte sequence appears more than once in the pattern.
fn extract_best_atom(segments: &[HexSegment]) -> Option<&[u8]> {
    segments
        .iter()
        .filter_map(|s| match s {
            HexSegment::Bytes(b) if !b.is_empty() => Some(b.as_slice()),
            _ => None,
        })
        .reduce(|best, b| if b.len() > best.len() { b } else { best })
}

/// A mandatory any-of atom set for a sequence with alternatives. Every
/// branch must supply an atom; an uncovered branch makes that alternative
/// unusable. Another mandatory segment can still supply the gate.
#[derive(Clone, Copy)]
struct HexAtom<'a> {
    bytes: &'a [u8],
    prefix_min: usize,
    prefix_max: usize,
}

fn mandatory_hex_atoms(segments: &[HexSegment]) -> Option<Vec<HexAtom<'_>>> {
    const MAX_ATOMS: usize = 64;
    let mut best: Option<Vec<HexAtom<'_>>> = None;
    let (mut prefix_min, mut prefix_max) = (0usize, 0usize);
    for segment in segments {
        let candidate = match segment {
            HexSegment::Bytes(bytes) if !bytes.is_empty() => Some(vec![HexAtom {
                bytes,
                prefix_min,
                prefix_max,
            }]),
            HexSegment::Alternative(branches) => {
                let mut atoms = Vec::new();
                let mut complete = !branches.is_empty();
                for branch in branches {
                    let Some(required) = mandatory_hex_atoms(branch) else {
                        complete = false;
                        break;
                    };
                    atoms.extend(required.into_iter().map(|atom| HexAtom {
                        bytes: atom.bytes,
                        prefix_min: prefix_min + atom.prefix_min,
                        prefix_max: prefix_max + atom.prefix_max,
                    }));
                    if atoms.len() > MAX_ATOMS {
                        complete = false;
                        break;
                    }
                }
                complete.then_some(atoms)
            }
            _ => None,
        };
        if let Some(mut atoms) = candidate {
            atoms.sort_unstable_by_key(|atom| (atom.bytes, atom.prefix_min, atom.prefix_max));
            atoms.dedup_by_key(|atom| (atom.bytes, atom.prefix_min, atom.prefix_max));
            let rank = |atoms: &[HexAtom<'_>]| {
                (
                    atoms.iter().map(|a| a.bytes.len()).min().unwrap_or(0),
                    std::cmp::Reverse(atoms.len()),
                )
            };
            if best
                .as_ref()
                .is_none_or(|current| rank(&atoms) > rank(current))
            {
                best = Some(atoms);
            }
        }
        let (min, max) = segment_length_bounds(segment);
        prefix_min += min;
        prefix_max += max;
    }
    best
}

/// Enumerate real matches from mandatory branch anchors, retaining the first
/// `limit` starts in file order. Wildcards and variable gaps before each atom
/// produce a range of possible starts; verify the complete original pattern at
/// every candidate. The bounded set deduplicates overlapping branches without
/// allocating an entry for every nonmatching candidate in a large binary.
fn anchored_hex_matches(
    data: &[u8],
    search_start: usize,
    search_end: usize,
    segments: &[HexSegment],
    atoms: &[HexAtom<'_>],
    accepts: impl Fn(usize) -> bool,
    limit: usize,
) -> std::collections::BTreeSet<usize> {
    let mut matches = std::collections::BTreeSet::new();
    if search_start >= search_end || limit == 0 {
        return matches;
    }
    for atom in atoms {
        // Starts are constrained by the location range; matching bytes may
        // extend beyond its end, just as in the unanchored verifier.
        let finder = memchr::memmem::Finder::new(atom.bytes);
        for offset in finder.find_iter(&data[search_start..]) {
            let abs_atom = search_start + offset;
            let Some(hi) = abs_atom.checked_sub(atom.prefix_min) else {
                continue;
            };
            let lo = abs_atom.saturating_sub(atom.prefix_max).max(search_start);
            let hi = hi.min(search_end - 1);
            // Subsequent atom hits have nondecreasing lower bounds. Once
            // these cannot precede the retained matches, this atom is done.
            if matches.len() == limit && matches.last().is_some_and(|last| lo > *last) {
                break;
            }
            for pos in lo..=hi {
                if matches.len() == limit && matches.last().is_some_and(|last| pos >= *last) {
                    break;
                }
                if !matches.contains(&pos) && match_pattern_at(data, pos, segments) && accepts(pos)
                {
                    matches.insert(pos);
                    if matches.len() > limit {
                        matches.pop_last();
                    }
                }
            }
        }
    }
    matches
}

/// Match pattern at a specific position in data
fn match_pattern_at(data: &[u8], pos: usize, segments: &[HexSegment]) -> bool {
    match_pattern_sequence(data, pos, segments)
}

fn match_pattern_sequence(data: &[u8], pos: usize, segments: &[HexSegment]) -> bool {
    let Some((segment, rest)) = segments.split_first() else {
        return true;
    };

    match segment {
        HexSegment::Bytes(bytes) => {
            if pos + bytes.len() > data.len() || &data[pos..pos + bytes.len()] != bytes.as_slice() {
                return false;
            }
            match_pattern_sequence(data, pos + bytes.len(), rest)
        }
        HexSegment::Wildcard => pos < data.len() && match_pattern_sequence(data, pos + 1, rest),
        HexSegment::Gap { min, max } => {
            (*min..=*max).any(|gap_len| match_pattern_sequence(data, pos + gap_len, rest))
        }
        HexSegment::NibbleMask {
            high_mask,
            low_mask,
            value,
        } => {
            let mask = high_mask | low_mask;
            pos < data.len()
                && (data[pos] & mask) == *value
                && match_pattern_sequence(data, pos + 1, rest)
        }
        HexSegment::NotByte { mask, value } => {
            pos < data.len()
                && (data[pos] & mask) != *value
                && match_pattern_sequence(data, pos + 1, rest)
        }
        HexSegment::ByteSet(bytes) => {
            pos < data.len()
                && bytes.contains(&data[pos])
                && match_pattern_sequence(data, pos + 1, rest)
        }
        HexSegment::NibbleSet(alternatives) => {
            pos < data.len()
                && alternatives
                    .iter()
                    .any(|(value, mask)| (data[pos] & *mask) == *value)
                && match_pattern_sequence(data, pos + 1, rest)
        }
        HexSegment::Alternative(branches) => branches.iter().any(|branch| {
            let mut combined = branch.clone();
            combined.extend_from_slice(rest);
            match_pattern_sequence(data, pos, &combined)
        }),
    }
}

/// Extract bytes corresponding to '??' wildcards in the matched pattern
fn extract_wildcard_bytes(data: &[u8], pos: usize, segments: &[HexSegment]) -> Vec<u8> {
    let mut extracted = Vec::new();
    let mut offset = pos;

    for (i, segment) in segments.iter().enumerate() {
        match segment {
            HexSegment::Bytes(bytes) => {
                offset += bytes.len();
            }
            HexSegment::Wildcard => {
                if offset < data.len() {
                    extracted.push(data[offset]);
                    offset += 1;
                }
            }
            HexSegment::Gap { min, max } => {
                if min == max {
                    offset += min;
                } else {
                    // Find which gap length worked
                    let remaining_segments = &segments[i + 1..];
                    for gap_len in *min..=*max {
                        if match_pattern_at(data, offset + gap_len, remaining_segments) {
                            offset += gap_len;
                            break;
                        }
                    }
                }
            }
            HexSegment::NibbleMask { .. } => {
                // Extract the matched byte for nibble masks
                if offset < data.len() {
                    extracted.push(data[offset]);
                    offset += 1;
                }
            }
            HexSegment::NotByte { .. } => {
                offset += 1;
            }
            HexSegment::ByteSet(_) => {
                // Extract the matched byte for byte sets
                if offset < data.len() {
                    extracted.push(data[offset]);
                    offset += 1;
                }
            }
            HexSegment::NibbleSet(_) => {
                // Extract the matched byte for nibble-wildcard alternatives
                if offset < data.len() {
                    extracted.push(data[offset]);
                    offset += 1;
                }
            }
            HexSegment::Alternative(branches) => {
                if let Some(branch) = branches
                    .iter()
                    .find(|branch| match_pattern_at(data, offset, branch))
                {
                    extracted.extend(extract_wildcard_bytes(data, offset, branch));
                    let (_, branch_end) = branch.iter().fold((0, 0), |(min, max), segment| {
                        let (segment_min, segment_max) = segment_length_bounds(segment);
                        (min + segment_min, max + segment_max)
                    });
                    offset += branch_end;
                }
            }
        }
    }
    extracted
}

/// Count bytes that actually constrain the match: full hex bytes, nibble
/// wildcards (`4?`), and alternations (`(5C|5D)` — one constrained byte no
/// matter how many branches). `??` and gap specifiers (`[N]`) constrain
/// nothing. Mirrors the validator's counter so `validate` and the matcher
/// agree on which patterns clear the floor.
fn count_concrete_hex_bytes(pattern: &str) -> usize {
    pattern
        .split_whitespace()
        .filter(|t| !t.starts_with('[') && *t != "??")
        .filter(|t| {
            (t.len() == 2 && t.chars().all(|c| c.is_ascii_hexdigit() || c == '?'))
                || is_hex_alternation(t)
        })
        .count()
}

/// `(NN|NN|...)` where every branch is a hex or nibble-wildcard byte.
fn is_hex_alternation(token: &str) -> bool {
    let Some(inner) = token.strip_prefix('(').and_then(|t| t.strip_suffix(')')) else {
        return false;
    };
    !inner.is_empty()
        && inner
            .split('|')
            .all(|b| b.len() == 2 && b.chars().all(|c| c.is_ascii_hexdigit() || c == '?'))
}

/// The value a hex match is shown and tested as: the bytes its wildcards,
/// alternations and gaps matched, as lowercase space-separated hex (`"e8 00"`),
/// or the pattern itself when it has none. `not:` exceptions test this same
/// value, so a match is excluded by what its evidence shows.
fn hex_match_value(data: &[u8], pos: usize, segments: &[HexSegment], pattern: &str) -> String {
    let extracted = extract_wildcard_bytes(data, pos, segments);
    if extracted.is_empty() {
        pattern.to_string()
    } else {
        extracted
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<Vec<_>>()
            .join(" ")
    }
}

/// Evaluate hex pattern condition
///
/// Uses YARA-style atom extraction for efficient searching:
/// 1. Extract longest fixed byte sequence from pattern
/// 2. Use fast memmem search to find atom candidates
/// 3. Verify full pattern only at candidate positions
///
/// A match whose [`hex_match_value`] a `not:` exception names is not counted.
#[must_use]
pub(crate) fn eval_hex<'a>(
    pattern: &str,
    not: Option<&Vec<NotException>>,
    location: &super::ContentLocationParams,
    ctx: &EvaluationContext<'a>,
    trait_id: Option<&str>,
) -> ConditionResult {
    // Reject short hex patterns unless search space is bounded (~1KB).
    // Acceptable: offset/offset_range, or section + (section_offset* or small file).
    // Density constraints (count_min, per_kb_min) are checked at trait level, not here.
    // A rejection carries a warning (not a silent no-match) so test-match and
    // test-rules can tell the author why the pattern never fires; `cleave
    // validate` reports the same floor for unpinned traits at load time.
    {
        let has_pinpoint = location.offset.is_some() || location.offset_range.is_some();
        let has_section_pinpoint = location.section.is_some()
            && (location.section_offset.is_some() || location.section_offset_range.is_some());
        if !has_pinpoint && !has_section_pinpoint {
            let concrete_bytes = count_concrete_hex_bytes(pattern);
            if concrete_bytes < 3 {
                return ConditionResult {
                    warnings: vec![AnalysisWarning::HexPatternTooShort {
                        concrete: concrete_bytes,
                    }],
                    ..ConditionResult::no_match()
                };
            }
        }
    }

    let data = ctx.binary_data;

    // Parse the pattern
    let segments = match parse_hex_pattern(pattern) {
        Ok(s) => s,
        Err(e) => {
            return ConditionResult {
                matched: false,
                evidence: vec![Evidence {
                    method: "hex".to_string(),
                    source: "error".to_string(),
                    value: format!("invalid hex pattern: {}", e),
                    location: Some("0x0".to_string()),
                    ..Default::default()
                }],
                match_count: 0,
                warnings: Vec::new(),
                precision: 0.0,
                matched_trait_ids: Vec::new(),
            };
        }
    };

    if segments.is_empty() {
        return ConditionResult::no_match();
    }

    let accepts = |pos: usize| {
        not.is_none_or(|exceptions| {
            let value = hex_match_value(data, pos, &segments, pattern);
            !exceptions.iter().any(|exception| exception.matches(&value))
        })
    };

    let mut matches: Vec<usize> = Vec::new();
    let mut total_count: usize = 0;

    /// Maximum match positions to store for evidence (memory-limited).
    /// Aligns with MAX_EVIDENCE_PER_TRAIT; counts continue beyond this limit.
    const MAX_STORED_MATCHES: usize = 16;
    /// Maximum total matches to count for density/count constraints.
    /// Beyond this we assume the pattern is too broad.
    const MAX_COUNT_MATCHES: usize = 16384;

    // Resolve effective range from location constraints
    let (search_start, search_end) = super::resolve_effective_range(location, ctx);

    // Ensure we don't exceed binary data bounds
    let search_start = search_start.min(data.len());
    let search_end = search_end.min(data.len());

    if search_start >= search_end {
        return ConditionResult::no_match();
    }

    // Handle single-byte offset constraint (optimization)
    if location.offset.is_some() && location.offset_range.is_none() {
        if match_pattern_at(data, search_start, &segments) && accepts(search_start) {
            matches.push(search_start);
            total_count = 1;
        }
    }
    // Handle search in range or entire file
    else if is_simple_pattern(&segments) {
        // Simple pattern: use fast memmem search
        if let HexSegment::Bytes(bytes) = &segments[0] {
            let finder = memchr::memmem::Finder::new(bytes);
            for pos in finder.find_iter(&data[search_start..search_end]) {
                let pos = search_start + pos;
                if !accepts(pos) {
                    continue;
                }
                total_count += 1;
                if matches.len() < MAX_STORED_MATCHES {
                    matches.push(pos);
                }
                if total_count >= MAX_COUNT_MATCHES {
                    break;
                }
            }
        }
    } else {
        // Complex pattern: use atom extraction for pre-filtering
        if let Some(atom) = extract_best_atom(&segments) {
            let finder = memchr::memmem::Finder::new(atom);

            // Distance from the pattern start to the chosen atom. A variable gap
            // BEFORE the atom makes this a RANGE, not a single value: the prefix can
            // be as short as the sum of gap minimums or as long as the sum of gap
            // maximums. Back-aligning by the minimum alone (the old behavior) silently
            // dropped every match whose preceding `[N-M]` gap consumed more than N
            // bytes — e.g. `44 8D 49 40 [0-8] 41 B8 ..` when the real gap was 5 and the
            // longest atom (`41 B8 ..`) sits after the gap.
            let (prefix_min, prefix_max): (usize, usize) = segments
                .iter()
                .take_while(|s| !matches!(s, HexSegment::Bytes(b) if b.as_slice() == atom))
                .fold((0usize, 0usize), |(lo, hi), s| {
                    let (segment_min, segment_max) = segment_length_bounds(s);
                    (lo + segment_min, hi + segment_max)
                });

            // Search for atom, then verify full pattern at every plausible start.
            // Track seen positions to avoid double-counting.
            let mut seen_positions = rustc_hash::FxHashSet::default();
            'atoms: for atom_pos in finder.find_iter(&data[search_start..search_end]) {
                let abs_atom = search_start + atom_pos;
                // Candidate pattern starts: abs_atom - prefix_max ..= abs_atom - prefix_min.
                // (Equal bounds when no variable gap precedes the atom — the common case,
                // so this stays a single probe and adds no overhead there.)
                let start_hi = abs_atom.saturating_sub(prefix_min);
                let start_lo = abs_atom.saturating_sub(prefix_max);
                for pattern_start in start_lo..=start_hi {
                    // Ensure candidate position is within our search range.
                    if pattern_start < search_start || pattern_start >= search_end {
                        continue;
                    }
                    if seen_positions.contains(&pattern_start) {
                        continue;
                    }
                    if match_pattern_at(data, pattern_start, &segments) && accepts(pattern_start) {
                        seen_positions.insert(pattern_start);
                        total_count += 1;
                        if matches.len() < MAX_STORED_MATCHES {
                            matches.push(pattern_start);
                        }
                        if total_count >= MAX_COUNT_MATCHES {
                            break 'atoms;
                        }
                        // One match per atom occurrence: a variable prefix gap could
                        // otherwise let several starts align to the same atom hit.
                        continue 'atoms;
                    }
                }
            }
        } else {
            // Whole-pattern alternatives have no single top-level atom. Use
            // each branch's mandatory atom to find candidates instead of
            // testing every byte whenever just one such atom exists.
            if let Some(atoms) = mandatory_hex_atoms(&segments) {
                let found = anchored_hex_matches(
                    data,
                    search_start,
                    search_end,
                    &segments,
                    &atoms,
                    accepts,
                    MAX_COUNT_MATCHES,
                );
                total_count = found.len();
                matches.extend(found.into_iter().take(MAX_STORED_MATCHES));
            } else {
                for pos in search_start..search_end {
                    if match_pattern_at(data, pos, &segments) && accepts(pos) {
                        total_count += 1;
                        if matches.len() < MAX_STORED_MATCHES {
                            matches.push(pos);
                        }
                        if total_count >= MAX_COUNT_MATCHES {
                            break;
                        }
                    }
                }
            }
        }
    }

    // Emit an informational trace if we hit the count limit.
    let truncated = total_count >= MAX_COUNT_MATCHES;
    if truncated {
        if let Some(trait_id_val) = trait_id {
            tracing::info!(
                trait_id = %trait_id_val,
                pattern = %pattern,
                count = total_count,
                limit = MAX_COUNT_MATCHES,
                "Hit hex-pattern match limit; stopping early"
            );
        } else {
            tracing::info!(
                pattern = %pattern,
                count = total_count,
                limit = MAX_COUNT_MATCHES,
                "Hit hex-pattern match limit; stopping early"
            );
        }
    }

    // count/density constraints are now checked at trait level
    let matched = total_count > 0;

    // Calculate precision: base 2.0 (hex patterns are specific) + modifiers
    let mut precision = 2.0f32;
    if location.offset.is_some() || location.offset_range.is_some() {
        precision += 0.5;
    }
    if location.section.is_some() {
        precision += 1.0;
    }

    let warnings = if truncated {
        vec![AnalysisWarning::PatternTruncated {
            pattern: pattern.to_string(),
            limit: MAX_COUNT_MATCHES,
        }]
    } else {
        Vec::new()
    };

    ConditionResult {
        matched,
        evidence: if matched {
            matches
                .iter()
                .take(MAX_EVIDENCE_PER_TRAIT)
                .map(|pos| {
                    // Always extract wildcard bytes (consistent with regex behavior)
                    Evidence {
                        method: "hex".to_string(),
                        source: "binary".to_string(),
                        value: hex_match_value(data, *pos, &segments, pattern),
                        location: Some(format!("0x{:x}", pos)),
                        ..Default::default()
                    }
                })
                .collect()
        } else {
            Vec::new()
        },
        match_count: total_count,
        warnings,
        precision,
        matched_trait_ids: Vec::new(),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests;
