//! YARA and hex pattern condition evaluators.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//!
//! This module handles evaluation of YARA-based conditions:
//! - YARA rule matching against pre-scanned results
//! - Inline YARA rule compilation and scanning
//! - Hex pattern matching with wildcards and gaps
//! - Atom extraction for efficient pattern searching

use super::{get_or_create_scanner, truncate_evidence};
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
        let scanner = get_or_create_scanner(pre_compiled.as_ref());
        let evidence = match scanner.scan(ctx.binary_data) {
            Ok(results) => collect_yara_evidence(&results, ctx.binary_data),
            Err(_) => Vec::new(),
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
    /// Byte alternation: matches any byte in the set
    ByteSet(Vec<u8>),
}

/// Parse a hex pattern string into segments
/// Format: "7F 45 4C 46" or "31 ?? 48" or "00 [4] FF" or "00 [2-8] FF"
fn parse_hex_pattern(pattern: &str) -> Result<Vec<HexSegment>, String> {
    let mut segments: Vec<HexSegment> = Vec::new();
    let mut current_bytes: Vec<u8> = Vec::new();

    for token in pattern.split_whitespace() {
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
                    .map_err(|_| format!("invalid nibble: {}", token))?;
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
                    .map_err(|_| format!("invalid nibble: {}", token))?;
                segments.push(HexSegment::NibbleMask {
                    high_mask: 0xF0,
                    low_mask: 0x00,
                    value: high_nibble << 4,
                });
                continue;
            }
            // Fall through to regular hex byte parsing for non-wildcard 2-char tokens
            let byte = u8::from_str_radix(token, 16)
                .map_err(|_| format!("invalid hex byte: {}", token))?;
            current_bytes.push(byte);
        } else if token.starts_with('(') && token.ends_with(')') {
            // Byte alternation: (XX|YY|ZZ)
            if !current_bytes.is_empty() {
                segments.push(HexSegment::Bytes(std::mem::take(&mut current_bytes)));
            }

            let inner = &token[1..token.len() - 1];
            let alternatives: Result<Vec<u8>, String> = inner
                .split('|')
                .map(|s| {
                    u8::from_str_radix(s.trim(), 16)
                        .map_err(|_| format!("invalid alternation byte: {}", s))
                })
                .collect();

            let bytes = alternatives?;
            if bytes.is_empty() {
                return Err("empty byte alternation".to_string());
            }

            segments.push(HexSegment::ByteSet(bytes));
        } else if token.starts_with('[') && token.ends_with(']') {
            // Gap: [N] or [N-M]
            if !current_bytes.is_empty() {
                segments.push(HexSegment::Bytes(std::mem::take(&mut current_bytes)));
            }
            let inner = &token[1..token.len() - 1];
            if let Some(dash_pos) = inner.find('-') {
                let min: usize = inner[..dash_pos]
                    .parse()
                    .map_err(|_| format!("invalid gap min: {}", inner))?;
                let max: usize = inner[dash_pos + 1..]
                    .parse()
                    .map_err(|_| format!("invalid gap max: {}", inner))?;
                segments.push(HexSegment::Gap { min, max });
            } else {
                let n: usize = inner
                    .parse()
                    .map_err(|_| format!("invalid gap: {}", inner))?;
                segments.push(HexSegment::Gap { min: n, max: n });
            }
        } else {
            // Regular hex byte
            let byte = u8::from_str_radix(token, 16)
                .map_err(|_| format!("invalid hex byte: {}", token))?;
            current_bytes.push(byte);
        }
    }

    // Flush remaining bytes
    if !current_bytes.is_empty() {
        segments.push(HexSegment::Bytes(current_bytes));
    }

    Ok(segments)
}

/// Check if pattern is simple (no wildcards or gaps)
fn is_simple_pattern(segments: &[HexSegment]) -> bool {
    segments.len() == 1 && matches!(segments.first(), Some(HexSegment::Bytes(_)))
}

/// Extract the longest fixed byte sequence (atom) for fast pre-filtering
fn extract_best_atom(segments: &[HexSegment]) -> Option<&[u8]> {
    segments
        .iter()
        .filter_map(|s| match s {
            HexSegment::Bytes(b) if b.len() >= 2 => Some(b.as_slice()),
            _ => None,
        })
        .max_by_key(|b| b.len())
}

/// Match pattern at a specific position in data
fn match_pattern_at(data: &[u8], pos: usize, segments: &[HexSegment]) -> bool {
    let mut offset = pos;

    for (i, segment) in segments.iter().enumerate() {
        match segment {
            HexSegment::Bytes(bytes) => {
                if offset + bytes.len() > data.len() {
                    return false;
                }
                if &data[offset..offset + bytes.len()] != bytes.as_slice() {
                    return false;
                }
                offset += bytes.len();
            }
            HexSegment::Wildcard => {
                if offset >= data.len() {
                    return false;
                }
                offset += 1;
            }
            HexSegment::Gap { min, max } => {
                // For gaps, we need to try all possible lengths
                if *min == *max {
                    // Fixed gap - just skip
                    offset += min;
                } else {
                    // Variable gap - try each length
                    let remaining_segments = &segments[i + 1..];
                    for gap_len in *min..=*max {
                        if match_pattern_at(data, offset + gap_len, remaining_segments) {
                            return true;
                        }
                    }
                    return false;
                }
            }
            HexSegment::NibbleMask {
                high_mask,
                low_mask,
                value,
            } => {
                if offset >= data.len() {
                    return false;
                }
                let byte = data[offset];
                let mask = high_mask | low_mask;
                if (byte & mask) != *value {
                    return false;
                }
                offset += 1;
            }
            HexSegment::ByteSet(bytes) => {
                if offset >= data.len() {
                    return false;
                }
                if !bytes.contains(&data[offset]) {
                    return false;
                }
                offset += 1;
            }
        }
    }

    true
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
            HexSegment::ByteSet(_) => {
                // Extract the matched byte for byte sets
                if offset < data.len() {
                    extracted.push(data[offset]);
                    offset += 1;
                }
            }
        }
    }
    extracted
}

/// Evaluate hex pattern condition
/// Uses YARA-style atom extraction for efficient searching:
/// 1. Extract longest fixed byte sequence from pattern
/// 2. Use fast memmem search to find atom candidates
/// 3. Verify full pattern only at candidate positions
#[allow(clippy::too_many_arguments)]
#[must_use]
pub(crate) fn eval_hex<'a>(
    pattern: &str,
    location: &super::ContentLocationParams,
    ctx: &EvaluationContext<'a>,
) -> ConditionResult {
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
                    location: None,
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
        if match_pattern_at(data, search_start, &segments) {
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
                total_count += 1;
                if matches.len() < MAX_STORED_MATCHES {
                    matches.push(search_start + pos);
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

            // Find the atom's position within the pattern
            let atom_offset_in_pattern: usize = segments
                .iter()
                .take_while(|s| !matches!(s, HexSegment::Bytes(b) if b.as_slice() == atom))
                .map(|s| match s {
                    HexSegment::Bytes(b) => b.len(),
                    HexSegment::Gap { min, .. } => *min,
                    HexSegment::Wildcard
                    | HexSegment::NibbleMask { .. }
                    | HexSegment::ByteSet(_) => 1,
                })
                .sum();

            // Search for atom, then verify full pattern
            // Track seen positions to avoid double-counting
            let mut seen_positions = rustc_hash::FxHashSet::default();
            for atom_pos in finder.find_iter(&data[search_start..search_end]) {
                let pattern_start =
                    (search_start + atom_pos).saturating_sub(atom_offset_in_pattern);

                // Ensure candidate position is within our search range
                if pattern_start < search_start || pattern_start >= search_end {
                    continue;
                }

                if match_pattern_at(data, pattern_start, &segments)
                    && !seen_positions.contains(&pattern_start)
                {
                    seen_positions.insert(pattern_start);
                    total_count += 1;
                    if matches.len() < MAX_STORED_MATCHES {
                        matches.push(pattern_start);
                    }
                    if total_count >= MAX_COUNT_MATCHES {
                        break;
                    }
                }
            }
        } else {
            // No good atom found - fall back to linear scan in range
            for pos in search_start..search_end {
                if match_pattern_at(data, pos, &segments) {
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

    // Warn if we hit the count limit (indicates potentially problematic pattern)
    let truncated = total_count >= MAX_COUNT_MATCHES;
    if truncated {
        if let Some(trait_id) = ctx.current_trait {
            tracing::debug!(
                trait_id = %trait_id,
                pattern = %pattern,
                count = total_count,
                limit = MAX_COUNT_MATCHES,
                "Hex pattern has excessive matches, count truncated"
            );
        } else {
            tracing::debug!(
                pattern = %pattern,
                count = total_count,
                limit = MAX_COUNT_MATCHES,
                "Hex pattern has excessive matches, count truncated"
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
                    let extracted = extract_wildcard_bytes(data, *pos, &segments);
                    let value = if extracted.is_empty() {
                        pattern.to_string()
                    } else {
                        // Format extracted bytes as hex string
                        let hex_str: Vec<String> =
                            extracted.iter().map(|b| format!("{:02x}", b)).collect();
                        format!("extracted: {}", hex_str.join(" "))
                    };

                    Evidence {
                        method: "hex".to_string(),
                        source: "binary".to_string(),
                        value,
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
mod tests {
    use super::*;

    #[test]
    fn test_parse_hex_pattern_simple() {
        let segments = parse_hex_pattern("7F 45 4C 46").unwrap();
        assert_eq!(segments.len(), 1);
        match &segments[0] {
            HexSegment::Bytes(b) => assert_eq!(b, &[0x7F, 0x45, 0x4C, 0x46]),
            _ => panic!("expected Bytes"),
        }
    }

    #[test]
    fn test_parse_hex_pattern_wildcards() {
        let segments = parse_hex_pattern("31 ?? 48 83").unwrap();
        assert_eq!(segments.len(), 3);
        match &segments[0] {
            HexSegment::Bytes(b) => assert_eq!(b, &[0x31]),
            _ => panic!("expected Bytes"),
        }
        assert!(matches!(segments[1], HexSegment::Wildcard));
        match &segments[2] {
            HexSegment::Bytes(b) => assert_eq!(b, &[0x48, 0x83]),
            _ => panic!("expected Bytes"),
        }
    }

    #[test]
    fn test_parse_hex_pattern_fixed_gap() {
        let segments = parse_hex_pattern("00 03 [4] 00 04").unwrap();
        assert_eq!(segments.len(), 3);
        match &segments[1] {
            HexSegment::Gap { min, max } => {
                assert_eq!(*min, 4);
                assert_eq!(*max, 4);
            }
            _ => panic!("expected Gap"),
        }
    }

    #[test]
    fn test_parse_hex_pattern_variable_gap() {
        let segments = parse_hex_pattern("00 [2-8] FF").unwrap();
        assert_eq!(segments.len(), 3);
        match &segments[1] {
            HexSegment::Gap { min, max } => {
                assert_eq!(*min, 2);
                assert_eq!(*max, 8);
            }
            _ => panic!("expected Gap"),
        }
    }

    #[test]
    fn test_match_simple_pattern() {
        let data = b"\x7F\x45\x4C\x46\x01\x02\x03";
        let segments = parse_hex_pattern("7F 45 4C 46").unwrap();
        assert!(match_pattern_at(data, 0, &segments));
        assert!(!match_pattern_at(data, 1, &segments));
    }

    #[test]
    fn test_match_wildcard_pattern() {
        let data = b"\x31\xC0\x48\x83";
        let segments = parse_hex_pattern("31 ?? 48 83").unwrap();
        assert!(match_pattern_at(data, 0, &segments));

        let data2 = b"\x31\xFF\x48\x83";
        assert!(match_pattern_at(data2, 0, &segments));

        let data3 = b"\x31\xC0\x48\x84"; // Last byte differs
        assert!(!match_pattern_at(data3, 0, &segments));
    }

    #[test]
    fn test_match_fixed_gap() {
        let data = b"\x00\x03\xAA\xBB\xCC\xDD\x00\x04";
        let segments = parse_hex_pattern("00 03 [4] 00 04").unwrap();
        assert!(match_pattern_at(data, 0, &segments));
    }

    #[test]
    fn test_match_variable_gap() {
        // Gap of 2
        let data2 = b"\x00\xAA\xBB\xFF";
        let segments = parse_hex_pattern("00 [2-4] FF").unwrap();
        assert!(match_pattern_at(data2, 0, &segments));

        // Gap of 4
        let data4 = b"\x00\xAA\xBB\xCC\xDD\xFF";
        assert!(match_pattern_at(data4, 0, &segments));

        // Gap of 5 (too long)
        let data5 = b"\x00\xAA\xBB\xCC\xDD\xEE\xFF";
        assert!(!match_pattern_at(data5, 0, &segments));
    }

    #[test]
    fn test_is_simple_pattern() {
        let simple = parse_hex_pattern("7F 45 4C 46").unwrap();
        assert!(is_simple_pattern(&simple));

        let with_wildcard = parse_hex_pattern("7F ?? 4C 46").unwrap();
        assert!(!is_simple_pattern(&with_wildcard));

        let with_gap = parse_hex_pattern("7F [2] 46").unwrap();
        assert!(!is_simple_pattern(&with_gap));
    }

    #[test]
    fn test_extract_best_atom() {
        let segments = parse_hex_pattern("31 ?? 48 83 C4 08").unwrap();
        let atom = extract_best_atom(&segments).unwrap();
        // Should extract "48 83 C4 08" (4 bytes) not "31" (1 byte)
        assert_eq!(atom, &[0x48, 0x83, 0xC4, 0x08]);
    }

    #[test]
    fn test_parse_invalid_hex() {
        assert!(parse_hex_pattern("ZZ 45").is_err());
        assert!(parse_hex_pattern("[abc]").is_err());
    }

    // === Nibble wildcard tests ===

    #[test]
    fn test_parse_nibble_wildcard_high() {
        // 4? = high nibble 0x40, low nibble wild
        let segments = parse_hex_pattern("4?").unwrap();
        assert_eq!(segments.len(), 1);
        match &segments[0] {
            HexSegment::NibbleMask {
                high_mask,
                low_mask,
                value,
            } => {
                assert_eq!(*high_mask, 0xF0);
                assert_eq!(*low_mask, 0x00);
                assert_eq!(*value, 0x40);
            }
            _ => panic!("expected NibbleMask"),
        }
    }

    #[test]
    fn test_parse_nibble_wildcard_low() {
        // ?A = high nibble wild, low nibble 0x0A
        let segments = parse_hex_pattern("?A").unwrap();
        assert_eq!(segments.len(), 1);
        match &segments[0] {
            HexSegment::NibbleMask {
                high_mask,
                low_mask,
                value,
            } => {
                assert_eq!(*high_mask, 0x00);
                assert_eq!(*low_mask, 0x0F);
                assert_eq!(*value, 0x0A);
            }
            _ => panic!("expected NibbleMask"),
        }
    }

    #[test]
    fn test_parse_nibble_wildcard_complex() {
        // Mozi-style pattern
        let segments = parse_hex_pattern("31 ?? 4? 7?").unwrap();
        assert_eq!(segments.len(), 4);
        assert!(matches!(&segments[0], HexSegment::Bytes(b) if b == &[0x31]));
        assert!(matches!(segments[1], HexSegment::Wildcard));
        assert!(matches!(
            segments[2],
            HexSegment::NibbleMask { value: 0x40, .. }
        ));
        assert!(matches!(
            segments[3],
            HexSegment::NibbleMask { value: 0x70, .. }
        ));
    }

    #[test]
    fn test_match_nibble_wildcard_high() {
        let segments = parse_hex_pattern("4?").unwrap();

        // 4? should match 0x40-0x4F
        assert!(match_pattern_at(&[0x40], 0, &segments));
        assert!(match_pattern_at(&[0x4F], 0, &segments));
        assert!(match_pattern_at(&[0x48], 0, &segments));

        // Should not match 0x5F (different high nibble)
        assert!(!match_pattern_at(&[0x5F], 0, &segments));
        assert!(!match_pattern_at(&[0x30], 0, &segments));
    }

    #[test]
    fn test_match_nibble_wildcard_low() {
        let segments = parse_hex_pattern("?A").unwrap();

        // ?A should match any byte ending in A
        assert!(match_pattern_at(&[0x0A], 0, &segments));
        assert!(match_pattern_at(&[0xFA], 0, &segments));
        assert!(match_pattern_at(&[0x5A], 0, &segments));

        // Should not match xB
        assert!(!match_pattern_at(&[0xFB], 0, &segments));
        assert!(!match_pattern_at(&[0x00], 0, &segments));
    }

    #[test]
    fn test_match_mozi_xor_pattern() {
        // Real Mozi XOR loop pattern: 31 ?? 88 ?? 4? 83 ?? ?? 7?
        let data = &[0x31, 0xC0, 0x88, 0x03, 0x48, 0x83, 0xC0, 0x01, 0x75];
        let segments = parse_hex_pattern("31 ?? 88 ?? 4? 83 ?? ?? 7?").unwrap();
        assert!(match_pattern_at(data, 0, &segments));

        // Different high nibble at position 4 should fail
        let data_bad = &[0x31, 0xC0, 0x88, 0x03, 0x58, 0x83, 0xC0, 0x01, 0x75];
        assert!(!match_pattern_at(data_bad, 0, &segments));
    }

    // === Byte alternation tests ===

    #[test]
    fn test_parse_byte_alternation() {
        let segments = parse_hex_pattern("(00|80)").unwrap();
        assert_eq!(segments.len(), 1);
        match &segments[0] {
            HexSegment::ByteSet(bytes) => {
                assert_eq!(bytes, &[0x00, 0x80]);
            }
            _ => panic!("expected ByteSet"),
        }
    }

    #[test]
    fn test_parse_byte_alternation_many() {
        // LZMA-style: many alternatives
        let segments = parse_hex_pattern("(01|02|03|04|05)").unwrap();
        assert_eq!(segments.len(), 1);
        match &segments[0] {
            HexSegment::ByteSet(bytes) => {
                assert_eq!(bytes, &[0x01, 0x02, 0x03, 0x04, 0x05]);
            }
            _ => panic!("expected ByteSet"),
        }
    }

    #[test]
    fn test_parse_combined_pattern() {
        // LZMA-style: fixed + alternation + gap + wildcard
        let segments = parse_hex_pattern("5D 00 00 (00|80) [7] ??").unwrap();
        assert_eq!(segments.len(), 4);
        assert!(matches!(&segments[0], HexSegment::Bytes(b) if b == &[0x5D, 0x00, 0x00]));
        assert!(matches!(&segments[1], HexSegment::ByteSet(b) if b == &[0x00, 0x80]));
        assert!(matches!(segments[2], HexSegment::Gap { min: 7, max: 7 }));
        assert!(matches!(segments[3], HexSegment::Wildcard));
    }

    #[test]
    fn test_match_byte_alternation() {
        let segments = parse_hex_pattern("(00|80)").unwrap();

        assert!(match_pattern_at(&[0x00], 0, &segments));
        assert!(match_pattern_at(&[0x80], 0, &segments));

        // Not in set
        assert!(!match_pattern_at(&[0x40], 0, &segments));
        assert!(!match_pattern_at(&[0x01], 0, &segments));
    }

    #[test]
    fn test_match_byte_alternation_in_context() {
        // Test alternation between fixed bytes
        let segments = parse_hex_pattern("5D 00 00 (00|80) 00").unwrap();

        let data1 = &[0x5D, 0x00, 0x00, 0x80, 0x00];
        assert!(match_pattern_at(data1, 0, &segments));

        let data2 = &[0x5D, 0x00, 0x00, 0x00, 0x00]; // 00 variant
        assert!(match_pattern_at(data2, 0, &segments));

        let data3 = &[0x5D, 0x00, 0x00, 0x40, 0x00]; // 40 not in set
        assert!(!match_pattern_at(data3, 0, &segments));
    }

    #[test]
    fn test_match_lzma_pattern() {
        // Simplified LZMA header pattern: 5D 00 00 (00|80) 00 (10|20) [7] ??
        let data = &[
            0x5D, 0x00, 0x00, 0x80, 0x00, 0x10, // Header + decompressed size byte
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // 7 bytes gap
            0xFF, // Final byte
        ];
        let segments = parse_hex_pattern("5D 00 00 (00|80) 00 (10|20) [7] ??").unwrap();
        assert!(match_pattern_at(data, 0, &segments));

        // With 00 variant instead of 80
        let data2 = &[
            0x5D, 0x00, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xAB,
        ];
        assert!(match_pattern_at(data2, 0, &segments));
    }

    #[test]
    fn test_extract_nibble_wildcard_bytes() {
        let segments = parse_hex_pattern("31 4? ??").unwrap();

        // Should match 31 48 XX (0x48 has high nibble 4)
        let data = &[0x31, 0x48, 0xFF];
        assert!(match_pattern_at(data, 0, &segments));

        let extracted = extract_wildcard_bytes(data, 0, &segments);
        // Should extract 0x48 (nibble mask) and 0xFF (wildcard)
        assert_eq!(extracted, vec![0x48, 0xFF]);
    }

    #[test]
    fn test_extract_byte_set_bytes() {
        let data = &[0x5D, 0x00, 0x80, 0xFF];
        let segments = parse_hex_pattern("5D 00 (00|80) ??").unwrap();
        assert!(match_pattern_at(data, 0, &segments));

        let extracted = extract_wildcard_bytes(data, 0, &segments);
        // Should extract 0x80 (byte set) and 0xFF (wildcard)
        assert_eq!(extracted, vec![0x80, 0xFF]);
    }

    #[test]
    fn test_is_simple_pattern_with_new_types() {
        let with_nibble = parse_hex_pattern("4? 45").unwrap();
        assert!(!is_simple_pattern(&with_nibble));

        let with_byteset = parse_hex_pattern("(00|80) 45").unwrap();
        assert!(!is_simple_pattern(&with_byteset));
    }
}
