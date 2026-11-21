//! `substr:` matches are the matched span, not the string around them.
//!
//! The matcher used to hand back the whole string a `substr:` was found in.
//! Evidence then anchored at that string's start with its head as the value,
//! so inside one long string (a minified file's single line, or a decoded layer
//! spanning it) every `substr:` hit of every trait landed on the same
//! `[start, 128]` span. These tests pin the span itself on every path that
//! matches content, and pin which text each filter judges:
//!
//! - `not:` judges only what the `substr:` matched.
//! - `is:` and `length_min`/`length_max` judge the string (or, on raw content,
//!   the 50 bytes around the hit) the substring was found in.

use super::*;
use crate::composite_rules::condition::{EncodingSpec, NotException, StringValidator};
use crate::composite_rules::context::{EvaluationContext, StringParams};
use crate::composite_rules::evaluators::{
    ContentLocationParams, TextPattern, eval_comment, eval_encoded, eval_raw,
};
use crate::composite_rules::types::FileType;
use crate::types::{AnalysisReport, StringInfo, TargetInfo};

fn report_with(strings: Vec<StringInfo>) -> AnalysisReport {
    let mut report = AnalysisReport::new(TargetInfo {
        path: "/test/binary".to_string(),
        file_type: "elf".to_string(),
        size_bytes: 1 << 20,
        sha256: "abc123".to_string(),
        architectures: None,
    });
    report.strings = strings;
    report
}

fn string(value: &str, offset: Option<u64>) -> StringInfo {
    StringInfo {
        value: value.to_string().into(),
        offset,
        encoding: "utf8".to_string(),
        string_type: None,
        section: None,
        encoding_chain: Vec::new(),
        fragments: None,
    }
}

fn decoded(value: &str, offset: u64, chain: &str) -> StringInfo {
    StringInfo {
        encoding_chain: vec![chain.to_string()],
        ..string(value, Some(offset))
    }
}

fn params<'a>(substr: &'a String) -> StringParams<'a> {
    StringParams {
        encoding: None,
        length_min: None,
        length_max: None,
        exclude_html_comments: false,
        exclude_comments: false,
        exact: None,
        substr: Some(substr),
        regex: None,
        word: None,
        case_insensitive: false,
        is_check: None,
        section: None,
        offset: None,
        offset_range: None,
        section_offset: None,
        section_offset_range: None,
        arch_clamp: None,
    }
}

fn not(json: serde_json::Value) -> Vec<NotException> {
    vec![serde_json::from_value(json).unwrap()]
}

/// Where `part` starts within `whole`, when it is a subslice of it.
fn displacement(whole: &str, part: &str) -> usize {
    let at = part.as_ptr() as usize - whole.as_ptr() as usize;
    assert!(
        at + part.len() <= whole.len(),
        "{part:?} is not inside {whole:?}"
    );
    at
}

fn substr_cs(needle: &str) -> StringMatcher<'static> {
    StringMatcher::SubstrCs(crate::composite_rules::condition::cached_finder(needle))
}

fn substr_ci(needle: &str) -> StringMatcher<'static> {
    StringMatcher::SubstrCi(crate::composite_rules::condition::cached_ci_searcher(needle).unwrap())
}

// ---------------------------------------------------------------------------
// The matcher
// ---------------------------------------------------------------------------

#[test]
fn substr_returns_the_first_matched_span() {
    let value = "xx needle yy needle";
    let got = substr_cs("needle").match_value_ref(value).unwrap();
    assert_eq!(got, "needle");
    assert_eq!(displacement(value, got), 3);
}

#[test]
fn case_insensitive_substr_returns_the_source_casing() {
    let value = "call NeEdLe now";
    let got = substr_ci("needle").match_value_ref(value).unwrap();
    assert_eq!(got, "NeEdLe");
    assert_eq!(displacement(value, got), 5);
}

#[test]
fn substr_spans_stay_on_char_boundaries() {
    let value = "αβ İİ déjà vu";
    let got = substr_cs("déjà").match_value_ref(value).unwrap();
    assert_eq!(got, "déjà");
    assert_eq!(displacement(value, got), value.find("déjà").unwrap());
    // ASCII case folding around non-ASCII bytes.
    let got = substr_ci("DÉJÀ VU").match_value_ref("DÉJÀ vu");
    assert_eq!(got, Some("DÉJÀ vu"));
}

#[test]
fn substr_misses_return_none() {
    assert_eq!(substr_cs("needle").match_value_ref("haystack"), None);
    assert_eq!(substr_ci("needle").match_value_ref("haystack"), None);
    assert_eq!(substr_cs("needle").match_value_ref(""), None);
}

#[test]
fn exact_still_returns_the_whole_value() {
    let matcher = StringMatcher::Exact {
        needle: "whole",
        ci: true,
    };
    assert_eq!(matcher.match_value_ref("WHOLE"), Some("WHOLE"));
    assert_eq!(matcher.match_value_ref("whole thing"), None);
}

#[test]
fn substr_length_bounds_judge_the_string_not_the_span() {
    let value = "a fairly long string holding abc somewhere";
    for matcher in [substr_cs("abc"), substr_ci("ABC")] {
        assert_eq!(
            matcher.match_value_bounded(value, (Some(10), None)),
            Some("abc")
        );
        assert_eq!(matcher.match_value_bounded(value, (None, Some(5))), None);
        assert_eq!(
            matcher.match_value_bounded("abc", (None, Some(5))),
            Some("abc")
        );
    }
    // `word:` bounds keep judging the matched span.
    let word = StringMatcher::WordCs {
        needle: "abc",
        finder: crate::composite_rules::condition::cached_finder("abc"),
    };
    assert_eq!(word.match_value_bounded(value, (Some(10), None)), None);
    assert_eq!(
        word.match_value_bounded(value, (None, Some(5))),
        Some("abc")
    );
}

#[test]
fn batched_substr_matches_the_unbatched_spans() {
    let values = ["", "needle", "a needle b", "NEEDLE", "no", "needleneedle"];
    for matcher in [substr_cs("needle"), substr_ci("needle")] {
        let expected: Vec<_> = values.iter().map(|v| matcher.match_value_ref(v)).collect();
        matcher.with_batch(values.len(), |batch| {
            for (value, expected) in values.iter().zip(&expected) {
                let got = batch.match_value_bounded(value, (None, None));
                assert_eq!(got, *expected);
                assert_eq!(got.map(str::as_ptr), expected.map(str::as_ptr));
            }
        });
    }
}

// ---------------------------------------------------------------------------
// `type: text` over extracted strings
// ---------------------------------------------------------------------------

#[test]
fn text_substr_evidence_is_the_match_at_its_offset() {
    let report = report_with(vec![string("prefix-text needle suffix", Some(0x1000))]);
    let ctx = EvaluationContext::test_only_new(&report, &[], FileType::All);
    let needle = "needle".to_string();
    let result = eval_text(&params(&needle), None, &ctx, None);
    assert!(result.matched);
    let evidence = &result.evidence[0];
    assert_eq!(evidence.value, "needle");
    assert_eq!(evidence.location.as_deref(), Some("0x100c"));
    assert_eq!(evidence.byte_offset(), Some(0x100c));
}

#[test]
fn case_insensitive_text_substr_evidence_keeps_the_source_casing() {
    let report = report_with(vec![string("Call NEEDLE now", Some(0x40))]);
    let ctx = EvaluationContext::test_only_new(&report, &[], FileType::All);
    let needle = "needle".to_string();
    let mut params = params(&needle);
    params.case_insensitive = true;
    let result = eval_text(&params, None, &ctx, None);
    assert_eq!(result.evidence[0].value, "NEEDLE");
    assert_eq!(result.evidence[0].byte_offset(), Some(0x45));
}

/// The regression: two traits matching far apart inside one long string at
/// offset 0 used to share the `[0, 128]` span of the string's head.
#[test]
fn matches_in_one_long_string_keep_their_own_locations() {
    let line = format!(
        "function a0_0x4b44(){{const _0x1fc5fa=['BlockDevice',{}'vant.tar.gz',{}'pool.supportxmr.com:443']}}",
        "'x',".repeat(100),
        "'y',".repeat(100),
    );
    let report = report_with(vec![string(&line, Some(0))]);
    let ctx = EvaluationContext::test_only_new(&report, &[], FileType::All);
    let mut seen = Vec::new();
    for needle in ["vant.tar.gz", "pool.supportxmr.com:443"] {
        let needle = needle.to_string();
        let result = eval_text(&params(&needle), None, &ctx, None);
        let evidence = &result.evidence[0];
        assert_eq!(evidence.value, needle);
        assert_eq!(evidence.byte_offset(), line.find(&needle).map(|o| o as u64));
        seen.push(evidence.byte_offset());
    }
    assert_ne!(seen[0], seen[1]);
    assert_ne!(seen[0], Some(0));
}

#[test]
fn text_not_judges_only_the_matched_substr() {
    let sentence = "RTLD_NEXT used in code not dynamically loaded";
    let report = report_with(vec![string(sentence, Some(0x200))]);
    let ctx = EvaluationContext::test_only_new(&report, &[], FileType::All);
    let needle = "RTLD_NEXT".to_string();
    let matched = |exceptions: Vec<NotException>| {
        eval_text(&params(&needle), Some(&exceptions), &ctx, None).matched
    };
    // Exceptions naming the text around the needle never apply.
    assert!(matched(not(serde_json::json!("RTLD_NEXT used in code"))));
    assert!(matched(not(
        serde_json::json!({"substr": "dynamically loaded"})
    )));
    assert!(matched(not(serde_json::json!({"exact": sentence}))));
    assert!(matched(not(
        serde_json::json!({"regex": "RTLD_NEXT\\s+used"})
    )));
    // Exceptions that hold for the needle itself exclude it.
    assert!(!matched(not(serde_json::json!("rtld_next"))));
    assert!(!matched(not(serde_json::json!({"substr": "NEXT"}))));
    assert!(!matched(not(serde_json::json!({"exact": "RTLD_NEXT"}))));
    assert!(!matched(not(serde_json::json!({"regex": "^RTLD_NEXT$"}))));
}

#[test]
fn text_substr_validator_still_judges_the_whole_string() {
    let report = report_with(vec![
        string("connect to 192.168.1.1:8080", Some(0x1000)),
        string("connect to 45.33.32.156:53", Some(0x2000)),
    ]);
    let ctx = EvaluationContext::test_only_new(&report, &[], FileType::All);
    let needle = "connect to".to_string();
    let mut params = params(&needle);
    params.is_check = Some(StringValidator::ExternalIp);
    let result = eval_text(&params, None, &ctx, None);
    assert_eq!(result.match_count, 1);
    assert_eq!(result.evidence[0].value, "connect to");
    assert_eq!(result.evidence[0].byte_offset(), Some(0x2000));
}

#[test]
fn text_substr_length_bounds_still_judge_the_whole_string() {
    let report = report_with(vec![
        string("short abc", Some(0x10)),
        string("a much longer string with abc in it", Some(0x20)),
    ]);
    let ctx = EvaluationContext::test_only_new(&report, &[], FileType::All);
    let needle = "abc".to_string();
    let mut params = params(&needle);
    params.length_min = Some(20);
    let result = eval_text(&params, None, &ctx, None);
    assert_eq!(result.match_count, 1);
    assert_eq!(result.evidence[0].value, "abc");
    assert_eq!(
        result.evidence[0].byte_offset(),
        Some(0x20 + "a much longer string with ".len() as u64)
    );
}

#[test]
fn decoded_base64_substr_spans_its_own_quads() {
    // 12 decoded bytes before the needle = 4 base64 quads = 16 encoded chars.
    let value = "0123456789abvant.tar.gz and the rest of the decoded layer";
    let report = report_with(vec![decoded(value, 0x1000, "base64")]);
    let ctx = EvaluationContext::test_only_new(&report, &[], FileType::All);
    let needle = "vant.tar.gz".to_string();
    let result = eval_text(&params(&needle), None, &ctx, None);
    let evidence = &result.evidence[0];
    assert_eq!(evidence.value, "vant.tar.gz");
    assert_eq!(evidence.byte_offset(), Some(0x1000 + 16));
    // Decoded bytes 12..23 sit in quads 4..8: 16 encoded chars, not the layer.
    assert_eq!(evidence.match_len, Some(16));
}

#[test]
fn decoded_layers_without_a_fixed_expansion_keep_the_decoded_length() {
    let value = "head vant.tar.gz tail";
    let report = report_with(vec![decoded(value, 0x400, "xor")]);
    let ctx = EvaluationContext::test_only_new(&report, &[], FileType::All);
    let needle = "vant.tar.gz".to_string();
    let result = eval_text(&params(&needle), None, &ctx, None);
    assert_eq!(result.evidence[0].byte_offset(), Some(0x405));
    assert_eq!(result.evidence[0].match_len, None);
}

#[test]
fn encoded_match_span_is_exact_to_the_quad() {
    let base64 = ["base64".to_string()];
    // Whole string: the old `encoded_source_len` result.
    assert_eq!(encoded_match_span(0, 34, &base64), (0, Some(48)));
    // Aligned and unaligned sub-spans cover only the quads they touch.
    assert_eq!(encoded_match_span(3, 3, &base64), (4, Some(4)));
    assert_eq!(encoded_match_span(2, 2, &base64), (0, Some(8)));
    assert_eq!(encoded_match_span(12, 11, &base64), (16, Some(16)));
    // An empty match covers the quad it falls in, or nothing on a boundary.
    assert_eq!(encoded_match_span(7, 0, &base64), (8, Some(4)));
    assert_eq!(encoded_match_span(6, 0, &base64), (8, Some(0)));
    // Anything else keeps decoded coordinates.
    assert_eq!(encoded_match_span(5, 3, &["xor".to_string()]), (5, None));
    assert_eq!(
        encoded_match_span(5, 3, &["base64".to_string(), "gzip".to_string()]),
        (5, None)
    );
    assert_eq!(encoded_match_span(5, 3, &[]), (5, None));
}

// ---------------------------------------------------------------------------
// `type: text` on source files: the decoded-layer pass beside raw search
// ---------------------------------------------------------------------------

#[test]
fn source_file_decoded_layer_substr_points_at_the_match() {
    // An escaped-string layer spanning a minified file, as obfuscator.io emits.
    let source = format!("var a='{}vant.tar.gz';", "\\x41".repeat(64));
    let layer = format!("var a='{}vant.tar.gz';", "A".repeat(64));
    let report = report_with(vec![decoded(&layer, 0, "unicode-escape")]);
    let ctx = EvaluationContext::test_only_new(&report, source.as_bytes(), FileType::JavaScript);
    let needle = "vant.tar.gz".to_string();
    let result = eval_text(&params(&needle), None, &ctx, None);
    assert!(result.matched);
    let decoded_hit = result
        .evidence
        .iter()
        .find(|e| e.method == "text")
        .expect("the decoded-layer pass reports its own hit");
    assert_eq!(decoded_hit.value, "vant.tar.gz");
    assert_eq!(
        decoded_hit.byte_offset(),
        layer.find("vant").map(|o| o as u64)
    );
    assert_ne!(decoded_hit.byte_offset(), Some(0));
}

#[test]
fn source_file_decoded_layer_not_judges_only_the_matched_substr() {
    let layer = "safe-context needle more";
    let report = report_with(vec![decoded(layer, 0x10, "base64")]);
    let ctx = EvaluationContext::test_only_new(&report, b"// nothing here", FileType::JavaScript);
    let needle = "needle".to_string();
    let matched = |exceptions: Vec<NotException>| {
        eval_text(&params(&needle), Some(&exceptions), &ctx, None).matched
    };
    assert!(matched(not(serde_json::json!("safe-context"))));
    assert!(!matched(not(serde_json::json!("needle"))));
}

// ---------------------------------------------------------------------------
// `type: literal`
// ---------------------------------------------------------------------------

fn literal(value: &str, offset: u64, section: &str) -> StringInfo {
    StringInfo {
        section: Some(section.to_string()),
        ..string(value, Some(offset))
    }
}

#[test]
fn literal_substr_evidence_is_the_match_at_its_offset() {
    let report = report_with(vec![literal("https://host/vant.tar.gz", 0x80, "ast")]);
    let ctx = EvaluationContext::test_only_new(&report, &[], FileType::Python);
    let needle = "vant.tar.gz".to_string();
    let result = eval_string_literal(&params(&needle), None, &ctx);
    assert_eq!(result.evidence[0].value, "vant.tar.gz");
    assert_eq!(result.evidence[0].byte_offset(), Some(0x80 + 13));
}

#[test]
fn compiled_literal_substr_keeps_the_parser_anchor() {
    // A compiled literal's decoded index is not a file displacement.
    let report = report_with(vec![literal("https://host/vant.tar.gz", 0x80, "literal")]);
    let ctx = EvaluationContext::test_only_new(&report, &[], FileType::Python);
    let needle = "vant.tar.gz".to_string();
    let result = eval_string_literal(&params(&needle), None, &ctx);
    assert_eq!(result.evidence[0].value, "vant.tar.gz");
    assert_eq!(result.evidence[0].byte_offset(), Some(0x80));
}

#[test]
fn literal_not_judges_only_the_matched_substr() {
    let report = report_with(vec![literal(
        "AppData/Local/Google/Chrome/Application",
        0x10,
        "ast",
    )]);
    let ctx = EvaluationContext::test_only_new(&report, &[], FileType::Python);
    let needle = "AppData/Local/Google/Chrome".to_string();
    let matched = |exceptions: Vec<NotException>| {
        eval_string_literal(&params(&needle), Some(&exceptions), &ctx).matched
    };
    assert!(matched(not(
        serde_json::json!({"substr": "Chrome/Application"})
    )));
    assert!(!matched(not(serde_json::json!({"substr": "Google"}))));
}

#[test]
fn distinct_literal_hits_at_one_anchor_are_still_deduplicated() {
    // Two compiled literals anchored at one parser offset count once.
    let report = report_with(vec![
        literal("a vant.tar.gz", 0x80, "literal"),
        literal("b vant.tar.gz", 0x80, "literal"),
    ]);
    let ctx = EvaluationContext::test_only_new(&report, &[], FileType::Python);
    let needle = "vant.tar.gz".to_string();
    let result = eval_string_literal(&params(&needle), None, &ctx);
    assert_eq!(result.match_count, 1);
}

// ---------------------------------------------------------------------------
// `type: raw`
// ---------------------------------------------------------------------------

fn raw(
    content: &[u8],
    needle: &str,
    case_insensitive: bool,
    external_ip: bool,
    exceptions: Option<&Vec<NotException>>,
) -> crate::composite_rules::context::ConditionResult {
    let report = report_with(Vec::new());
    let ctx = EvaluationContext::test_only_new(&report, content, FileType::All);
    let needle = needle.to_string();
    eval_raw(
        TextPattern {
            substr: Some(&needle),
            case_insensitive,
            ..TextPattern::default()
        },
        (None, None),
        external_ip.then_some(StringValidator::ExternalIp),
        exceptions,
        &ContentLocationParams::default(),
        &ctx,
        None,
    )
}

#[test]
fn raw_not_judges_only_the_matched_substr_on_every_scan() {
    // ASCII and Unicode needles take different scans; case folding a third.
    for (needle, content) in [
        ("token", "safe-context token tail"),
        ("déjà", "safe-context déjà tail"),
    ] {
        for case_insensitive in [false, true] {
            let content = if case_insensitive {
                content.to_uppercase()
            } else {
                content.to_string()
            };
            let context = not(serde_json::json!("safe-context"));
            let result = raw(
                content.as_bytes(),
                needle,
                case_insensitive,
                false,
                Some(&context),
            );
            assert!(
                result.matched,
                "{needle}/{case_insensitive}: context is not judged"
            );
            let own = not(serde_json::json!(needle));
            let result = raw(
                content.as_bytes(),
                needle,
                case_insensitive,
                false,
                Some(&own),
            );
            assert!(
                !result.matched,
                "{needle}/{case_insensitive}: the needle is judged"
            );
        }
    }
}

#[test]
fn raw_substr_validator_still_judges_the_surrounding_window() {
    for needle in ["connect", "déjà"] {
        let near = format!("{needle} 45.33.32.156 done");
        assert!(
            raw(near.as_bytes(), needle, false, true, None).matched,
            "{needle}"
        );
        let far = format!("{needle} {} 45.33.32.156", "x".repeat(80));
        assert!(
            !raw(far.as_bytes(), needle, false, true, None).matched,
            "{needle}"
        );
    }
}

#[test]
fn raw_not_and_validator_combine_per_hit() {
    // First hit: no IP nearby (rejected by `is:`); second: IP nearby. The
    // `not:` names the first hit's neighborhood, which is never judged.
    let content = format!("blocked token {} token 45.33.32.156", "x".repeat(120));
    let exceptions = not(serde_json::json!("blocked"));
    let result = raw(content.as_bytes(), "token", false, true, Some(&exceptions));
    assert_eq!(result.match_count, 1);
    assert_eq!(
        result.evidence[0].offsets[0],
        content.rfind("token").unwrap() as u64
    );
}

// ---------------------------------------------------------------------------
// `type: encoded`
// ---------------------------------------------------------------------------

fn encoded(
    strings: Vec<StringInfo>,
    needle: &str,
    case_insensitive: bool,
    external_ip: bool,
    exceptions: Option<&Vec<NotException>>,
) -> crate::composite_rules::context::ConditionResult {
    let report = report_with(strings);
    let ctx = EvaluationContext::test_only_new(&report, &[], FileType::All);
    let needle = needle.to_string();
    eval_encoded(
        None,
        TextPattern {
            substr: Some(&needle),
            case_insensitive,
            ..TextPattern::default()
        },
        &ContentLocationParams::default(),
        external_ip.then_some(StringValidator::ExternalIp),
        exceptions,
        &ctx,
    )
}

#[test]
fn encoded_not_judges_only_the_matched_substr() {
    for case_insensitive in [false, true] {
        let layer = if case_insensitive {
            "İİ SAFE-CONTEXT DÉJÀ TAIL"
        } else {
            "İİ safe-context déjà tail"
        };
        let strings = || vec![decoded(layer, 0x100, "base64")];
        let context = not(serde_json::json!("safe-context"));
        assert!(
            encoded(strings(), "déjà", case_insensitive, false, Some(&context)).matched,
            "{case_insensitive}: context is not judged"
        );
        let own = not(serde_json::json!({"exact": if case_insensitive { "DÉJÀ" } else { "déjà" }}));
        assert!(
            !encoded(strings(), "déjà", case_insensitive, false, Some(&own)).matched,
            "{case_insensitive}: exactly the matched text (in its source casing) is judged"
        );
    }
}

#[test]
fn encoded_regex_not_judges_only_the_match() {
    let report = report_with(vec![decoded("safe-context token", 0x100, "base64")]);
    let ctx = EvaluationContext::test_only_new(&report, &[], FileType::All);
    let run = |pattern: &str, exception: &str| {
        let pattern = pattern.to_string();
        let exceptions = not(serde_json::json!(exception));
        eval_encoded(
            None,
            TextPattern {
                regex: Some(&pattern),
                ..TextPattern::default()
            },
            &ContentLocationParams::default(),
            None,
            Some(&exceptions),
            &ctx,
        )
        .matched
    };
    // Text beside the match no longer excuses it, as in every evaluator.
    assert!(run("tok[e]n", "safe-context"));
    assert!(!run("(safe-context )?tok[e]n", "safe-context"));
}

#[test]
fn encoded_substr_validator_still_judges_the_whole_string() {
    let strings = vec![
        decoded("connect to 192.168.1.1", 0x100, "base64"),
        decoded("connect to 45.33.32.156", 0x200, "base64"),
    ];
    let result = encoded(strings, "connect to", false, true, None);
    assert_eq!(result.match_count, 1);
}

#[test]
fn encoded_scope_filters_still_apply() {
    let strings = vec![decoded("needle", 0x100, "xor")];
    let report = report_with(strings);
    let ctx = EvaluationContext::test_only_new(&report, &[], FileType::All);
    let needle = "needle".to_string();
    let only_base64 = EncodingSpec::Single("base64".to_string());
    let result = eval_encoded(
        Some(&only_base64),
        TextPattern {
            substr: Some(&needle),
            ..TextPattern::default()
        },
        &ContentLocationParams::default(),
        None,
        None,
        &ctx,
    );
    assert!(!result.matched);
}

#[test]
fn comment_not_judges_only_the_match() {
    let mut report = report_with(Vec::new());
    report.comments = vec![string("TODO: remove the backdoor before release", Some(0))];
    let ctx = EvaluationContext::test_only_new(&report, &[], FileType::All);
    let substr = "backdoor".to_string();
    let regex = r"remove the \w+".to_string();
    let run = |params: StringParams<'_>, exception: &str| {
        eval_comment(&params, Some(&not(serde_json::json!(exception))), &ctx).matched
    };
    // `TODO` sits beside either match, so it cannot excuse it.
    assert!(run(params(&substr), "TODO"));
    assert!(run(
        StringParams {
            substr: None,
            regex: Some(&regex),
            ..params(&substr)
        },
        "TODO"
    ));
    // What the regex matched does.
    assert!(!run(
        StringParams {
            substr: None,
            regex: Some(&regex),
            ..params(&substr)
        },
        "remove"
    ));
    // Case-insensitive substr: the match is judged in its source casing.
    let upper = "BACKDOOR".to_string();
    assert!(!run(
        StringParams {
            case_insensitive: true,
            ..params(&upper)
        },
        "backdoor"
    ));
}
