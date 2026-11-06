use super::*;
use crate::composite_rules::{Arch, Platform};

// ==================== TraitIndex Tests ====================

#[test]
fn trait_index_matches_direct_gate_for_every_file_type_and_platform() {
    let types: Vec<_> = std::iter::once(RuleFileType::All)
        .chain(RuleFileType::all_concrete_variants())
        .collect();
    let traits: Vec<_> = types
        .iter()
        .flat_map(|ft| {
            [Platform::All, Platform::Linux, Platform::Windows]
                .into_iter()
                .map(move |platform| TraitDefinition {
                    platforms: vec![platform],
                    r#for: vec![*ft],
                    ..Default::default()
                })
        })
        .chain(std::iter::once(TraitDefinition {
            r#for: Vec::new(),
            ..Default::default()
        }))
        .collect();
    for platforms in [
        vec![Platform::All],
        vec![Platform::Linux],
        vec![Platform::Windows],
    ] {
        let index = TraitIndex::build_filtered(&traits, &platforms);
        for ft in &types {
            let actual: Vec<_> = index.applicable(ft).into_indices_static().collect();
            let expected: Vec<_> = traits
                .iter()
                .enumerate()
                .filter(|(_, t)| {
                    platforms_intersect(&t.platforms, &platforms)
                        && RuleFileType::rule_applies_to(&t.r#for, *ft)
                })
                .map(|(i, _)| i)
                .collect();
            assert_eq!(actual, expected, "{ft:?}, {platforms:?}");
        }
    }
}

#[test]
fn test_trait_index_new() {
    let index = TraitIndex::new();
    assert!(index.universal.bits.is_empty());
    assert!(index.by_file_type.is_empty());
}

#[test]
fn trait_index_archive_buckets_follow_the_container_base() {
    // A JAR draws the `zip` bucket (it is a zip) but not `android_apk`
    // or `deb`: the index must agree with the evaluate-time gate, which
    // used to be an any-archive-for-any-archive "family" union.
    let def = |ft: RuleFileType| TraitDefinition {
        platforms: vec![Platform::All],
        r#for: vec![ft],
        ..Default::default()
    };
    let traits = [
        def(RuleFileType::Zip),
        def(RuleFileType::AndroidApk),
        def(RuleFileType::Deb),
    ];
    let index = TraitIndex::build_filtered(&traits, &[Platform::All]);
    let applicable =
        |ft: RuleFileType| -> Vec<usize> { index.applicable(&ft).into_indices_static().collect() };
    assert_eq!(applicable(RuleFileType::Jar), vec![0]);
    assert_eq!(applicable(RuleFileType::AndroidApk), vec![0, 1]);
    assert_eq!(applicable(RuleFileType::Zip), vec![0]);
    assert_eq!(applicable(RuleFileType::Deb), vec![2]);
    assert!(applicable(RuleFileType::Npm).is_empty());
    // A container with no type of its own still sees every archive rule.
    assert_eq!(applicable(RuleFileType::All), vec![0, 1, 2]);
}

#[test]
fn test_trait_index_get_applicable_empty() {
    let index = TraitIndex::new();
    let applicable: Vec<usize> = index
        .applicable(&RuleFileType::All)
        .into_indices_static()
        .collect();
    assert!(applicable.is_empty());
}

#[test]
fn test_trait_bitset_into_indices_static_advances_words() {
    let mut bitset = TraitBitSet::with_capacity(130);
    bitset.insert(1);
    bitset.insert(65);
    bitset.insert(129);

    let indices: Vec<usize> = bitset.into_indices_static().collect();
    assert_eq!(indices, vec![1, 65, 129]);
}

// ==================== StringMatchIndex Tests ====================

#[test]
fn test_extract_regex_literal_simple() {
    // Simple alphanumeric prefix
    // .* is a wildcard (matches any chars), so we stop before the .
    assert_eq!(
        StringMatchIndex::extract_regex_literal("hello.*world"),
        Some("hello".to_string())
    );
}

#[test]
fn test_extract_regex_literal_with_special_chars() {
    // regex_syntax correctly handles escaped \. as literal dot
    assert_eq!(
        StringMatchIndex::extract_regex_literal("http://example\\.com/.*"),
        Some("http://example.com/".to_string())
    );
    // Unescaped . is a metachar (matches any char), so stops before it
    assert_eq!(
        StringMatchIndex::extract_regex_literal("example/path/file.txt"),
        Some("example/path/file".to_string())
    );
    // With escaped dot, full literal is extracted
    assert_eq!(
        StringMatchIndex::extract_regex_literal(r"example/path/file\.txt"),
        Some("example/path/file.txt".to_string())
    );
}

#[test]
fn test_extract_regex_literal_too_short() {
    // "ab" is only 2 chars, too short for useful prefiltering
    assert_eq!(StringMatchIndex::extract_regex_literal("ab.*"), None);
    // Prefix extraction only - .* at start means no guaranteed prefix
    assert_eq!(StringMatchIndex::extract_regex_literal(".*test"), None);
    // Truly no literal
    assert_eq!(StringMatchIndex::extract_regex_literal(".*"), None);
    assert_eq!(StringMatchIndex::extract_regex_literal(".*.*"), None);
}

#[test]
fn test_extract_regex_literal_escaped() {
    // Escaped metacharacters
    assert_eq!(
        StringMatchIndex::extract_regex_literal(r"test\.\*\+"),
        Some("test.*+".to_string())
    );
}

#[test]
fn test_extract_regex_literal_meta_escape() {
    // \d, \w, etc. should stop extraction
    assert_eq!(
        StringMatchIndex::extract_regex_literal(r"test\d+"),
        Some("test".to_string())
    );
}

#[test]
fn test_extract_regex_literal_with_path_chars() {
    // Unix path-like patterns - .* is a wildcard, so stop before the .
    assert_eq!(
        StringMatchIndex::extract_regex_literal("/usr/bin/.*"),
        Some("/usr/bin/".to_string())
    );
    // regex_syntax correctly handles \\ as escaped backslash, : as literal
    assert_eq!(
        StringMatchIndex::extract_regex_literal(r"C:\\Windows\\.*"),
        Some("C:\\Windows\\".to_string())
    );
    // Windows paths without drive letter
    assert_eq!(
        StringMatchIndex::extract_regex_literal(r"\\Windows\\System32\\.*"),
        Some("\\Windows\\System32\\".to_string())
    );
}

#[test]
fn test_extract_regex_literal_with_underscore() {
    // Underscores are allowed - .* is a wildcard, so stop before the .
    assert_eq!(
        StringMatchIndex::extract_regex_literal("some_function_name.*"),
        Some("some_function_name".to_string())
    );
}

#[test]
fn test_extract_regex_literal_with_hyphen() {
    // Hyphens are allowed - .* is a wildcard, so stop before the .
    assert_eq!(
        StringMatchIndex::extract_regex_literal("my-app-name-.*"),
        Some("my-app-name-".to_string())
    );
}

#[test]
fn test_extract_regex_literal_starts_with_metachar() {
    // Prefix extraction - .* at start means no guaranteed prefix
    assert_eq!(StringMatchIndex::extract_regex_literal(".*hello"), None);
    // Pattern starting with other metachars returns None
    assert_eq!(StringMatchIndex::extract_regex_literal("[a-z]+"), None);
    assert_eq!(StringMatchIndex::extract_regex_literal("(foo|bar)"), None);
}

#[test]
fn test_extract_regex_literal_empty() {
    assert_eq!(StringMatchIndex::extract_regex_literal(""), None);
}

#[test]
fn test_extract_regex_literal_only_metachar() {
    assert_eq!(StringMatchIndex::extract_regex_literal(".*"), None);
    assert_eq!(StringMatchIndex::extract_regex_literal(".+"), None);
    assert_eq!(StringMatchIndex::extract_regex_literal("\\d+"), None);
}

#[test]
fn test_extract_regex_literal_alternation() {
    // Alternation with no common prefix returns None
    assert_eq!(StringMatchIndex::extract_regex_literal("foo|bar"), None);
    // Alternation with common prefix extracts it
    assert_eq!(
        StringMatchIndex::extract_regex_literal("hello_foo|hello_bar"),
        Some("hello_".to_string())
    );
}

#[test]
fn test_extract_regex_literal_question_mark() {
    // ? makes preceding char optional - common prefix is "hell" (without optional 'o')
    assert_eq!(
        StringMatchIndex::extract_regex_literal("hello?world"),
        Some("hell".to_string())
    );
    // https? matches http:// or https:// - common prefix is "http" (this is the bug we fixed!)
    assert_eq!(
        StringMatchIndex::extract_regex_literal("https?://"),
        Some("http".to_string())
    );
}

#[test]
fn test_extract_regex_literal_plus() {
    // + means one or more - at least one 'o' is guaranteed
    assert_eq!(
        StringMatchIndex::extract_regex_literal("hello+world"),
        Some("hello".to_string())
    );
}

#[test]
fn test_extract_regex_literal_bracket() {
    // Bracket should stop extraction
    assert_eq!(
        StringMatchIndex::extract_regex_literal("hello[0-9]"),
        Some("hello".to_string())
    );
}

/// The common prefix of a class's literals can end inside a multi-byte
/// character (`é` = C3 A9, `ê` = C3 AA). The prefix must stop at the last
/// whole character: a U+FFFD stand-in names bytes no matching input holds,
/// and every prefilter built on it would reject the trait's real matches.
#[test]
fn test_extract_regex_literal_splits_no_utf8_char() {
    assert_eq!(
        StringMatchIndex::extract_regex_literal("abc[éê]"),
        Some("abc".to_string())
    );
    assert_eq!(
        StringMatchIndex::extract_regex_literal("(?i)123é"),
        Some("123".to_string())
    );
    assert_eq!(StringMatchIndex::extract_regex_literal("ab[éê]"), None);
}

#[test]
fn test_string_match_index_build_empty() {
    let index = StringMatchIndex::build(&[]);

    assert!(!index.has_patterns());
    assert_eq!(index.total_patterns, 0);
    assert!(index.exact_patterns.is_empty());
    assert!(index.ci_exact_patterns.is_empty());
}

#[test]
fn test_string_match_index_is_regex_trait_empty() {
    let index = StringMatchIndex::build(&[]);
    assert!(!index.is_regex_trait(0));
    assert!(!index.is_regex_trait(100));
}

// ==================== RawContentRegexIndex Tests ====================

#[test]
fn test_raw_content_regex_index_build_empty() {
    let index = RawContentRegexIndex::build(&[]);

    assert!(!index.has_patterns());
}

#[test]
fn test_raw_content_regex_index_is_indexed_trait_empty() {
    let index = RawContentRegexIndex::build(&[]);

    assert!(!index.is_indexed_trait(0));
    assert!(!index.is_indexed_trait(100));
}

#[test]
fn test_raw_content_regex_index_find_matches_empty() {
    let index = RawContentRegexIndex::build(&[]);
    let content = b"some content";

    let matches = index.find_matches(content, &RuleFileType::All);
    assert!(matches.is_empty());
}

#[test]
fn test_raw_content_regex_index_find_matches_invalid_utf8() {
    let trait_def = TraitDefinition {
        id: "test".to_string(),
        desc: "test".to_string(),
        conf: 1.0,
        crit: crate::types::Criticality::Baseline,
        mbc: None,
        attack: None,
        platforms: vec![Platform::All],
        arch: vec![Arch::All],
        r#for: vec![RuleFileType::All],
        for_from_groups: false,
        r#if: Condition::Raw(RawQuery {
            length_min: None,
            length_max: None,
            exact: None,
            substr: None,
            regex: Some("test".to_string()),
            word: None,
            case_insensitive: false,
            is_check: None,
            section: None,
            offset: None,
            offset_range: None,
            section_offset: None,
            section_offset_range: None,
            not: None,
        }),
        size_max: None,
        count_min: None,
        count_max: None,
        per_kb_min: None,
        per_kb_max: None,
        entropy_min: None,
        entropy_max: None,
        size_min: None,
        not: None,
        unless: None,
        downgrade: None,
        defined_in: std::path::PathBuf::from("test.yaml"),
        precision: None,
        ..Default::default()
    };

    let index = RawContentRegexIndex::build(&[trait_def]);
    // Content with invalid UTF-8 and the target string
    let content = &[0xFF, b't', b'e', b's', b't', 0xFE];

    let matches = index.find_matches(content, &RuleFileType::All);
    // Direct binary matching handles invalid UTF-8 naturally
    assert!(!matches.is_empty());
}

#[test]
fn test_raw_content_regex_index_lazy_verifiers_match_per_bucket() {
    let make_raw_regex_trait = |id: &str, file_type: RuleFileType| TraitDefinition {
        id: id.to_string(),
        desc: id.to_string(),
        conf: 1.0,
        crit: crate::types::Criticality::Baseline,
        mbc: None,
        attack: None,
        platforms: vec![Platform::All],
        arch: vec![Arch::All],
        r#for: vec![file_type],
        for_from_groups: false,
        r#if: Condition::Raw(RawQuery {
            length_min: None,
            length_max: None,
            exact: None,
            substr: None,
            regex: Some("test".to_string()),
            word: None,
            case_insensitive: false,
            is_check: None,
            section: None,
            offset: None,
            offset_range: None,
            section_offset: None,
            section_offset_range: None,
            not: None,
        }),
        size_max: None,
        count_min: None,
        count_max: None,
        per_kb_min: None,
        per_kb_max: None,
        entropy_min: None,
        entropy_max: None,
        size_min: None,
        not: None,
        unless: None,
        downgrade: None,
        defined_in: std::path::PathBuf::from("test.yaml"),
        precision: None,
        ..Default::default()
    };

    let index = RawContentRegexIndex::build(&[
        make_raw_regex_trait("js", RuleFileType::JavaScript),
        make_raw_regex_trait("py", RuleFileType::Python),
    ]);

    // Verifier regexes are lazy: slots start empty and compile on first
    // atom hit (formerly they were eagerly compiled and Arc-shared across
    // buckets — the eager pass cost ~300 ms of every process start).
    let js_set = index.set(&RuleFileType::JavaScript).unwrap();
    let py_set = index.set(&RuleFileType::Python).unwrap();
    assert!(js_set.individual_regexes[0].get().is_none());
    assert!(py_set.individual_regexes[0].get().is_none());

    // A find_matches pass over content containing the literal atom must
    // trigger compilation and match in each bucket independently.
    let js_matches = index.find_matches(b"some test content", &RuleFileType::JavaScript);
    let py_matches = index.find_matches(b"some test content", &RuleFileType::Python);
    assert!(!js_matches.is_empty());
    assert!(!py_matches.is_empty());
    assert!(js_set.individual_regexes[0].get().is_some());
    assert!(py_set.individual_regexes[0].get().is_some());
}

// ==================== Overlapping Substr Match Tests ====================

/// Helper: build a TraitDefinition with a substr Text condition
fn make_substr_trait(id: &str, substr: &str) -> TraitDefinition {
    TraitDefinition {
        id: id.to_string(),
        desc: id.to_string(),
        conf: 1.0,
        crit: crate::types::Criticality::Notable,
        mbc: None,
        attack: None,
        platforms: vec![Platform::All],
        arch: vec![Arch::All],
        r#for: vec![RuleFileType::All],
        for_from_groups: false,
        r#if: Condition::Text(TextQuery {
            encoding: None,
            length_min: None,
            length_max: None,
            exclude_html_comments: false,
            exact: None,
            substr: Some(substr.to_string()),
            regex: None,
            word: None,
            case_insensitive: false,
            is_check: None,
            not: None,
            platforms: None,
            section: None,
            offset: None,
            offset_range: None,
            section_offset: None,
            section_offset_range: None,
        }),
        size_max: None,
        count_min: None,
        count_max: None,
        per_kb_min: None,
        per_kb_max: None,
        entropy_min: None,
        entropy_max: None,
        size_min: None,
        not: None,
        unless: None,
        downgrade: None,
        defined_in: std::path::PathBuf::from("test.yaml"),
        precision: None,
        ..Default::default()
    }
}

/// Helper: build a StringInfo with a value
fn make_string(value: &str) -> StringInfo {
    StringInfo {
        value: (value.to_string()).into(),
        offset: None,
        encoding: "utf-8".to_string(),
        string_type: None,
        section: None,
        encoding_chain: Vec::new(),
        fragments: None,
    }
}

fn make_text_regex_trait(id: &str, regex: &str) -> TraitDefinition {
    TraitDefinition {
        id: id.to_string(),
        desc: id.to_string(),
        conf: 1.0,
        crit: crate::types::Criticality::Notable,
        mbc: None,
        attack: None,
        platforms: vec![Platform::All],
        arch: vec![Arch::All],
        r#for: vec![RuleFileType::All],
        for_from_groups: false,
        r#if: Condition::Text(TextQuery {
            encoding: None,
            length_min: None,
            length_max: None,
            exclude_html_comments: false,
            exact: None,
            substr: None,
            regex: Some(regex.to_string()),
            word: None,
            case_insensitive: false,
            is_check: None,
            not: None,
            platforms: None,
            section: None,
            offset: None,
            offset_range: None,
            section_offset: None,
            section_offset_range: None,
        }),
        size_max: None,
        count_min: None,
        count_max: None,
        per_kb_min: None,
        per_kb_max: None,
        entropy_min: None,
        entropy_max: None,
        size_min: None,
        not: None,
        unless: None,
        downgrade: None,
        defined_in: std::path::PathBuf::from("test.yaml"),
        precision: None,
        ..Default::default()
    }
}

fn make_symbol_regex_trait(id: &str, regex: &str) -> TraitDefinition {
    let mut t = make_text_regex_trait(id, regex);
    t.r#if = Condition::Symbol(crate::composite_rules::condition::SymbolQuery {
        regex: Some(regex.to_string()),
        ..Default::default()
    });
    t
}

/// No-literal symbol regexes gated by their any-of atom set match exactly
/// the symbols a full regex sweep matches, with the same evidence;
/// an atom-less fallback (`^[a-z]\d+$`) still sweeps every symbol.
#[test]
fn symbol_fallback_atom_gate_matches_full_sweep() {
    let patterns = [
        r"^(exec|execSync)$",
        r"(?i)(^|\.)(post|postasync)$",
        r"^_?(stat|lstat)$",
        r"^[a-z]\d+$",
    ];
    let traits: Vec<TraitDefinition> = patterns
        .iter()
        .enumerate()
        .map(|(i, p)| make_symbol_regex_trait(&format!("t{i}"), p))
        .collect();
    let index = SymbolMatchIndex::build_filtered(&traits, &[Platform::All]);
    assert_eq!(index.regex_fallback_patterns.len(), patterns.len());
    assert_eq!(
        index.regex_fallback_gated,
        vec![true, true, true, false],
        "alternations gate, the class-only pattern does not"
    );
    let symbols = [
        "execSync",
        "exec",
        "__exec",
        "execx",
        "req.POST",
        "client.postAsync",
        "post",
        "_stat",
        "lstat",
        "fstat",
        "a12",
        "B12",
        "x9",
    ];
    let (matched, evidence) = index.find_matches_with_evidence(&symbols);
    for (i, p) in patterns.iter().enumerate() {
        let re = regex::Regex::new(p).unwrap();
        let mut want: Vec<&str> = symbols
            .iter()
            .copied()
            .filter(|s| {
                let n = s.strip_prefix('_').unwrap_or(s);
                let n = n.strip_prefix('_').unwrap_or(n);
                !n.is_empty() && re.is_match(n)
            })
            .collect();
        let mut got: Vec<&str> = evidence
            .get(&i)
            .map(|v| v.iter().map(|e| e.value.as_str()).collect())
            .unwrap_or_default();
        // `deduplicate_evidence` returns hash order on both paths.
        got.sort_unstable();
        want.sort_unstable();
        assert_eq!(got, want, "pattern {p}");
        assert_eq!(matched.contains(&i), !want.is_empty(), "pattern {p}");
    }
}

/// A regex trait with a mandatory atom (`\bfetch\s+...` → "fetch") is
/// a candidate exactly when some string holds the atom. Guards the
/// precomputed `regex_traits_without_atoms` hoist.
#[test]
fn test_regex_candidate_with_extractable_atom() {
    let pat = r"\bfetch\s+(-|https?://|ftp://)";
    let traits = vec![make_text_regex_trait("fetch-cmd", pat)];
    let index = StringMatchIndex::build(&traits);
    assert!(index.regex_traits_without_atoms.is_empty());
    let (hit, _) =
        index.find_regex_candidate_strings(&[&make_string("fetch http://evil.example/x")], 1);
    assert!(
        hit.contains(&0),
        "fetch-cmd must be a candidate when 'fetch' is present"
    );
    let (miss, _) = index.find_regex_candidate_strings(&[&make_string("nothing relevant here")], 1);
    assert!(
        !miss.contains(&0),
        "fetch-cmd must NOT be a candidate without its atom"
    );
}

fn make_text_word_trait(id: &str, word: &str, ci: bool) -> TraitDefinition {
    let mut t = make_text_regex_trait(id, "unused");
    if let Condition::Text(ref mut q) = t.r#if {
        q.regex = None;
        q.word = Some(word.to_string());
        q.case_insensitive = ci;
    }
    t
}

/// Per-trait candidate string lists hold exactly the (native) string
/// indices containing one of the trait's atoms, ascending and
/// deduplicated; atom-less traits get no list; pseudo-entry-only hits
/// give an empty list; `(?i)` and `word:` atoms are case-aware.
#[test]
fn test_regex_candidate_strings_lists() {
    let traits = vec![
        make_text_regex_trait("fetch-cmd", r"\bfetch\s+(-|https?://|ftp://)"),
        make_text_regex_trait("no-literal", r"\d{3}-\d{4}"),
        make_text_regex_trait("curl-cmd", r"curl\s+-"),
        make_text_regex_trait("winrar", r"(?i)\bwinrar\b"),
        make_text_word_trait("word-cs", "fetch", false),
        make_text_word_trait("word-ci", "curl", true),
    ];
    let index = StringMatchIndex::build(&traits);
    let strings = [
        make_string("nothing"),
        make_string("fetch fetch http://x"),
        make_string("CURL -s"),
        make_string("fetch - WinRAR"),
        make_string("curl -L fetch"),
    ];
    let refs: Vec<&StringInfo> = strings.iter().collect();
    let (cands, lists) = index.find_regex_candidate_strings(&refs, 4);
    for idx in 0..traits.len() {
        assert!(cands.contains(&idx), "trait {idx} must be a candidate");
    }
    assert_eq!(lists.get(&0).map(Vec::as_slice), Some(&[1u32, 3][..]));
    assert!(
        !lists.contains_key(&1),
        "atom-less trait keeps the full sweep"
    );
    assert_eq!(
        lists.get(&2).map(Vec::as_slice),
        Some(&[][..]),
        "CS atom skips CURL"
    );
    assert_eq!(
        lists.get(&3).map(Vec::as_slice),
        Some(&[3u32][..]),
        "(?i) atom hits WinRAR"
    );
    assert_eq!(lists.get(&4).map(Vec::as_slice), Some(&[1u32, 3][..]));
    assert_eq!(
        lists.get(&5).map(Vec::as_slice),
        Some(&[2u32][..]),
        "CI word hits CURL"
    );
    // No atom anywhere: not a candidate at all (and the atom-less trait still is).
    let (cands, lists) = index.find_regex_candidate_strings(&[&make_string("zzz")], 1);
    assert_eq!(cands.into_iter().collect::<Vec<_>>(), vec![1]);
    assert!(lists.is_empty());
    // Atom only in a pseudo entry (index >= native_len): candidate, empty list.
    let only_pseudo = [make_string("x"), make_string("fetch -")];
    let refs: Vec<&StringInfo> = only_pseudo.iter().collect();
    let (cands, lists) = index.find_regex_candidate_strings(&refs, 1);
    assert!(cands.contains(&0));
    assert_eq!(lists.get(&0).map(Vec::len), Some(0));
    // Oversized lists are dropped (full sweep) rather than kept.
    let many: Vec<StringInfo> = (0..200).map(|_| make_string("fetch -")).collect();
    let refs: Vec<&StringInfo> = many.iter().collect();
    let (cands, lists) = index.find_regex_candidate_strings(&refs, many.len());
    assert!(cands.contains(&0));
    assert!(!lists.contains_key(&0));
}

/// A regex trait with NO extractable atom must always be a candidate
/// (it can't be prefiltered). This is the case the precompute must never drop.
#[test]
fn test_regex_candidate_without_extractable_atom() {
    let pat = r"\d{3}-\d{4}"; // no >=3-byte mandatory literal
    let traits = vec![make_text_regex_trait("no-literal", pat)];
    let index = StringMatchIndex::build(&traits);
    assert_eq!(index.regex_traits_without_atoms, vec![0]);
    // Always a candidate, regardless of input strings.
    assert!(
        index
            .find_regex_candidate_strings(&[&make_string("xyz")], 1)
            .0
            .contains(&0)
    );
    assert!(index.find_regex_candidate_strings(&[], 0).0.contains(&0));
}

/// Regression test: a longer substr pattern must match even when a shorter
/// pattern is embedded within it. Before the fix, Aho-Corasick's
/// non-overlapping `find_iter` would match "output" (from another trait)
/// and skip "set volume output muted true" entirely.
#[test]
fn test_substr_overlapping_short_pattern_inside_long() {
    let traits = vec![
        make_substr_trait("short-trait", "output"),
        make_substr_trait("long-trait", "set volume output muted true"),
    ];
    let index = StringMatchIndex::build(&traits);

    let strings = [make_string("set volume output muted true")];
    let (matched, evidence) = index.find_matches_with_evidence(&strings.iter().collect::<Vec<_>>());

    // Both traits must match: the short "output" AND the long full string
    assert!(
        matched.contains(&0),
        "short-trait (idx=0, pattern='output') should match"
    );
    assert!(
        matched.contains(&1),
        "long-trait (idx=1, pattern='set volume output muted true') should match"
    );
    assert!(
        evidence.contains_key(&0),
        "short-trait should have evidence"
    );
    assert!(evidence.contains_key(&1), "long-trait should have evidence");
}

/// Same test but with patterns in reverse order (long before short)
#[test]
fn test_substr_overlapping_long_pattern_before_short() {
    let traits = vec![
        make_substr_trait("long-trait", "set volume output muted true"),
        make_substr_trait("short-trait", "output"),
    ];
    let index = StringMatchIndex::build(&traits);

    let strings = [make_string("set volume output muted true")];
    let (matched, _) = index.find_matches_with_evidence(&strings.iter().collect::<Vec<_>>());

    assert!(matched.contains(&0), "long-trait should match");
    assert!(matched.contains(&1), "short-trait should match");
}

/// Multiple overlapping patterns at different positions
#[test]
fn test_substr_multiple_overlapping_patterns() {
    let traits = vec![
        make_substr_trait("trait-a", "curl"),
        make_substr_trait("trait-b", "curl_easy"),
        make_substr_trait("trait-c", "curl_easy_setopt"),
    ];
    let index = StringMatchIndex::build(&traits);

    let strings = [make_string("curl_easy_setopt")];
    let (matched, _) = index.find_matches_with_evidence(&strings.iter().collect::<Vec<_>>());

    assert!(matched.contains(&0), "'curl' should match");
    assert!(matched.contains(&1), "'curl_easy' should match");
    assert!(matched.contains(&2), "'curl_easy_setopt' should match");
}

/// Parallel path: same overlapping test but with enough strings to trigger parallel
#[test]
fn test_substr_overlapping_parallel_path() {
    let traits = vec![
        make_substr_trait("short-trait", "output"),
        make_substr_trait("long-trait", "set volume output muted true"),
    ];
    let index = StringMatchIndex::build(&traits);

    // Build >1000 strings to trigger parallel path
    let mut strings: Vec<StringInfo> = (0..1001)
        .map(|i| make_string(&format!("filler string {i}")))
        .collect();
    strings.push(make_string("set volume output muted true"));

    let (matched, _) = index.find_matches_with_evidence(&strings.iter().collect::<Vec<_>>());

    assert!(
        matched.contains(&0),
        "short-trait should match in parallel path"
    );
    assert!(
        matched.contains(&1),
        "long-trait should match in parallel path"
    );
}

/// Case-insensitive overlapping patterns
#[test]
fn test_substr_overlapping_case_insensitive() {
    let make_ci_substr_trait = |id: &str, substr: &str| -> TraitDefinition {
        let mut t = make_substr_trait(id, substr);
        if let Condition::Text(TextQuery {
            ref mut case_insensitive,
            ..
        }) = t.r#if
        {
            *case_insensitive = true;
        }
        t
    };

    let traits = vec![
        make_ci_substr_trait("short-ci", "output"),
        make_ci_substr_trait("long-ci", "set volume output muted true"),
    ];
    let index = StringMatchIndex::build(&traits);

    let strings = [make_string("Set Volume Output Muted True")];
    let (matched, _) = index.find_matches_with_evidence(&strings.iter().collect::<Vec<_>>());

    assert!(
        matched.contains(&0),
        "case-insensitive short pattern should match"
    );
    assert!(
        matched.contains(&1),
        "case-insensitive long pattern should match"
    );
}

fn make_exact_trait(id: &str, exact: &str) -> TraitDefinition {
    let mut t = make_substr_trait(id, "unused");
    t.r#if = Condition::Text(TextQuery {
        exact: Some(exact.to_string()),
        ..Default::default()
    });
    t
}

#[test]
fn raw_source_prefilter_exact_is_substring_not_whole_file() {
    let traits = vec![
        make_exact_trait("has-eval", "eval"),
        make_exact_trait("pe-api", "VirtualAlloc"),
    ];
    let index = StringMatchIndex::build(&traits);
    let mut src = String::from("const x = 1;\neval('x');\n");
    while src.len() < StringMatchIndex::MIN_SOURCE_TEXT_PREFILTER_BYTES {
        src.push_str("// pad\n");
    }
    let (matched, _regex) = index
        .find_matches_in_raw_source(src.as_bytes())
        .expect("UTF-8 source in the prefilter window");
    assert!(
        matched.contains(&0),
        "exact eval is a substring of the file"
    );
    assert!(
        !matched.contains(&1),
        "absent PE exact must not be a candidate"
    );
}

#[test]
fn raw_source_prefilter_rejects_tiny_huge_and_non_utf8() {
    let index = StringMatchIndex::build(&[make_exact_trait("eval", "eval")]);
    assert!(index.find_matches_in_raw_source(&[b'x'; 50]).is_none());
    assert!(
        index
            .find_matches_in_raw_source(&vec![
                b'x';
                StringMatchIndex::MAX_SOURCE_TEXT_PREFILTER_BYTES + 1
            ])
            .is_none()
    );
    let mut bad = vec![b'x'; StringMatchIndex::MIN_SOURCE_TEXT_PREFILTER_BYTES];
    bad[10] = 0xff;
    assert!(index.find_matches_in_raw_source(&bad).is_none());
    assert!(
        index
            .find_matches_in_raw_source(&vec![
                b'x';
                StringMatchIndex::MIN_SOURCE_TEXT_PREFILTER_BYTES
            ])
            .is_some()
    );
}
