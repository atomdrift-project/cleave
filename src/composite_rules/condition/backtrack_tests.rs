use super::find_backtrack_issue;
use crate::composite_rules::condition::SymbolKind;
use crate::composite_rules::{Condition, KvQuery, LiteralQuery, PathQuery, SymbolQuery};

// ── patterns that MUST be flagged ──────────────────────────────────────

#[test]
fn dot_star_caught() {
    assert!(find_backtrack_issue(".*").is_some());
}

#[test]
fn dot_plus_caught() {
    assert!(find_backtrack_issue(".+").is_some());
}

#[test]
fn dot_star_in_middle_caught() {
    assert!(find_backtrack_issue("foo.*bar").is_some());
}

#[test]
fn dot_star_after_flag_group_caught() {
    // (?i).* — the (?i) flag group should not suppress detection
    assert!(find_backtrack_issue("(?i).*").is_some());
}

#[test]
fn negated_class_plus_caught() {
    assert!(find_backtrack_issue("[^)]+").is_some());
}

#[test]
fn negated_class_star_caught() {
    assert!(find_backtrack_issue("[^abc]*").is_some());
}

#[test]
fn negated_class_with_escape_inside_caught() {
    // [^\s]+ — backslash-s inside the class, class still negated
    assert!(find_backtrack_issue(r"[^\s]+").is_some());
}

#[test]
fn nested_quantifier_word_char_caught() {
    // (\w+)+ — the canonical ReDoS pattern
    assert!(find_backtrack_issue(r"(\w+)+").is_some());
}

#[test]
fn nested_quantifier_dot_plus_caught() {
    // (.+)+ — .+ is caught as an unbounded wildcard before the nesting is relevant
    assert!(find_backtrack_issue("(.+)+").is_some());
}

#[test]
fn nested_quantifier_char_class_caught() {
    // ([a-z]+)+ — bounded class, but the outer quantifier creates the danger
    assert!(find_backtrack_issue("([a-z]+)+").is_some());
}

#[test]
fn nested_quantifier_alternation_caught() {
    // (?:a+|b+)+ — quantified branches inside a repeated group
    assert!(find_backtrack_issue("(?:a+|b+)+").is_some());
}

#[test]
fn doubly_nested_quantifier_caught() {
    // ((\w+))+ — inner group propagates its quantifier flag to the outer
    assert!(find_backtrack_issue(r"((\w+))+").is_some());
}

#[test]
fn nested_quantifier_with_star_caught() {
    assert!(find_backtrack_issue(r"(\w+)*").is_some());
}

#[test]
fn real_world_eval_decrypt_pattern_caught() {
    let pat = r"(?i)(\$[a-zA-Z0-9_]+\s*=\s*[a-zA-Z0-9_]*Decrypt.*\(.+\);\s*eval\s*\(\s*\$[a-zA-Z0-9_]+\s*\)|eval\s*\(\s*[a-zA-Z0-9_]*Decrypt.*\(.+\)\s*\))";
    assert!(find_backtrack_issue(pat).is_some());
}

#[test]
fn greedy_pattern_lint_skips_kv_regex() {
    let cond = Condition::Kv(KvQuery {
        match_mode: Default::default(),
        path: "debug.pdb_path".to_string(),
        exact: None,
        substr: None,
        regex: Some(r"(?i)PQT_Downloader[\\/].*[\\/]PQT_Downloader\.pdb$".to_string()),
        eq: None,
        ne: None,
        case_insensitive: false,
        exists: None,
        length_min: None,
        length_max: None,
        is_check: None,
        not: None,
    });
    assert!(cond.check_greedy_patterns().is_none());
}

#[test]
fn symbol_family_condition_types_set_kind() {
    let import_cond: Condition = crate::yaml::from_str(
        r#"
type: import
regex: "^CreateFileW$"
"#,
    )
    .unwrap();
    let export_cond: Condition = crate::yaml::from_str(
        r#"
type: export
substr: DllRegisterServer
"#,
    )
    .unwrap();
    let function_cond: Condition = crate::yaml::from_str(
        r#"
type: function
exact: main
"#,
    )
    .unwrap();

    assert!(matches!(
        import_cond,
        Condition::Symbol(SymbolQuery {
            kind: Some(SymbolKind::Import),
            regex: Some(ref r),
            ..
        }) if r == "^CreateFileW$"
    ));
    assert!(matches!(
        export_cond,
        Condition::Symbol(SymbolQuery {
            kind: Some(SymbolKind::Export),
            substr: Some(ref s),
            ..
        }) if s == "DllRegisterServer"
    ));
    assert!(matches!(
        function_cond,
        Condition::Symbol(SymbolQuery {
            kind: Some(SymbolKind::Function),
            exact: Some(ref s),
            ..
        }) if s == "main"
    ));
}

/// The wire enum hands each variant's map to the query struct, so the
/// struct's own `deny_unknown_fields` is what rejects typos. Cover a plain
/// variant, both legacy-alias payloads, and a renamed type. (The untagged
/// `ConditionDeser` reports every failure as "did not match any variant",
/// so each case checks that the input loads without the extra field.)
#[test]
fn wire_format_rejects_unknown_fields() {
    for (valid, extra) in [
        ("type: symbol\nexact: main\n", "excat: x\n"),
        ("type: import\nexact: main\n", "kind: export\n"),
        ("type: basename\nexact: a.txt\n", "basename: false\n"),
        ("type: value\npath: a.b\nexact: x\n", "match_mode: any\n"),
        ("type: tree-sitter\nquery: \"(x)\"\n", "qeury: y\n"),
    ] {
        assert!(
            crate::yaml::from_str::<Condition>(valid).is_ok(),
            "rejected {valid:?}"
        );
        let typo = format!("{valid}{extra}");
        assert!(
            crate::yaml::from_str::<Condition>(&typo).is_err(),
            "accepted {typo:?}"
        );
    }
}

#[test]
fn wire_format_aliases_load_and_serialize_canonically() {
    let literal: Condition = crate::yaml::from_str("type: string_literal\nexact: x\n").unwrap();
    assert!(matches!(literal, Condition::Literal(_)));
    assert_eq!(
        serde_json::to_value(&literal).unwrap()["type"],
        serde_json::Value::from("literal")
    );

    let kv: Condition =
        crate::yaml::from_str("type: value\npath: a\nsize_min: 2\nmatch: all\n").unwrap();
    let Condition::Kv(ref query) = kv else {
        panic!("expected kv, got {kv:?}");
    };
    assert_eq!(query.length_min, Some(2));
    assert_eq!(
        serde_json::to_value(&kv).unwrap()["length_min"],
        serde_json::Value::from(2)
    );

    // Legacy alias types load as their canonical condition and serialize
    // as it, so a cached rule never reproduces the alias.
    let basename: Condition = crate::yaml::from_str("type: basename\nexact: a.txt\n").unwrap();
    assert!(matches!(
        basename,
        Condition::Path(PathQuery {
            basename: true,
            dirname: false,
            ..
        })
    ));
    let import: Condition = crate::yaml::from_str("type: import\nexact: f\n").unwrap();
    let reloaded: Condition =
        crate::yaml::from_str(&serde_saphyr::to_string(&import).unwrap()).unwrap();
    assert!(matches!(
        reloaded,
        Condition::Symbol(SymbolQuery {
            kind: Some(SymbolKind::Import),
            ..
        })
    ));
}

#[test]
fn legacy_call_target_spellings_are_normalized_when_loaded() {
    let cond: Condition = crate::yaml::from_str(
        r#"
type: symbol
kind: call
exact: Runtime.getRuntime()
"#,
    )
    .unwrap();
    assert!(matches!(
        cond,
        Condition::Symbol(SymbolQuery {
            exact: Some(ref value),
            kind: Some(SymbolKind::Call),
            ..
        }) if value == "Runtime.getRuntime"
    ));

    let cond: Condition = crate::yaml::from_str(
        r#"
type: symbol
kind: call
substr: open().read
"#,
    )
    .unwrap();
    assert!(matches!(
        cond,
        Condition::Symbol(SymbolQuery {
            substr: Some(ref value),
            kind: Some(SymbolKind::Call),
            ..
        }) if value == "open.read"
    ));

    let cond: Condition = crate::yaml::from_str(
        r#"
type: symbol
kind: call
regex: 'open\(\)\.read$'
"#,
    )
    .unwrap();
    assert!(matches!(
        cond,
        Condition::Symbol(SymbolQuery {
            regex: Some(ref value),
            kind: Some(SymbolKind::Call),
            ..
        }) if value == r"open\.read$"
    ));

    let cond: Condition = crate::yaml::from_str(
        r#"
type: symbol
kind: member
exact: Runtime.getRuntime()
"#,
    )
    .unwrap();
    assert!(matches!(
        cond,
        Condition::Symbol(SymbolQuery {
            exact: Some(ref value),
            kind: Some(SymbolKind::Member),
            ..
        }) if value == "Runtime.getRuntime()"
    ));
}

#[test]
fn value_condition_carries_not_exceptions() {
    // A `not:` on a value condition parsed cleanly and was then dropped:
    // `Kv` had no such field, and nothing rejects an unknown key. The
    // exception silently did nothing, which is the worst way for a
    // suppression to fail. Parse it here so the field cannot go missing
    // again without a test noticing.
    let cond: Condition = crate::yaml::from_str(
        r#"
type: value
path: pdf.embedded_files[*].filename
regex: '(?i)\.html?$'
not:
  - regex: 'accreport\.html?$'
"#,
    )
    .unwrap();
    let Condition::Kv(KvQuery { not, .. }) = cond else {
        panic!("expected a value condition");
    };
    let not = not.expect("not: was dropped during deserialization");
    assert_eq!(not.len(), 1);
    assert!(not[0].matches("report.accreport.html"));
    assert!(!not[0].matches("index.html"));
}

#[test]
fn value_condition_accepts_the_shorthand_not_form() {
    // A bare string is the substring shorthand every other condition
    // type accepts; the value matcher has to read it the same way.
    let cond: Condition = crate::yaml::from_str(
        r#"
type: value
path: files[*]
regex: '\.html$'
not:
  - accreport
"#,
    )
    .unwrap();
    let Condition::Kv(KvQuery { not, .. }) = cond else {
        panic!("expected a value condition");
    };
    let not = not.expect("not: was dropped");
    assert!(not[0].matches("x.accreport.html"));
    assert!(!not[0].matches("x.html"));
}

#[test]
fn value_condition_is_now_the_validator_not_exact() {
    // `is` used to be an alias for `exact` on value conditions. It now
    // carries the validator, matching every other condition type. No rule
    // in the corpus used the alias, and the migration is safe because a
    // stale literal cannot masquerade as a validator -- see the sibling
    // test below.
    let cond: Condition = crate::yaml::from_str(
        r#"
type: value
path: office.creator
is: random_like
"#,
    )
    .unwrap();
    assert_eq!(cond.type_name(), "value");
    assert!(matches!(
        cond,
        Condition::Kv(KvQuery {
            exact: None,
            is_check: Some(super::StringValidator::RandomLike),
            ..
        })
    ));

    // `exact` is untouched and remains the spelling every rule uses.
    let legacy: Condition = crate::yaml::from_str(
        r#"
type: value
path: scripts.postinstall
exact: curl
"#,
    )
    .unwrap();
    assert!(matches!(
        legacy,
        Condition::Kv(KvQuery { exact: Some(ref s), is_check: None, .. }) if s == "curl"
    ));
}

#[test]
fn value_condition_rejects_a_literal_where_a_validator_belongs() {
    // The safety property behind reusing the key: an old-style
    // `is: <literal>` fails to parse rather than silently changing from
    // an exact match into a validator that is not there.
    let err = crate::yaml::from_str::<Condition>(
        r#"
type: value
path: scripts.postinstall
is: curl
"#,
    );
    assert!(err.is_err(), "a bare literal must not parse as a validator");
}

#[test]
fn literal_yaml_accepts_both_type_literal_and_type_string_literal() {
    // Backward-compat alias: rules authored as `type: string_literal`
    // must continue parsing into Condition::Literal so the existing
    // trait corpus keeps working.
    let new_form: Condition =
        crate::yaml::from_str("type: literal\nsubstr: rm -rf").expect("parse type: literal");
    let old_form: Condition = crate::yaml::from_str("type: string_literal\nsubstr: rm -rf")
        .expect("parse type: string_literal");
    assert!(matches!(new_form, Condition::Literal(LiteralQuery { .. })));
    assert!(matches!(old_form, Condition::Literal(LiteralQuery { .. })));
}

#[test]
fn numeric_literal_match_fires_on_chmod_octal_777() {
    // End-to-end: synthesize what the AST walker would produce for
    // an octal literal `0o777`, then exercise the evaluator dispatch
    // for `type: literal, kind: number, value: 511, radix: 8`. The
    // value+radix pair lets authors distinguish `0o777` from
    // decimal `511` even though they represent the same integer.
    use crate::composite_rules::types::Platform;
    use crate::types::binary::StringInfo;
    use crate::types::{AnalysisReport, TargetInfo};

    let mut report = AnalysisReport::new(TargetInfo::default());
    report.strings.push(StringInfo {
        value: ("511".to_string()).into(),
        offset: Some(0x40),
        string_type: None,
        encoding: "8".to_string(),
        section: Some("ast-number".to_string()),
        encoding_chain: Vec::new(),
        fragments: None,
    });
    let platforms = vec![Platform::All];
    let ctx = crate::composite_rules::EvaluationContext::new(
        &report,
        b"",
        crate::composite_rules::types::FileType::Python,
        &platforms,
        None,
        None,
    );

    // Right value + right radix → match.
    let res = crate::composite_rules::evaluators::symbol_string::eval_numeric_literal(
        Some(511),
        Some(8),
        &ctx,
    );
    assert!(res.matched, "0o777 (value=511, radix=8) should match");
    assert_eq!(res.match_count, 1);

    // Right value, wrong radix → no match (source wrote octal, not decimal).
    let res = crate::composite_rules::evaluators::symbol_string::eval_numeric_literal(
        Some(511),
        Some(10),
        &ctx,
    );
    assert!(!res.matched, "wrong radix should not match");

    // Wrong value → no match.
    let res = crate::composite_rules::evaluators::symbol_string::eval_numeric_literal(
        Some(777),
        Some(8),
        &ctx,
    );
    assert!(!res.matched, "wrong value should not match");

    // Value-only (no radix constraint) → match.
    let res = crate::composite_rules::evaluators::symbol_string::eval_numeric_literal(
        Some(511),
        None,
        &ctx,
    );
    assert!(res.matched, "value-only filter should match");
}

#[test]
fn literal_yaml_parses_numeric_kind_with_value_and_radix() {
    // The new numeric-matching surface: `kind: number` with
    // `value` + `radix`. The evaluator dispatch is a TODO; this
    // test just locks in that the grammar accepts the shape.
    let cond: Condition =
        crate::yaml::from_str("type: literal\nkind: number\nvalue: 511\nradix: 8")
            .expect("parse numeric literal");
    assert!(matches!(cond, Condition::Literal(LiteralQuery { .. })));
    if let Condition::Literal(LiteralQuery {
        kind, value, radix, ..
    }) = cond
    {
        assert_eq!(kind.as_deref(), Some("number"));
        assert_eq!(value, Some(511));
        assert_eq!(radix, Some(8));
    }
}

#[test]
fn literal_yaml_parses_docstring_exclusion() {
    let cond: Condition =
        crate::yaml::from_str("type: literal\nregex: 'https?://'\nexclude_docstrings: true")
            .expect("parse source literal options");
    let Condition::Literal(query) = cond else {
        panic!("expected a literal condition");
    };
    assert!(query.exclude_docstrings);
}

#[test]
fn greedy_pattern_lint_skips_string_literal_regex() {
    let cond = Condition::Literal(LiteralQuery {
        kind: None,
        exact: None,
        substr: None,
        regex: Some(r"^ssh(d|-.+)?$".to_string()),
        word: None,
        value: None,
        radix: None,
        case_insensitive: false,
        exclude_docstrings: false,
        is_check: None,
        not: None,
        platforms: None,
        section: None,
        offset: None,
        offset_range: None,
        section_offset: None,
        section_offset_range: None,
    });
    assert!(cond.check_greedy_patterns().is_none());
}

#[test]
fn greedy_pattern_lint_skips_symbol_regex() {
    let cond = Condition::Symbol(SymbolQuery {
        exact: None,
        substr: None,
        regex: Some(r"^libc\.so(\.[0-9]+)*$".to_string()),
        platforms: None,
        is_check: None,
        kind: None,
        arg: None,
        args: None,
        alias: None,
        not: None,
        module_level: false,
        receiver: None,
    });
    assert!(cond.check_greedy_patterns().is_none());
}

#[test]
fn greedy_pattern_lint_skips_basename_regex() {
    let cond = Condition::Path(PathQuery {
        exact: None,
        substr: None,
        regex: Some(r"^ssh(d|-.+)?$".to_string()),
        case_insensitive: false,
        is_check: None,
        basename: true,
        dirname: false,
    });
    assert!(cond.check_greedy_patterns().is_none());
}

#[test]
fn open_ended_range_quantifier_caught() {
    // .{1,} is semantically equivalent to .+ and must be flagged
    assert!(find_backtrack_issue(".{1,}").is_some());
}

#[test]
fn open_ended_range_zero_caught() {
    // .{0,} is semantically equivalent to .* and must be flagged
    assert!(find_backtrack_issue(".{0,}").is_some());
}

#[test]
fn open_ended_range_in_pattern_caught() {
    // .{2,} embedded in a larger pattern must be flagged
    assert!(find_backtrack_issue(r"foo.{2,}bar").is_some());
}

// ── patterns that must NOT be flagged ──────────────────────────────────

#[test]
fn lazy_dot_star_ok() {
    assert!(find_backtrack_issue(".*?").is_none());
}

#[test]
fn lazy_dot_plus_ok() {
    assert!(find_backtrack_issue(".+?").is_none());
}

#[test]
fn bounded_repetition_ok() {
    assert!(find_backtrack_issue(".{0,50}").is_none());
}

#[test]
fn word_char_plus_alone_ok() {
    // \w+ is not nested and not a wildcard — safe
    assert!(find_backtrack_issue(r"\w+").is_none());
}

#[test]
fn whitespace_star_ok() {
    // \s* is bounded by the whitespace character class — safe on its own
    assert!(find_backtrack_issue(r"\s*").is_none());
}

#[test]
fn non_negated_class_plus_ok() {
    // [a-z]+ is a bounded positive class — safe
    assert!(find_backtrack_issue("[a-z]+").is_none());
}

#[test]
fn escaped_dot_ok() {
    // \. is a literal dot, not a wildcard — \. followed by * is fine
    assert!(find_backtrack_issue(r"\.*").is_none());
}

#[test]
fn dot_inside_class_ok() {
    // [.*]+ — the . inside [] is a literal character, not a wildcard
    assert!(find_backtrack_issue("[.*]+").is_none());
}

#[test]
fn simple_alternation_ok() {
    // (foo|bar)+ — no quantifiers inside the group branches
    assert!(find_backtrack_issue("(foo|bar)+").is_none());
}

#[test]
fn simple_literal_group_repeated_ok() {
    assert!(find_backtrack_issue("(abc)+").is_none());
}

#[test]
fn empty_pattern_ok() {
    assert!(find_backtrack_issue("").is_none());
}

#[test]
fn plain_literal_ok() {
    assert!(find_backtrack_issue("hello world").is_none());
}

// ── message content ────────────────────────────────────────────────────

#[test]
fn dot_star_message_mentions_wildcard() {
    let msg = find_backtrack_issue(".*").unwrap();
    assert!(msg.contains("wildcard"), "got: {msg}");
}

#[test]
fn negated_class_message_mentions_negated() {
    let msg = find_backtrack_issue("[^x]+").unwrap();
    assert!(msg.contains("negated"), "got: {msg}");
}

#[test]
fn nested_quantifier_message_mentions_nested() {
    let msg = find_backtrack_issue(r"(\w+)+").unwrap();
    assert!(msg.contains("nested"), "got: {msg}");
}

// ── word_match_start: literal `word:` matcher equivalence ────────────────

/// `word_match_start` must agree with the regex `\bneedle\b` it replaced,
/// including at non-ASCII (Unicode word-char) neighbours.
#[allow(clippy::expect_used)]
fn assert_word_matches_regex(haystack: &str, needle: &str) {
    let pat = format!(r"\b{}\b", regex::escape(needle));
    let re = regex::Regex::new(&pat).expect("valid regex");
    let want = re.find(haystack).map(|m| m.start());
    let got = super::word_match_start(haystack, needle, false);
    assert_eq!(
        want, got,
        "needle={needle:?} haystack={haystack:?}: regex={want:?} literal={got:?}"
    );
}

#[test]
fn word_match_agrees_with_regex_word_boundary() {
    for (h, n) in [
        ("run eval here", "eval"),
        ("evaluate", "eval"),   // suffix → no boundary
        ("preeval", "eval"),    // prefix → no boundary
        ("eval", "eval"),       // whole string
        ("(eval)", "eval"),     // punctuation neighbours
        ("a.eval.b", "eval"),   // dotted
        ("ñeval", "eval"),      // leading non-ASCII letter → no boundary
        ("evalé done", "eval"), // trailing non-ASCII letter → no boundary
        ("no match", "eval"),
    ] {
        assert_word_matches_regex(h, n);
    }
}

#[test]
#[allow(clippy::expect_used)]
fn word_match_returns_matched_slice_preserving_case() {
    // Case-insensitive match still reports the text as it appears in the
    // haystack (not the lowercased needle) — mirrors the old `mat.as_str()`.
    let start = super::word_match_start("call EVAL now", "eval", true).expect("match");
    assert_eq!(&"call EVAL now"[start..start + "eval".len()], "EVAL");
}

/// `raw_word_match_offsets` (the raw-content `word:` scan) must return the
/// SAME match offsets the `\bneedle\b` regex `find_iter` yields — this is the
/// parity the byte-scan replacement of the compiled raw regex relies on.
#[allow(clippy::expect_used)]
fn assert_raw_word_offsets_match_regex(haystack: &str, needle: &str, ci: bool) {
    let pat = format!(r"\b{}\b", regex::escape(needle));
    let re = regex::RegexBuilder::new(&pat)
        .case_insensitive(ci)
        .build()
        .expect("valid regex");
    let want: Vec<usize> = re.find_iter(haystack).map(|m| m.start()).collect();
    let got = super::raw_word_match_offsets(haystack.as_bytes(), needle, ci, 4096);
    assert_eq!(
        want, got,
        "needle={needle:?} ci={ci} haystack={haystack:?}: regex={want:?} scan={got:?}"
    );
}

#[test]
fn raw_word_offsets_agree_with_regex_find_iter() {
    let cases = [
        ("zsh ~/.zshrc and /etc/zshrc plus zshrc.bak", "zshrc"),
        ("zshrcbak myzshrc nope", "zshrc"), // both have a word-char neighbour → no match
        ("eval eval eval", "eval"),         // repeated, non-overlapping
        ("(eval) [eval] {eval}", "eval"),   // punctuation neighbours
        ("a.eval.b eval", "eval"),
        ("ñeval evalé", "eval"), // non-ASCII letter neighbours → no match
        ("no hits here", "eval"),
    ];
    for (h, n) in cases {
        assert_raw_word_offsets_match_regex(h, n, false);
        assert_raw_word_offsets_match_regex(h, n, true);
    }
    // case-insensitive: content case varies, boundaries still hold
    assert_raw_word_offsets_match_regex("ZSHRC zshrc ZsHrC", "zshrc", true);
}

#[test]
fn raw_word_offsets_respect_cap() {
    let hay = "x ".repeat(10); // 10 word-`x` occurrences, all boundary-valid
    let got = super::raw_word_match_offsets(hay.as_bytes(), "x", false, 3);
    assert_eq!(got.len(), 3);
}

#[test]
fn word_match_empty_needle_never_matches() {
    assert_eq!(super::word_match_start("anything", "", false), None);
}

/// One byte-searching engine per pattern, selected at compile time.
///
/// Pins the deliberate semantic change: pure-ASCII patterns get
/// byte semantics (YARA's model), while patterns carrying non-ASCII text
/// keep codepoint semantics so `(?i)` still folds their case.
#[test]
fn trait_regex_engine_selection() {
    // ASCII pattern + ASCII haystack: identical to the Unicode engine
    // across a semantics-sensitive pattern zoo. This is the invariant that
    // makes the change safe for the overwhelming majority of scans.
    for pat in [
        r"user\w+",
        r"[\w .-]{3,}",
        r"a.b",
        r#"x[^"]+y"#,
        r"q[\s\S]{2}r",
        r"(?i)PoWeR\s+shell",
        r"\btoken\b",
        r"^start.*end$",
    ] {
        let re = super::TraitRegex::compile(pat).unwrap();
        let uni = super::compile_codepoint(pat).unwrap();
        let mut cache = uni.create_cache();
        for hay in ["user_x a b-c 4", "x'y start token end", "POWER  SHELL", ""] {
            let uni_hit = uni
                .search_with(&mut cache, &regex_automata::Input::new(hay))
                .map(|m| &hay[m.start()..m.end()]);
            assert_eq!(re.find_str(hay), uni_hit, "pattern {pat:?} on {hay:?}");
        }
    }

    // ASCII pattern + NON-ASCII haystack: byte semantics. `\w` and `.` no
    // longer span a multi-byte codepoint. This is the accepted trade.
    let re = super::TraitRegex::compile(r"user\w+").unwrap();
    assert_eq!(re.find_str("userabc"), Some("userabc"));
    assert_eq!(
        re.find_str("userñx"),
        None,
        "\\w is ASCII-only in byte mode"
    );
    let re = super::TraitRegex::compile(r"a.b").unwrap();
    assert_eq!(re.find_str("axb"), Some("axb"));
    assert_eq!(re.find_str("aéb"), None, ". matches one byte in byte mode");
    // Negated classes still span whole codepoints: they match any byte.
    let re = super::TraitRegex::compile(r#"x[^"]+y"#).unwrap();
    assert_eq!(re.find_str("xéñy"), Some("xéñy"));

    // Non-ASCII pattern: codepoint semantics preserved, `(?i)` still folds.
    // This is what keeps the impersonation traits working.
    let re = super::TraitRegex::compile(r"(?i)Майкрософт").unwrap();
    assert_eq!(re.find_str("майкрософт"), Some("майкрософт"));
    let re = super::TraitRegex::compile(r"ñ\w+").unwrap();
    assert!(re.is_match("ñé"));

    // Patterns that cannot parse in byte mode take the same fallback.
    let re = super::TraitRegex::compile(r"\p{Han}{2,}").unwrap();
    assert_eq!(re.find_str("ab漢字cd"), Some("漢字"));
    let re = super::TraitRegex::compile(r"[Ѐ-ӿ]+").unwrap();
    assert_eq!(re.find_str("ab Привет cd"), Some("Привет"));

    // min_len is engine-independent.
    let re = super::TraitRegex::compile(r"abc\w{2}").unwrap();
    assert_eq!(re.min_len, 5);
    assert!(!re.is_match("abcd"));
}
