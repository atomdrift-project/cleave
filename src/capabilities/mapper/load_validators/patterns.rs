//! Checks on the patterns traits search for: duplicates, overlaps, and
//! regexes that are slow, memory-hungry or unsupported by the engine.

use super::{Report, ValidationInput, collect_early, enabled, report};
use crate::capabilities::validation::{
    check_basename_pattern_duplicates, check_exact_contained_by_substr,
    check_overlapping_regex_patterns, check_regex_alternative_subsets,
    check_regex_or_overlapping_exact, check_regex_should_be_exact,
    check_same_string_different_types, find_ast_function_call_should_use_symbol,
    find_brittle_path_patterns, find_case_insensitive_overlap_issues, find_duplicate_atomic_traits,
    find_duplicate_composite_rules, find_duplicate_inline_exclusions,
    find_incompatible_regex_features, find_literal_regex_patterns,
    find_literals_covered_by_regexes, find_memory_hungry_regex_patterns, find_non_capturing_groups,
    find_raw_should_use_text, find_regex_literal_overlap_issues, find_slow_regex_patterns,
    find_string_literal_should_use_text, find_string_pattern_duplicates,
    find_structural_regex_duplicates, find_uncompilable_ast_queries,
};

/// Duplicate atomic traits, duplicate composites, and inline exclusions
/// repeated within one rule.
pub(super) fn duplicate_rules<'a>(input: &'a ValidationInput<'a>) -> Report<'a> {
    let duplicate_atomics = collect_early("dupe-atomic", |w| {
        find_duplicate_atomic_traits(input.trait_definitions, w);
    });
    let duplicate_composites = collect_early("duplicate-composites", |w| {
        find_duplicate_composite_rules(input.composite_rules, w);
    });
    let duplicate_inline_exclusions = collect_early("duplicate-inline-exclusion", |w| {
        find_duplicate_inline_exclusions(input.trait_definitions, input.composite_rules, w);
    });
    report(move |warnings| {
        let step_start = std::time::Instant::now();
        tracing::trace!("Step 1c/15: Detecting duplicate traits and composites");
        if let Some(messages) = duplicate_atomics {
            warnings.collect_as("dupe-atomic", |warnings| warnings.extend(messages));
        }
        if let Some(messages) = duplicate_composites {
            warnings.collect_as("duplicate-composites", |warnings| warnings.extend(messages));
        }
        if let Some(messages) = duplicate_inline_exclusions {
            warnings.collect_as("duplicate-inline-exclusion", |warnings| {
                warnings.extend(messages)
            });
        }
        tracing::trace!("Step 1c completed in {:?}", step_start.elapsed());
    })
}

/// Detect string pattern duplicates and overlaps
pub(super) fn duplicate_patterns<'a>(input: &'a ValidationInput<'a>) -> Report<'a> {
    let literal_coverage = collect_early("literal-covered-by-regexes", |w| {
        find_literals_covered_by_regexes(&input.patterns, w);
    });
    let duplicate_patterns = collect_early("duplicate-patterns", |w| {
        find_string_pattern_duplicates(&input.patterns, w);
    });
    report(move |warnings| {
        let step_start = std::time::Instant::now();
        tracing::trace!("Step 1d/15: Detecting string pattern duplicates and overlaps");
        if let Some(messages) = duplicate_patterns {
            warnings.collect_as("duplicate-patterns", |warnings| warnings.extend(messages));
        }
        if let Some(messages) = literal_coverage {
            warnings.collect_as("literal-covered-by-regexes", |warnings| {
                warnings.extend(messages)
            });
        }
        tracing::trace!("Step 1d completed in {:?}", step_start.elapsed());
    })
}

/// Check for regex OR patterns overlapping with exact matches
pub(super) fn regex_or_literal_overlap<'a>(input: &'a ValidationInput<'a>) -> Report<'a> {
    let regex_or_literal = collect_early("regex-or-literal-overlap", |w| {
        check_regex_or_overlapping_exact(&input.patterns, w);
    });
    report(move |warnings| {
        let step_start = std::time::Instant::now();
        tracing::trace!("Step 1e/15: Checking for regex OR patterns overlapping exact matches");
        if let Some(messages) = regex_or_literal {
            warnings.collect_as("regex-or-literal-overlap", |warnings| {
                warnings.extend(messages)
            });
        }
        tracing::trace!("Step 1e completed in {:?}", step_start.elapsed());
    })
}

/// Regex patterns that overlap on the same file types.
pub(super) fn overlapping_regex_patterns<'a>(input: &'a ValidationInput<'a>) -> Report<'a> {
    let overlapping_regex = collect_early("overlapping-regex-patterns", |w| {
        check_overlapping_regex_patterns(&input.patterns, w);
    });
    report(move |warnings| {
        let step_start = std::time::Instant::now();
        tracing::trace!(
            "Step 1e2/15: Checking for overlapping regex patterns with same filetype coverage"
        );
        if let Some(messages) = overlapping_regex {
            warnings.collect_as("overlapping-regex-patterns", |warnings| {
                warnings.extend(messages)
            });
        }
        tracing::trace!("Step 1e2 completed in {:?}", step_start.elapsed());
    })
}

/// Catch structurally-identical regex pairs (e.g. only the inside of
/// a character class differs) — common copy/paste duplication.
pub(super) fn structural_regex_duplicates<'a>(input: &'a ValidationInput<'a>) -> Report<'a> {
    let structural_duplicates = collect_early("redundant-patterns", |w| {
        find_structural_regex_duplicates(input.trait_definitions, w);
    });
    report(move |warnings| {
        let step_start = std::time::Instant::now();
        tracing::trace!("Step 1e3/15: Checking for structurally duplicate regex patterns");
        if let Some(messages) = structural_duplicates {
            warnings.collect_as("redundant-patterns", |warnings| warnings.extend(messages));
        }
        tracing::trace!("Step 1e3 completed in {:?}", step_start.elapsed());
    })
}

/// Check for simple regex that should be exact
pub(super) fn regex_should_be_exact<'a>(input: &'a ValidationInput<'a>) -> Report<'a> {
    let should_be_exact = collect_early("exact-regex-canonicalization", |w| {
        check_regex_should_be_exact(&input.patterns, w);
    });
    report(move |warnings| {
        let step_start = std::time::Instant::now();
        tracing::trace!("Step 1f/15: Checking for regex patterns that should be exact");
        if let Some(messages) = should_be_exact {
            warnings.collect_as("exact-regex-canonicalization", |warnings| {
                warnings.extend(messages)
            });
        }
        tracing::trace!("Step 1f completed in {:?}", step_start.elapsed());
    })
}

/// Check for same pattern with different types
pub(super) fn cross_type_patterns<'a>(input: &'a ValidationInput<'a>) -> Report<'a> {
    let cross_type = collect_early("cross-type-canonicalization", |w| {
        check_same_string_different_types(&input.patterns, w);
    });
    report(move |warnings| {
        let step_start = std::time::Instant::now();
        tracing::trace!("Step 1g/15: Checking for patterns with conflicting types");
        if let Some(messages) = cross_type {
            warnings.collect_as("cross-type-canonicalization", |warnings| {
                warnings.extend(messages)
            });
        }
        tracing::trace!("Step 1g completed in {:?}", step_start.elapsed());
    })
}

/// Detect regex patterns that are costly for broad raw/text scans.
pub(super) fn slow_regexes<'a>(input: &'a ValidationInput<'a>) -> Report<'a> {
    let slow_regexes = collect_early("regex-performance", |w| {
        find_slow_regex_patterns(input.trait_definitions, w);
    });
    report(move |warnings| {
        let step_start = std::time::Instant::now();
        tracing::trace!("Step 1h/15: Detecting potentially slow regex patterns");
        if let Some(messages) = slow_regexes {
            warnings.collect_as("regex-performance", |warnings| warnings.extend(messages));
        }
        tracing::trace!("Step 1h completed in {:?}", step_start.elapsed());
    })
}

/// Detect regex patterns whose compiled engines hog memory
pub(super) fn memory_hungry_regexes<'a>(input: &'a ValidationInput<'a>) -> Report<'a> {
    let regex_memory = collect_early("regex-memory", |w| {
        find_memory_hungry_regex_patterns(input.trait_definitions, input.composite_rules, w);
    });
    report(move |warnings| {
        let step_start = std::time::Instant::now();
        tracing::trace!("Step 1h1/15: Detecting memory-hungry regex patterns");
        if let Some(messages) = regex_memory {
            warnings.collect_as("regex-memory", |warnings| warnings.extend(messages));
        }
        tracing::trace!("Step 1h1 completed in {:?}", step_start.elapsed());
    })
}

/// Probe each text/raw regex's lazy DFA on its own alphabet: a
/// pattern that explodes there explodes on real bundles (soft).
pub(super) fn pathological_regexes<'a>(input: &'a ValidationInput<'a>) -> Report<'a> {
    let regex_explosion = collect_early("regex-explosion", |w| {
        crate::capabilities::validation::find_pathological_regex_patterns(
            input.trait_definitions,
            w,
        );
    });
    report(move |warnings| {
        let step_start = std::time::Instant::now();
        tracing::trace!("Step 1h2/15: Probing regexes for lazy-DFA explosion");
        if let Some(messages) = regex_explosion {
            warnings.collect_as("regex-explosion", |warnings| warnings.extend(messages));
        }
        tracing::trace!("Step 1h2 completed in {:?}", step_start.elapsed());
    })
}

/// Compile every tree-sitter `query:`. Evaluation swallows a compile
/// failure and caches it, so a broken query is a silently dead rule.
pub(super) fn uncompilable_ast_queries<'a>(input: &'a ValidationInput<'a>) -> Report<'a> {
    let ast_queries = collect_early("ast-query-compile", |w| {
        find_uncompilable_ast_queries(input.trait_definitions, input.composite_rules, w);
    });
    report(move |warnings| {
        let step_start = std::time::Instant::now();
        tracing::trace!("Step 1h1a/15: Compiling tree-sitter AST queries");
        if let Some(messages) = ast_queries {
            warnings.collect_as("ast-query-compile", |warnings| warnings.extend(messages));
        }
        tracing::trace!("Step 1h1a completed in {:?}", step_start.elapsed());
    })
}

/// Detect unnecessary non-capturing groups in regex patterns
pub(super) fn non_capturing_groups<'a>(input: &'a ValidationInput<'a>) -> Report<'a> {
    let non_capturing_groups = collect_early("unnecessary-non-capturing-group", |w| {
        find_non_capturing_groups(input.trait_definitions, w);
    });
    report(move |warnings| {
        let step_start = std::time::Instant::now();
        tracing::trace!("Step 1h2/15: Detecting non-capturing groups in regex patterns");
        if let Some(messages) = non_capturing_groups {
            warnings.collect_as("unnecessary-non-capturing-group", |warnings| {
                warnings.extend(messages)
            });
        }
        tracing::trace!("Step 1h2 completed in {:?}", step_start.elapsed());
    })
}

/// Reject regexes the linear-time engine can't compile (lookaround,
/// backreferences) — a silently-dead condition, so this is Hard.
pub(super) fn incompatible_regexes<'a>(input: &'a ValidationInput<'a>) -> Report<'a> {
    let incompatible_regex = collect_early("incompatible-regex", |w| {
        find_incompatible_regex_features(input.trait_definitions, w);
    });
    report(move |warnings| {
        let step_start = std::time::Instant::now();
        tracing::trace!("Step 1h2a/15: Detecting engine-incompatible regex features");
        if let Some(messages) = incompatible_regex {
            warnings.collect_as("incompatible-regex", |warnings| warnings.extend(messages));
        }
        tracing::trace!("Step 1h2a completed in {:?}", step_start.elapsed());
    })
}

/// Detect brittle `type: path` / `type: basename` search patterns
pub(super) fn brittle_path_patterns<'a>(input: &'a ValidationInput<'a>) -> Report<'a> {
    let brittle_paths = collect_early("brittle-path-pattern", |w| {
        find_brittle_path_patterns(input.trait_definitions, w);
    });
    report(move |warnings| {
        let step_start = std::time::Instant::now();
        tracing::trace!("Step 1h2b/15: Detecting brittle path search patterns");
        if let Some(messages) = brittle_paths {
            warnings.collect_as("brittle-path-pattern", |warnings| warnings.extend(messages));
        }
        tracing::trace!("Step 1h2b completed in {:?}", step_start.elapsed());
    })
}

/// Detect raw patterns on binary types that would be faster as text
pub(super) fn raw_should_use_text<'a>(input: &'a ValidationInput<'a>) -> Report<'a> {
    let mut raw_should_use_text = Vec::new();
    find_raw_should_use_text(input.trait_definitions, &mut raw_should_use_text);
    let mut literal_regexes = Vec::new();
    find_literal_regex_patterns(input.trait_definitions, &mut literal_regexes);
    report(move |warnings| {
        let step_start = std::time::Instant::now();
        tracing::trace!("Step 1h3/15: Detecting raw patterns that should use text");
        warnings.collect_as("raw-should-use-text", |warnings| {
            warnings.extend(raw_should_use_text)
        });
        warnings.collect_as("literal-regex", |warnings| warnings.extend(literal_regexes));
        tracing::trace!("Step 1h3 completed in {:?}", step_start.elapsed());
    })
}

/// Detect string_literal patterns that should use text
pub(super) fn string_literal_should_use_text<'a>(input: &'a ValidationInput<'a>) -> Report<'a> {
    let mut string_literals_should_use_text = Vec::new();
    find_string_literal_should_use_text(
        input.trait_definitions,
        &mut string_literals_should_use_text,
    );
    report(move |warnings| {
        let step_start = std::time::Instant::now();
        tracing::trace!("Step 1h4/15: Detecting literal-only text mismatches");
        warnings.collect_as("string-literal-should-use-text", |warnings| {
            warnings.extend(string_literals_should_use_text)
        });
        tracing::trace!("Step 1h4 completed in {:?}", step_start.elapsed());
    })
}

/// Detect text/raw function-call patterns on AST source types — these
/// should use `type: symbol` for performance and accuracy.
pub(super) fn ast_calls_should_use_symbol<'a>(input: &'a ValidationInput<'a>) -> Report<'a> {
    let ast_calls_should_use_symbol = collect_early("ast-text-call-performance", |w| {
        find_ast_function_call_should_use_symbol(input.trait_definitions, w);
    });
    report(move |warnings| {
        let step_start = std::time::Instant::now();
        tracing::trace!(
            "Step 1h5/15: Detecting text function-call patterns that should use symbol"
        );
        if let Some(messages) = ast_calls_should_use_symbol {
            warnings.collect_as("ast-text-call-performance", |warnings| {
                warnings.extend(messages)
            });
        }
        tracing::trace!("Step 1h5 completed in {:?}", step_start.elapsed());
    })
}

/// Check for exact patterns contained by substr patterns (redundancy)
pub(super) fn exact_contained_by_substr<'a>(input: &'a ValidationInput<'a>) -> Report<'a> {
    let exact_in_substr = collect_early("redundant-patterns", |w| {
        check_exact_contained_by_substr(&input.patterns, w);
    });
    report(move |warnings| {
        let step_start = std::time::Instant::now();
        tracing::trace!("Step 1i/15: Checking for exact ⊂ substr containment");
        if let Some(messages) = exact_in_substr {
            warnings.collect_as("redundant-patterns", |warnings| warnings.extend(messages));
        }
        tracing::trace!("Step 1i completed in {:?}", step_start.elapsed());
    })
}

/// Check for case-insensitive overlaps and subsumption
pub(super) fn case_insensitive_overlaps<'a>(input: &'a ValidationInput<'a>) -> Report<'a> {
    let case_overlaps = (enabled("regex-case-subsumption")
        || enabled("case-subsumption")
        || enabled("duplicate-case-only"))
    .then(|| find_case_insensitive_overlap_issues(input.trait_definitions));
    report(move |warnings| {
        let step_start = std::time::Instant::now();
        tracing::trace!("Step 1j/15: Checking for case-insensitive overlaps");
        if let Some(issues) = case_overlaps {
            for (validator_id, message) in issues {
                if !crate::validation_controls::is_validator_disabled(validator_id) {
                    warnings.push_id(validator_id, message);
                }
            }
        }
        tracing::trace!("Step 1j completed in {:?}", step_start.elapsed());
    })
}

/// Check for regex vs literal overlaps (cross-type and containment)
pub(super) fn regex_literal_overlaps<'a>(input: &'a ValidationInput<'a>) -> Report<'a> {
    let regex_literal = (enabled("regex-contains-literal")
        || enabled("regex-vs-literal-duplicate"))
    .then(|| find_regex_literal_overlap_issues(input.trait_definitions));
    report(move |warnings| {
        let step_start = std::time::Instant::now();
        tracing::trace!("Step 1k/15: Checking for regex vs literal overlaps");
        if let Some(issues) = regex_literal {
            for (validator_id, message) in issues {
                if !crate::validation_controls::is_validator_disabled(validator_id) {
                    warnings.push_id(validator_id, message);
                }
            }
        }
        tracing::trace!("Step 1k completed in {:?}", step_start.elapsed());
    })
}

/// Check for regex alternative subsets and case-insensitive regex overlaps
pub(super) fn regex_alternative_subsets<'a>(input: &'a ValidationInput<'a>) -> Report<'a> {
    let alternative_subsets = collect_early("regex-alternative-subset", |w| {
        check_regex_alternative_subsets(input.trait_definitions, w);
    });
    report(move |warnings| {
        let step_start = std::time::Instant::now();
        tracing::trace!("Step 1l/15: Checking for regex alternative subsets");
        if let Some(messages) = alternative_subsets {
            warnings.collect_as("regex-alternative-subset", |warnings| {
                warnings.extend(messages)
            });
        }
        tracing::trace!("Step 1l completed in {:?}", step_start.elapsed());
    })
}

/// Check for basename pattern duplicates
pub(super) fn basename_duplicates<'a>(input: &'a ValidationInput<'a>) -> Report<'a> {
    let mut basename_duplicates = Vec::new();
    check_basename_pattern_duplicates(input.trait_definitions, &mut basename_duplicates);
    report(move |warnings| {
        let step_start = std::time::Instant::now();
        tracing::trace!("Step 1m/15: Checking for basename pattern duplicates");
        warnings.collect_as("basename-duplicate", |warnings| {
            warnings.extend(basename_duplicates)
        });
        tracing::trace!("Step 1m completed in {:?}", step_start.elapsed());
    })
}
