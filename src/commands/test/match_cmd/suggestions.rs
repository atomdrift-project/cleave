//! Suggestions when a `test-match` search finds nothing: other search
//! types or file types under which the pattern would match.

// Split out of the parent module for size; it shares the parent's namespace.
#[allow(clippy::wildcard_imports)]
use super::*;

pub(super) fn suggest_alternatives(ctx: &MatchCtx<'_>, output: &mut String) {
    let MatchRequest {
        kind: search_type,
        method,
        count_min,
        count_max,
        case_insensitive,
        entropy_min,
        entropy_max,
        length_min,
        length_max,
        ..
    } = ctx.request;
    let MatchCtx {
        pattern,
        file_type,
        internal_file_type,
        capability_mapper,
        binary_data,
        report,
        engine,
        path,
        ..
    } = *ctx;
    output.push_str("\nSuggestions:\n");

    // Check alternative search types
    match search_type {
        cli::SearchType::StringValue => {
            // Check if pattern exists in symbols
            let symbols: Vec<&str> = report
                .imports
                .iter()
                .map(|i| i.symbol.as_str())
                .chain(report.exports.iter().map(|e| e.symbol.as_str()))
                .chain(report.functions.iter().map(|f| f.name.as_str()))
                .collect();
            let exact = if method == cli::MatchMethod::Exact {
                Some(pattern.to_string())
            } else {
                None
            };
            let regex = if method == cli::MatchMethod::Regex {
                Some(pattern.to_string())
            } else {
                None
            };
            let symbol_matches =
                find_matching_symbols(&symbols, exact.as_deref(), None, regex.as_deref(), false);
            if !symbol_matches.is_empty() {
                output.push_str(&format!(
                    "  Found in symbols ({} matches) - try `--type symbol`\n",
                    symbol_matches.len()
                ));
            }

            // Check if pattern exists in content
            let content = String::from_utf8_lossy(binary_data);
            let content_matched = match method {
                cli::MatchMethod::Exact | cli::MatchMethod::Contains => content.contains(pattern),
                cli::MatchMethod::Regex => {
                    regex::Regex::new(pattern).is_ok_and(|re| re.is_match(&content))
                }
                cli::MatchMethod::Word => {
                    let word_pattern = format!(r"\b{}\b", regex::escape(pattern));
                    regex::Regex::new(&word_pattern).is_ok_and(|re| re.is_match(&content))
                }
            };
            if content_matched {
                output.push_str("  Found in content - try `--type raw`\n");
            }
        }
        cli::SearchType::Text => {
            if internal_file_type.uses_raw_text_search_in(ctx.report) {
                // For raw-text mode, `type: text exact:` matches a complete trimmed line.
                // If the pattern appears as substring but never as a standalone line, the
                // author almost certainly wanted `substr:` or a word-boundary regex.
                if method == cli::MatchMethod::Exact {
                    let needle = if case_insensitive {
                        pattern.to_ascii_lowercase()
                    } else {
                        pattern.to_string()
                    };
                    let haystack = if case_insensitive {
                        String::from_utf8_lossy(binary_data).to_ascii_lowercase()
                    } else {
                        String::from_utf8_lossy(binary_data).to_string()
                    };
                    let substr_hits = haystack.matches(needle.as_str()).count();
                    if substr_hits > 0 {
                        output.push_str(&format!(
                            "  Pattern appears {substr_hits} time(s) as substring but never as a standalone line.\n  In raw-text mode (source files, manifests), `text exact:` matches a complete trimmed line.\n  Did you want `--method contains`, or `--method regex` with `\\b...\\b`?\n"
                        ));
                    }
                }

                let ast_literal_matches = {
                    let strings: Vec<&str> = report
                        .strings
                        .iter()
                        .filter(|s| s.section.as_deref() == Some("ast"))
                        .map(|s| s.value.as_str())
                        .collect();
                    let exact = if method == cli::MatchMethod::Exact {
                        Some(pattern.to_string())
                    } else {
                        None
                    };
                    let contains = if method == cli::MatchMethod::Contains {
                        Some(pattern.to_string())
                    } else {
                        None
                    };
                    let regex = if method == cli::MatchMethod::Regex {
                        Some(pattern.to_string())
                    } else {
                        None
                    };
                    let word = if method == cli::MatchMethod::Word {
                        Some(pattern.to_string())
                    } else {
                        None
                    };
                    find_matching_strings(
                        &strings,
                        exact.as_deref(),
                        contains.as_deref(),
                        regex.as_deref(),
                        word.as_deref(),
                        case_insensitive,
                    )
                };
                if !ast_literal_matches.is_empty() {
                    output.push_str(&format!(
                        "  Found in AST string literals ({} matches) - try `--type string-literal`\n",
                        ast_literal_matches.len()
                    ));
                }
            } else {
                let symbols: Vec<&str> = report
                    .imports
                    .iter()
                    .map(|i| i.symbol.as_str())
                    .chain(report.exports.iter().map(|e| e.symbol.as_str()))
                    .chain(report.functions.iter().map(|f| f.name.as_str()))
                    .collect();
                let exact = if method == cli::MatchMethod::Exact {
                    Some(pattern.to_string())
                } else {
                    None
                };
                let regex = if method == cli::MatchMethod::Regex {
                    Some(pattern.to_string())
                } else {
                    None
                };
                let symbol_matches = find_matching_symbols(
                    &symbols,
                    exact.as_deref(),
                    None,
                    regex.as_deref(),
                    false,
                );
                if !symbol_matches.is_empty() {
                    output.push_str(&format!(
                        "  Found in symbols ({} matches) - try `--type symbol`\n",
                        symbol_matches.len()
                    ));
                }
            }
        }
        cli::SearchType::StringLiteral => {
            let content = String::from_utf8_lossy(binary_data);
            let content_matched = match method {
                cli::MatchMethod::Exact | cli::MatchMethod::Contains => content.contains(pattern),
                cli::MatchMethod::Regex => {
                    regex::Regex::new(pattern).is_ok_and(|re| re.is_match(&content))
                }
                cli::MatchMethod::Word => {
                    let word_pattern = format!(r"\b{}\b", regex::escape(pattern));
                    regex::Regex::new(&word_pattern).is_ok_and(|re| re.is_match(&content))
                }
            };
            if content_matched {
                output.push_str("  Found in file text - try `--type text`\n");
            }
        }
        cli::SearchType::Symbol => {
            // Check if pattern exists in strings (try exact first, then contains)
            let strings: Vec<&str> = report.strings.iter().map(|s| s.value.as_str()).collect();
            let exact = if method == cli::MatchMethod::Exact {
                Some(pattern.to_string())
            } else {
                None
            };
            let contains = if method == cli::MatchMethod::Contains {
                Some(pattern.to_string())
            } else {
                None
            };
            let regex = if method == cli::MatchMethod::Regex {
                Some(pattern.to_string())
            } else {
                None
            };
            let word = if method == cli::MatchMethod::Word {
                Some(pattern.to_string())
            } else {
                None
            };
            let string_matches = find_matching_strings(
                &strings,
                exact.as_deref(),
                contains.as_deref(),
                regex.as_deref(),
                word.as_deref(),
                case_insensitive,
            );
            if !string_matches.is_empty() {
                output.push_str(&format!(
                    "  Found in text search corpus ({} matches) - try `--type text`\n",
                    string_matches.len()
                ));
            } else if method == cli::MatchMethod::Exact {
                // Also try contains for exact searches
                let contains_matches = find_matching_strings(
                    &strings,
                    None,
                    Some(pattern.to_string()).as_deref(),
                    None,
                    None,
                    case_insensitive,
                );
                if !contains_matches.is_empty() {
                    output.push_str(&format!(
                        "  Found in text search corpus ({} substring matches) - try `--type text --method contains`\n",
                        contains_matches.len()
                    ));
                }
            }

            // Check if pattern exists in content
            let content = String::from_utf8_lossy(binary_data);
            let content_matched = match method {
                cli::MatchMethod::Exact | cli::MatchMethod::Contains => content.contains(pattern),
                cli::MatchMethod::Regex => {
                    regex::Regex::new(pattern).is_ok_and(|re| re.is_match(&content))
                }
                cli::MatchMethod::Word => {
                    let word_pattern = format!(r"\b{}\b", regex::escape(pattern));
                    regex::Regex::new(&word_pattern).is_ok_and(|re| re.is_match(&content))
                }
            };
            if content_matched {
                output.push_str("  Found in content - try `--type raw`\n");
            }
        }
        cli::SearchType::Raw => {
            // Check if pattern exists in strings
            let strings: Vec<&str> = report.strings.iter().map(|s| s.value.as_str()).collect();
            let exact = if method == cli::MatchMethod::Exact {
                Some(pattern.to_string())
            } else {
                None
            };
            let contains = if method == cli::MatchMethod::Contains {
                Some(pattern.to_string())
            } else {
                None
            };
            let regex = if method == cli::MatchMethod::Regex {
                Some(pattern.to_string())
            } else {
                None
            };
            let word = if method == cli::MatchMethod::Word {
                Some(pattern.to_string())
            } else {
                None
            };
            let string_matches = find_matching_strings(
                &strings,
                exact.as_deref(),
                contains.as_deref(),
                regex.as_deref(),
                word.as_deref(),
                case_insensitive,
            );
            if !string_matches.is_empty() {
                output.push_str(&format!(
                    "  Found in text search corpus ({} matches) - try `--type text`\n",
                    string_matches.len()
                ));
            }

            // Check if pattern exists in symbols
            let symbols: Vec<&str> = report
                .imports
                .iter()
                .map(|i| i.symbol.as_str())
                .chain(report.exports.iter().map(|e| e.symbol.as_str()))
                .chain(report.functions.iter().map(|f| f.name.as_str()))
                .collect();
            let symbol_matches =
                find_matching_symbols(&symbols, exact.as_deref(), None, regex.as_deref(), false);
            if !symbol_matches.is_empty() {
                output.push_str(&format!(
                    "  Found in symbols ({} matches) - try `--type symbol`\n",
                    symbol_matches.len()
                ));
            }
        }
        cli::SearchType::Kv => {
            // No cross-search suggestions for kv - it's a different paradigm
            output.push_str("  Check that the path exists in the file structure\n");
            output.push_str("  Try without a pattern for existence check\n");
        }
        cli::SearchType::Hex => {
            // Suggest content search as alternative
            output.push_str("  Try --type raw for string-based search\n");
            output.push_str("  Ensure hex pattern has correct format: \"7F 45 4C 46\"\n");
            output.push_str("  Try --offset or --offset-range to target specific locations\n");
        }
        cli::SearchType::Encoded => {
            output
                .push_str("  Encoded search looks for decoded strings (base64, hex, xor, etc.)\n");
            output.push_str("  Use --encoding to filter by type: --encoding base64\n");
            output.push_str("  Try `--type text` for regular text\n");
            output.push_str("  Try `--type raw` for raw content search\n");
        }
        cli::SearchType::Section => {
            output.push_str("  Section search matches binary section metadata\n");
            if pattern.is_empty()
                && entropy_min.is_none()
                && entropy_max.is_none()
                && length_min.is_none()
                && length_max.is_none()
                && count_min <= 1
                && count_max.is_none()
            {
                output.push_str("  Specify --pattern for name matching\n");
                output.push_str("  Use --entropy-min/--entropy-max for entropy constraints\n");
                output.push_str("  Use --length-min/--length-max for section size constraints\n");
                output.push_str("  Use --count-min/--count-max for number of matching sections\n");
            }
            if !report.sections.is_empty() {
                output.push_str(&format!(
                    "  Available sections: {}\n",
                    report
                        .sections
                        .iter()
                        .map(|s| s.name.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                ));
            }
        }
        cli::SearchType::Metrics => {
            output.push_str("  Metrics search tests computed file metrics against thresholds\n");
            output.push_str("  Use --pattern for field path (e.g., 'binary.avg_complexity')\n");
            output.push_str("  Use --value-min/--value-max for thresholds\n");
            output.push_str("  Use --min-size/--max-size for file size constraints\n");
            let flat_keys: Vec<&str> = report
                .filefacts_metrics
                .as_ref()
                .map(|m| m.keys().map(String::as_str).collect())
                .unwrap_or_default();
            let has_prefix = |p: &str| flat_keys.iter().any(|k| k.starts_with(p));

            if !flat_keys.is_empty() {
                output.push_str("\n  Available metric fields:\n");
                if has_prefix("binary.") {
                    output.push_str(
                        "    file.entropy, binary.avg_complexity, binary.import_count, ...\n",
                    );
                }
                if has_prefix("text.") {
                    output.push_str("    text.char_entropy, text.avg_line_length, ...\n");
                }
                if has_prefix("functions.") {
                    output.push_str("    functions.total, functions.avg_params, functions.max_nesting_depth, ...\n");
                }
                if has_prefix("identifiers.") {
                    output.push_str("    identifiers.avg_entropy, identifiers.reuse_ratio, ...\n");
                }
                output.push_str("  Run `cleave metrics <file>` to see all available fields\n");
            } else {
                output.push_str("  No metrics available for this file type\n");
            }
        }
    }

    // Suggest alternative match methods
    output.push_str("\n  Try different match methods:\n");
    match method {
        cli::MatchMethod::Exact | cli::MatchMethod::Word => {
            output.push_str("    --method contains (substring match)\n");
            output.push_str("    --method regex (pattern match)\n");
        }
        cli::MatchMethod::Contains => {
            output.push_str("    --method exact (exact match)\n");
            output.push_str("    --method regex (pattern match)\n");
        }
        cli::MatchMethod::Regex => {
            output.push_str("    --method contains (substring match)\n");
            output.push_str("    --method exact (exact match)\n");
        }
    }

    // Check if pattern would match with different file types
    output.push_str("\n  File type analysis:\n");
    output.push_str(&format!("    Current file type: {:?}\n", file_type));

    // Try analyzing as different file types
    let alternative_types = vec![
        ("ELF", FileType::Elf),
        ("PE", FileType::Pe),
        ("Mach-O", FileType::MachO),
        ("JavaScript", FileType::JavaScript),
        ("Python", FileType::Python),
        ("Go", FileType::Go),
    ];

    for (type_name, alt_type) in alternative_types {
        if alt_type != file_type {
            // Try to create a report with alternative file type
            if let Ok(alt_report) = create_analysis_report(path, &alt_type, binary_data, engine) {
                let alt_debugger = RuleDebugger::with_parsed(
                    capability_mapper,
                    &alt_report,
                    binary_data,
                    vec![composite_rules::Platform::All], // Check all platforms for alt file types
                    None, // test-match evaluates conditions directly
                    engine.filefacts_options().path(path).open(binary_data),
                );
                let alt_context = alt_debugger.context_info();

                // Quick check if search would work with this type
                let would_match = match search_type {
                    cli::SearchType::StringValue => {
                        let strings: Vec<&str> = alt_report
                            .strings
                            .iter()
                            .map(|s| s.value.as_str())
                            .collect();
                        let exact = if method == cli::MatchMethod::Exact {
                            Some(pattern.to_string())
                        } else {
                            None
                        };
                        let contains = if method == cli::MatchMethod::Contains {
                            Some(pattern.to_string())
                        } else {
                            None
                        };
                        let regex = if method == cli::MatchMethod::Regex {
                            Some(pattern.to_string())
                        } else {
                            None
                        };
                        let word = if method == cli::MatchMethod::Word {
                            Some(pattern.to_string())
                        } else {
                            None
                        };
                        let matches = find_matching_strings(
                            &strings,
                            exact.as_deref(),
                            contains.as_deref(),
                            regex.as_deref(),
                            word.as_deref(),
                            case_insensitive,
                        );
                        !matches.is_empty()
                    }
                    cli::SearchType::Text => {
                        if matches!(
                            alt_type,
                            FileType::JavaScript
                                | FileType::Python
                                | FileType::Go
                                | FileType::Java
                                | FileType::Rust
                                | FileType::Ruby
                                | FileType::Shell
                                | FileType::PowerShell
                                | FileType::Php
                                | FileType::TypeScript
                                | FileType::C
                                | FileType::CSharp
                                | FileType::Lua
                                | FileType::Perl
                                | FileType::Swift
                                | FileType::ObjectiveC
                                | FileType::Groovy
                                | FileType::Scala
                                | FileType::Zig
                                | FileType::Elixir
                                | FileType::Html
                                | FileType::Markdown
                        ) {
                            let content = String::from_utf8_lossy(binary_data);
                            match method {
                                cli::MatchMethod::Exact | cli::MatchMethod::Contains => {
                                    content.contains(pattern)
                                }
                                cli::MatchMethod::Regex => {
                                    regex::Regex::new(pattern).is_ok_and(|re| re.is_match(&content))
                                }
                                cli::MatchMethod::Word => {
                                    let word_pattern = format!(r"\b{}\b", regex::escape(pattern));
                                    regex::Regex::new(&word_pattern)
                                        .is_ok_and(|re| re.is_match(&content))
                                }
                            }
                        } else {
                            let strings: Vec<&str> = alt_report
                                .strings
                                .iter()
                                .map(|s| s.value.as_str())
                                .collect();
                            let exact = if method == cli::MatchMethod::Exact {
                                Some(pattern.to_string())
                            } else {
                                None
                            };
                            let contains = if method == cli::MatchMethod::Contains {
                                Some(pattern.to_string())
                            } else {
                                None
                            };
                            let regex = if method == cli::MatchMethod::Regex {
                                Some(pattern.to_string())
                            } else {
                                None
                            };
                            let word = if method == cli::MatchMethod::Word {
                                Some(pattern.to_string())
                            } else {
                                None
                            };
                            let matches = find_matching_strings(
                                &strings,
                                exact.as_deref(),
                                contains.as_deref(),
                                regex.as_deref(),
                                word.as_deref(),
                                case_insensitive,
                            );
                            !matches.is_empty()
                        }
                    }
                    cli::SearchType::StringLiteral => {
                        let strings: Vec<&str> = alt_report
                            .strings
                            .iter()
                            .filter(|s| s.section.as_deref() == Some("ast"))
                            .map(|s| s.value.as_str())
                            .collect();
                        let exact = if method == cli::MatchMethod::Exact {
                            Some(pattern.to_string())
                        } else {
                            None
                        };
                        let contains = if method == cli::MatchMethod::Contains {
                            Some(pattern.to_string())
                        } else {
                            None
                        };
                        let regex = if method == cli::MatchMethod::Regex {
                            Some(pattern.to_string())
                        } else {
                            None
                        };
                        let word = if method == cli::MatchMethod::Word {
                            Some(pattern.to_string())
                        } else {
                            None
                        };
                        let matches = find_matching_strings(
                            &strings,
                            exact.as_deref(),
                            contains.as_deref(),
                            regex.as_deref(),
                            word.as_deref(),
                            case_insensitive,
                        );
                        !matches.is_empty()
                    }
                    cli::SearchType::Symbol => {
                        let symbols: Vec<&str> = alt_report
                            .imports
                            .iter()
                            .map(|i| i.symbol.as_str())
                            .chain(alt_report.exports.iter().map(|e| e.symbol.as_str()))
                            .chain(alt_report.functions.iter().map(|f| f.name.as_str()))
                            .collect();
                        let exact = if method == cli::MatchMethod::Exact {
                            Some(pattern.to_string())
                        } else {
                            None
                        };
                        let regex = if method == cli::MatchMethod::Regex {
                            Some(pattern.to_string())
                        } else {
                            None
                        };
                        let matches = find_matching_symbols(
                            &symbols,
                            exact.as_deref(),
                            None,
                            regex.as_deref(),
                            false,
                        );
                        !matches.is_empty()
                    }
                    cli::SearchType::Raw => {
                        let content = String::from_utf8_lossy(binary_data);
                        match method {
                            cli::MatchMethod::Exact | cli::MatchMethod::Contains => {
                                content.contains(pattern)
                            }
                            cli::MatchMethod::Regex => {
                                regex::Regex::new(pattern).is_ok_and(|re| re.is_match(&content))
                            }
                            cli::MatchMethod::Word => {
                                let word_pattern = format!(r"\b{}\b", regex::escape(pattern));
                                regex::Regex::new(&word_pattern)
                                    .is_ok_and(|re| re.is_match(&content))
                            }
                        }
                    }
                    cli::SearchType::Kv
                    | cli::SearchType::Hex
                    | cli::SearchType::Encoded
                    | cli::SearchType::Section
                    | cli::SearchType::Metrics => false,
                };

                if would_match {
                    output.push_str(&format!(
                        "    Would match if file type was: {} (strings: {}, symbols: {})\n",
                        type_name, alt_context.string_count, alt_context.symbol_count
                    ));
                }
            }
        }
    }
}
