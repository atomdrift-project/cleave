//! One search per `test-match` search type.

// Split out of the parent module for size; it shares the parent's namespace.
#[allow(clippy::wildcard_imports)]
use super::*;

pub(super) fn string_value(ctx: &MatchCtx<'_>) -> Outcome {
    let MatchRequest {
        method,
        count_min,
        count_max,
        per_kb_min,
        per_kb_max,
        case_insensitive,
        section,
        offset,
        offset_range,
        section_offset,
        section_offset_range,
        is_check,
        ..
    } = ctx.request;
    let MatchCtx {
        pattern,
        file_type,
        binary_data,
        report,
        section_map,
        has_location_constraints,
        ..
    } = *ctx;
    let resolve_effective_range = |a, b, c, d, e| ctx.effective_range(a, b, c, d, e);
    let (matched, match_count, out) = {
        // Resolve effective range for filtering strings by offset
        let effective_range = resolve_effective_range(
            section,
            offset,
            offset_range,
            section_offset,
            section_offset_range,
        );

        let (range_start, range_end) = match effective_range {
            Ok((s, e)) => (s, e),
            Err(msg) => {
                let mut out = String::new();
                out.push_str("Search: strings\n");
                out.push_str(&format!("Pattern: {}\n", pattern));
                out.push_str(&format!("\n{}\n", "NOT MATCHED".red().bold()));
                out.push_str(&format!("{}\n", msg));
                if section_map.has_sections() {
                    out.push_str(&format!(
                        "Available sections: {}\n",
                        section_map.section_names().join(", ")
                    ));
                }
                return Outcome::Done(out);
            }
        };

        // Filter strings by offset range if location constraints are specified
        let filtered_strings: Vec<&types::StringInfo> = if has_location_constraints {
            report
                .strings
                .iter()
                .filter(|s| {
                    if let Some(off) = s.offset {
                        let off = off as usize;
                        off >= range_start && off < range_end
                    } else {
                        false // Skip strings without offset info
                    }
                })
                .collect()
        } else {
            report.strings.iter().collect()
        };

        let strings: Vec<&str> = filtered_strings.iter().map(|s| s.value.as_str()).collect();

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

        let matched_strings = find_matching_strings(
            &strings,
            exact.as_deref(),
            contains.as_deref(),
            regex.as_deref(),
            word.as_deref(),
            case_insensitive,
        );

        // Filter by validator if required
        let matched_strings: Vec<&str> = if is_check.is_some() {
            matched_strings
                .into_iter()
                .filter(|s| validate_match(s, is_check))
                .collect()
        } else {
            matched_strings
        };
        let match_count = matched_strings.len();

        // Use effective range size for density calculations when location constraints apply
        let effective_size = if has_location_constraints {
            range_end.saturating_sub(range_start)
        } else {
            binary_data.len()
        };
        let effective_size_kb = effective_size as f64 / 1024.0;
        let density = if effective_size_kb > 0.0 {
            match_count as f64 / effective_size_kb
        } else {
            0.0
        };

        // Check all constraints
        let count_min_ok = match_count >= count_min;
        let count_max_ok = count_max.is_none_or(|max| match_count <= max);
        let per_kb_min_ok = per_kb_min.is_none_or(|min| density >= min);
        let per_kb_max_ok = per_kb_max.is_none_or(|max| density <= max);
        let matched = count_min_ok && count_max_ok && per_kb_min_ok && per_kb_max_ok;

        let mut out = String::new();
        out.push_str("Search: strings\n");
        out.push_str(&format!("  count_min: {}", count_min));
        if let Some(max) = count_max {
            out.push_str(&format!(", count_max: {}", max));
        }
        if let Some(min) = per_kb_min {
            out.push_str(&format!(", per_kb_min: {:.2}", min));
        }
        if let Some(max) = per_kb_max {
            out.push_str(&format!(", per_kb_max: {:.2}", max));
        }
        if let Some(validator) = is_check {
            out.push_str(&format!(", is: {:?}", validator));
        }
        out.push('\n');
        out.push_str(&format!("Pattern: {}\n", pattern));

        // Show location constraints if specified
        if has_location_constraints {
            out.push_str(&format!(
                "Search range: [{:#x}, {:#x}) of {} bytes\n",
                range_start,
                range_end,
                binary_data.len()
            ));
        }

        out.push_str(&format!(
            "Context: file_type={:?}, strings={} (filtered from {})\n",
            file_type,
            filtered_strings.len(),
            report.strings.len()
        ));

        if matched {
            out.push_str(&format!(
                "\n{} ({} matches, {:.3}/KB in search range)\n",
                "MATCHED".green().bold(),
                match_count,
                density
            ));
            let display_count = match_count.min(10);
            for s in matched_strings.iter().take(display_count) {
                out.push_str(&format!("  \"{}\"\n", s));
            }
            if match_count > display_count {
                out.push_str(&format!("  ... and {} more\n", match_count - display_count));
            }
        } else {
            out.push_str(&format!("\n{}\n", "NOT MATCHED".red().bold()));
            out.push_str(&format!(
                "Found {} matches ({:.3}/KB in search range)\n",
                match_count, density
            ));
            // Show which constraints failed
            if !count_min_ok {
                out.push_str(&format!(
                    "  count_min: {} < {} (FAILED)\n",
                    match_count, count_min
                ));
            }
            if !count_max_ok && let Some(max) = count_max {
                out.push_str(&format!(
                    "  count_max: {} > {} (FAILED)\n",
                    match_count, max
                ));
            }
            if !per_kb_min_ok && let Some(min) = per_kb_min {
                out.push_str(&format!(
                    "  per_kb_min: {:.3} < {:.3} (FAILED)\n",
                    density, min
                ));
            }
            if !per_kb_max_ok && let Some(max) = per_kb_max {
                out.push_str(&format!(
                    "  per_kb_max: {:.3} > {:.3} (FAILED)\n",
                    density, max
                ));
            }
        }

        (matched, match_count, out)
    };
    Outcome::Searched(matched, match_count, out)
}

pub(super) fn text(ctx: &MatchCtx<'_>) -> Outcome {
    let MatchRequest {
        method,
        count_min,
        count_max,
        per_kb_min,
        per_kb_max,
        case_insensitive,
        section,
        offset,
        offset_range,
        section_offset,
        section_offset_range,
        is_check,
        encoding,
        ..
    } = ctx.request;
    let MatchCtx {
        pattern,
        file_type,
        internal_file_type,
        binary_data,
        report,
        context_info,
        section_map,
        has_location_constraints,
        ..
    } = *ctx;
    let resolve_effective_range = |a, b, c, d, e| ctx.effective_range(a, b, c, d, e);
    let (matched, match_count, out) = {
        let effective_range = resolve_effective_range(
            section,
            offset,
            offset_range,
            section_offset,
            section_offset_range,
        );
        let (range_start, range_end) = match effective_range {
            Ok((s, e)) => (s, e),
            Err(msg) => {
                let mut out = String::new();
                out.push_str("Search: text\n");
                out.push_str(&format!("Pattern: {}\n", pattern));
                out.push_str(&format!("\n{}\n", "NOT MATCHED".red().bold()));
                out.push_str(&format!("{}\n", msg));
                if section_map.has_sections() {
                    out.push_str(&format!(
                        "Available sections: {}\n",
                        section_map.section_names().join(", ")
                    ));
                }
                return Outcome::Done(out);
            }
        };

        // `--encoding none` on a text search is the CLI spelling of the
        // trait option `encoding: none`, so `test-match` can reproduce
        // what `analyze` and `test-rules` do for such a condition.
        let text_encoding_scope = match encoding {
            Some(e) if e.eq_ignore_ascii_case("none") => {
                Some(crate::composite_rules::condition::TextEncodingScope::None)
            }
            Some(e) if e.eq_ignore_ascii_case("any") => {
                Some(crate::composite_rules::condition::TextEncodingScope::Any)
            }
            _ => None,
        };
        let pattern_value = pattern.to_string();
        let section_value = section.map(str::to_owned);
        let params = StringParams {
            encoding: text_encoding_scope,
            exact: (method == cli::MatchMethod::Exact).then_some(&pattern_value),
            substr: (method == cli::MatchMethod::Contains).then_some(&pattern_value),
            regex: (method == cli::MatchMethod::Regex).then_some(&pattern_value),
            word: (method == cli::MatchMethod::Word).then_some(&pattern_value),
            case_insensitive,
            length_min: None,
            length_max: None,
            exclude_html_comments: false,
            exclude_comments: false,
            is_check,
            section: section_value.as_ref(),
            offset,
            offset_range,
            section_offset,
            section_offset_range,
            arch_clamp: None,
        };

        let ctx = composite_rules::EvaluationContext::new(
            report,
            binary_data,
            internal_file_type,
            ctx.platforms,
            None,
            None,
        )
        .with_section_map(section_map);

        let result = composite_rules::evaluators::eval_text(&params, None, &ctx, None);
        let match_count = result.match_count;
        let effective_size = if has_location_constraints {
            range_end.saturating_sub(range_start)
        } else {
            binary_data.len()
        };
        let effective_size_kb = effective_size as f64 / 1024.0;
        let density = if effective_size_kb > 0.0 {
            match_count as f64 / effective_size_kb
        } else {
            0.0
        };

        let count_min_ok = match_count >= count_min;
        let count_max_ok = count_max.is_none_or(|max| match_count <= max);
        let per_kb_min_ok = per_kb_min.is_none_or(|min| density >= min);
        let per_kb_max_ok = per_kb_max.is_none_or(|max| density <= max);
        let matched =
            result.matched && count_min_ok && count_max_ok && per_kb_min_ok && per_kb_max_ok;

        let mode = if internal_file_type.uses_raw_text_search_in(ctx.report) {
            "raw-text"
        } else {
            "extracted-strings"
        };

        let mut out = String::new();
        out.push_str(&format!("Search: text ({})\n", mode));
        out.push_str(&format!("Pattern: {}\n", pattern));
        if has_location_constraints {
            out.push_str(&format!(
                "Search range: [{:#x}, {:#x}) of {} bytes\n",
                range_start,
                range_end,
                binary_data.len()
            ));
        }
        out.push_str(&format!(
            "Context: file_type={:?}, strings={}, symbols={}\n",
            file_type, context_info.string_count, context_info.symbol_count
        ));

        if matched {
            out.push_str(&format!(
                "\n{} ({} matches, {:.3}/KB)\n",
                "MATCHED".green().bold(),
                match_count,
                density
            ));
            for ev in result.evidence.iter().take(10) {
                out.push_str(&format!("  {}\n", ev.value));
            }
        } else {
            out.push_str(&format!("\n{}\n", "NOT MATCHED".red().bold()));
            out.push_str(&format!(
                "Found {} matches ({:.3}/KB)\n",
                match_count, density
            ));
        }

        (matched, match_count, out)
    };
    Outcome::Searched(matched, match_count, out)
}

pub(super) fn string_literal(ctx: &MatchCtx<'_>) -> Outcome {
    let MatchRequest {
        method,
        count_min,
        count_max,
        per_kb_min,
        per_kb_max,
        case_insensitive,
        section,
        offset,
        offset_range,
        section_offset,
        section_offset_range,
        is_check,
        ..
    } = ctx.request;
    let MatchCtx {
        pattern,
        file_type,
        internal_file_type,
        binary_data,
        report,
        section_map,
        has_location_constraints,
        ..
    } = *ctx;
    let resolve_effective_range = |a, b, c, d, e| ctx.effective_range(a, b, c, d, e);
    let (matched, match_count, out) = {
        let effective_range = resolve_effective_range(
            section,
            offset,
            offset_range,
            section_offset,
            section_offset_range,
        );
        let (range_start, range_end) = match effective_range {
            Ok((s, e)) => (s, e),
            Err(msg) => {
                let mut out = String::new();
                out.push_str("Search: string_literal\n");
                out.push_str(&format!("Pattern: {}\n", pattern));
                out.push_str(&format!("\n{}\n", "NOT MATCHED".red().bold()));
                out.push_str(&format!("{}\n", msg));
                if section_map.has_sections() {
                    out.push_str(&format!(
                        "Available sections: {}\n",
                        section_map.section_names().join(", ")
                    ));
                }
                return Outcome::Done(out);
            }
        };

        let pattern_value = pattern.to_string();
        let section_value = section.map(str::to_owned);
        let params = StringParams {
            encoding: None,
            exact: (method == cli::MatchMethod::Exact).then_some(&pattern_value),
            substr: (method == cli::MatchMethod::Contains).then_some(&pattern_value),
            regex: (method == cli::MatchMethod::Regex).then_some(&pattern_value),
            word: (method == cli::MatchMethod::Word).then_some(&pattern_value),
            case_insensitive,
            length_min: None,
            length_max: None,
            exclude_html_comments: false,
            exclude_comments: false,
            is_check,
            section: section_value.as_ref(),
            offset,
            offset_range,
            section_offset,
            section_offset_range,
            arch_clamp: None,
        };

        let ctx = composite_rules::EvaluationContext::new(
            report,
            binary_data,
            internal_file_type,
            ctx.platforms,
            None,
            None,
        )
        .with_section_map(section_map);

        let result = composite_rules::evaluators::eval_string_literal(&params, None, &ctx);
        let match_count = result.match_count;
        let effective_size = if has_location_constraints {
            range_end.saturating_sub(range_start)
        } else {
            binary_data.len()
        };
        let effective_size_kb = effective_size as f64 / 1024.0;
        let density = if effective_size_kb > 0.0 {
            match_count as f64 / effective_size_kb
        } else {
            0.0
        };
        let matched = result.matched
            && match_count >= count_min
            && count_max.is_none_or(|max| match_count <= max)
            && per_kb_min.is_none_or(|min| density >= min)
            && per_kb_max.is_none_or(|max| density <= max);

        let mut out = String::new();
        out.push_str("Search: string_literal\n");
        out.push_str(&format!("Pattern: {}\n", pattern));
        if has_location_constraints {
            out.push_str(&format!(
                "Search range: [{:#x}, {:#x}) of {} bytes\n",
                range_start,
                range_end,
                binary_data.len()
            ));
        }
        out.push_str(&format!(
            "Context: file_type={:?}, ast_strings={}\n",
            file_type,
            report
                .strings
                .iter()
                .filter(|s| s.section.as_deref() == Some("ast"))
                .count()
        ));

        if matched {
            out.push_str(&format!(
                "\n{} ({} matches, {:.3}/KB)\n",
                "MATCHED".green().bold(),
                match_count,
                density
            ));
            for ev in result.evidence.iter().take(10) {
                out.push_str(&format!("  {}\n", ev.value));
            }
        } else {
            out.push_str(&format!("\n{}\n", "NOT MATCHED".red().bold()));
            out.push_str(&format!(
                "Found {} matches ({:.3}/KB)\n",
                match_count, density
            ));
            if !internal_file_type.supports_ast_queries() {
                out.push_str("This file type does not support AST-backed literal search.\n");
            }
        }

        (matched, match_count, out)
    };
    Outcome::Searched(matched, match_count, out)
}

pub(super) fn symbol(ctx: &MatchCtx<'_>) -> Outcome {
    let MatchRequest {
        method,
        case_insensitive,
        ..
    } = ctx.request;
    let MatchCtx {
        pattern,
        file_type,
        report,
        context_info,
        ..
    } = *ctx;
    let (matched, match_count, out) = {
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

        let matched_symbols = find_matching_symbols(
            &symbols,
            exact.as_deref(),
            None,
            regex.as_deref(),
            case_insensitive,
        );
        let matched = !matched_symbols.is_empty();

        let mut out = String::new();
        out.push_str("Search: symbols\n");
        if case_insensitive {
            out.push_str("  case_insensitive: true\n");
        }
        out.push_str(&format!("Pattern: {}\n", pattern));
        out.push_str(&format!(
            "Context: file_type={:?}, strings={}, symbols={}\n",
            file_type, context_info.string_count, context_info.symbol_count
        ));

        if matched {
            out.push_str(&format!(
                "\n{} ({} matches)\n",
                "MATCHED".green().bold(),
                matched_symbols.len()
            ));
            let display_count = matched_symbols.len().min(10);
            for s in matched_symbols.iter().take(display_count) {
                out.push_str(&format!("  \"{}\"\n", s));
            }
            if matched_symbols.len() > display_count {
                out.push_str(&format!(
                    "  ... and {} more\n",
                    matched_symbols.len() - display_count
                ));
            }
        } else {
            out.push_str(&format!("\n{}\n", "NOT MATCHED".red().bold()));
            out.push_str(&format!(
                "Total symbols: {} ({} imports, {} exports)\n",
                symbols.len(),
                report.imports.len(),
                report.exports.len()
            ));
        }

        (matched, matched_symbols.len(), out)
    };
    Outcome::Searched(matched, match_count, out)
}

pub(super) fn raw(ctx: &MatchCtx<'_>) -> Outcome {
    let MatchRequest {
        method,
        count_min,
        count_max,
        per_kb_min,
        per_kb_max,
        section,
        offset,
        offset_range,
        section_offset,
        section_offset_range,
        is_check,
        ..
    } = ctx.request;
    let MatchCtx {
        pattern,
        file_type,
        binary_data,
        section_map,
        has_location_constraints,
        ..
    } = *ctx;
    let resolve_effective_range = |a, b, c, d, e| ctx.effective_range(a, b, c, d, e);
    let (matched, match_count, out) = {
        // Resolve effective range for content search
        let effective_range = resolve_effective_range(
            section,
            offset,
            offset_range,
            section_offset,
            section_offset_range,
        );

        let (range_start, range_end) = match effective_range {
            Ok((s, e)) => (s, e),
            Err(msg) => {
                let mut out = String::new();
                out.push_str("Search: content\n");
                out.push_str(&format!("Pattern: {}\n", pattern));
                out.push_str(&format!("\n{}\n", "NOT MATCHED".red().bold()));
                out.push_str(&format!("{}\n", msg));
                if section_map.has_sections() {
                    out.push_str(&format!(
                        "Available sections: {}\n",
                        section_map.section_names().join(", ")
                    ));
                }
                return Outcome::Done(out);
            }
        };

        // Slice binary data to effective range
        let search_data = &binary_data[range_start..range_end];
        let content = String::from_utf8_lossy(search_data);

        // Count all matches for density calculation
        // When external_ip is set, only count matches that contain external IPs
        let match_count = match method {
            // Exact: entire content slice must equal the pattern
            cli::MatchMethod::Exact => {
                let matched = &*content == pattern && validate_match(pattern, is_check);
                if matched { 1 } else { 0 }
            }
            cli::MatchMethod::Contains => {
                if is_check.is_some() {
                    // For validator, we need to check context around each match
                    let mut count = 0;
                    let mut start = 0;
                    while let Some(pos) = content[start..].find(pattern) {
                        let abs_pos = start + pos;
                        // Get context around match to check for validator
                        let context_start = abs_pos.saturating_sub(50);
                        let context_end = (abs_pos + pattern.len() + 50).min(content.len());
                        let context = &content[context_start..context_end];
                        if validate_match(context, is_check) {
                            count += 1;
                        }
                        start = abs_pos + 1;
                    }
                    count
                } else {
                    content.matches(pattern).count()
                }
            }
            cli::MatchMethod::Regex => regex::Regex::new(pattern)
                .map(|re| {
                    if is_check.is_some() {
                        re.find_iter(&content)
                            .filter(|m| validate_match(m.as_str(), is_check))
                            .count()
                    } else {
                        re.find_iter(&content).count()
                    }
                })
                .unwrap_or(0),
            cli::MatchMethod::Word => {
                let word_pattern = format!(r"\b{}\b", regex::escape(pattern));
                regex::Regex::new(&word_pattern)
                    .map(|re| {
                        if is_check.is_some() {
                            re.find_iter(&content)
                                .filter(|m| validate_match(m.as_str(), is_check))
                                .count()
                        } else {
                            re.find_iter(&content).count()
                        }
                    })
                    .unwrap_or(0)
            }
        };

        // Use effective range size for density calculations
        let effective_size = range_end.saturating_sub(range_start);
        let effective_size_kb = effective_size as f64 / 1024.0;
        let density = if effective_size_kb > 0.0 {
            match_count as f64 / effective_size_kb
        } else {
            0.0
        };

        // Check all constraints
        let count_min_ok = match_count >= count_min;
        let count_max_ok = count_max.is_none_or(|max| match_count <= max);
        let per_kb_min_ok = per_kb_min.is_none_or(|min| density >= min);
        let per_kb_max_ok = per_kb_max.is_none_or(|max| density <= max);
        let matched = count_min_ok && count_max_ok && per_kb_min_ok && per_kb_max_ok;

        let mut out = String::new();
        out.push_str("Search: content\n");
        out.push_str(&format!("  count_min: {}", count_min));
        if let Some(max) = count_max {
            out.push_str(&format!(", count_max: {}", max));
        }
        if let Some(min) = per_kb_min {
            out.push_str(&format!(", per_kb_min: {:.2}", min));
        }
        if let Some(max) = per_kb_max {
            out.push_str(&format!(", per_kb_max: {:.2}", max));
        }
        if let Some(validator) = is_check {
            out.push_str(&format!(", is: {:?}", validator));
        }
        out.push('\n');
        out.push_str(&format!("Pattern: {}\n", pattern));

        // Show location constraints if specified
        if has_location_constraints {
            out.push_str(&format!(
                "Search range: [{:#x}, {:#x}) of {} bytes\n",
                range_start,
                range_end,
                binary_data.len()
            ));
        }

        out.push_str(&format!(
            "Context: file_type={:?}, search_size={} bytes\n",
            file_type, effective_size
        ));

        if matched {
            out.push_str(&format!(
                "\n{} ({} matches, {:.3}/KB in search range)\n",
                "MATCHED".green().bold(),
                match_count,
                density
            ));
        } else {
            out.push_str(&format!("\n{}\n", "NOT MATCHED".red().bold()));
            out.push_str(&format!(
                "Found {} matches ({:.3}/KB in search range)\n",
                match_count, density
            ));
            // Show which constraints failed
            if !count_min_ok {
                out.push_str(&format!(
                    "  count_min: {} < {} (FAILED)\n",
                    match_count, count_min
                ));
            }
            if !count_max_ok && let Some(max) = count_max {
                out.push_str(&format!(
                    "  count_max: {} > {} (FAILED)\n",
                    match_count, max
                ));
            }
            if !per_kb_min_ok && let Some(min) = per_kb_min {
                out.push_str(&format!(
                    "  per_kb_min: {:.3} < {:.3} (FAILED)\n",
                    density, min
                ));
            }
            if !per_kb_max_ok && let Some(max) = per_kb_max {
                out.push_str(&format!(
                    "  per_kb_max: {:.3} > {:.3} (FAILED)\n",
                    density, max
                ));
            }
        }

        (matched, match_count, out)
    };
    Outcome::Searched(matched, match_count, out)
}

pub(super) fn kv(ctx: &MatchCtx<'_>) -> Outcome {
    let MatchRequest {
        method,
        kv_path,
        exists: kv_exists,
        size_min: kv_size_min,
        size_max: kv_size_max,
        case_insensitive,
        is_check,
        ..
    } = ctx.request;
    let MatchCtx {
        pattern,
        file_type,
        binary_data,
        report,
        ..
    } = *ctx;
    let (matched, match_count, out) = {
        let kv_path_str = kv_path.unwrap_or_default();

        // Build the kv condition
        let exact = if method == cli::MatchMethod::Exact && !pattern.is_empty() {
            Some(pattern.to_string())
        } else {
            None
        };
        let substr = if method == cli::MatchMethod::Contains && !pattern.is_empty() {
            Some(pattern.to_string())
        } else {
            None
        };
        let regex_str = if method == cli::MatchMethod::Regex && !pattern.is_empty() {
            Some(pattern.to_string())
        } else {
            None
        };
        let condition = composite_rules::Condition::Kv(composite_rules::KvQuery {
            match_mode: Default::default(),
            path: kv_path_str.to_string(),
            exact: exact.clone(),
            substr: substr.clone(),
            regex: regex_str.clone(),
            eq: None,
            ne: None,
            case_insensitive,
            exists: kv_exists,
            length_min: kv_size_min,
            length_max: kv_size_max,
            is_check,
            // `test-match` builds the condition from CLI flags, which
            // carry no exclusions.
            not: None,
        });

        // Create minimal context for kv evaluation
        let internal_file_type = match file_type {
            FileType::Pe => composite_rules::FileType::Pe,
            FileType::Elf => composite_rules::FileType::Elf,
            FileType::MachO => composite_rules::FileType::Macho,
            FileType::JavaScript => composite_rules::FileType::JavaScript,
            FileType::Python => composite_rules::FileType::Python,
            FileType::Java => composite_rules::FileType::Java,
            FileType::Go => composite_rules::FileType::Go,
            FileType::Rust => composite_rules::FileType::Rust,
            FileType::Ruby => composite_rules::FileType::Ruby,
            FileType::Shell => composite_rules::FileType::Shell,
            FileType::Jcl => composite_rules::FileType::Jcl,
            FileType::PowerShell => composite_rules::FileType::PowerShell,
            FileType::Php => composite_rules::FileType::Php,
            FileType::SystemdService => composite_rules::FileType::SystemdService,
            _ => composite_rules::FileType::All,
        };
        let eval_ctx = composite_rules::EvaluationContext::new(
            report,
            binary_data,
            internal_file_type,
            ctx.platforms,
            None,
            None,
        );

        // Use the actual value evaluator with caching
        let evidence = composite_rules::evaluators::evaluate_kv(&condition, &eval_ctx);
        let _matched = evidence.is_some();

        let mut out = String::new();
        out.push_str("Search: value\n");
        out.push_str(&format!("Path: {}\n", kv_path_str));
        if !pattern.is_empty() {
            out.push_str(&format!(
                "Pattern: {} ({})\n",
                pattern,
                format!("{:?}", method).to_lowercase()
            ));
        } else {
            out.push_str("Pattern: (existence check)\n");
        }
        out.push_str(&format!(
            "Context: file_type={:?}, file_size={} bytes\n",
            file_type,
            binary_data.len()
        ));

        if let Some(ev) = evidence {
            out.push_str(&format!("\n{}\n", "MATCHED".green().bold()));
            out.push_str(&format!("  Value: {}\n", ev.value));
            if let Some(loc) = &ev.location {
                out.push_str(&format!("  Location: {}\n", loc));
            }
            (true, 1, out)
        } else {
            out.push_str(&format!("\n{}\n", "NOT MATCHED".red().bold()));

            // Try to parse and show available keys
            if let Ok(content) = std::str::from_utf8(binary_data) {
                if let Ok(json) = serde_json::from_str::<serde_json::Value>(content) {
                    if let Some(obj) = json.as_object() {
                        let keys: Vec<_> = obj.keys().take(15).collect();
                        out.push_str(&format!("Available top-level keys: {:?}\n", keys));
                    }
                } else if let Ok(yaml) = crate::yaml::from_str::<serde_json::Value>(content)
                    && let Some(obj) = yaml.as_object()
                {
                    let keys: Vec<_> = obj.keys().take(15).collect();
                    out.push_str(&format!("Available top-level keys: {:?}\n", keys));
                }
            }

            (false, 0, out)
        }
    };
    Outcome::Searched(matched, match_count, out)
}

pub(super) fn hex(ctx: &MatchCtx<'_>) -> Outcome {
    let MatchRequest {
        section,
        offset,
        offset_range,
        section_offset,
        section_offset_range,
        ..
    } = ctx.request;
    let MatchCtx {
        pattern,
        file_type,
        binary_data,
        report,
        ..
    } = *ctx;
    let (matched, match_count, out) = {
        use composite_rules::SectionMap;
        use composite_rules::evaluators::eval_hex;

        // Create section map for location constraints
        let section_map = SectionMap::from_binary(binary_data);

        // Resolve effective search range and convert to offset/offset_range for eval_hex
        let (effective_start, effective_end, _resolved_offset, _resolved_offset_range) =
            if let Some(sec) = section {
                if let Some(bounds) = section_map.bounds(sec) {
                    // Apply section-relative offsets if specified
                    if let Some(sec_off) = section_offset {
                        let abs_off = if sec_off >= 0 {
                            bounds.0 + sec_off as u64
                        } else {
                            bounds.1.saturating_sub((-sec_off) as u64)
                        };
                        (
                            abs_off as usize,
                            (abs_off + 1) as usize,
                            Some(abs_off as i64),
                            None,
                        )
                    } else if let Some((start, end_opt)) = section_offset_range {
                        let section_size = bounds.1 - bounds.0;
                        let rel_start = if start >= 0 {
                            start as u64
                        } else {
                            section_size.saturating_sub((-start) as u64)
                        };
                        let rel_end = end_opt
                            .map(|e| {
                                if e >= 0 {
                                    e as u64
                                } else {
                                    section_size.saturating_sub((-e) as u64)
                                }
                            })
                            .unwrap_or(section_size);
                        let abs_start = (bounds.0 + rel_start) as usize;
                        let abs_end = (bounds.0 + rel_end).min(bounds.1) as usize;
                        (
                            abs_start,
                            abs_end,
                            None,
                            Some((abs_start as i64, Some(abs_end as i64))),
                        )
                    } else {
                        // Entire section
                        (
                            bounds.0 as usize,
                            bounds.1 as usize,
                            None,
                            Some((bounds.0 as i64, Some(bounds.1 as i64))),
                        )
                    }
                } else {
                    let mut out = String::new();
                    out.push_str("Search: hex\n");
                    out.push_str(&format!("Pattern: {}\n", pattern));
                    out.push_str(&format!("\n{}\n", "NOT MATCHED".red().bold()));
                    out.push_str(&format!("Section '{}' not found in binary\n", sec));
                    if section_map.has_sections() {
                        out.push_str(&format!(
                            "Available sections: {}\n",
                            section_map.section_names().join(", ")
                        ));
                    }
                    return Outcome::Done(out);
                }
            } else if let Some(off) = offset {
                let file_size = binary_data.len();
                let abs_off = if off >= 0 {
                    off as usize
                } else {
                    file_size.saturating_sub((-off) as usize)
                };
                (abs_off, abs_off + 1, offset, None)
            } else if let Some((start, end_opt)) = offset_range {
                let file_size = binary_data.len();
                let abs_start = if start >= 0 {
                    start as usize
                } else {
                    file_size.saturating_sub((-start) as usize)
                };
                let abs_end = end_opt
                    .map(|e| {
                        if e >= 0 {
                            e as usize
                        } else {
                            file_size.saturating_sub((-e) as usize)
                        }
                    })
                    .unwrap_or(file_size);
                (abs_start, abs_end.min(file_size), None, offset_range)
            } else {
                (0, binary_data.len(), None, None)
            };

        // Create evaluation context
        let ctx = composite_rules::EvaluationContext::new(
            report,
            binary_data,
            composite_rules::FileType::All,
            ctx.platforms,
            None,
            None,
        )
        .with_section_map(&section_map);

        // Evaluate hex pattern with resolved location constraints
        let result = eval_hex(
            pattern,
            None,
            &composite_rules::evaluators::ContentLocationParams {
                section: section.map(std::string::ToString::to_string),
                offset,
                offset_range,
                section_offset,
                section_offset_range,
                arch_clamp: None,
            },
            &ctx,
            None,
        );

        let match_count = result.evidence.len();
        let effective_size = effective_end.saturating_sub(effective_start);
        let effective_size_kb = effective_size as f64 / 1024.0;
        let density = if effective_size_kb > 0.0 {
            match_count as f64 / effective_size_kb
        } else {
            0.0
        };

        let mut out = String::new();
        out.push_str("Search: hex\n");
        out.push_str(&format!("Pattern: {}\n", pattern));

        // Show location constraints
        if let Some(sec) = section {
            out.push_str(&format!("Section: {}\n", sec));
        }
        if let Some(off) = offset {
            out.push_str(&format!("Offset: {:#x}\n", off));
        }
        if let Some((start, end_opt)) = offset_range {
            if let Some(end) = end_opt {
                out.push_str(&format!("Offset range: [{:#x}, {:#x})\n", start, end));
            } else {
                out.push_str(&format!("Offset range: [{:#x}, end)\n", start));
            }
        }

        out.push_str(&format!(
            "Context: file_type={:?}, file_size={} bytes",
            file_type,
            binary_data.len()
        ));
        if effective_size != binary_data.len() {
            out.push_str(&format!(
                ", search_range=[{:#x},{:#x}) ({} bytes)",
                effective_start, effective_end, effective_size
            ));
        }
        if section_map.has_sections() {
            out.push_str(&format!(", sections={}", section_map.section_names().len()));
        }
        out.push('\n');

        if result.matched {
            out.push_str(&format!(
                "\n{} ({} matches, {:.3}/KB)\n",
                "MATCHED".green().bold(),
                match_count,
                density
            ));
            let display_count = match_count.min(10);
            for ev in result.evidence.iter().take(display_count) {
                out.push_str(&format!(
                    "  {} @ {}\n",
                    ev.value,
                    ev.location.as_deref().unwrap_or("?")
                ));
            }
            if match_count > display_count {
                out.push_str(&format!("  ... and {} more\n", match_count - display_count));
            }
        } else {
            out.push_str(&format!("\n{}\n", "NOT MATCHED".red().bold()));
            out.push_str(&format!(
                "Found {} matches ({:.3}/KB)\n",
                match_count, density
            ));

            if !result.warnings.is_empty() {
                out.push_str("\n  Warnings:\n");
                for warning in &result.warnings {
                    out.push_str(&format!("    - {warning}\n"));
                }
            }

            // Show available sections as suggestion
            if section_map.has_sections() && section.is_none() {
                out.push_str(&format!(
                    "\nBinary has sections: {} - try --section for targeted search\n",
                    section_map.section_names().join(", ")
                ));
            }
        }

        (result.matched, match_count, out)
    };
    Outcome::Searched(matched, match_count, out)
}

pub(super) fn encoded(ctx: &MatchCtx<'_>) -> Outcome {
    let MatchRequest {
        method,
        count_min,
        count_max,
        per_kb_min,
        per_kb_max,
        case_insensitive,
        is_check,
        encoding,
        ..
    } = ctx.request;
    let MatchCtx {
        pattern,
        file_type,
        binary_data,
        report,
        ..
    } = *ctx;
    let (matched, match_count, out) = {
        // Search in encoded/decoded strings with optional encoding filter
        // Parse encoding parameter: single ("base64"), multiple ("base64,hex"), or None (all)
        let encoding_filter: Option<Vec<String>> =
            encoding.map(|enc_str| enc_str.split(',').map(|s| s.trim().to_string()).collect());

        // Filter strings by encoding_chain
        let encoded_strings: Vec<&str> = report
            .strings
            .iter()
            .filter(|s| {
                if s.encoding_chain.is_empty() {
                    return false; // Not an encoded string
                }
                match &encoding_filter {
                    None => true, // No filter: accept all encoded strings
                    Some(filters) => {
                        // Accept if ANY filter matches (OR logic)
                        filters.iter().any(|enc| s.encoding_chain.contains(enc))
                    }
                }
            })
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

        let matched_strings = find_matching_strings(
            &encoded_strings,
            exact.as_deref(),
            contains.as_deref(),
            regex.as_deref(),
            word.as_deref(),
            case_insensitive,
        );

        // Filter by validator if required
        let matched_strings: Vec<&str> = if is_check.is_some() {
            matched_strings
                .into_iter()
                .filter(|s| validate_match(s, is_check))
                .collect()
        } else {
            matched_strings
        };
        let match_count = matched_strings.len();

        let file_size_kb = binary_data.len() as f64 / 1024.0;
        let density = if file_size_kb > 0.0 {
            match_count as f64 / file_size_kb
        } else {
            0.0
        };

        let count_min_ok = match_count >= count_min;
        let count_max_ok = count_max.is_none_or(|max| match_count <= max);
        let per_kb_min_ok = per_kb_min.is_none_or(|min| density >= min);
        let per_kb_max_ok = per_kb_max.is_none_or(|max| density <= max);
        let matched = count_min_ok && count_max_ok && per_kb_min_ok && per_kb_max_ok;

        let mut out = String::new();
        if let Some(ref filters) = encoding_filter {
            out.push_str(&format!("Search: encoded ({})\n", filters.join(", ")));
        } else {
            out.push_str("Search: encoded (all encodings)\n");
        }
        out.push_str(&format!("  count_min: {}", count_min));
        if let Some(max) = count_max {
            out.push_str(&format!(", count_max: {}", max));
        }
        if let Some(min) = per_kb_min {
            out.push_str(&format!(", per_kb_min: {:.2}", min));
        }
        if let Some(max) = per_kb_max {
            out.push_str(&format!(", per_kb_max: {:.2}", max));
        }
        if let Some(validator) = is_check {
            out.push_str(&format!(", is: {:?}", validator));
        }
        out.push('\n');
        out.push_str(&format!("Pattern: {}\n", pattern));
        out.push_str(&format!(
            "Context: file_type={:?}, encoded_strings={} (from {} total strings)\n",
            file_type,
            encoded_strings.len(),
            report.strings.len()
        ));

        if matched {
            out.push_str(&format!(
                "\n{} ({} matches, {:.3}/KB)\n",
                "MATCHED".green().bold(),
                match_count,
                density
            ));
            let display_count = match_count.min(10);
            for s in matched_strings.iter().take(display_count) {
                out.push_str(&format!("  \"{}\"\n", s));
            }
            if match_count > display_count {
                out.push_str(&format!("  ... and {} more\n", match_count - display_count));
            }
        } else {
            out.push_str(&format!("\n{}\n", "NOT MATCHED".red().bold()));
            out.push_str(&format!(
                "Found {} matches ({:.3}/KB)\n",
                match_count, density
            ));
            if encoded_strings.is_empty() {
                out.push_str("  No encoded strings found in this file\n");
                if encoding_filter.is_some() {
                    out.push_str("  Try removing --encoding to search all encoded strings\n");
                }
                out.push_str("  Try `--type text` or `--type raw` instead\n");
            }
        }

        (matched, match_count, out)
    };
    Outcome::Searched(matched, match_count, out)
}

pub(super) fn section(ctx: &MatchCtx<'_>) -> Outcome {
    let MatchRequest {
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
        report,
        ..
    } = *ctx;
    let (matched, match_count, out) = {
        // Search for sections by name, size, and/or entropy
        // count_min/count_max = number of matching sections
        // length_min/length_max = size of each section in bytes
        let sections: Vec<&types::Section> = report.sections.iter().collect();

        // Helper function to check if a section name matches the pattern
        let name_matches = |section_name: &str| -> bool {
            if pattern.is_empty() {
                return true; // No pattern = match all names
            }

            let name = if case_insensitive {
                section_name.to_lowercase()
            } else {
                section_name.to_string()
            };
            let pat = if case_insensitive {
                pattern.to_lowercase()
            } else {
                pattern.to_string()
            };

            match method {
                cli::MatchMethod::Exact => name == pat,
                cli::MatchMethod::Contains => name.contains(&pat),
                cli::MatchMethod::Regex => {
                    if let Ok(re) = regex::Regex::new(&pat) {
                        re.is_match(&name)
                    } else {
                        false
                    }
                }
                cli::MatchMethod::Word => {
                    // Word boundary match
                    let word_pattern = format!(r"\b{}\b", regex::escape(&pat));
                    if let Ok(re) = regex::Regex::new(&word_pattern) {
                        re.is_match(&name)
                    } else {
                        false
                    }
                }
            }
        };

        // Filter sections by name pattern, length constraints, and entropy
        let matched_sections: Vec<&types::Section> = sections
            .into_iter()
            .filter(|sec| {
                // Check name match
                if !name_matches(&sec.name) {
                    return false;
                }

                // Check length constraints
                if let Some(min) = length_min
                    && sec.size < min
                {
                    return false;
                }
                if let Some(max) = length_max
                    && sec.size > max
                {
                    return false;
                }

                // Check entropy constraints
                if let Some(min) = entropy_min
                    && sec.entropy < min
                {
                    return false;
                }
                if let Some(max) = entropy_max
                    && sec.entropy > max
                {
                    return false;
                }

                true
            })
            .collect();

        let match_count = matched_sections.len();

        // Check count constraints (number of matching sections)
        let count_ok = match_count >= count_min && count_max.is_none_or(|max| match_count <= max);
        let matched = count_ok;

        let mut out = String::new();
        out.push_str("Search: sections\n");
        let mut constraints = Vec::new();
        if count_min > 1 {
            constraints.push(format!("count_min: {}", count_min));
        }
        if let Some(max) = count_max {
            constraints.push(format!("count_max: {}", max));
        }
        if let Some(min) = length_min {
            constraints.push(format!("length_min: {}", min));
        }
        if let Some(max) = length_max {
            constraints.push(format!("length_max: {}", max));
        }
        if let Some(min) = entropy_min {
            constraints.push(format!("entropy_min: {:.2}", min));
        }
        if let Some(max) = entropy_max {
            constraints.push(format!("entropy_max: {:.2}", max));
        }
        if !constraints.is_empty() {
            out.push_str(&format!("  {}\n", constraints.join(", ")));
        }
        if !pattern.is_empty() {
            out.push_str(&format!("Pattern: {}\n", pattern));
        }
        out.push_str(&format!(
            "Context: file_type={:?}, total_sections={}\n",
            file_type,
            report.sections.len()
        ));

        if matched {
            out.push_str(&format!(
                "\n{} ({} sections matched)\n",
                "MATCHED".green().bold(),
                match_count
            ));
            for sec in matched_sections.iter().take(10) {
                let addr_str = sec
                    .address
                    .map(|a| format!("0x{:x}", a))
                    .unwrap_or_else(|| "-".to_string());
                out.push_str(&format!(
                    "  {} (addr: {}, size: {}, entropy: {:.2})\n",
                    sec.name, addr_str, sec.size, sec.entropy
                ));
            }
            if match_count > 10 {
                out.push_str(&format!("  ... and {} more\n", match_count - 10));
            }
        } else {
            out.push_str(&format!("\n{}\n", "NOT MATCHED".red().bold()));
            if report.sections.is_empty() {
                out.push_str("  No sections found (not a binary file?)\n");
                out.push_str("  Section search only works on ELF, PE, and Mach-O binaries\n");
            } else {
                out.push_str(&format!(
                    "Found 0 matching sections (out of {} total)\n",
                    report.sections.len()
                ));
                if !pattern.is_empty() {
                    out.push_str(&format!(
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
        }

        (matched, match_count, out)
    };
    Outcome::Searched(matched, match_count, out)
}

pub(super) fn metrics(ctx: &MatchCtx<'_>) -> Outcome {
    let MatchRequest {
        value_min,
        value_max,
        min_size,
        max_size,
        ..
    } = ctx.request;
    let MatchCtx {
        pattern,
        binary_data,
        report,
        ..
    } = *ctx;
    let (matched, match_count, out) = {
        // Test metrics conditions using eval_metrics
        let field = pattern;

        let mut out = String::new();
        out.push_str("Search: metrics\n");
        out.push_str(&format!("Field: {}\n", field));
        if let Some(min) = value_min {
            out.push_str(&format!("Min value: {}\n", min));
        }
        if let Some(max) = value_max {
            out.push_str(&format!("Max value: {}\n", max));
        }
        if let Some(min) = min_size {
            out.push_str(&format!("Min file size: {} bytes\n", min));
        }
        if let Some(max) = max_size {
            out.push_str(&format!("Max file size: {} bytes\n", max));
        }

        // Create evaluation context
        let ctx = composite_rules::EvaluationContext::new(
            report,
            binary_data,
            composite_rules::FileType::All, // FileType doesn't matter for metrics
            ctx.platforms,
            None, // No additional findings
            None, // No cached AST
        );

        // Use eval_metrics from the composite_rules module
        let result = composite_rules::evaluators::eval_metrics(
            field, value_min, value_max, min_size, max_size, &ctx,
        );

        let matched = result.matched;
        let match_count = if matched { 1 } else { 0 };

        if matched {
            out.push_str(&format!("\n{}\n", "MATCHED".green().bold()));

            // Try to extract and display the actual metric value
            if let Some(val) = types::scores::metric_value(report, field) {
                out.push_str(&format!("  Current value: {:.2}\n", val));
            }

            out.push_str(&format!(
                "  File size: {} bytes\n",
                report.target.size_bytes
            ));

            if !result.warnings.is_empty() {
                out.push_str("\n  Warnings:\n");
                for warning in &result.warnings {
                    out.push_str(&format!("    - {:?}\n", warning));
                }
            }
        } else {
            out.push_str(&format!("\n{}\n", "NOT MATCHED".red().bold()));

            // Show current value for debugging
            {
                let value = types::scores::metric_value(report, field);
                if let Some(val) = value {
                    out.push_str(&format!("  Current value: {:.2}\n", val));
                    if let Some(min) = value_min
                        && val < min
                    {
                        out.push_str(&format!("  Value {:.2} is below minimum {:.2}\n", val, min));
                    }
                    if let Some(max) = value_max
                        && val > max
                    {
                        out.push_str(&format!("  Value {:.2} exceeds maximum {:.2}\n", val, max));
                    }
                } else {
                    out.push_str(&format!(
                        "  Metric field '{}' not found or not applicable to this file type\n",
                        field
                    ));
                }
            }

            // Show file size constraint failures
            let file_size = report.target.size_bytes;
            if let Some(min) = min_size
                && file_size < min
            {
                out.push_str(&format!(
                    "  File size {} bytes is below minimum {} bytes\n",
                    file_size, min
                ));
            }
            if let Some(max) = max_size
                && file_size > max
            {
                out.push_str(&format!(
                    "  File size {} bytes exceeds maximum {} bytes\n",
                    file_size, max
                ));
            }
        }

        (matched, match_count, out)
    };
    Outcome::Searched(matched, match_count, out)
}
