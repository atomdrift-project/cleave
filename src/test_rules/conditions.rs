//! Debug traces for each condition type: symbol, metrics, YARA, raw, kv, AST and hex.

// Split out of the parent module for size; it shares the parent's namespace.
#[allow(clippy::wildcard_imports)]
use super::*;

impl<'a> RuleDebugger<'a> {
    pub(super) fn debug_symbol_condition(
        query: &SymbolQuery,
        ctx: &EvaluationContext<'_>,
    ) -> ConditionDebugResult {
        use crate::composite_rules::condition::SymbolKind;
        use crate::composite_rules::evaluators::symbol_string::{
            CallSite, eval_call, eval_symbol, eval_symbol_fact,
        };

        // Use the production evaluators, including symbol-family selection,
        // canonical flow targets, argument predicates, and import aliases.
        // Searching flattened import/export names cannot explain a call rule.
        let result = match query.kind {
            Some(SymbolKind::Call) => eval_call(
                query.exact.as_ref(),
                query.substr.as_ref(),
                query.regex.as_ref(),
                query.arg.as_ref(),
                query.args.as_deref(),
                CallSite {
                    module_level: query.module_level,
                    receiver: query.receiver.as_ref().map(|r| &r.from),
                },
                ctx,
            ),
            Some(kind @ (SymbolKind::Member | SymbolKind::Bind | SymbolKind::Identifier)) => {
                eval_symbol_fact(
                    kind,
                    query.exact.as_ref(),
                    query.substr.as_ref(),
                    query.regex.as_ref(),
                    query.arg.as_ref(),
                    ctx,
                )
            }
            _ => eval_symbol(
                query.exact.as_ref(),
                query.substr.as_ref(),
                query.regex.as_ref(),
                query.platforms.as_ref(),
                query.is_check,
                query.kind,
                query.not.as_ref(),
                query.alias.as_ref(),
                ctx,
            ),
        };
        let desc = describe_condition(&Condition::Symbol(query.clone()));
        let mut debug =
            ConditionDebugResult::new(desc, result.matched).with_evidence(result.evidence);
        debug
            .details
            .push(format!("Matching symbol records: {}", result.match_count));
        if query.arg.is_some() || query.args.is_some() {
            debug.details.push(
                "Call-site argument predicates applied, including requested provenance.".into(),
            );
        }
        debug
    }

    pub(super) fn debug_metrics_condition(
        &self,
        field: &str,
        min: Option<f64>,
        max: Option<f64>,
    ) -> ConditionDebugResult {
        let desc = format!("metrics: {} (min: {:?}, max: {:?})", field, min, max);

        let value = crate::types::scores::metric_value(self.report, field);
        let matched =
            value.is_some_and(|v| min.is_none_or(|m| v >= m) && max.is_none_or(|m| v <= m));

        let mut result = ConditionDebugResult::new(desc, matched);

        if let Some(v) = value {
            result.details.push(format!("Actual value: {:.4}", v));
        } else {
            result
                .details
                .push(format!("Metric '{}' not found in report", field));
            if let Some(flat) = &self.report.filefacts_metrics {
                for key in [
                    "text.lines",
                    "functions.total",
                    "identifiers.single_char_ratio",
                    "identifiers.avg_length",
                    "identifiers.count",
                    "identifiers.unique",
                ] {
                    if let Some(v) = flat.get(key) {
                        result.details.push(format!("  {key}: {v}"));
                    }
                }
            }
        }

        result
    }

    pub(super) fn debug_yara_inline_condition(
        &self,
        source: &str,
        namespace: Option<&str>,
        compiled: Option<&std::sync::Arc<yara_x::Rules>>,
    ) -> ConditionDebugResult {
        use crate::composite_rules::evaluators::eval_yara_inline;

        // Extract rule name from YARA source
        let rule_name = source
            .lines()
            .find(|l| l.trim().starts_with("rule "))
            .and_then(|l| l.trim().strip_prefix("rule "))
            .and_then(|l| l.split_whitespace().next())
            .unwrap_or("inline");

        let desc = format!("yara: {} ({} chars)", rule_name, source.len());

        // Reuse production's combined-engine result when available. For an
        // isolated condition without a precompiled rule, compile it locally;
        // passing neither results nor compiled rules means YARA is disabled.
        let mut fallback = None;
        if compiled.is_none() && (namespace.is_none() || self.inline_yara_results.is_none()) {
            let mut condition = Condition::Yara {
                source: source.to_string(),
                compiled: None,
                namespace: None,
            };
            condition.compile_yara();
            if let Condition::Yara { compiled, .. } = condition {
                fallback = compiled;
            }
            if fallback.is_none() {
                let mut result = ConditionDebugResult::new(desc, false);
                result
                    .details
                    .push("✗ Inline YARA rule failed to compile".to_string());
                return result;
            }
        }
        let ctx = self.create_eval_context(None);
        let eval_result = eval_yara_inline(source, namespace, compiled.or(fallback.as_ref()), &ctx);

        let mut result = ConditionDebugResult::new(desc, eval_result.matched);
        result.evidence = eval_result.evidence;

        if eval_result.matched {
            result
                .details
                .push("✓ Inline YARA rule matched".to_string());
        } else {
            result
                .details
                .push("✗ Inline YARA rule did not match".to_string());
        }

        result.details.push(format!(
            "Rule source preview: {}...",
            truncate_string(source, 100)
        ));

        result
    }

    #[allow(clippy::too_many_arguments)]
    /// Debug a `type: raw` condition with the evaluator a scan uses, so the
    /// verdict here is the verdict there; the details add hints on top.
    pub(super) fn debug_raw_condition(
        &self,
        query: &RawQuery,
        ctx: &EvaluationContext<'_>,
    ) -> ConditionDebugResult {
        use crate::composite_rules::evaluators::{ContentLocationParams, TextPattern, eval_raw};
        let RawQuery {
            exact,
            substr,
            regex,
            word,
            case_insensitive,
            length_min,
            length_max,
            is_check,
            not,
            section,
            offset,
            offset_range,
            section_offset,
            section_offset_range,
        } = query;
        let section_constraint = section.as_ref();
        let (offset, offset_range, section_offset, section_offset_range) = (
            *offset,
            *offset_range,
            *section_offset,
            *section_offset_range,
        );
        let pattern = TextPattern {
            exact: exact.as_ref(),
            substr: substr.as_ref(),
            regex: regex.as_ref(),
            word: word.as_ref(),
            case_insensitive: *case_insensitive,
        };
        let evaluate = |location: &ContentLocationParams| {
            eval_raw(
                TextPattern { ..pattern },
                (*length_min, *length_max),
                *is_check,
                not.as_ref(),
                location,
                ctx,
                None,
            )
        };
        let pattern_desc = if let Some(e) = exact {
            format!("exact: \"{}\"", truncate_string(e, 40))
        } else if let Some(c) = substr {
            format!("substr: \"{}\"", truncate_string(c, 40))
        } else if let Some(r) = regex {
            format!("regex: /{}/", truncate_string(r, 40))
        } else if let Some(w) = word {
            format!("word: \"{}\"", w)
        } else {
            "unknown".to_string()
        };

        // Build location constraint description
        let mut location_parts = Vec::new();
        if let Some(sec) = section_constraint {
            location_parts.push(format!("section={}", sec));
        }
        if let Some(off) = offset {
            location_parts.push(format!("offset={}", off));
        }
        if let Some((start, end)) = &offset_range {
            let end_str = end.map_or("EOF".to_string(), |e| e.to_string());
            location_parts.push(format!("range=[{},{})", start, end_str));
        }
        if let Some(off) = section_offset {
            location_parts.push(format!("section_offset={}", off));
        }
        if let Some((start, end)) = &section_offset_range {
            let end_str = end.map_or("end".to_string(), |e| e.to_string());
            location_parts.push(format!("section_range=[{},{})", start, end_str));
        }

        let location_desc = if location_parts.is_empty() {
            String::new()
        } else {
            format!(" @{{{}}}", location_parts.join(", "))
        };

        let desc = format!("raw: {}{}", pattern_desc, location_desc);

        // Resolve the effective search range
        let file_size = self.binary_data.len();
        let (search_start, search_end) = self.resolve_search_range(
            section_constraint,
            offset,
            offset_range.as_ref(),
            section_offset,
            section_offset_range.as_ref(),
            file_size,
        );

        let outcome = evaluate(&ContentLocationParams {
            section: section.clone(),
            offset,
            offset_range,
            section_offset,
            section_offset_range,
            arch_clamp: None,
        });
        let matched = outcome.matched;
        let mut result = ConditionDebugResult::new(desc, matched);
        result.evidence = outcome.evidence;

        // Show search range details
        if search_start != 0 || search_end != file_size {
            result.details.push(format!(
                "Search range: [{}, {}) of {} bytes ({} bytes searched)",
                search_start,
                search_end,
                file_size,
                search_end.saturating_sub(search_start)
            ));
        } else {
            result
                .details
                .push(format!("File size: {} bytes", file_size));
        }

        // Check alternatives if content didn't match
        if !matched {
            // Check if pattern exists outside the constrained range
            if search_start != 0 || search_end != file_size {
                let found_outside = evaluate(&ContentLocationParams {
                    section: None,
                    offset: None,
                    offset_range: None,
                    section_offset: None,
                    section_offset_range: None,
                    arch_clamp: None,
                })
                .matched;
                if found_outside {
                    result.details.push(
                        "💡 Pattern exists in file but outside the specified range".to_string(),
                    );
                }
            }

            // Check symbols (only for exact or regex patterns)
            if exact.is_some() || regex.is_some() {
                let symbols: Vec<&str> = self
                    .report
                    .imports
                    .iter()
                    .map(|i| i.symbol.as_str())
                    .chain(self.report.exports.iter().map(|e| e.symbol.as_str()))
                    .chain(self.report.functions.iter().map(|f| f.name.as_str()))
                    .collect();
                let symbol_matches = find_matching_symbols(
                    &symbols,
                    exact.as_deref(),
                    None,
                    regex.as_deref(),
                    false,
                );
                if !symbol_matches.is_empty() {
                    result.details.push(format!(
                        "💡 Found in symbols ({} matches) - try `symbol:` instead",
                        symbol_matches.len()
                    ));
                }
            }

            // Check strings
            let strings: Vec<&str> = self
                .report
                .strings
                .iter()
                .map(|s| s.value.as_str())
                .collect();
            let string_matches = find_matching_strings(
                &strings,
                exact.as_deref(),
                substr.as_deref(),
                regex.as_deref(),
                word.as_deref(),
                false,
            );
            if !string_matches.is_empty() {
                result.details.push(format!(
                    "💡 Found in strings ({} matches) - try `string:` instead",
                    string_matches.len()
                ));
            }
        }

        // Section suggestions for binaries
        if self.section_map.has_sections() && matched {
            // List available sections
            let sections = self.section_map.section_names();
            if !sections.is_empty() && section_constraint.is_none() {
                result.details.push(format!(
                    "📍 Binary has sections: {} - consider section filtering for precision",
                    sections.join(", ")
                ));
            }
        } else if section_constraint.is_some() && !self.section_map.has_sections() {
            result.details.push(
                "⚠️  Section constraint specified but file has no binary sections".to_string(),
            );
        }

        result
    }

    // Mirrors the full set of value-condition operators a trait can
    // declare; bundling into a struct here would just push the
    // boilerplate one layer over.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn debug_kv_condition(
        &self,
        path: &str,
        exact: &Option<String>,
        substr: &Option<String>,
        regex: &Option<String>,
        case_insensitive: bool,
        exists: Option<bool>,
        length_min: Option<usize>,
        length_max: Option<usize>,
        is_check: Option<crate::composite_rules::condition::StringValidator>,
        not: &Option<Vec<crate::composite_rules::condition::NotException>>,
    ) -> ConditionDebugResult {
        let pattern_desc = if let Some(e) = exact {
            format!("exact: \"{}\"", truncate_string(e, 40))
        } else if let Some(c) = substr {
            format!("substr: \"{}\"", truncate_string(c, 40))
        } else if let Some(r) = regex {
            format!("regex: /{}/", truncate_string(r, 40))
        } else if exists == Some(true) {
            "exists".to_string()
        } else if let (Some(min), Some(max)) = (length_min, length_max) {
            format!("len {}..{}", min, max)
        } else if let Some(min) = length_min {
            format!("length_min {}", min)
        } else if let Some(max) = length_max {
            format!("length_max {}", max)
        } else {
            "(no constraint)".to_string()
        };

        let desc = format!("value: path=\"{}\" {}", path, pattern_desc);

        // Use the actual value evaluator. Earlier this discarded `exists`,
        // `length_min`, and `length_max` from the parent condition, so a
        // YAML trait like `type: value, path: …, exists: true, length_min: 1`
        // was rebuilt as a no-op match — every value-only trait reported
        // NOT MATCHED in test-rules even when it fired in production.
        let condition = Condition::Kv(KvQuery {
            match_mode: Default::default(),
            path: path.to_string(),
            exact: exact.clone(),
            substr: substr.clone(),
            regex: regex.clone(),
            eq: None,
            ne: None,
            case_insensitive,
            exists,
            length_min,
            length_max,
            is_check,
            not: not.clone(),
        });

        // Create evaluation context
        let ctx = EvaluationContext::new(
            self.report,
            self.binary_data,
            self.file_type,
            &self.platforms,
            None,
            None,
        );

        if let Some(evidence) = crate::composite_rules::evaluators::evaluate_kv(&condition, &ctx) {
            let mut result = ConditionDebugResult::new(desc, true);
            result.details.push(format!("Matched: {}", evidence.value));
            if let Some(loc) = &evidence.location {
                result.details.push(format!("Location: {}", loc));
            }
            result.evidence = vec![evidence];
            result
        } else {
            let mut result = ConditionDebugResult::new(desc, false);

            // Try to parse the file and show what's available
            if let Ok(content) = std::str::from_utf8(self.binary_data) {
                // Try to detect format and show available paths
                if let Ok(json) = serde_json::from_str::<serde_json::Value>(content) {
                    if let Some(obj) = json.as_object() {
                        let top_keys: Vec<_> = obj.keys().take(10).collect();
                        result
                            .details
                            .push(format!("Available top-level keys: {:?}", top_keys));
                    }
                } else if let Ok(yaml) = crate::yaml::from_str::<serde_json::Value>(content)
                    && let Some(obj) = yaml.as_object()
                {
                    let top_keys: Vec<_> = obj.keys().take(10).collect();
                    result
                        .details
                        .push(format!("Available top-level keys: {:?}", top_keys));
                }
            }

            result
        }
    }

    pub(super) fn debug_ast_condition(
        &self,
        kind: &Option<String>,
        node: &Option<String>,
        exact: &Option<String>,
        substr: &Option<String>,
        regex: &Option<String>,
        query: &Option<String>,
        case_insensitive: bool,
    ) -> ConditionDebugResult {
        // Build description based on mode
        let desc = if let Some(q) = query {
            format!("tree-sitter: query={}", truncate_string(q, 50))
        } else {
            let node_spec = kind
                .as_ref()
                .map(|k| format!("kind={}", k))
                .or_else(|| node.as_ref().map(|n| format!("node={}", n)))
                .unwrap_or_else(|| "unknown".to_string());
            let pattern_spec = exact
                .as_ref()
                .map(|e| format!("exact=\"{}\"", truncate_string(e, 30)))
                .or_else(|| {
                    substr
                        .as_ref()
                        .map(|s| format!("substr=\"{}\"", truncate_string(s, 30)))
                })
                .or_else(|| {
                    regex
                        .as_ref()
                        .map(|r| format!("regex=/{}/", truncate_string(r, 30)))
                })
                .unwrap_or_default();
            format!(
                "tree-sitter: {} {} (case_insensitive: {})",
                node_spec, pattern_spec, case_insensitive
            )
        };

        // For query mode, show simplified debug info
        if query.is_some() {
            let mut result = ConditionDebugResult::new(desc, false);
            result
                .details
                .push("AST query debugging not yet implemented".to_string());
            return result;
        }

        // Without `cached_ast`, every kind/node match short-circuits to
        // no-match; reuse the filefacts parse we did at construction.
        let cached_ast = self
            .parsed
            .as_ref()
            .and_then(filefacts::ParsedFile::source_ast)
            .map(|a| a.tree);
        let cached_source_utf8 = std::str::from_utf8(self.binary_data).ok();

        // For simple mode, use eval_ast directly
        let ctx = EvaluationContext {
            report: self.report,
            target_path_override: None,
            member_files: None,
            binary_data: self.binary_data,
            file_type: self.file_type,
            platforms: &self.platforms,
            arch: vec![Arch::All].into(),
            arch_ranges: None,
            findings: crate::composite_rules::FindingScope::with_index(
                &self.report.findings,
                None,
                None,
            ),
            cached_ast,
            ast_kind_cache: None,
            ast_query_cache: None,
            measured_ast_queries: None,
            ast_node_text: None,
            debug_collector: None,
            suppressions: None,
            section_map: None,
            inline_yara_results: None,
            cached_kv_offsets: std::sync::Arc::new(std::sync::OnceLock::new()),
            cached_lossy_utf8: std::sync::Arc::new(std::sync::OnceLock::new()),
            cached_ast_source_utf8: std::sync::Arc::new(std::sync::OnceLock::new()),
            string_exact_index: std::sync::Arc::new(std::sync::OnceLock::new()),
            string_exact_index_ci: std::sync::Arc::new(std::sync::OnceLock::new()),
            encoded_string_indices: std::sync::Arc::new(std::sync::OnceLock::new()),
            literal_string_indices: std::sync::Arc::new(std::sync::OnceLock::new()),
            flow_call_index: std::sync::Arc::new(std::sync::OnceLock::new()),
            flow_targets: std::sync::Arc::new(std::sync::OnceLock::new()),
            cached_html_comment_free_source: std::sync::Arc::new(std::sync::OnceLock::new()),
            cached_comment_free_source: std::sync::Arc::new(std::sync::OnceLock::new()),
            cached_commentless_ast: std::sync::Arc::new(std::sync::OnceLock::new()),
            deadline: None,
            slow_rule_ms: 4000,
            cached_evidence: None,
            current_trait_idx: None,
            finding_origins: None,
            for_mask: TypeMask::ALL,
            raw_atom_offsets: None,
            decoded_skip: None,
            regex_candidate_strings: None,
            cached_source_utf8,
            parent_is_exception: false,
            cancellation: None,
        };

        let eval_result = crate::composite_rules::evaluators::eval_ast(
            kind.as_deref(),
            node.as_deref(),
            exact.as_deref(),
            substr.as_deref(),
            regex.as_deref(),
            query.as_deref(),
            case_insensitive,
            &ctx,
        );

        let mut result = ConditionDebugResult::new(desc, eval_result.matched);
        if eval_result.matched {
            result.details.push(format!(
                "Found {} matching AST node(s)",
                eval_result.evidence.len()
            ));
            for ev in eval_result.evidence.iter().take(10) {
                if let Some(loc) = &ev.location {
                    result
                        .details
                        .push(format!("  {}: {}", loc, truncate_string(&ev.value, 60)));
                } else {
                    result
                        .details
                        .push(format!("  {}", truncate_string(&ev.value, 60)));
                }
            }
        } else {
            result
                .details
                .push("No matching AST nodes found".to_string());

            // Hint: the most common `kind: call exact: <bare-name>` mistake.
            // The AST evaluator compares the pattern against the full call
            // expression text (`name(args)`), so `exact: name` never
            // matches. Detect the pattern and suggest the canonical
            // workarounds, preferring `type: symbol` when the name is
            // already extracted by the symbol pass.
            if kind.as_deref() == Some("call")
                && let Some(name) = exact.as_deref()
            {
                let looks_like_bare_name = !name.is_empty()
                    && !name.contains('(')
                    && name
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b':');
                if looks_like_bare_name {
                    let found_as_symbol = self.report.imports.iter().any(|i| i.symbol == name)
                        || self.report.exports.iter().any(|e| e.symbol == name)
                        || self.report.functions.iter().any(|f| f.name == name);
                    result.details.push(format!(
                        "  hint: `ast kind=call exact: {n}` compares against the full \
                             call expression text (e.g. `{n}(args)`), not just the name, so \
                             it never matches.",
                        n = name
                    ));
                    if found_as_symbol {
                        result.details.push(format!(
                            "        the symbol extractor sees `{n}` — switch this \
                                 condition to `type: symbol exact: {n}`.",
                            n = name
                        ));
                    } else {
                        result.details.push(format!(
                            "        switch to `type: symbol exact: {n}`, or stay on \
                                 AST with `substr: \"{n}(\"` or `regex: \"^{n}\\\\b\"`.",
                            n = name
                        ));
                    }
                }
            }
        }

        result
    }

    pub(super) fn debug_hex_condition(
        &self,
        pattern: &str,
        not: Option<&Vec<crate::composite_rules::condition::NotException>>,
        offset: Option<i64>,
        offset_range: Option<(i64, Option<i64>)>,
        section: Option<&str>,
        section_offset: Option<i64>,
        section_offset_range: Option<(i64, Option<i64>)>,
    ) -> ConditionDebugResult {
        use crate::composite_rules::evaluators::{ContentLocationParams, eval_hex};

        let mut desc = format!("hex: \"{}\"", truncate_string(pattern, 40));
        if let Some(sec) = section {
            desc.push_str(&format!(" in section: {}", sec));
        }
        if let Some(off) = offset {
            desc.push_str(&format!(" @{:#x}", off));
        }
        if let Some((start, end)) = offset_range {
            match end {
                Some(e) => desc.push_str(&format!(" @[{:#x},{:#x})", start, e)),
                None => desc.push_str(&format!(" @[{:#x},)", start)),
            }
        }

        let ctx = EvaluationContext {
            report: self.report,
            target_path_override: None,
            member_files: None,
            binary_data: self.binary_data,
            file_type: self.file_type,
            platforms: &self.platforms,
            arch: vec![Arch::All].into(),
            arch_ranges: None,
            findings: crate::composite_rules::FindingScope::with_index(
                &self.report.findings,
                None,
                None,
            ),
            cached_ast: None,
            ast_kind_cache: None,
            ast_query_cache: None,
            measured_ast_queries: None,
            ast_node_text: None,
            debug_collector: None,
            suppressions: None,
            section_map: Some(&self.section_map),
            inline_yara_results: None,
            cached_kv_offsets: std::sync::Arc::new(std::sync::OnceLock::new()),
            cached_lossy_utf8: std::sync::Arc::new(std::sync::OnceLock::new()),
            cached_ast_source_utf8: std::sync::Arc::new(std::sync::OnceLock::new()),
            string_exact_index: std::sync::Arc::new(std::sync::OnceLock::new()),
            string_exact_index_ci: std::sync::Arc::new(std::sync::OnceLock::new()),
            encoded_string_indices: std::sync::Arc::new(std::sync::OnceLock::new()),
            literal_string_indices: std::sync::Arc::new(std::sync::OnceLock::new()),
            flow_call_index: std::sync::Arc::new(std::sync::OnceLock::new()),
            flow_targets: std::sync::Arc::new(std::sync::OnceLock::new()),
            cached_html_comment_free_source: std::sync::Arc::new(std::sync::OnceLock::new()),
            cached_comment_free_source: std::sync::Arc::new(std::sync::OnceLock::new()),
            cached_commentless_ast: std::sync::Arc::new(std::sync::OnceLock::new()),
            deadline: None,
            slow_rule_ms: 4000,
            cached_evidence: None,
            current_trait_idx: None,
            finding_origins: None,
            for_mask: TypeMask::ALL,
            raw_atom_offsets: None,
            decoded_skip: None,
            regex_candidate_strings: None,
            cached_source_utf8: None,
            parent_is_exception: false,
            cancellation: None,
        };

        let eval_result = eval_hex(
            pattern,
            not,
            &ContentLocationParams {
                section: section.map(std::borrow::ToOwned::to_owned),
                offset,
                offset_range,
                section_offset,
                section_offset_range,
                arch_clamp: None,
            },
            &ctx,
            None,
        );

        let mut result = ConditionDebugResult::new(desc, eval_result.matched);

        result
            .details
            .push(format!("File size: {} bytes", self.binary_data.len()));
        result
            .details
            .push(format!("Found {} matches", eval_result.evidence.len()));

        for ev in eval_result.evidence.iter().take(5) {
            if let Some(loc) = &ev.location {
                result.details.push(format!("  {} @ {}", ev.value, loc));
            } else {
                result.details.push(format!("  {}", ev.value));
            }
        }
        if eval_result.evidence.len() > 5 {
            result
                .details
                .push(format!("  ... and {} more", eval_result.evidence.len() - 5));
        }

        result.evidence = eval_result.evidence;
        result
    }
}
