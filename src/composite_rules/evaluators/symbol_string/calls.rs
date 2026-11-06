//! Symbol-call conditions: call sites, argument and origin filters.

// Split out of the parent module for size; it shares the parent's namespace.
#[allow(clippy::wildcard_imports)]
use super::*;

/// Evaluate `type: symbol, kind: call [+ arg: ...]` — match call
/// sites from filefacts's unified `Symbol::Call` records, optionally
/// narrowing by an arg-position filter that matches against the
/// per-arg shape+value carried on each call.
///
/// Iterates `ctx.report.filefacts.symbols` (the raw filefacts JSON
/// mirror), filters to entries with `kind: "call"`, matches `target`
/// against the rule's name predicates, and — when `arg` is set —
/// requires at least one of the call's `args[]` to match the arg
/// filter on shape + value.
/// Call-site constraints beyond the target name and its arguments, both
/// answered by filefacts' flow graph.
#[derive(Clone, Copy, Default)]
pub(crate) struct CallSite<'q> {
    /// The call must run in module-level (load-time) code.
    pub module_level: bool,
    /// Where the call's receiver must come from.
    pub receiver: Option<&'q crate::composite_rules::condition::FlowOriginFilter>,
}

impl CallSite<'_> {
    pub(super) const fn needs_flow(self) -> bool {
        self.module_level || self.receiver.is_some()
    }
}

#[must_use]
pub(crate) fn eval_call<'a>(
    exact: Option<&String>,
    substr: Option<&String>,
    regex: Option<&String>,
    arg_filter: Option<&crate::composite_rules::condition::ArgFilter>,
    args_filters: Option<&[crate::composite_rules::condition::ArgFilter]>,
    site: CallSite<'_>,
    ctx: &EvaluationContext<'a>,
) -> ConditionResult {
    let Some(view) = ctx.report.filefacts.as_ref() else {
        if arg_filter.is_some_and(|f| f.from.is_some())
            || args_filters.is_some_and(|fs| fs.iter().any(|f| f.from.is_some()))
            || site.needs_flow()
        {
            ctx.report
                .analysis_gaps
                .record(crate::types::AnalysisGap::FlowUnavailable);
        }
        return ConditionResult::no_match();
    };
    let mut evidence = Vec::new();
    let mut match_count = 0usize;
    let compiled_regex = regex.and_then(|r| crate::composite_rules::condition::cached_regex(r));

    for sym in &view.symbols {
        let filefacts::Symbol::Call {
            target,
            args,
            offset,
            ..
        } = sym
        else {
            continue;
        };
        let target = target.as_deref().unwrap_or("");
        let needs_flow = arg_filter.is_some_and(|f| f.from.is_some())
            || args_filters.is_some_and(|fs| fs.iter().any(|f| f.from.is_some()))
            || site.needs_flow();
        let canonical = if needs_flow {
            flow(ctx)
                .and_then(|flow| flow_call(ctx, flow, *offset, target, args.len()))
                .and_then(|v| v.target.as_deref())
        } else {
            None
        };

        // Match the target name against any name predicate.
        let name_matches = [Some(target), canonical]
            .into_iter()
            .flatten()
            .any(|target| match (exact, substr, compiled_regex.as_ref()) {
                (None, None, None) => true, // no name filter — every call qualifies
                (Some(e), _, _) => target == e,
                (_, Some(s), _) => target.contains(s.as_str()),
                (_, _, Some(re)) => re.is_match(target),
            });
        if !name_matches {
            continue;
        }

        // If an arg filter is set, require at least one arg to match it.
        if let Some(filter) = arg_filter
            && !args.iter().enumerate().any(|(i, a)| {
                filter.index.is_none_or(|wanted| wanted == i)
                    && arg_matches(a, filter)
                    && origin_matches(
                        *offset,
                        target,
                        args.len(),
                        FlowInput::Argument(i),
                        filter.from.as_ref(),
                        ctx,
                    )
            })
        {
            continue;
        }

        // If a multi-arg filter is set, require every filter to be satisfied by
        // a *distinct* arg (greedy assignment) — for matching a specific
        // multi-positional shape like `File.rename("a.png", "b.exe")`.
        if let Some(filters) = args_filters
            && !all_filters_match_distinct_with(args, filters, |i, filter| {
                origin_matches(
                    *offset,
                    target,
                    args.len(),
                    FlowInput::Argument(i),
                    filter.from.as_ref(),
                    ctx,
                )
            })
        {
            continue;
        }

        if site.module_level
            && !flow(ctx)
                .and_then(|flow| flow_call(ctx, flow, *offset, target, args.len()))
                .is_some_and(|call| call.module_level)
        {
            continue;
        }
        if site.receiver.is_some()
            && !origin_matches(
                *offset,
                target,
                args.len(),
                FlowInput::Receiver,
                site.receiver,
                ctx,
            )
        {
            continue;
        }

        match_count += 1;
        if evidence.len() < MAX_EVIDENCE_PER_TRAIT
            && let Some(location) = offset.map(|o| format!("{:#x}", o))
        {
            evidence.push(Evidence {
                method: "symbol".to_string(),
                source: "call".to_string(),
                value: target.to_string(),
                location: Some(location),
                ..Default::default()
            });
        }
    }

    ConditionResult {
        matched: match_count > 0,
        evidence,
        match_count,
        warnings: Vec::new(),
        precision: 2.0,
        matched_trait_ids: Vec::new(),
    }
}

/// Evaluate `type: symbol, kind: member|bind|identifier` — match the
/// pre-extracted member-access chains, static bindings, and bare
/// identifiers from filefacts's `Symbol::{Member,Bind,Identifier}`
/// records against the rule's name predicates.
///
/// These projections replace per-member tree-sitter cursor walks for
/// `query:` traits that only keyed off a dotted path (`process.env`), an
/// assignment target, or an identifier name — the fact is extracted once
/// per file and matched here without re-walking the AST per rule.
#[must_use]
pub(crate) fn eval_symbol_fact<'a>(
    kind: crate::composite_rules::condition::SymbolKind,
    exact: Option<&String>,
    substr: Option<&String>,
    regex: Option<&String>,
    arg: Option<&crate::composite_rules::condition::ArgFilter>,
    ctx: &EvaluationContext<'a>,
) -> ConditionResult {
    use crate::composite_rules::condition::SymbolKind;
    let Some(view) = ctx.report.filefacts.as_ref() else {
        return ConditionResult::no_match();
    };
    let mut evidence = Vec::new();
    let mut match_count = 0usize;
    let compiled_regex = regex.and_then(|r| crate::composite_rules::condition::cached_regex(r));

    for sym in &view.symbols {
        // Project each fact to its matchable name + evidence location,
        // skipping symbols whose kind the rule didn't ask for.
        let (name, source_tag, offset): (&str, &str, Option<u64>) = match (kind, sym) {
            (SymbolKind::Member, filefacts::Symbol::Member { path, offset, .. }) => {
                (path.as_str(), "member", *offset)
            }
            (
                SymbolKind::Bind,
                filefacts::Symbol::Bind {
                    target,
                    offset,
                    shape,
                },
            ) => {
                if let Some(wanted) = arg.and_then(|a| a.kind.as_deref()) {
                    use filefacts::ArgShape;
                    let actual = match shape {
                        ArgShape::String => "string",
                        ArgShape::Number => "number",
                        ArgShape::Bool => "bool",
                        ArgShape::Null => "null",
                        ArgShape::Identifier => "identifier",
                        ArgShape::Object => "object",
                        ArgShape::Array => "array",
                        ArgShape::Function => "function",
                        ArgShape::Template => "template",
                        ArgShape::Call => "call",
                        ArgShape::Expression => "expression",
                        _ => "unknown",
                    };
                    if wanted != actual {
                        continue;
                    }
                }
                (target.as_str(), "bind", Some(*offset))
            }
            (SymbolKind::Identifier, filefacts::Symbol::Identifier { name, offset, .. }) => {
                (name.as_str(), "identifier", *offset)
            }
            _ => continue,
        };

        let name_matches = match (exact, substr, compiled_regex.as_ref()) {
            (None, None, None) => true,
            (Some(e), _, _) => name == e.as_str(),
            (_, Some(s), _) => name.contains(s.as_str()),
            (_, _, Some(re)) => re.is_match(name),
        };
        if !name_matches {
            continue;
        }

        match_count += 1;
        if evidence.len() < MAX_EVIDENCE_PER_TRAIT
            && let Some(location) = offset.map(|o| format!("{:#x}", o))
        {
            evidence.push(Evidence {
                method: "symbol".to_string(),
                source: source_tag.to_string(),
                value: name.to_string(),
                location: Some(location),
                ..Default::default()
            });
        }
    }

    ConditionResult {
        matched: match_count > 0,
        evidence,
        match_count,
        warnings: Vec::new(),
        precision: 2.0,
        matched_trait_ids: Vec::new(),
    }
}

/// True when every filter in `filters` can be matched to a **distinct** arg in
/// `args` (a bipartite matching). Used by the multi-arg `args:` filter to match
/// a specific multi-positional call shape like `File.rename("a.png", "b.exe")`
/// without letting one arg satisfy two filters. Backtracks so a greedy
/// mis-assignment can't produce a false negative; inputs are tiny (a handful of
/// args and filters).
#[cfg(test)]
pub(super) fn all_filters_match_distinct(
    args: &[filefacts::Arg],
    filters: &[crate::composite_rules::condition::ArgFilter],
) -> bool {
    all_filters_match_distinct_with(args, filters, |_, filter| filter.from.is_none())
}

pub(super) fn all_filters_match_distinct_with(
    args: &[filefacts::Arg],
    filters: &[crate::composite_rules::condition::ArgFilter],
    extra: impl Fn(usize, &crate::composite_rules::condition::ArgFilter) -> bool,
) -> bool {
    // Explicitly selected, distinct named fields are distinct logical
    // arguments even when the producer stores them in one keyword object.
    // Resolve explicit named-field selectors first, including in a mixture
    // with positional selectors. Two fields of argument 1 must not consume
    // two physical argument positions or displace the positional URL at 0.
    let mut seen = std::collections::BTreeSet::new();
    let mut positional = Vec::new();
    for filter in filters {
        if let (Some(index), Some(field)) = (
            filter.index,
            filter.from.as_ref().and_then(|from| from.field.as_ref()),
        ) {
            if !seen.insert((index, field))
                || !args.get(index).is_some_and(|arg| arg_matches(arg, filter))
                || !extra(index, filter)
            {
                return false;
            }
        } else {
            positional.push(filter);
        }
    }
    if positional.len() > args.len() {
        return false;
    }
    // Precompute candidates once, including any bounded provenance queries.
    // Augmenting paths avoid factorial backtracking on overlapping filters.
    let candidates: Vec<Vec<usize>> = positional
        .iter()
        .map(|filter| {
            args.iter()
                .enumerate()
                .filter(|(i, arg)| {
                    filter.index.is_none_or(|wanted| wanted == *i)
                        && arg_matches(arg, filter)
                        && extra(*i, filter)
                })
                .map(|(i, _)| i)
                .collect()
        })
        .collect();
    let mut owners: Vec<Option<usize>> = vec![None; args.len()];
    for start in 0..positional.len() {
        let mut queue = std::collections::VecDeque::from([start]);
        let mut previous: Vec<Option<(usize, usize)>> = vec![None; positional.len()];
        let mut seen_args = vec![false; args.len()];
        let mut end = None;
        while let Some(filter) = queue.pop_front() {
            for &arg in &candidates[filter] {
                if seen_args[arg] {
                    continue;
                }
                seen_args[arg] = true;
                if let Some(owner) = owners[arg] {
                    if owner != start && previous[owner].is_none() {
                        previous[owner] = Some((filter, arg));
                        queue.push_back(owner);
                    }
                } else {
                    end = Some((filter, arg));
                    break;
                }
            }
            if end.is_some() {
                break;
            }
        }
        let Some((mut filter, mut arg)) = end else {
            return false;
        };
        loop {
            owners[arg] = Some(filter);
            let Some((parent, old_arg)) = previous[filter] else {
                break;
            };
            filter = parent;
            arg = old_arg;
        }
    }
    true
}

pub(super) fn flow_call<'a>(
    ctx: &EvaluationContext<'_>,
    flow: &'a filefacts::Flow,
    offset: Option<u64>,
    target: &str,
    argument_count: usize,
) -> Option<&'a filefacts::FlowValue> {
    let offset = offset?;
    let index = ctx.flow_call_index.get_or_init(|| {
        let mut index = rustc_hash::FxHashMap::<_, Vec<usize>>::default();
        for (i, value) in flow.values.iter().enumerate() {
            if value.kind == filefacts::FlowKind::Call {
                index
                    .entry((value.offset, value.inputs.len()))
                    .or_default()
                    .push(i);
            }
        }
        index
    });
    let mut candidates = index
        .get(&(offset, argument_count))?
        .iter()
        .map(|&i| &flow.values[i]);
    let first = candidates.next()?;
    if first.target.as_deref() == Some(target) {
        return Some(first);
    }
    let mut unique = true;
    for value in candidates {
        unique = false;
        if value.target.as_deref() == Some(target) {
            return Some(value);
        }
    }
    // Chained calls can share an offset but have different argument counts.
    // A unique candidate can have a canonical import spelling different from
    // the raw symbol; still-ambiguous candidates must match their target too.
    unique.then_some(first)
}

#[cfg(test)]
#[test]
pub(super) fn indexed_flow_call_preserves_ambiguity_and_order() -> anyhow::Result<()> {
    use crate::composite_rules::context::FileEvalCaches;
    use crate::composite_rules::types::FileType;
    use crate::types::{AnalysisReport, TargetInfo};

    let mut flow = filefacts::Flow::default();
    flow.values = serde_json::from_value(serde_json::json!([
        {"kind":"literal", "offset":10, "inputs":[], "target":"ignored"},
        {"kind":"call", "offset":10, "inputs":[], "target":"first"},
        {"kind":"call", "offset":10, "inputs":[], "target":"second"},
        {"kind":"call", "offset":20, "inputs":[0], "target":"canonical"},
        {"kind":"call", "offset":10, "inputs":[0,0], "target":"chained"},
        {"kind":"call", "offset":10, "inputs":[], "target":"first"},
        {"kind":"call", "offset":30, "inputs":[]}
    ]))?;
    let report = AnalysisReport::new(TargetInfo {
        path: "calls.js".into(),
        file_type: "javascript".into(),
        size_bytes: 0,
        sha256: String::new(),
        architectures: None,
    });
    let caches = FileEvalCaches::default();
    let ctx =
        EvaluationContext::test_only_new(&report, b"", FileType::All).with_file_caches(&caches);
    for (offset, target, arity, expected) in [
        (Some(10), "first", 0, Some(1)),
        (Some(10), "second", 0, Some(2)),
        (Some(10), "ignored", 0, None),
        (Some(10), "unresolved", 0, None),
        (Some(20), "alias", 1, Some(3)),
        (Some(20), "canonical", 0, None),
        (Some(10), "chained", 2, Some(4)),
        (Some(30), "computed", 0, Some(6)),
        (Some(99), "first", 0, None),
        (None, "first", 0, None),
    ] {
        let found = flow_call(&ctx, &flow, offset, target, arity)
            .and_then(|value| flow.values.iter().position(|v| std::ptr::eq(v, value)));
        assert_eq!(found, expected, "{offset:?}/{target}/{arity}");
    }
    let next =
        EvaluationContext::test_only_new(&report, b"", FileType::All).with_file_caches(&caches);
    assert!(std::sync::Arc::ptr_eq(
        &ctx.flow_call_index,
        &next.flow_call_index
    ));
    assert!(next.flow_call_index.get().is_some());
    Ok(())
}

/// Which of a call's inputs a provenance filter traces.
#[derive(Clone, Copy)]
pub(super) enum FlowInput {
    Argument(usize),
    Receiver,
}

pub(super) fn origin_matches(
    offset: Option<u64>,
    target: &str,
    argument_count: usize,
    input: FlowInput,
    origin: Option<&crate::composite_rules::condition::FlowOriginFilter>,
    ctx: &EvaluationContext<'_>,
) -> bool {
    use crate::types::AnalysisGap;
    let gaps = &ctx.report.analysis_gaps;
    let Some(origin) = origin else {
        return true;
    };
    let source_pattern = (!origin.call.is_empty())
        .then(|| crate::composite_rules::condition::cached_regex(&origin.call))
        .flatten();
    let value_pattern = origin
        .value
        .as_ref()
        .and_then(|p| crate::composite_rules::condition::cached_regex(p));
    let member_pattern = origin
        .member
        .as_ref()
        .and_then(|p| crate::composite_rules::condition::cached_regex(p));
    let whole_pattern = origin
        .whole_value
        .as_ref()
        .and_then(|p| crate::composite_rules::condition::cached_regex(p));
    if source_pattern.is_none()
        && value_pattern.is_none()
        && member_pattern.is_none()
        && whole_pattern.is_none()
        && origin.whole_number.is_none()
        && !origin.field_exists
        && !origin.field_absent
    {
        return false;
    }
    let Some(flow) = flow(ctx) else { return false };
    let Some(call) = flow_call(ctx, flow, offset, target, argument_count) else {
        gaps.record(AnalysisGap::FlowCallUnavailable);
        return false;
    };
    let value = match input {
        FlowInput::Argument(argument) => call.inputs.get(argument).copied(),
        FlowInput::Receiver => call.receiver,
    };
    let Some(value) = value else {
        gaps.record(AnalysisGap::FlowCallUnavailable);
        return false;
    };
    if origin.field_absent {
        let Some(field) = origin.field.as_deref() else {
            return false;
        };
        // Absent projections through aliases/opaque objects are not proof.
        // CFML's parsed tag attributes are concrete keyword maps; callers
        // can explicitly exclude attributeCollection in a second predicate.
        return flow.values.get(value).is_some_and(|object| {
            object.kind == filefacts::FlowKind::Keyword
                && object.inputs.is_empty()
                && !object.fields.contains_key(field)
        });
    }
    if origin.field_exists {
        let Some(field) = origin.field.as_deref() else {
            return false;
        };
        if let Some(object) = flow.values.get(value).filter(|v| {
            matches!(
                v.kind,
                filefacts::FlowKind::Object | filefacts::FlowKind::Keyword
            )
        }) {
            return object.fields.contains_key(field);
        }
        let found = flow.field_origins(value, field, &[], 10_000);
        // The projected value itself is evidence of presence even when its
        // contents are opaque. A missing projection is not evidence of absence.
        if found.values.is_empty() && found.incomplete {
            gaps.record(AnalysisGap::FlowFieldUnavailable);
        }
        return !found.values.is_empty();
    }
    if let Some(expected) = origin.whole_number {
        let values = flow.complete_values(value, origin.field.as_deref(), 10_000);
        if values.incomplete {
            gaps.record(AnalysisGap::FlowQueryIncomplete);
        }
        return values.values.iter().any(|v| {
            matches!(flow.values[v.value].literal.as_ref(),
                Some(filefacts::Arg::Number { value, .. }) if *value == expected)
        });
    }
    if let Some(pattern) = whole_pattern {
        let values = flow.complete_values(value, origin.field.as_deref(), 10_000);
        if values.incomplete {
            gaps.record(AnalysisGap::FlowQueryIncomplete);
        }
        return values.values.iter().any(|v| {
            matches!(flow.values[v.value].literal.as_ref(),
                Some(filefacts::Arg::String { value })
                    if pattern.is_match(value))
        });
    }
    let mut models = Vec::new();
    // The flow's distinct call targets, sorted, computed once per file: this
    // runs per (rule x call site), and sorting every value's target into a
    // fresh `BTreeSet` each time was ~2/3 of the evaluator's cost.
    let flow_targets = ctx.flow_targets.get_or_init(|| {
        flow.values
            .iter()
            .filter_map(|v| v.target.clone())
            .collect::<std::collections::BTreeSet<String>>()
            .into_iter()
            .collect()
    });
    for model in &origin.through {
        let Some(pattern) = crate::composite_rules::condition::cached_regex(&model.call) else {
            return false;
        };
        models.extend(
            flow_targets
                .iter()
                .filter(|t| pattern.is_match(t))
                .map(|target| {
                    filefacts::FlowTransfer::new(
                        target.clone(),
                        model.arguments.clone(),
                        model.receiver,
                    )
                }),
        );
    }
    // Selected sources are terminal evidence for this query. Their internal
    // implementation need not be modeled to establish that they supply data.
    // Argument constraints are still checked below, in the same invocation.
    if let Some(p) = source_pattern.as_ref() {
        for target in flow_targets {
            if p.is_match(target) {
                models.push(filefacts::FlowTransfer::new(
                    target.clone(),
                    Vec::new(),
                    false,
                ));
            }
        }
    }
    let found = if let Some(field) = &origin.field {
        flow.field_origins(value, field, &models, 10_000)
    } else {
        flow.origins(value, &models, 10_000)
    };
    if found.incomplete {
        gaps.record(AnalysisGap::FlowQueryIncomplete);
        if origin.field.is_some() {
            gaps.record(AnalysisGap::FlowFieldUnavailable);
        }
    }
    found.values.iter().any(|observation| {
        let Some(value) = flow.values.get(observation.value) else { return false };
        if let Some(pattern) = &member_pattern {
            return value.kind == filefacts::FlowKind::Member
                && value.target.as_ref().is_some_and(|path| pattern.is_match(path));
        }
        if let Some(pattern) = &value_pattern {
            return value.literal.as_ref().is_some_and(|a| matches!(a,
                filefacts::Arg::String { value } | filefacts::Arg::Template { value } if pattern.is_match(value)));
        }
        if value.kind != filefacts::FlowKind::Call || !value.target.as_ref().is_some_and(|t| source_pattern.as_ref().is_some_and(|p| p.is_match(t))) { return false; }
        let Some(literal_pattern) = &origin.literal else { return true };
        let Some(pattern) = crate::composite_rules::condition::cached_regex(literal_pattern) else { return false };
        let arguments = flow.argument_origins(observation, origin.argument, &models, 10_000);
        if arguments.incomplete { gaps.record(AnalysisGap::FlowQueryIncomplete); }
        arguments.values.iter().any(|id| {
            flow.values.get(id.value).and_then(|v| v.literal.as_ref())
                .is_some_and(|a| matches!(a, filefacts::Arg::String { value } | filefacts::Arg::Template { value } if pattern.is_match(value)))
        })
    })
}

pub(super) fn flow<'a>(ctx: &'a EvaluationContext<'_>) -> Option<&'a filefacts::Flow> {
    use crate::types::AnalysisGap;
    let Some(flow) = ctx.report.filefacts.as_ref().and_then(|v| v.flow.as_ref()) else {
        ctx.report
            .analysis_gaps
            .record(AnalysisGap::FlowUnavailable);
        return None;
    };
    if flow.version != 1 {
        ctx.report
            .analysis_gaps
            .record(AnalysisGap::FlowSchemaUnsupported);
        return None;
    }
    if flow
        .limitations
        .iter()
        .any(|limit| *limit != filefacts::Limitation::SourceLocalMayFlowNotReachability)
    {
        ctx.report
            .analysis_gaps
            .record(AnalysisGap::FlowGraphLimited);
    }
    Some(flow)
}

/// Match one arg JSON value against an [`ArgFilter`]. Argstring/number/
/// identifier are tagged `{"shape": ...}` in filefacts's serialization.
pub(super) fn arg_matches(
    arg: &filefacts::Arg,
    filter: &crate::composite_rules::condition::ArgFilter,
) -> bool {
    use filefacts::Arg;
    if let Some(want_kind) = filter.kind.as_deref()
        && arg_shape(arg) != want_kind
    {
        return false;
    }
    // Value constraints imply a compatible shape even when `kind` is omitted.
    // Unknown arguments cannot satisfy a literal predicate by skipping its
    // match arm. Provenance-only filters still defer to origin_matches.
    if (filter.exact.is_some() || filter.substr.is_some() || filter.regex.is_some())
        && !matches!(arg, Arg::String { .. } | Arg::Template { .. })
    {
        return false;
    }
    if (filter.value.is_some() || filter.radix.is_some()) && !matches!(arg, Arg::Number { .. }) {
        return false;
    }
    if (filter.name.is_some() || filter.name_regex.is_some())
        && !matches!(arg, Arg::Identifier { .. })
    {
        return false;
    }
    if filter.is.is_some() && !arg_text(arg).is_some_and(|t| validate_match(t, filter.is)) {
        return false;
    }
    match arg {
        Arg::Number { value, radix, .. } => {
            if let Some(want_value) = filter.value
                && *value != want_value
            {
                return false;
            }
            if let Some(want_radix) = filter.radix
                && *radix != want_radix
            {
                return false;
            }
        }
        Arg::String { value } | Arg::Template { value } => {
            if let Some(want_exact) = filter.exact.as_deref()
                && value != want_exact
            {
                return false;
            }
            if let Some(want_substr) = filter.substr.as_deref()
                && !value.contains(want_substr)
            {
                return false;
            }
            if let Some(want_regex) = filter.regex.as_deref()
                && !crate::composite_rules::condition::cached_regex(want_regex)
                    .is_some_and(|re| re.is_match(value))
            {
                return false;
            }
        }
        Arg::Identifier { name } => {
            if let Some(pattern) = &filter.name_regex
                && !crate::composite_rules::condition::cached_regex(pattern)
                    .is_some_and(|r| r.is_match(name))
            {
                return false;
            }
            if let Some(want_name) = filter.name.as_deref()
                && name != want_name
            {
                return false;
            }
        }
        // Other shapes carry no matchable scalar value. Only shape/position
        // and separately evaluated provenance constraints can match them.
        _ => {}
    }
    true
}

/// The literal text an argument carries, if any: a string or template value,
/// or an identifier's name.
pub(super) fn arg_text(arg: &filefacts::Arg) -> Option<&str> {
    use filefacts::Arg;
    match arg {
        Arg::String { value } | Arg::Template { value } => Some(value),
        Arg::Identifier { name } => Some(name),
        _ => None,
    }
}

/// Lowercase shape tag for an [`filefacts::Arg`], matching the `shape:` /
/// `kind:` values rule authors write (mirrors filefacts's `#[serde(tag =
/// "shape", rename_all = "lowercase")]`).
pub(super) fn arg_shape(arg: &filefacts::Arg) -> &'static str {
    use filefacts::Arg;
    match arg {
        Arg::String { .. } => "string",
        Arg::Number { .. } => "number",
        Arg::Bool { .. } => "bool",
        Arg::Null => "null",
        Arg::Identifier { .. } => "identifier",
        Arg::Object => "object",
        Arg::Array => "array",
        Arg::Function => "function",
        Arg::Template { .. } => "template",
        Arg::Call => "call",
        Arg::Expression => "expression",
        _ => "",
    }
}
