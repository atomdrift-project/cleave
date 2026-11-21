//! Every regex a rule lists, wherever it sits.
//!
//! The per-pattern regex checks — does it compile (`incompatible-regex`), how
//! big is its engine (`regex-memory`), is it costly (`regex-performance`),
//! does its lazy DFA explode (`regex-explosion`), does it have a backtracking
//! shape (`nested-quantifier`) — all run over this one inventory, so none of
//! them can miss a place a pattern hides: a trait's `if:`, `unless:` and
//! `downgrade:` legs, a composite's `all:`/`any:`/`unless:`/`downgrade:` legs,
//! every `not:` exception (trait-, condition- and composite-level), and the
//! regexes inside a symbol condition's argument, alias and provenance filters.

use crate::composite_rules::condition::{ArgFilter, FlowOriginFilter, NotException};
use crate::composite_rules::{
    CommentQuery, CompositeTrait, Condition, DowngradeConditions, EncodedQuery, HexQuery, KvQuery,
    LiteralQuery, PathQuery, RawQuery, SectionQuery, SymbolQuery, TextQuery, TraitDefinition,
    TreeSitterQuery,
};
use std::path::Path;

/// One regex a rule lists.
#[derive(Clone, Copy, Debug)]
pub(crate) struct RuleRegex<'a> {
    /// `trait` or `composite`.
    pub(crate) kind: &'static str,
    pub(crate) id: &'a str,
    pub(crate) defined_in: &'a Path,
    /// Where in the rule it sits: `if:`, `not:`, `unless:`, `downgrade:`,
    /// `all:` or `any:` — with ` not:` appended for an exception inline in
    /// that condition (`unless: not:`).
    pub(crate) place: &'static str,
    pub(crate) pattern: &'a str,
    /// Evaluation compiles it with `(?i)`.
    pub(crate) case_insensitive: bool,
    /// The surface it searches, as a `type:` label (`text`, `raw`, `symbol`,
    /// `value`, …). A `not:` exception reads what the condition it filters
    /// read, so it carries that condition's label.
    pub(crate) reads: &'static str,
}

impl RuleRegex<'_> {
    /// `kind 'id' in file:line`, for messages.
    pub(crate) fn rule(&self) -> String {
        let file = self.defined_in.to_str().unwrap_or("unknown");
        match super::helpers::find_line_number(file, self.id) {
            Some(line) => format!("{} '{}' in {file}:{line}", self.kind, self.id),
            None => format!("{} '{}' in {file}", self.kind, self.id),
        }
    }

    /// Whether it searches whole files or large blobs, where a costly shape
    /// costs per byte, rather than a short bounded value such as a symbol
    /// name, a path or a structured value.
    pub(crate) fn reads_broad_input(&self) -> bool {
        matches!(
            self.reads,
            "text" | "raw" | "encoded" | "comment" | "tree-sitter"
        )
    }
}

/// Every regex in `traits` and `composites`, in rule order.
pub(crate) fn rule_regexes<'a>(
    traits: &'a [TraitDefinition],
    composites: &'a [CompositeTrait],
) -> Vec<RuleRegex<'a>> {
    let mut out = Vec::new();
    for t in traits {
        let mut push = |place, pattern, case_insensitive, reads| {
            out.push(RuleRegex {
                kind: "trait",
                id: &t.id,
                defined_in: &t.defined_in,
                place,
                pattern,
                case_insensitive,
                reads,
            });
        };
        for_each_condition_regex(&t.r#if, &mut |p, ci, reads, inline| {
            push(within("if:", inline), p, ci, reads);
        });
        // A trait-level `not:` filters what the `if:` matched.
        let reads = surface(&t.r#if).unwrap_or("text");
        for_each_not_regex(t.not.as_deref(), &mut |p| push("not:", p, false, reads));
        for condition in t.unless.iter().flatten() {
            for_each_condition_regex(condition, &mut |p, ci, reads, inline| {
                push(within("unless:", inline), p, ci, reads);
            });
        }
        for_each_downgrade_regex(t.downgrade.as_ref(), &mut |p, ci, reads, inline| {
            push(within("downgrade:", inline), p, ci, reads);
        });
    }
    for rule in composites {
        let mut push = |place, pattern, case_insensitive, reads| {
            out.push(RuleRegex {
                kind: "composite",
                id: &rule.id,
                defined_in: &rule.defined_in,
                place,
                pattern,
                case_insensitive,
                reads,
            });
        };
        for (place, legs) in [
            ("all:", &rule.all),
            ("any:", &rule.any),
            ("unless:", &rule.unless),
        ] {
            for condition in legs.iter().flatten() {
                for_each_condition_regex(condition, &mut |p, ci, reads, inline| {
                    push(within(place, inline), p, ci, reads);
                });
            }
        }
        // A composite's `not:` filters its legs' evidence, read from content.
        for_each_not_regex(rule.not.as_deref(), &mut |p| push("not:", p, false, "text"));
        for_each_downgrade_regex(rule.downgrade.as_ref(), &mut |p, ci, reads, inline| {
            push(within("downgrade:", inline), p, ci, reads);
        });
    }
    out
}

/// `place`, or the exception list inline in a condition at `place`.
fn within(place: &'static str, inline_not: bool) -> &'static str {
    match (place, inline_not) {
        (place, false) => place,
        ("if:", true) => "if: not:",
        ("unless:", true) => "unless: not:",
        ("downgrade:", true) => "downgrade: not:",
        ("all:", true) => "all: not:",
        ("any:", true) => "any: not:",
        (_, true) => "not:",
    }
}

/// The `type:` label of the surface a condition's own `regex:` searches.
fn surface(condition: &Condition) -> Option<&'static str> {
    Some(match condition {
        Condition::Symbol(_) => "symbol",
        Condition::Text(_) => "text",
        Condition::Raw(_) | Condition::Hex(_) => "raw",
        Condition::Encoded(_) => "encoded",
        Condition::Comment(_) => "comment",
        Condition::Literal(_) => "string_literal",
        Condition::TreeSitter(_) => "tree-sitter",
        Condition::Section(_) => "section",
        Condition::Path(_) => "basename",
        Condition::Kv(_) => "value",
        _ => return None,
    })
}

/// Invoke `f(pattern, case_insensitive, reads, inline_not)` with every regex
/// one condition compiles: its `regex:`, its inline `not:` exceptions
/// (`inline_not`), and a symbol condition's argument, alias and provenance
/// regexes.
fn for_each_condition_regex<'a>(
    condition: &'a Condition,
    f: &mut impl FnMut(&'a str, bool, &'static str, bool),
) {
    let Some(reads) = surface(condition) else {
        return;
    };
    let (regex, case_insensitive, not) = match condition {
        Condition::Symbol(SymbolQuery { regex, not, .. }) => (regex, false, not),
        Condition::Text(TextQuery {
            regex,
            case_insensitive,
            not,
            ..
        })
        | Condition::Raw(RawQuery {
            regex,
            case_insensitive,
            not,
            ..
        })
        | Condition::Encoded(EncodedQuery {
            regex,
            case_insensitive,
            not,
            ..
        })
        | Condition::Comment(CommentQuery {
            regex,
            case_insensitive,
            not,
            ..
        })
        | Condition::Literal(LiteralQuery {
            regex,
            case_insensitive,
            not,
            ..
        })
        | Condition::Kv(KvQuery {
            regex,
            case_insensitive,
            not,
            ..
        }) => (regex, *case_insensitive, not),
        Condition::TreeSitter(TreeSitterQuery {
            regex,
            case_insensitive,
            ..
        })
        | Condition::Section(SectionQuery {
            regex,
            case_insensitive,
            ..
        })
        | Condition::Path(PathQuery {
            regex,
            case_insensitive,
            ..
        }) => (regex, *case_insensitive, &None),
        Condition::Hex(HexQuery { not, .. }) => (&None, false, not),
        _ => return,
    };
    if let Some(regex) = regex {
        f(regex, case_insensitive, reads, false);
    }
    for_each_not_regex(not.as_deref(), &mut |p| f(p, false, reads, true));
    if let Condition::Symbol(query) = condition {
        for_each_symbol_filter_regex(query, &mut |p| f(p, false, "symbol", false));
    }
}

/// Every regex in a symbol condition's `arg:`/`args:`, `alias:` and
/// `receiver:` filters.
fn for_each_symbol_filter_regex<'a>(query: &'a SymbolQuery, f: &mut impl FnMut(&'a str)) {
    let args = query
        .arg
        .as_deref()
        .into_iter()
        .chain(query.args.iter().flatten());
    for ArgFilter {
        regex,
        name_regex,
        from,
        ..
    } in args
    {
        regex.iter().chain(name_regex).for_each(|p| f(p));
        if let Some(origin) = from {
            for_each_origin_regex(origin, f);
        }
    }
    if let Some(alias) = &query.alias {
        alias.regex.iter().for_each(|p| f(p));
    }
    if let Some(receiver) = &query.receiver {
        for_each_origin_regex(&receiver.from, f);
    }
}

/// Every regex a provenance filter matches against: the source call, the
/// contributing or whole literal value, the member path, the call's literal
/// argument, and each transfer model's call.
fn for_each_origin_regex<'a>(origin: &'a FlowOriginFilter, f: &mut impl FnMut(&'a str)) {
    std::iter::once(&origin.call)
        .filter(|call| !call.trim().is_empty())
        .chain(&origin.value)
        .chain(&origin.whole_value)
        .chain(&origin.member)
        .chain(&origin.literal)
        .chain(origin.through.iter().map(|model| &model.call))
        .for_each(|p| f(p));
}

/// Every `regex:` exception in a `not:` list (shorthand and `substr:`/`exact:`
/// exceptions are literal).
fn for_each_not_regex<'a>(exceptions: Option<&'a [NotException]>, f: &mut impl FnMut(&'a str)) {
    for exception in exceptions.into_iter().flatten() {
        if let NotException::Structured(structured) = exception
            && let Some(regex) = &structured.regex
        {
            f(regex);
        }
    }
}

fn for_each_downgrade_regex<'a>(
    downgrade: Option<&'a DowngradeConditions>,
    f: &mut impl FnMut(&'a str, bool, &'static str, bool),
) {
    if let Some(d) = downgrade {
        for condition in d.any.iter().chain(&d.all).flatten() {
            for_each_condition_regex(condition, f);
        }
    }
}

#[cfg(test)]
#[path = "rule_regexes_tests.rs"]
mod tests;
