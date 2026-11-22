//! `not:` exceptions that cannot apply to what their regex condition matches.
//!
//! A `not:` judges only the text its condition matched, never the text around
//! it. `regex: '^http://'` matches `http://` and nothing more, so an exception
//! naming the rest of a URL (`^http://localhost/`) never applies, and the rule
//! fires on every URL it was meant to excuse. Spotting that by eye takes
//! knowing what each match can span; this check decides it on the automata.
//!
//! The question is one of languages. Let `M` be the strings the condition can
//! report as its match and `X` the strings an exception matches somewhere
//! inside. The exception is dead when no string in `M` contains a match of
//! `X`, and the exceptions together exclude every match when every string in
//! `M` does. Both are decided by walking the two DFAs in lockstep
//! ([`super::convictions::product_walk`]).
//!
//! `M` is over-approximated, never under: the condition is compiled from its
//! syntax tree with every word-boundary assertion dropped, because a match's
//! boundary assertions were judged against the text around it, which a
//! standalone span does not have. Text-start and text-end assertions are kept:
//! a span always satisfies them where the match did. A larger `M` can only
//! make an exception look more alive, so every reported exception really is
//! dead. Anything the automata cannot settle within budget is not reported.

// Split out of the parent module for size; it shares the parent's namespace.
#[allow(clippy::wildcard_imports)]
use super::*;

use super::convictions::{ValueSetDfa, product_walk};
use crate::composite_rules::CommentQuery;
use crate::composite_rules::condition::NotException;
use crate::composite_rules::condition::NotExceptionStructured;
use regex_automata::dfa::dense;
use regex_automata::nfa::thompson;
use regex_syntax::hir::{Capture, Hir, HirKind, Look, Repetition};
use std::path::Path;

/// One finding: the rule it is in, and what is wrong.
pub(crate) struct DeadException {
    pub(crate) rule: String,
    pub(crate) file: String,
    pub(crate) problem: String,
}

/// Every regex or `word:` condition, wherever it sits, whose `not:`
/// exceptions are dead or exclude every match, and every rule-level `not:`
/// that applies to none of its rule's matches.
#[must_use]
pub(crate) fn find_dead_regex_exceptions(
    traits: &[TraitDefinition],
    composites: &[CompositeTrait],
) -> Vec<DeadException> {
    rules(traits, composites)
        .par_iter()
        .flat_map_iter(|rule| {
            rule_problems(rule)
                .into_iter()
                .map(|problem| DeadException {
                    rule: rule.id.to_owned(),
                    file: rule.file.display().to_string(),
                    problem,
                })
        })
        .collect()
}

/// A rule, every condition it lists (`if:`, `unless:`, composite legs and
/// `downgrade:` legs), and its rule-level `not:`.
pub(super) struct RuleConditions<'a> {
    pub(super) id: &'a str,
    pub(super) file: &'a Path,
    pub(super) conditions: Vec<&'a Condition>,
    pub(super) not: Option<&'a [NotException]>,
}

pub(super) fn rules<'a>(
    traits: &'a [TraitDefinition],
    composites: &'a [CompositeTrait],
) -> Vec<RuleConditions<'a>> {
    let traits = traits.iter().map(|t| RuleConditions {
        id: &t.id,
        file: &t.defined_in,
        conditions: std::iter::once(&t.r#if)
            .chain(t.unless.iter().flatten())
            .chain(downgrade_conditions(t.downgrade.as_ref()))
            .collect(),
        not: t.not.as_deref(),
    });
    let composites = composites.iter().map(|c| RuleConditions {
        id: &c.id,
        file: &c.defined_in,
        conditions: [&c.all, &c.any, &c.unless]
            .into_iter()
            .flatten()
            .flatten()
            .chain(downgrade_conditions(c.downgrade.as_ref()))
            .collect(),
        not: c.not.as_deref(),
    });
    traits.chain(composites).collect()
}

fn downgrade_conditions(
    downgrade: Option<&DowngradeConditions>,
) -> impl Iterator<Item = &Condition> {
    downgrade
        .into_iter()
        .flat_map(|d| d.any.iter().chain(&d.all).flatten())
}

/// Whether evaluation merges the rule-level `not:` into this condition's own
/// (see `eval_condition`): `id:` references and structural conditions do not.
fn takes_rule_not(condition: &Condition) -> bool {
    matches!(
        condition,
        Condition::Text(_)
            | Condition::Raw(_)
            | Condition::Encoded(_)
            | Condition::Comment(_)
            | Condition::Literal(_)
            | Condition::Kv(_)
            | Condition::Symbol(_)
            | Condition::Hex(_)
    )
}

/// What is wrong with one rule's exceptions. A condition's own `not:` is
/// judged against that condition's matches; a rule-level `not:` applies to
/// every leg that takes it, so it is dead only when it can apply to none.
fn rule_problems(rule: &RuleConditions<'_>) -> Vec<String> {
    let rule_not: Vec<&NotException> = rule.not.into_iter().flatten().collect();
    // Per rule-level exception: `Some(false)` while no leg it applies to was
    // found to admit it, `Some(true)` once one does, `None` when some leg
    // could not be settled.
    let mut applies: Vec<Option<bool>> = vec![Some(false); rule_not.len()];
    let mut judged_against = Vec::new();
    let mut problems = Vec::new();
    for &condition in &rule.conditions {
        let inherited: &[&NotException] = if takes_rule_not(condition) {
            &rule_not
        } else {
            &[]
        };
        let analyzed = matcher(condition).and_then(|(pattern, own)| {
            let own: Vec<&NotException> = own.into_iter().flatten().collect();
            if own.is_empty() && inherited.is_empty() {
                return Some(());
            }
            let matched = match_language(&pattern)?;
            problems.extend(leg_problems(&pattern, &matched, &own, inherited));
            for (state, exception) in applies.iter_mut().zip(inherited) {
                if *state == Some(false) {
                    *state = can_apply(&matched, exception);
                }
            }
            if !inherited.is_empty() {
                judged_against.push(pattern);
            }
            Some(())
        });
        if analyzed.is_none() && !inherited.is_empty() {
            applies.fill(None);
        }
    }
    for (exception, state) in rule_not.iter().zip(applies) {
        if state != Some(false) {
            continue;
        }
        problems.push(match judged_against.as_slice() {
            [] => format!(
                "rule-level not: exception {} applies to none of its conditions ({}) - only text, raw, encoded, comment, string_literal, value, symbol and hex conditions take it; put it on the leg it is meant for, or use unless:",
                exception.shown(),
                condition_types(&rule.conditions)
            ),
            [pattern] => dead_message(exception, pattern),
            patterns => format!(
                "rule-level not: exception {} can never apply to what any of the {} conditions it filters match - a not: judges only the matched text, not the text around it",
                exception.shown(),
                patterns.len()
            ),
        });
    }
    problems
}

/// `text, trait` - the distinct `type:`s of `conditions`, for messages.
fn condition_types(conditions: &[&Condition]) -> String {
    let mut types: Vec<&str> = conditions.iter().map(|c| c.type_name()).collect();
    types.sort_unstable();
    types.dedup();
    types.join(", ")
}

fn dead_message(exception: &NotException, pattern: &str) -> String {
    format!(
        "not: exception {} can never apply to what regex '{pattern}' matches - a not: judges only the matched text, not the text around it; take the context into the regex as an optional group, or use unless:",
        exception.shown()
    )
}

/// The condition's match, as the regex the engine compiles for it, and its
/// own `not:` list. `None` for conditions whose match is not a regex or word
/// span (substr and exact are checked where the trait is loaded).
fn matcher(condition: &Condition) -> Option<(String, Option<&Vec<NotException>>)> {
    let (regex, word, case_insensitive, not, multi_line) = match condition {
        Condition::Text(TextQuery {
            regex,
            word,
            case_insensitive,
            not,
            ..
        })
        | Condition::Encoded(EncodedQuery {
            regex,
            word,
            case_insensitive,
            not,
            ..
        })
        | Condition::Comment(CommentQuery {
            regex,
            word,
            case_insensitive,
            not,
            ..
        }) => (regex, word, *case_insensitive, not, false),
        Condition::Raw(RawQuery {
            regex,
            word,
            case_insensitive,
            not,
            ..
        }) => (regex, word, *case_insensitive, not, true),
        Condition::Literal(LiteralQuery {
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
        }) => (regex, &None, *case_insensitive, not, false),
        // Symbol names match case-sensitively.
        Condition::Symbol(SymbolQuery { regex, not, .. }) => (regex, &None, false, not, false),
        _ => return None,
    };
    let body = match (regex, word) {
        (Some(regex), _) => regex.clone(),
        (None, Some(word)) => format!(r"\b{}\b", regex::escape(word)),
        (None, None) => return None,
    };
    let flags = match (case_insensitive, multi_line) {
        (false, false) => "",
        (true, false) => "(?i)",
        (false, true) => "(?m)",
        (true, true) => "(?im)",
    };
    Some((format!("{flags}{body}"), not.as_ref()))
}

/// What is wrong with one condition's exceptions: each of its `own` that can
/// never apply, or, when none is dead, `own` and `inherited` together
/// excluding every match.
fn leg_problems(
    pattern: &str,
    matched: &ValueSetDfa,
    own: &[&NotException],
    inherited: &[&NotException],
) -> Vec<String> {
    let problems: Vec<String> = own
        .iter()
        .filter(|exception| can_apply(matched, exception) == Some(false))
        .map(|exception| dead_message(exception, pattern))
        .collect();
    if !problems.is_empty() {
        return problems;
    }
    let alternatives: Vec<String> = own
        .iter()
        .chain(inherited)
        .filter_map(|exception| exception_regex(exception))
        .map(|regex| format!("(?:{regex})"))
        .collect();
    if !alternatives.is_empty()
        && let Some(contains) = containing(&alternatives.join("|"))
        && product_walk(matched, &contains, true, |m, x| m && !x, false) == Some(false)
    {
        return vec![format!(
            "not: exceptions exclude every match of regex '{pattern}', so it can never fire"
        )];
    }
    Vec::new()
}

/// Whether `exception` applies to some string in `matched`; `None` when the
/// automata cannot settle it.
fn can_apply(matched: &ValueSetDfa, exception: &NotException) -> Option<bool> {
    let contains = containing(&exception_regex(exception)?)?;
    product_walk(matched, &contains, true, |m, x| m && x, false)
}

/// An exception as the regex its `matches` applies to the matched span.
fn exception_regex(exception: &NotException) -> Option<String> {
    Some(match exception {
        // Case-insensitive substrings.
        NotException::Shorthand(text)
        | NotException::Structured(NotExceptionStructured {
            exact: None,
            regex: None,
            substr: Some(text),
            ..
        }) => format!("(?i:{})", regex::escape(text)),
        NotException::Structured(NotExceptionStructured {
            exact: Some(text), ..
        }) => format!(r"\A{}\z", regex::escape(text)),
        NotException::Structured(NotExceptionStructured {
            regex: Some(regex), ..
        }) => regex.clone(),
        NotException::Structured(_) => return None,
    })
}

/// The strings with a match of `regex` somewhere in them, read whole.
fn containing(regex: &str) -> Option<ValueSetDfa> {
    let syntax = syntax_for(regex);
    let any = if syntax.get_unicode() {
        "(?s:.)"
    } else {
        "(?s-u:.)"
    };
    build(&format!("{any}*(?:{regex}){any}*"), syntax)
}

/// The strings `pattern` can report as its match, read whole, with
/// word-boundary assertions dropped (see the module docs).
fn match_language(pattern: &str) -> Option<ValueSetDfa> {
    let syntax = syntax_for(pattern);
    let hir = regex_syntax::ParserBuilder::new()
        .unicode(syntax.get_unicode())
        .utf8(syntax.get_utf8())
        .build()
        .parse(pattern)
        .ok()?;
    let nfa = thompson::Compiler::new()
        .configure(thompson::Config::new().utf8(syntax.get_utf8()))
        .build_from_hir(&without_word_boundaries(&hir))
        .ok()?;
    dense::Builder::new()
        .configure(dfa_config())
        .build_from_nfa(&nfa)
        .ok()
}

/// The engine's choice of semantics: bytes for an ASCII pattern that parses
/// that way, codepoints otherwise (see `TraitRegex::compile`).
fn syntax_for(pattern: &str) -> regex_automata::util::syntax::Config {
    let bytes = regex_automata::util::syntax::Config::new()
        .unicode(false)
        .utf8(false);
    if pattern.is_ascii() && regex_automata::util::syntax::parse_with(pattern, &bytes).is_ok() {
        bytes
    } else {
        regex_automata::util::syntax::Config::new()
    }
}

fn build(pattern: &str, syntax: regex_automata::util::syntax::Config) -> Option<ValueSetDfa> {
    dense::Builder::new()
        .configure(dfa_config())
        .syntax(syntax)
        .thompson(thompson::Config::new().utf8(syntax.get_utf8()))
        .build(pattern)
        .ok()
}

fn dfa_config() -> dense::Config {
    dense::Config::new()
        .match_kind(regex_automata::MatchKind::All)
        .start_kind(regex_automata::dfa::StartKind::Both)
        .dfa_size_limit(Some(1 << 22))
        .determinize_size_limit(Some(1 << 22))
}

/// `hir` with every assertion other than text and line boundaries replaced by
/// the empty match.
fn without_word_boundaries(hir: &Hir) -> Hir {
    match hir.kind() {
        HirKind::Look(
            Look::Start | Look::End | Look::StartLF | Look::EndLF | Look::StartCRLF | Look::EndCRLF,
        )
        | HirKind::Empty
        | HirKind::Literal(_)
        | HirKind::Class(_) => hir.clone(),
        HirKind::Look(_) => Hir::empty(),
        HirKind::Repetition(rep) => Hir::repetition(Repetition {
            sub: Box::new(without_word_boundaries(&rep.sub)),
            ..rep.clone()
        }),
        HirKind::Capture(cap) => Hir::capture(Capture {
            sub: Box::new(without_word_boundaries(&cap.sub)),
            ..cap.clone()
        }),
        HirKind::Concat(subs) => Hir::concat(subs.iter().map(without_word_boundaries).collect()),
        HirKind::Alternation(subs) => {
            Hir::alternation(subs.iter().map(without_word_boundaries).collect())
        }
    }
}

#[cfg(test)]
#[path = "dead_exceptions_tests.rs"]
mod tests;
