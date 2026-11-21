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
/// exceptions are dead or exclude every match.
#[must_use]
pub(crate) fn find_dead_regex_exceptions(
    traits: &[TraitDefinition],
    composites: &[CompositeTrait],
) -> Vec<DeadException> {
    rule_conditions(traits, composites)
        .par_iter()
        .flat_map_iter(|&((id, file), condition, rule_not)| {
            let problems = matcher(condition)
                .map(|(pattern, own_not)| {
                    let exceptions: Vec<&NotException> = own_not
                        .into_iter()
                        .flatten()
                        .chain(rule_not.into_iter().flatten())
                        .collect();
                    exception_problems(&pattern, &exceptions)
                })
                .unwrap_or_default();
            problems.into_iter().map(move |problem| DeadException {
                rule: id.to_owned(),
                file: file.display().to_string(),
                problem,
            })
        })
        .collect()
}

/// A rule's `(id, file)`, one condition it lists, and the trait-level `not:`
/// that filters it (only a trait's `if:` has one).
pub(super) type RuleCondition<'a> = (
    (&'a str, &'a Path),
    &'a Condition,
    Option<&'a [NotException]>,
);

/// Every condition a trait or composite lists: `if:`, `unless:`, composite
/// legs and `downgrade:` legs.
pub(super) fn rule_conditions<'a>(
    traits: &'a [TraitDefinition],
    composites: &'a [CompositeTrait],
) -> Vec<RuleCondition<'a>> {
    let mut targets = Vec::new();
    for t in traits {
        let rule = (t.id.as_str(), t.defined_in.as_path());
        targets.push((rule, &t.r#if, t.not.as_deref()));
        for condition in t.unless.iter().flatten() {
            targets.push((rule, condition, None));
        }
        for condition in downgrade_conditions(t.downgrade.as_ref()) {
            targets.push((rule, condition, None));
        }
    }
    for c in composites {
        let rule = (c.id.as_str(), c.defined_in.as_path());
        for condition in [&c.all, &c.any, &c.unless].into_iter().flatten().flatten() {
            targets.push((rule, condition, None));
        }
        for condition in downgrade_conditions(c.downgrade.as_ref()) {
            targets.push((rule, condition, None));
        }
    }
    targets
}

fn downgrade_conditions(
    downgrade: Option<&DowngradeConditions>,
) -> impl Iterator<Item = &Condition> {
    downgrade
        .into_iter()
        .flat_map(|d| d.any.iter().chain(&d.all).flatten())
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

/// What is wrong with `exceptions` on a condition matching `pattern`.
fn exception_problems(pattern: &str, exceptions: &[&NotException]) -> Vec<String> {
    if exceptions.is_empty() {
        return Vec::new();
    }
    let Some(matched) = match_language(pattern) else {
        return Vec::new();
    };
    let mut problems = Vec::new();
    let mut alternatives = Vec::new();
    for exception in exceptions {
        let Some(regex) = exception_regex(exception) else {
            continue;
        };
        if let Some(contains) = containing(&regex)
            && product_walk(&matched, &contains, true, |m, x| m && x, false) == Some(false)
        {
            problems.push(format!(
                "not: exception {} can never apply to what regex '{pattern}' matches - a not: judges only the matched text, not the text around it; take the context into the regex as an optional group, or use unless:",
                exception.shown()
            ));
        }
        alternatives.push(format!("(?:{regex})"));
    }
    if problems.is_empty()
        && let Some(contains) = containing(&alternatives.join("|"))
        && product_walk(&matched, &contains, true, |m, x| m && !x, false) == Some(false)
    {
        problems.push(format!(
            "not: exceptions exclude every match of regex '{pattern}', so it can never fire"
        ));
    }
    problems
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
