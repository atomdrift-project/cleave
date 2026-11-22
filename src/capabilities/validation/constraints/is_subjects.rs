//! `is:` validators whose subject is ambiguous or fixed.
//!
//! `is:` judges a regex's first capture group, or the whole match when the
//! regex has none. Two shapes defeat that: a regex with several groups, where
//! a group added for alternation or repetition silently becomes the subject,
//! and a fixed-text matcher (`exact:`, `substr:`, `word:`), whose match is the
//! same text every time, so the validator's answer never changes.

// Split out of the parent module for size; it shares the parent's namespace.
#[allow(clippy::wildcard_imports)]
use super::*;

use super::dead_exceptions::rules;
use crate::composite_rules::CommentQuery;

/// `rule 'id' in file: problem` for every condition whose `is:` subject is
/// ambiguous or fixed.
#[must_use]
pub(crate) fn find_ambiguous_is_subjects(
    traits: &[TraitDefinition],
    composites: &[CompositeTrait],
) -> Vec<String> {
    rules(traits, composites)
        .iter()
        .flat_map(|rule| {
            rule.conditions.iter().filter_map(|condition| {
                let problem = is_subject_problem(condition)?;
                Some(format!(
                    "rule '{}' in {}: {problem}",
                    rule.id,
                    rule.file.display()
                ))
            })
        })
        .collect()
}

fn is_subject_problem(condition: &Condition) -> Option<String> {
    let (is_check, regex, fixed) = match condition {
        Condition::Text(TextQuery {
            is_check,
            regex,
            exact,
            substr,
            word,
            ..
        })
        | Condition::Raw(RawQuery {
            is_check,
            regex,
            exact,
            substr,
            word,
            ..
        })
        | Condition::Encoded(EncodedQuery {
            is_check,
            regex,
            exact,
            substr,
            word,
            ..
        })
        | Condition::Comment(CommentQuery {
            is_check,
            regex,
            exact,
            substr,
            word,
            ..
        }) => (
            is_check,
            regex,
            exact.as_ref().or(substr.as_ref()).or(word.as_ref()),
        ),
        Condition::Literal(LiteralQuery {
            is_check,
            regex,
            exact,
            substr,
            ..
        })
        | Condition::Kv(KvQuery {
            is_check,
            regex,
            exact,
            substr,
            ..
        })
        | Condition::Path(PathQuery {
            is_check,
            regex,
            exact,
            substr,
            ..
        })
        | Condition::Symbol(SymbolQuery {
            is_check,
            regex,
            exact,
            substr,
            ..
        }) => (is_check, regex, exact.as_ref().or(substr.as_ref())),
        _ => return None,
    };
    is_check.as_ref()?;
    if let Some(text) = fixed {
        return Some(format!(
            "is: judges what matched, and '{text}' is fixed text, so the check never varies - match the value with a regex"
        ));
    }
    let groups = regex_syntax::parse(regex.as_deref()?)
        .ok()?
        .properties()
        .explicit_captures_len();
    (groups > 1).then(|| {
        format!(
            "is: judges the first capture group, and regex '{}' has {groups} - make the others non-capturing (?:...)",
            regex.as_deref().unwrap_or_default()
        )
    })
}

#[cfg(test)]
#[path = "is_subjects_tests.rs"]
mod tests;
