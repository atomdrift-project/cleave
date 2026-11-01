//! A one-line summary of what each rule's conditions do, for the slow-rule
//! audit of `cleave validate --slow-rules`: which evaluators a rule reaches
//! for decides what a faster equivalent could look like.

use super::CapabilityMapper;
use crate::composite_rules::condition::Condition;
use std::collections::BTreeMap;

/// Where a rule is defined and the shape of its conditions.
#[derive(Clone, Debug)]
pub(crate) struct RuleShape {
    pub(crate) defined_in: String,
    /// `for:` as written, or `all`.
    pub(crate) r#for: String,
    /// Condition summaries, e.g. `text/regex`, `tree-sitter/query`,
    /// `any(trait, raw/substr) near_lines`.
    pub(crate) conditions: String,
}

/// `text/regex`, `raw/substr`, `tree-sitter/query`, `yara`, ... : the
/// evaluator a condition reaches and the matcher it runs there.
#[must_use]
pub(crate) fn condition_shape(condition: &Condition) -> String {
    let matcher = |exact: &Option<String>, substr: &Option<String>, regex: &Option<String>| {
        if regex.is_some() {
            Some("regex")
        } else if substr.is_some() {
            Some("substr")
        } else if exact.is_some() {
            Some("exact")
        } else {
            None
        }
    };
    let detail: Option<&str> = match condition {
        Condition::Text(q) => matcher(&q.exact, &q.substr, &q.regex),
        Condition::Raw(q) => matcher(&q.exact, &q.substr, &q.regex),
        Condition::Comment(q) => matcher(&q.exact, &q.substr, &q.regex),
        Condition::Literal(q) => matcher(&q.exact, &q.substr, &q.regex),
        Condition::Symbol(q) => matcher(&q.exact, &q.substr, &q.regex),
        Condition::TreeSitter(q) => {
            if q.query.is_some() {
                Some("query")
            } else if q.node.is_some() {
                Some("node")
            } else {
                matcher(&q.exact, &q.substr, &q.regex).or(Some("kind"))
            }
        }
        _ => None,
    };
    match detail {
        Some(detail) => format!("{}/{detail}", condition.type_name()),
        None => condition.type_name().to_owned(),
    }
}

fn join(conditions: &[Condition]) -> String {
    let mut parts: Vec<String> = conditions.iter().map(condition_shape).collect();
    parts.sort();
    parts.dedup();
    parts.join(", ")
}

fn for_list(r#for: &[crate::composite_rules::FileType]) -> String {
    if r#for.is_empty() {
        "all".to_owned()
    } else {
        r#for
            .iter()
            // The enum serializes `rename_all = "lowercase"`.
            .map(|ft| format!("{ft:?}").to_lowercase())
            .collect::<Vec<_>>()
            .join(",")
    }
}

impl CapabilityMapper {
    /// Every rule's shape by id.
    #[must_use]
    pub(crate) fn rule_shapes(&self) -> BTreeMap<String, RuleShape> {
        let mut shapes = BTreeMap::new();
        for t in &self.trait_definitions {
            let mut conditions = condition_shape(&t.r#if);
            if let Some(unless) = &t.unless
                && !unless.is_empty()
            {
                conditions.push_str(&format!(" unless({})", join(unless)));
            }
            shapes.insert(
                t.id.clone(),
                RuleShape {
                    defined_in: t.defined_in.display().to_string(),
                    r#for: for_list(&t.r#for),
                    conditions,
                },
            );
        }
        for c in &self.composite_rules {
            let mut parts = Vec::new();
            if let Some(all) = &c.all
                && !all.is_empty()
            {
                parts.push(format!("all({})", join(all)));
            }
            if let Some(any) = &c.any
                && !any.is_empty()
            {
                parts.push(format!("any({})", join(any)));
            }
            if c.near_lines.is_some() {
                parts.push("near_lines".to_owned());
            }
            if c.near_bytes.is_some() {
                parts.push("near_bytes".to_owned());
            }
            if let Some(unless) = &c.unless
                && !unless.is_empty()
            {
                parts.push(format!("unless({})", join(unless)));
            }
            shapes.insert(
                c.id.clone(),
                RuleShape {
                    defined_in: c.defined_in.display().to_string(),
                    r#for: for_list(&c.r#for),
                    conditions: parts.join(" "),
                },
            );
        }
        shapes
    }
}
