//! Shared validation controls and display metadata.
//!
//! This keeps temporary validator disables centralized while validators are
//! re-enabled one at a time.

use anyhow::{bail, Result};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{OnceLock, RwLock};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum ValidatorCategory {
    Quality,
    Dedup,
    Reuse,
    Policy,
    Regression,
}

impl ValidatorCategory {
    #[must_use]
    pub(crate) const fn display(self) -> &'static str {
        match self {
            Self::Quality => "qual",
            Self::Dedup => "dedup",
            Self::Reuse => "reuse",
            Self::Policy => "policy",
            Self::Regression => "regress",
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct ValidatorSpec {
    pub(crate) id: &'static str,
    pub(crate) category: ValidatorCategory,
    pub(crate) display_id: &'static str,
    pub(crate) description: &'static str,
    pub(crate) fix: &'static str,
}

impl ValidatorSpec {
    #[must_use]
    pub(crate) fn label(self) -> String {
        format!("{}/{}", self.category.display(), self.display_id)
    }
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct ValidationIssue {
    pub(crate) validator_id: &'static str,
    pub(crate) label: String,
    pub(crate) category: &'static str,
    pub(crate) display_id: &'static str,
    pub(crate) description: &'static str,
    pub(crate) fix: &'static str,
    pub(crate) message: String,
    pub(crate) count: usize,
    pub(crate) file: Option<String>,
    pub(crate) line: Option<usize>,
    pub(crate) rule_id: Option<String>,
}

#[derive(Debug, Default)]
pub(crate) struct ValidationIssues {
    issues: Vec<ValidationIssue>,
}

impl ValidationIssues {
    #[must_use]
    pub(crate) fn new() -> Self {
        Self { issues: Vec::new() }
    }

    pub(crate) fn push(&mut self, message: impl Into<String>) {
        self.push_legacy(message);
    }

    pub(crate) fn push_id(&mut self, validator_id: &'static str, message: impl Into<String>) {
        self.issues
            .push(ValidationIssue::new(validator_id, message));
    }

    pub(crate) fn push_count(
        &mut self,
        validator_id: &'static str,
        count: usize,
        message: impl Into<String>,
    ) {
        self.issues
            .push(ValidationIssue::new(validator_id, message).with_count(count));
    }

    pub(crate) fn push_legacy(&mut self, message: impl Into<String>) {
        self.issues.push(ValidationIssue::legacy(message));
    }

    pub(crate) fn extend_legacy(&mut self, messages: impl IntoIterator<Item = String>) {
        self.issues
            .extend(messages.into_iter().map(ValidationIssue::legacy));
    }

    pub(crate) fn collect_as(
        &mut self,
        validator_id: &'static str,
        f: impl FnOnce(&mut Vec<String>),
    ) {
        let mut messages = Vec::new();
        f(&mut messages);
        self.issues.extend(
            messages
                .into_iter()
                .map(|message| ValidationIssue::new(validator_id, message)),
        );
    }

    #[must_use]
    pub(crate) fn is_empty(&self) -> bool {
        self.issues.is_empty()
    }

    #[must_use]
    pub(crate) fn len(&self) -> usize {
        self.issues.len()
    }

    #[must_use]
    pub(crate) fn as_slice(&self) -> &[ValidationIssue] {
        &self.issues
    }

    pub(crate) fn truncate(&mut self, len: usize) {
        self.issues.truncate(len);
    }

    pub(crate) fn iter(&self) -> impl Iterator<Item = &ValidationIssue> {
        self.issues.iter()
    }
}

impl ValidationIssue {
    #[must_use]
    pub(crate) fn new(validator_id: &'static str, message: impl Into<String>) -> Self {
        let spec = validator_spec(validator_id).unwrap_or(&UNKNOWN_VALIDATOR);
        Self {
            validator_id: spec.id,
            label: spec.label(),
            category: spec.category.display(),
            display_id: spec.display_id,
            description: spec.description,
            fix: spec.fix,
            message: message.into(),
            count: 1,
            file: None,
            line: None,
            rule_id: None,
        }
    }

    #[must_use]
    pub(crate) fn legacy(message: impl Into<String>) -> Self {
        let message = message.into();
        let (file, line) = parse_location(&message);
        let mut issue = Self::new("validation", message);
        if let Some(file) = file {
            issue = issue.with_location(file, line);
        }
        issue
    }

    #[must_use]
    pub(crate) fn with_location(mut self, file: impl Into<String>, line: Option<usize>) -> Self {
        self.file = Some(file.into());
        self.line = line;
        self
    }

    #[must_use]
    pub(crate) fn with_count(mut self, count: usize) -> Self {
        self.count = count;
        self
    }

    #[must_use]
    pub(crate) fn location(&self) -> String {
        match (&self.file, self.line) {
            (Some(file), Some(line)) => format!("{file}:{line}"),
            (Some(file), None) => file.clone(),
            (None, _) => "-".to_string(),
        }
    }

    #[must_use]
    pub(crate) fn compact_message(&self) -> String {
        let mut out = format!("{} {}", self.label, self.message);
        if let Some(rule_id) = &self.rule_id {
            out.push_str(&format!(" [{rule_id}]"));
        }
        out
    }
}

fn parse_location(message: &str) -> (Option<String>, Option<usize>) {
    if let Some((file, line)) = parse_prefix_location(message) {
        return (Some(file), Some(line));
    }
    if let Some(file) = parse_in_location(message) {
        return (Some(file), None);
    }
    (None, None)
}

fn parse_prefix_location(message: &str) -> Option<(String, usize)> {
    let (left, rest) = message.split_once(':')?;
    if left.is_empty() {
        return None;
    }
    let (line_text, _) = rest.split_once(':')?;
    let line = line_text.parse().ok()?;
    Some((left.trim_matches('"').to_string(), line))
}

fn parse_in_location(message: &str) -> Option<String> {
    let start = message.find(" in ")?;
    let after = message[start + 4..].trim_start();
    let quote = after.chars().next()?;
    if quote != '"' && quote != '\'' {
        return None;
    }
    let rest = &after[1..];
    let end = rest.find(quote)?;
    Some(rest[..end].to_string())
}

const UNKNOWN_VALIDATOR: ValidatorSpec = ValidatorSpec {
    id: "validation",
    category: ValidatorCategory::Quality,
    display_id: "validation",
    description: "General validation issue.",
    fix: "Review the validation message and update the trait.",
};

const DISABLED_VALIDATOR_IDS: &[&str] = &[
    "regex-contains-literal",
    "regex-alternative-subset",
    "duplicate-patterns",
    "overlapping-regex-patterns",
    "redundant-patterns",
    "cross-type-canonicalization",
];

static DISABLED_VALIDATOR_OVERRIDE: OnceLock<RwLock<Option<BTreeSet<String>>>> = OnceLock::new();

fn disabled_validator_override() -> &'static RwLock<Option<BTreeSet<String>>> {
    DISABLED_VALIDATOR_OVERRIDE.get_or_init(|| RwLock::new(None))
}

pub(crate) const VALIDATOR_SPECS: &[ValidatorSpec] = &[
    UNKNOWN_VALIDATOR,
    ValidatorSpec {
        id: "regex-length",
        category: ValidatorCategory::Quality,
        display_id: "re-len",
        description: "Regex pattern is too long for a single trait.",
        fix: "Split long regex into named atoms/composites; prefer kv, symbol, or ast when available.",
    },
    ValidatorSpec {
        id: "regex-contains-literal",
        category: ValidatorCategory::Dedup,
        display_id: "re-lit",
        description: "Regex duplicates an existing literal matcher.",
        fix: "Reuse the literal atom or remove the duplicate local pattern.",
    },
    ValidatorSpec {
        id: "regex-alternative-subset",
        category: ValidatorCategory::Dedup,
        display_id: "re-alt",
        description: "Regex alternatives duplicate another regex.",
        fix: "Remove redundant alternatives or split shared atoms.",
    },
    ValidatorSpec {
        id: "unnecessary-non-capturing-group",
        category: ValidatorCategory::Quality,
        display_id: "re-group",
        description: "Regex has grouping that does not change meaning.",
        fix: "Remove the unnecessary group.",
    },
    ValidatorSpec {
        id: "defaults-hoist",
        category: ValidatorCategory::Reuse,
        display_id: "defaults",
        description: "Repeated file-level fields should use defaults.",
        fix: "Move shared field values into defaults.",
    },
    ValidatorSpec {
        id: "unbounded-negated-char-class",
        category: ValidatorCategory::Quality,
        display_id: "re-negclass",
        description: "Regex has an unbounded negated character class.",
        fix: "Bound broad negated classes.",
    },
    ValidatorSpec {
        id: "simple-alternation-chain",
        category: ValidatorCategory::Reuse,
        display_id: "alt-chain",
        description: "Simple alternatives should be reusable atoms.",
        fix: "Split alternatives into atoms and join with a composite.",
    },
    ValidatorSpec {
        id: "case-insensitive-no-effect",
        category: ValidatorCategory::Quality,
        display_id: "case-noop",
        description: "case_insensitive has no effect.",
        fix: "Remove case_insensitive.",
    },
    ValidatorSpec {
        id: "duplicate-composites",
        category: ValidatorCategory::Dedup,
        display_id: "dup-comp",
        description: "Composite rules duplicate each other.",
        fix: "Keep one composite and update references.",
    },
    ValidatorSpec {
        id: "orphaned-components",
        category: ValidatorCategory::Reuse,
        display_id: "orphan-comp",
        description: "Component traits are never referenced.",
        fix: "Reference components from a composite, or convert/delete them.",
    },
    ValidatorSpec {
        id: "dupe-atomic",
        category: ValidatorCategory::Dedup,
        display_id: "dupe-atomic",
        description: "Atomic traits use the same matcher.",
        fix: "Keep one atom in the best taxonomy location and reference it.",
    },
    ValidatorSpec {
        id: "oversized-dir",
        category: ValidatorCategory::Policy,
        display_id: "oversized-dir",
        description: "Directory is too broad for useful ML directory signal.",
        fix: "Split by language/platform-neutral technique so ML can group similar behavior; use platform dirs only when the technique requires them.",
    },
    ValidatorSpec {
        id: "leaf-yaml",
        category: ValidatorCategory::Policy,
        display_id: "leaf-yaml",
        description: "YAML traits are defined above leaf directories.",
        fix: "Put YAML in leaf directories named for the shared technique; flatten child YAML up when extra depth adds no ML signal.",
    },
    ValidatorSpec {
        id: "many-directory-references",
        category: ValidatorCategory::Reuse,
        display_id: "many-dir-refs",
        description: "Composite hand-maintains many refs to one directory.",
        fix: "Use directory syntax for any: clauses; for all: clauses, split only when there are clear sub-techniques.",
    },
    ValidatorSpec {
        id: "directory-alias-composite",
        category: ValidatorCategory::Reuse,
        display_id: "dir-alias",
        description: "Composite is equivalent to a directory reference.",
        fix: "Delete the composite and reference the directory directly.",
    },
    ValidatorSpec {
        id: "duplicate-patterns",
        category: ValidatorCategory::Dedup,
        display_id: "dup-pattern",
        description: "Pattern is duplicated across traits.",
        fix: "Keep the best-located trait and reference it where appropriate.",
    },
    ValidatorSpec {
        id: "tier-violation",
        category: ValidatorCategory::Policy,
        display_id: "tier",
        description: "Trait violates taxonomy dependency direction.",
        fix: "Move or reference traits according to TAXONOMY.md tiers.",
    },
    ValidatorSpec {
        id: "regex-case-subsumption",
        category: ValidatorCategory::Dedup,
        display_id: "re-case",
        description: "Case-insensitive regex already covers another regex.",
        fix: "Remove the covered regex.",
    },
    ValidatorSpec {
        id: "simple-word-boundary-regex",
        category: ValidatorCategory::Quality,
        display_id: "re-word",
        description: "Regex is only a word-boundary literal.",
        fix: "Use word or exact when semantics match.",
    },
    ValidatorSpec {
        id: "regex-or-literal-overlap",
        category: ValidatorCategory::Dedup,
        display_id: "re-or-lit",
        description: "Regex alternatives overlap literal atoms.",
        fix: "Remove redundant alternatives or reference the literal atoms.",
    },
    ValidatorSpec {
        id: "case-subsumption",
        category: ValidatorCategory::Dedup,
        display_id: "case-sub",
        description: "Case-insensitive pattern covers another pattern.",
        fix: "Remove the covered pattern.",
    },
    ValidatorSpec {
        id: "duplicate-case-only",
        category: ValidatorCategory::Dedup,
        display_id: "dup-case",
        description: "Case-insensitive duplicates differ only by spelling.",
        fix: "Keep one canonical spelling.",
    },
    ValidatorSpec {
        id: "regex-vs-literal-duplicate",
        category: ValidatorCategory::Dedup,
        display_id: "re-lit-dup",
        description: "Regex and literal express the same signal.",
        fix: "Keep the more semantic matcher type.",
    },
    ValidatorSpec {
        id: "overlapping-regex-patterns",
        category: ValidatorCategory::Dedup,
        display_id: "re-overlap",
        description: "Regexes overlap for the same file types.",
        fix: "Merge or narrow rules so each trait has distinct signal.",
    },
    ValidatorSpec {
        id: "redundant-patterns",
        category: ValidatorCategory::Dedup,
        display_id: "redundant",
        description: "Pattern is redundant with a broader matcher.",
        fix: "Remove only when the broader matcher is the right home.",
    },
    ValidatorSpec {
        id: "nested-quantifier",
        category: ValidatorCategory::Quality,
        display_id: "re-nested",
        description: "Regex has nested quantifiers.",
        fix: "Rewrite with bounded or simpler structure.",
    },
    ValidatorSpec {
        id: "exact-regex-canonicalization",
        category: ValidatorCategory::Quality,
        display_id: "re-exact",
        description: "Regex is only an anchored literal.",
        fix: "Use exact matching.",
    },
    ValidatorSpec {
        id: "cross-type-canonicalization",
        category: ValidatorCategory::Dedup,
        display_id: "cross-type",
        description: "Same signal appears under multiple matcher types.",
        fix: "Keep the matcher type that best expresses the signal.",
    },
    ValidatorSpec {
        id: "wellknown-size-filter",
        category: ValidatorCategory::Policy,
        display_id: "wk-size",
        description: "well-known traits lack file-size bounds.",
        fix: "Add size_min or size_max for the family/tool marker.",
    },
    ValidatorSpec {
        id: "binary-section-filter",
        category: ValidatorCategory::Policy,
        display_id: "bin-section",
        description: "Binary text/raw/hex trait lacks a section filter.",
        fix: "Add a normalized section filter, usually text, rdata, data, or rsrc.",
    },
    ValidatorSpec {
        id: "regex-performance",
        category: ValidatorCategory::Policy,
        display_id: "re-perf",
        description: "Regex is costly on broad input.",
        fix: "Add literal focus, split broad scans, or use bounded matchers like kv/symbol.",
    },
    ValidatorSpec {
        id: "ast-text-call-performance",
        category: ValidatorCategory::Policy,
        display_id: "ast-call",
        description: "Text/raw function-call pattern should use symbols.",
        fix: "Use symbol matching when context is not needed.",
    },
    ValidatorSpec {
        id: "raw-should-use-text",
        category: ValidatorCategory::Policy,
        display_id: "raw-text",
        description: "Raw binary matcher should use text matching.",
        fix: "Use text when byte-exact raw matching is not needed.",
    },
    ValidatorSpec {
        id: "string-literal-should-use-text",
        category: ValidatorCategory::Policy,
        display_id: "strlit-text",
        description: "String-literal matcher should use text matching.",
        fix: "Use text for literal strings when parser context is not needed.",
    },
    ValidatorSpec {
        id: "basename-duplicate",
        category: ValidatorCategory::Dedup,
        display_id: "base-dupe",
        description: "Basename patterns duplicate each other.",
        fix: "Keep one filename matcher in the best taxonomy location and reference it.",
    },
    ValidatorSpec {
        id: "precision",
        category: ValidatorCategory::Quality,
        display_id: "precision",
        description: "Trait or composite precision is below threshold.",
        fix: "Tighten the matcher, add context, or lower the rule criticality.",
    },
    ValidatorSpec {
        id: "invalid-file-type",
        category: ValidatorCategory::Quality,
        display_id: "for-invalid",
        description: "Trait uses an invalid file type.",
        fix: "Use a supported file type or remove the invalid for: value.",
    },
    ValidatorSpec {
        id: "unknown-file-type",
        category: ValidatorCategory::Quality,
        display_id: "for-unknown",
        description: "Trait uses a file type unknown to this binary.",
        fix: "Upgrade cleave or update the trait to a supported file type.",
    },
    ValidatorSpec {
        id: "excessive-suppression",
        category: ValidatorCategory::Policy,
        display_id: "suppress",
        description: "Rule relies on too many unless:/downgrade: suppressions.",
        fix: "Tighten the matcher, split by technique, lower criticality, or delete low-signal catch-alls.",
    },
    ValidatorSpec {
        id: "score-caps",
        category: ValidatorCategory::Regression,
        display_id: "score-caps",
        description: "Fixture score exceeded its regression cap.",
        fix: "Review score changes before adjusting traits or caps.",
    },
];

#[must_use]
pub(crate) fn validator_spec(id: &str) -> Option<&'static ValidatorSpec> {
    VALIDATOR_SPECS.iter().find(|spec| spec.id == id)
}

fn resolve_validator_id(id: &str) -> Option<&'static str> {
    if id == "full-directory-composite" || id == "full-dir" || id == "reuse/full-dir" {
        return Some("many-directory-references");
    }
    VALIDATOR_SPECS
        .iter()
        .find(|spec| id == spec.id || id == spec.display_id || id == spec.label())
        .map(|spec| spec.id)
}

#[allow(clippy::expect_used)]
pub(crate) fn set_disabled_validators_override(ids: Option<&str>) -> Result<()> {
    let Some(ids) = ids else {
        return Ok(());
    };

    let mut disabled = BTreeSet::new();
    for raw_id in ids.split(',') {
        let raw_id = raw_id.trim();
        if raw_id.is_empty() {
            continue;
        }
        let Some(id) = resolve_validator_id(raw_id) else {
            bail!("unknown validator in --exclude: {raw_id}");
        };
        disabled.insert(id.to_string());
    }

    *disabled_validator_override()
        .write()
        .expect("validator override lock poisoned") = Some(disabled);
    Ok(())
}

#[must_use]
pub(crate) fn disabled_validator_specs() -> Vec<&'static ValidatorSpec> {
    VALIDATOR_SPECS
        .iter()
        .filter(|spec| is_validator_disabled(spec.id))
        .collect()
}

#[must_use]
#[allow(clippy::expect_used)]
pub(crate) fn is_validator_disabled(id: &str) -> bool {
    if let Some(disabled) = disabled_validator_override()
        .read()
        .expect("validator override lock poisoned")
        .as_ref()
    {
        return disabled.contains(id);
    }
    DISABLED_VALIDATOR_IDS.contains(&id)
}

#[derive(Debug, Serialize)]
pub(crate) struct DisabledValidatorView {
    pub(crate) id: &'static str,
    pub label: String,
    pub(crate) category: &'static str,
    pub(crate) display_id: &'static str,
    pub(crate) description: &'static str,
    pub(crate) fix: &'static str,
}

#[must_use]
pub(crate) fn disabled_validators_by_category() -> BTreeMap<&'static str, Vec<DisabledValidatorView>>
{
    let mut grouped: BTreeMap<&'static str, Vec<DisabledValidatorView>> = BTreeMap::new();
    for spec in disabled_validator_specs() {
        grouped
            .entry(spec.category.display())
            .or_default()
            .push(DisabledValidatorView {
                id: spec.id,
                label: spec.label(),
                category: spec.category.display(),
                display_id: spec.display_id,
                description: spec.description,
                fix: spec.fix,
            });
    }
    grouped
}

#[must_use]
pub(crate) fn format_disabled_validators_terminal() -> String {
    let grouped = disabled_validators_by_category();
    if grouped.is_empty() {
        return String::new();
    }

    let mut out = String::new();
    for (category, specs) in grouped {
        let labels = specs
            .iter()
            .map(|spec| spec.display_id)
            .collect::<Vec<_>>()
            .join(",");
        out.push_str(&format!("NOTE: disabled {category} validators: {labels}\n"));
    }
    out
}

#[must_use]
pub(crate) fn format_validation_issues_terminal(issues: &[ValidationIssue]) -> String {
    if issues.is_empty() {
        return String::new();
    }

    let mut grouped: BTreeMap<String, Vec<&ValidationIssue>> = BTreeMap::new();
    for issue in issues {
        grouped.entry(issue.location()).or_default().push(issue);
    }

    let mut out = String::new();
    out.push_str(&format!(
        "\nvalidation failed: {} issue(s) in {} location(s)\n",
        issues.len(),
        grouped.len()
    ));
    out.push_str("counts\n");
    for (label, count) in issue_counts(issues) {
        out.push_str(&format!("  {label:<24} {count}\n"));
    }
    out.push('\n');
    for (location, group) in grouped {
        out.push_str(&format!("{location}\n"));
        for issue in group {
            out.push_str(&format!("  {:<24} {}\n", issue.label, issue.message));
            if let Some(rule_id) = &issue.rule_id {
                out.push_str(&format!("  {:<24} {}\n", "", rule_id));
            }
        }
    }

    out.push_str("\nsuggested fixes\n");
    for line in issue_fix_lines(issues) {
        out.push_str(&format!("  {line}\n"));
    }
    out
}

#[must_use]
pub(crate) fn format_validation_issues_tiny(issues: &[ValidationIssue]) -> String {
    if issues.is_empty() {
        return String::new();
    }

    let mut out = String::new();
    out.push_str(&format!("validation failed issues={}\n", issues.len()));
    out.push_str("counts\n");
    for (label, count) in issue_counts(issues) {
        out.push_str(&format!("{label} {count}\n"));
    }
    for issue in issues {
        out.push_str(&format!(
            "{} {} {}\n",
            issue.location(),
            issue.label,
            issue.message
        ));
    }
    out.push_str("fixes\n");
    for line in issue_fix_lines(issues) {
        out.push_str(&format!("{line}\n"));
    }
    out
}

#[must_use]
pub(crate) fn format_validation_issues_json(issues: &[ValidationIssue]) -> String {
    #[derive(Serialize)]
    struct ValidationFailure<'a> {
        ok: bool,
        counts: BTreeMap<String, usize>,
        issues: &'a [ValidationIssue],
        fixes: Vec<String>,
    }

    let failure = ValidationFailure {
        ok: false,
        counts: issue_counts(issues),
        issues,
        fixes: issue_fix_lines(issues),
    };
    serde_json::to_string_pretty(&failure).unwrap_or_else(|_| "{\"ok\":false}".to_string())
}

fn issue_counts(issues: &[ValidationIssue]) -> BTreeMap<String, usize> {
    let mut counts = BTreeMap::new();
    for issue in issues {
        *counts.entry(issue.label.clone()).or_insert(0) += issue.count;
    }
    counts
}

fn issue_fix_lines(issues: &[ValidationIssue]) -> Vec<String> {
    let mut seen = BTreeSet::new();
    let mut lines = Vec::new();
    for issue in issues {
        if seen.insert(issue.label.clone()) {
            lines.push(format!("{}: {}", issue.label, issue.fix));
        }
    }
    lines
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_issue_extracts_prefix_location() {
        let issue = ValidationIssue::legacy("./traits/a.yaml:12: broken rule");
        assert_eq!(issue.file.as_deref(), Some("./traits/a.yaml"));
        assert_eq!(issue.line, Some(12));
        assert_eq!(issue.location(), "./traits/a.yaml:12");
    }

    #[test]
    fn legacy_issue_extracts_in_location() {
        let issue = ValidationIssue::legacy("trait 'x' in \"./traits/a.yaml\": bad");
        assert_eq!(issue.file.as_deref(), Some("./traits/a.yaml"));
        assert_eq!(issue.line, None);
        assert_eq!(issue.location(), "./traits/a.yaml");
    }

    #[test]
    fn terminal_output_groups_fixes() {
        let issues = vec![
            ValidationIssue::new("regex-length", "first").with_location("a.yaml", Some(1)),
            ValidationIssue::new("regex-length", "second").with_location("a.yaml", Some(1)),
        ];
        let out = format_validation_issues_terminal(&issues);
        assert!(out.contains("a.yaml:1"));
        assert!(out.contains("qual/re-len              2"));
        assert_eq!(out.matches("qual/re-len:").count(), 1);
    }
}
