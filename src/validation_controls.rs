//! Shared validation controls and display metadata.
//!
//! This keeps temporary validator disables centralized while validators are
//! re-enabled one at a time.

use anyhow::{Result, bail};
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

/// How serious a validation problem is.
///
/// This is the single axis that decides pass/fail. `validate` rejects any
/// problem; `validate --soft` rejects only [`Severity::Hard`] ones. The ordering
/// (`Soft < Hard`) lets the command pick a threshold and fail when a problem
/// meets it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Severity {
    /// The rule loads and fires correctly — it is just badly organized,
    /// duplicated, or styled. Fatal for `validate`, reported-only for `--soft`.
    Soft,
    /// The rule won't load or won't fire as written, so detection is lost or
    /// wrong. Fatal for both `validate` and `validate --soft`.
    Hard,
}

/// Validators whose failure means a rule won't load or won't fire correctly —
/// detection is lost or wrong. Everything not listed here is authoring hygiene
/// ([`Severity::Soft`]): the rule works, it is just poorly organized. Keeping the
/// hard set explicit in one place is the whole pass/fail policy — `validate
/// --soft` fails on exactly these (plus unparseable YAML and uncompilable regex,
/// which are structural errors handled before validators run).
const HARD_VALIDATOR_IDS: &[&str] = &[
    // A `directory::id` collision silently shadows one definition; references
    // resolve by id, so a real detection disappears.
    "duplicate-trait-id",
    // `for:` names a structurally invalid file type — the rule can never match.
    "invalid-file-type",
    // Fixture score regressed past its cap: a measured detection regression.
    "score-caps",
    // A trait or composite that references itself never fires.
    "self-reference",
    // A composite references a trait id that does not exist — it never fires.
    "broken-reference",
    // size/count/needs bounds make the rule unsatisfiable (or always-true).
    "impossible-constraint",
    // Nothing concrete to match (empty pattern, or one so short it matches
    // everything) — the rule cannot produce a meaningful detection.
    "no-search-pattern",
    // The condition is structurally broken (e.g. `not:` without `regex:`,
    // proximity on a none-only rule), so it matches incorrectly.
    "malformed-condition",
    // count_min totals occurrences across all regex alternatives, so repeated
    // hits on one branch can incorrectly satisfy a rule intended to require
    // distinct signals.
    "count-min-regex-alternation",
    // An id with invalid characters can't be referenced, breaking composites.
    "invalid-id-chars",
];

/// The severity of a validator, looked up by id. Unknown/legacy ids default to
/// [`Severity::Soft`]; only the detection-integrity ids in [`HARD_VALIDATOR_IDS`]
/// are [`Severity::Hard`].
#[must_use]
pub(crate) fn validator_severity(id: &str) -> Severity {
    if HARD_VALIDATOR_IDS.contains(&id) {
        Severity::Hard
    } else {
        Severity::Soft
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
    pub(crate) severity: Severity,
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

    /// Keep only the issues for which `keep` returns `true`.
    ///
    /// Used to drop disabled-validator issues before deciding fatality, so the
    /// disabled set (including the `--soft` preset) is authoritative over
    /// pass/fail even for issues pushed without a per-site gate.
    pub(crate) fn retain(&mut self, keep: impl Fn(&ValidationIssue) -> bool) {
        self.issues.retain(|issue| keep(issue));
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
            severity: validator_severity(spec.id),
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

static DISABLED_VALIDATOR_OVERRIDE: OnceLock<RwLock<Option<BTreeSet<String>>>> = OnceLock::new();

/// Whether validation runs in `--soft` mode, where only [`Severity::Hard`]
/// problems are fatal. Set once per process by the `validate` command (or the
/// `CLEAVE_VALIDATE_SOFT` env toggle) before the mapper loads.
static SOFT_VALIDATION_MODE: OnceLock<RwLock<bool>> = OnceLock::new();

fn soft_validation_mode_lock() -> &'static RwLock<bool> {
    SOFT_VALIDATION_MODE.get_or_init(|| RwLock::new(false))
}

/// Enable or disable soft validation for the rest of the process.
pub(crate) fn set_soft_validation_mode(on: bool) {
    if let Ok(mut g) = soft_validation_mode_lock().write() {
        *g = on;
    }
}

/// The pass/fail threshold: in soft mode only [`Severity::Hard`] problems fail;
/// otherwise any problem (`Soft` or `Hard`) fails.
#[must_use]
pub(crate) fn fatal_severity_threshold() -> Severity {
    if soft_validation_mode_lock().read().is_ok_and(|g| *g) {
        Severity::Hard
    } else {
        Severity::Soft
    }
}

/// Output format selector for validation issues emitted during mapper load.
///
/// `validate` sets this so the mapper loader can render warnings using the
/// caller's chosen format without consulting the process environment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ValidationOutputFormat {
    Terminal,
    Tiny,
    Json,
}

static VALIDATION_OUTPUT_FORMAT: OnceLock<RwLock<Option<ValidationOutputFormat>>> = OnceLock::new();

fn validation_output_format_lock() -> &'static RwLock<Option<ValidationOutputFormat>> {
    VALIDATION_OUTPUT_FORMAT.get_or_init(|| RwLock::new(None))
}

/// Set the validation-issue output format for the rest of the process.
/// Pass `None` to clear (the mapper will fall back to terminal rendering).
pub(crate) fn set_validation_output_format(fmt: Option<ValidationOutputFormat>) {
    if let Ok(mut g) = validation_output_format_lock().write() {
        *g = fmt;
    }
}

#[must_use]
pub(crate) fn validation_output_format() -> Option<ValidationOutputFormat> {
    validation_output_format_lock().read().ok().and_then(|g| *g)
}

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
        id: "brittle-path-pattern",
        category: ValidatorCategory::Quality,
        display_id: "path-brittle",
        description: "type: path substr/regex won't match consistently once an archive is extracted.",
        fix: "Match a basename or single component, not the archive prefix/layout: no '!', \u{2264}2 '/' separators, \u{2264}64 chars.",
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
        id: "count-min-regex-alternation",
        category: ValidatorCategory::Quality,
        display_id: "count-re-alt",
        description: "count_min on a regex alternation counts repeated branches, not distinct alternatives.",
        fix: "Split alternatives into atomic conditions and use a composite with any: and needs:.",
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
        id: "duplicate-trait-id",
        category: ValidatorCategory::Dedup,
        display_id: "dup-id",
        description: "Two traits or composites resolve to the same directory::id.",
        fix: "Rename or remove one definition; each directory::id must be unique. References resolve by id, so a collision silently shadows one definition.",
    },
    ValidatorSpec {
        id: "duplicate-inline-exclusion",
        category: ValidatorCategory::Dedup,
        display_id: "dup-unless",
        description: "The same inline unless: exclusion is copy-pasted across many files.",
        fix: "Define one shared atom and reference it via `- id:` in each unless block, or delete the guard if the matched file type is never processed.",
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
        id: "suppression-only-building-block",
        category: ValidatorCategory::Policy,
        display_id: "supp-only",
        description: "Baseline/component rule in objectives/ or well-known/ never feeds a notable+ detection (only suppressed, or unreferenced).",
        fix: "Add the missing notable identifier these fragments feed, relocate a genuine suppressor per TAXONOMY.md, or raise the consuming composite's crit:.",
    },
    ValidatorSpec {
        id: "exception-atomic",
        category: ValidatorCategory::Policy,
        display_id: "exc-atomic",
        description: "Atomic trait declares crit: exception, which is composite-only.",
        fix: "Make it a composite, or use a different criticality.",
    },
    ValidatorSpec {
        id: "exception-positive-ref",
        category: ValidatorCategory::Policy,
        display_id: "exc-positive",
        description: "A crit: exception composite is referenced as positive evidence.",
        fix: "Reference exceptions only from unless:/downgrade: clauses, never all:/any:/atomic if:.",
    },
    ValidatorSpec {
        id: "exception-unreferenced",
        category: ValidatorCategory::Policy,
        display_id: "exc-unref",
        description: "A crit: exception composite is never referenced by any rule.",
        fix: "Reference it from some rule's unless:/downgrade:, or remove it.",
    },
    ValidatorSpec {
        id: "exception-member-crit",
        category: ValidatorCategory::Policy,
        display_id: "exc-member",
        description: "A member of a crit: exception composite is not exactly notable.",
        fix: "Build exceptions only from named notable traits; drop baseline/component or suspicious/hostile members.",
    },
    ValidatorSpec {
        id: "exception-inline-condition",
        category: ValidatorCategory::Policy,
        display_id: "exc-inline",
        description: "A crit: exception composite has an inline (non-trait) condition.",
        fix: "Promote inline matchers to named traits and reference them; exceptions are named-traits-only.",
    },
    ValidatorSpec {
        id: "benign-misplaced",
        category: ValidatorCategory::Policy,
        display_id: "benign-loc",
        description: "Rule reads as benign suppression (benign / *-context / *-fp / *-exceptions / false-positive / allowlist) but sits in objectives/ or well-known/malware/.",
        fix: "Make it a crit: exception composite (may live anywhere) referenced from unless:/downgrade:, or rename it for what it detects. See TAXONOMY.md.",
    },
    ValidatorSpec {
        id: "long-description",
        category: ValidatorCategory::Quality,
        display_id: "desc-len",
        description: "Composite description is too long for one-line triage.",
        fix: "Shorten desc: to a concise one-line summary — name the key entities, drop filler.",
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
        id: "broad-filetype-cap",
        category: ValidatorCategory::Policy,
        display_id: "ft-cap",
        description: "Trait `for:` targets more file types than its matcher-type cap allows.",
        fix: "Narrow `for:`, or add a type-qualified allowlist entry (\"<type>:<dir-prefix>\").",
    },
    ValidatorSpec {
        id: "broad-platform-scope",
        category: ValidatorCategory::Policy,
        display_id: "plat-scope",
        description: "Trait targets 4+ platforms instead of a platform-neutral technique.",
        fix: "Narrow the platform scope, or move to an allowlisted directory (objectives/supply-chain/).",
    },
    ValidatorSpec {
        id: "hostile-missing-notable-leg",
        category: ValidatorCategory::Policy,
        display_id: "hostile-no-notable",
        description: "Hostile composite references no notable-or-higher leg, so its capability is buried at the wrong tier.",
        fix: "Upgrade the best purpose-defining leg to notable per TAXONOMY.md, relocate a mislabelled capability, or delete the composite.",
    },
    ValidatorSpec {
        id: "unknown-subdirectory",
        category: ValidatorCategory::Policy,
        display_id: "unknown-subdir",
        description: "Directory is not an allowed subdirectory for its taxonomy tier.",
        fix: "Move the rules under an allowed subdirectory (see TAXONOMY.md).",
    },
    ValidatorSpec {
        id: "duplicate-second-level-dir",
        category: ValidatorCategory::Policy,
        display_id: "dup-2nd-dir",
        description: "Second-level directory name is duplicated across tiers.",
        fix: "Rename or consolidate so each second-level directory is unique.",
    },
    ValidatorSpec {
        id: "metadata-hostile-criticality",
        category: ValidatorCategory::Policy,
        display_id: "meta-hostile",
        description: "metadata/ rule declares hostile criticality.",
        fix: "Lower the criticality or move the detection out of metadata/.",
    },
    ValidatorSpec {
        id: "malware-subcategory",
        category: ValidatorCategory::Policy,
        display_id: "malware-subcat",
        description: "malware/ used as a subcategory of objectives/ or micro-behaviors/.",
        fix: "Place malware-family rules under the malware/ tier, not as a subcategory.",
    },
    ValidatorSpec {
        id: "wellknown-composite-only",
        category: ValidatorCategory::Policy,
        display_id: "wk-comp-only",
        description: "well-known/ directory contains only composites, no atomic identifier.",
        fix: "Add an atomic identifier trait for the family/tool in this directory.",
    },
    ValidatorSpec {
        id: "overlapping-conditions",
        category: ValidatorCategory::Dedup,
        display_id: "overlap-cond",
        description: "Composite has overlapping all:/any: conditions.",
        fix: "Remove the redundant condition leg.",
    },
    ValidatorSpec {
        id: "pure-alias",
        category: ValidatorCategory::Reuse,
        display_id: "pure-alias",
        description: "Trait is a pure alias that adds no detection value.",
        fix: "Reference the underlying trait directly instead of aliasing it.",
    },
    ValidatorSpec {
        id: "unknown-metric-field",
        category: ValidatorCategory::Policy,
        display_id: "unknown-metric",
        description: "Trait references a metric field this engine does not define.",
        fix: "Use a known metric field; a newer field degrades gracefully on older engines.",
    },
    ValidatorSpec {
        id: "composite-inline-primitive",
        category: ValidatorCategory::Reuse,
        display_id: "inline-prim",
        description: "Composite inlines a primitive instead of referencing a building block.",
        fix: "Extract the primitive into an atomic trait and reference it.",
    },
    ValidatorSpec {
        id: "single-trait-composite",
        category: ValidatorCategory::Reuse,
        display_id: "single-comp",
        description: "Single-trait composite adds no value over the referenced trait.",
        fix: "Reference the trait directly instead of wrapping it in a composite.",
    },
    ValidatorSpec {
        id: "unless-only-composite",
        category: ValidatorCategory::Reuse,
        display_id: "unless-comp",
        description: "Single-trait composite only adds an 'unless' clause.",
        fix: "Fold the 'unless' clause into the referenced trait or a shared exclusion.",
    },
    ValidatorSpec {
        id: "regex-performance",
        category: ValidatorCategory::Policy,
        display_id: "re-perf",
        description: "Regex is costly on broad input.",
        fix: "Add literal focus, split broad scans, or use bounded matchers like kv/symbol.",
    },
    ValidatorSpec {
        id: "regex-memory",
        category: ValidatorCategory::Policy,
        display_id: "re-mem",
        description: "Regex compiles to an oversized engine that wastes memory and CPU.",
        fix: "Replace counted runs (`X{4000,}`) with a loop plus length_min (`X+` + `length_min: 4000`); split wide `X{0,N}` gaps into atomic traits joined by a near_lines:/near_bytes: composite.",
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
    ValidatorSpec {
        id: "self-reference",
        category: ValidatorCategory::Quality,
        display_id: "self-ref",
        description: "Trait or composite references itself, so it can never fire.",
        fix: "Remove the self-reference or point it at the intended other rule.",
    },
    ValidatorSpec {
        id: "broken-reference",
        category: ValidatorCategory::Quality,
        display_id: "broken-ref",
        description: "Composite references a trait id that does not exist.",
        fix: "Fix the id, or add the missing trait; references resolve by directory::id.",
    },
    ValidatorSpec {
        id: "impossible-constraint",
        category: ValidatorCategory::Quality,
        display_id: "impossible",
        description: "size/count/needs bounds make the rule unsatisfiable or always-true.",
        fix: "Correct the bounds so the constraint can be met (size_min ≤ size_max, needs ≥ 1, etc.).",
    },
    ValidatorSpec {
        id: "no-search-pattern",
        category: ValidatorCategory::Quality,
        display_id: "no-pattern",
        description: "Trait has no concrete pattern, or one too short to match meaningfully.",
        fix: "Add a pattern of at least 3 concrete characters/bytes.",
    },
    ValidatorSpec {
        id: "malformed-condition",
        category: ValidatorCategory::Quality,
        display_id: "malformed",
        description: "Condition is structurally broken (e.g. not: without regex:, proximity on a none-only rule).",
        fix: "Fix the condition so it expresses a valid match.",
    },
    ValidatorSpec {
        id: "invalid-id-chars",
        category: ValidatorCategory::Quality,
        display_id: "id-chars",
        description: "Trait/rule id contains characters that break referencing.",
        fix: "Use only the allowed id characters so composites can reference it.",
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

/// Whether a validator has been silenced for this run via `--exclude`.
///
/// No validator is disabled by default: `validate` runs every check. Soft mode
/// does not disable validators — it only changes which severities are fatal (see
/// [`fatal_severity_threshold`]) — so soft issues are still reported, just not
/// fatal under `--soft`.
#[must_use]
#[allow(clippy::expect_used)]
pub(crate) fn is_validator_disabled(id: &str) -> bool {
    disabled_validator_override()
        .read()
        .expect("validator override lock poisoned")
        .as_ref()
        .is_some_and(|disabled| disabled.contains(id))
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
    fn detection_integrity_validators_are_hard() {
        // The whole `--soft` policy: these break loading or firing, so they stay
        // fatal even in soft mode.
        for id in [
            "duplicate-trait-id",
            "invalid-file-type",
            "score-caps",
            "self-reference",
            "broken-reference",
            "impossible-constraint",
            "no-search-pattern",
            "malformed-condition",
            "count-min-regex-alternation",
            "invalid-id-chars",
        ] {
            assert_eq!(
                validator_severity(id),
                Severity::Hard,
                "{id} must be Hard (fatal in --soft)"
            );
        }
    }

    #[test]
    fn hygiene_validators_are_soft() {
        // Representative authoring-hygiene checks: the rule loads and fires, so
        // soft mode downgrades them to advisory.
        for id in [
            "regex-length",
            "regex-memory",
            "brittle-path-pattern",
            "oversized-dir",
            "tier-violation",
            "precision",
            "wellknown-size-filter",
            "broad-filetype-cap",
            "unknown-subdirectory",
            "malware-subcategory",
            "wellknown-composite-only",
            "pure-alias",
            "broad-platform-scope",
            "hostile-missing-notable-leg",
            // Forward-compat degradation on older engines, not a load-breaking flaw.
            "unknown-metric-field",
            "unknown-file-type",
            // Unknown/legacy ids default to Soft.
            "validation",
        ] {
            assert_eq!(
                validator_severity(id),
                Severity::Soft,
                "{id} must be Soft (advisory in --soft)"
            );
        }
    }

    #[test]
    fn every_hard_id_has_a_spec() {
        // Hard ids must render with a real label/fix, not the UNKNOWN fallback.
        for id in HARD_VALIDATOR_IDS {
            assert!(
                validator_spec(id).is_some(),
                "hard validator {id} needs a ValidatorSpec"
            );
        }
    }

    #[test]
    fn soft_threshold_only_when_soft_mode() {
        set_soft_validation_mode(false);
        assert_eq!(fatal_severity_threshold(), Severity::Soft);
        set_soft_validation_mode(true);
        assert_eq!(fatal_severity_threshold(), Severity::Hard);
        set_soft_validation_mode(false);
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
