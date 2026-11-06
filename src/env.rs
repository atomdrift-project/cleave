//! The `CLEAVE_*` environment variables, read one way.
//!
//! Public so the CLI and embedding hosts parse a variable exactly as the
//! library does.
//!
//! Every boolean variable is read through [`flag`] or [`bool_var`] and every
//! numeric one through [`parse`], so `CLEAVE_X=0` means off everywhere and a
//! value that does not parse is logged instead of silently ignored.
//!
//! Every variable the crate reads is listed in [`VARIABLES`]; a test fails
//! when code reads one that is not.

/// What a variable is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Group {
    /// Supported configuration, documented in the README.
    Configuration,
    /// Extra logging or self-checks for debugging; no effect on results.
    Diagnostics,
    /// Scheduling and memory knobs for large deployments and benchmarks.
    /// Unstable: they may change or disappear in any release.
    Tuning,
    /// Hooks for cleave's own tests, and paths to private samples that some
    /// ignored tests read.
    Testing,
}

/// A `CLEAVE_*` variable: its name, its group and what it does.
#[derive(Debug, Clone, Copy)]
pub struct Variable {
    /// The variable's name.
    pub name: &'static str,
    /// What it is for.
    pub group: Group,
    /// What setting it does.
    pub summary: &'static str,
}

const fn var(name: &'static str, group: Group, summary: &'static str) -> Variable {
    Variable {
        name,
        group,
        summary,
    }
}

use Group::{Configuration, Diagnostics, Testing, Tuning};

/// Every `CLEAVE_*` variable cleave reads.
pub const VARIABLES: &[Variable] = &[
    var(
        "CLEAVE_TRAITS_DIR",
        Configuration,
        "Load rules from this directory.",
    ),
    var(
        "CLEAVE_CACHE_DIR",
        Configuration,
        "Keep caches here instead of the user cache directory.",
    ),
    var(
        "CLEAVE_LOG_LEVEL",
        Configuration,
        "Log level: error, warn, info, debug or trace.",
    ),
    var(
        "CLEAVE_FORMAT",
        Configuration,
        "Default output format when no format flag is given.",
    ),
    var(
        "CLEAVE_NO_UPDATE_CHECK",
        Configuration,
        "Skip the background check for a newer release.",
    ),
    var(
        "CLEAVE_RAYON_THREADS",
        Configuration,
        "Worker threads (default: all CPUs).",
    ),
    var(
        "CLEAVE_SKIP_CACHE",
        Configuration,
        "Analyze afresh, ignoring cached results.",
    ),
    var(
        "CLEAVE_SKIP_MAPPER_CACHE",
        Configuration,
        "Reparse rules instead of loading the compiled rule cache.",
    ),
    var(
        "CLEAVE_SKIP_YARA_CACHE",
        Configuration,
        "Recompile YARA rules instead of loading compiled ones.",
    ),
    var(
        "CLEAVE_VALIDATE",
        Configuration,
        "Run full rule validation while loading rules.",
    ),
    var(
        "CLEAVE_VALIDATE_SOFT",
        Configuration,
        "Make `cleave validate` fail only on rule-breaking problems.",
    ),
    var(
        "CLEAVE_REGEX_STR_MB",
        Configuration,
        "Memory budget for compiled string-rule regexes.",
    ),
    var(
        "CLEAVE_REGEX_RAW_MB",
        Configuration,
        "Memory budget for compiled byte-rule regexes.",
    ),
    var(
        "CLEAVE_REGEX_SCRATCH_MB",
        Configuration,
        "Per-thread regex scratch memory; lower trades speed for memory.",
    ),
    var(
        "CLEAVE_MEMBER_PRESSURE_FLOOR_MB",
        Configuration,
        "Serialize archive members below this much free memory (0 disables).",
    ),
    var(
        "CLEAVE_ANALYSIS_MEMO_MB",
        Configuration,
        "Size of the in-process cache of recent results.",
    ),
    var(
        "CLEAVE_DEBUG_BACKTRACE",
        Diagnostics,
        "Allow a debugger to attach and print backtraces on SIGUSR1.",
    ),
    var(
        "CLEAVE_TRAIT_TIMING",
        Diagnostics,
        "Log the slowest rules at the end of a scan.",
    ),
    var(
        "CLEAVE_TRAIT_TIMING_TOP",
        Diagnostics,
        "How many rules CLEAVE_TRAIT_TIMING lists.",
    ),
    var(
        "CLEAVE_PHASE_STATS",
        Diagnostics,
        "Log time spent in each analysis phase.",
    ),
    var(
        "CLEAVE_PROFILE",
        Diagnostics,
        "Log per-evaluation timing of byte rules.",
    ),
    var(
        "CLEAVE_YARA_RULE_TIMING",
        Diagnostics,
        "Log the slowest YARA rules (needs the `yara-profiling` build feature).",
    ),
    var(
        "CLEAVE_WARN_DEAD_ANY",
        Diagnostics,
        "Warn about `any:` legs that can never match during validation.",
    ),
    var(
        "CLEAVE_VALIDATE_FACTS",
        Diagnostics,
        "0 disables the validation facts cache.",
    ),
    var(
        "CLEAVE_SKIP_CLEAN_MARK",
        Diagnostics,
        "Revalidate even a rule tree already validated clean.",
    ),
    var(
        "CLEAVE_AST_BATCH",
        Tuning,
        "0 evaluates syntax-tree queries one at a time.",
    ),
    var(
        "CLEAVE_AST_BATCH_CPU_MS",
        Tuning,
        "CPU budget for the shared syntax-tree query walk.",
    ),
    var(
        "CLEAVE_AST_LOOP_GATE",
        Tuning,
        "Gate loop-shaped syntax-tree queries on a cheap pre-check.",
    ),
    var(
        "CLEAVE_HEAVY_MEMBER_PARALLEL",
        Tuning,
        "How many large archive members run at once.",
    ),
    var(
        "CLEAVE_INNER_PARALLEL_OWNERS",
        Tuning,
        "How many files may fan their own work across the pool.",
    ),
    var(
        "CLEAVE_LEAF_CPUS",
        Tuning,
        "CPU list leaf analysis threads are pinned to (Linux).",
    ),
    var(
        "CLEAVE_MEMBER_WINDOW_COUNT",
        Tuning,
        "Archive members in flight per window.",
    ),
    var(
        "CLEAVE_MEMBER_WINDOW_MB",
        Tuning,
        "Archive member bytes in flight per window.",
    ),
    var(
        "CLEAVE_MEMGATE_EXPANSION",
        Tuning,
        "Memory reserved per archive byte by the admission gate.",
    ),
    var(
        "CLEAVE_NATIVE_FACTS_ISOLATED",
        Tuning,
        "Run fact extraction on its own thread pool.",
    ),
    var(
        "CLEAVE_NATIVE_FACTS_THREADS",
        Tuning,
        "Threads in that pool.",
    ),
    var(
        "CLEAVE_NATIVE_MEMBER_THREADS",
        Tuning,
        "Threads for native archive members.",
    ),
    var(
        "CLEAVE_PIPELINE_MEMBER_WINDOWS",
        Tuning,
        "Start the next member window before the last one drains.",
    ),
    var(
        "CLEAVE_PRIORITY_HEAVY_MEMBERS",
        Tuning,
        "Start large archive members first.",
    ),
    var(
        "CLEAVE_RAW_GATE_SOURCE_MAX_KB",
        Tuning,
        "Largest source file the windowed byte-rule gate covers.",
    ),
    var(
        "CLEAVE_SCAN_LANES",
        Tuning,
        "How many files a scan admits at once.",
    ),
    var(
        "CLEAVE_SERIAL_TRAITS",
        Tuning,
        "Evaluate a file's rules on one thread.",
    ),
    var(
        "CLEAVE_SOURCE_EARLY_DISPATCH",
        Tuning,
        "Dispatch source members before the archive walk ends.",
    ),
    var(
        "CLEAVE_SOURCE_FLIGHT_WAIT",
        Tuning,
        "Wait for a duplicate source member already in analysis.",
    ),
    var(
        "CLEAVE_SOURCE_LEAF_MIN_KB",
        Tuning,
        "Smallest source member sent to the leaf pool.",
    ),
    var(
        "CLEAVE_SOURCE_LEAF_THREADS",
        Tuning,
        "Threads in the source leaf pool.",
    ),
    var("CLEAVE_SKIP_TRAITS", Testing, "Run without any rules."),
    var("CLEAVE_SKIP_YARA", Testing, "Run without YARA rules."),
    var(
        "CLEAVE_BUILTIN_YARA_ONLY",
        Testing,
        "Load only the YARA rules built into cleave.",
    ),
    var(
        "CLEAVE_UPDATE_URL",
        Testing,
        "Check for releases at this URL.",
    ),
    var(
        "CLEAVE_BATCH_HEX_FIXTURE",
        Testing,
        "Private sample for an ignored test.",
    ),
    var(
        "CLEAVE_BATCH_HEX_PE",
        Testing,
        "Private sample for an ignored test.",
    ),
    var(
        "CLEAVE_FRAGMENT_GCM_FIXTURE",
        Testing,
        "Private sample for an ignored test.",
    ),
    var(
        "CLEAVE_FRAGMENT_GCM_REKEYED_FIXTURE",
        Testing,
        "Private sample for an ignored test.",
    ),
    var(
        "CLEAVE_GRAFT_DLL",
        Testing,
        "Private sample for an ignored test.",
    ),
    var(
        "CLEAVE_GRAFT_FIXTURE",
        Testing,
        "Private sample for an ignored test.",
    ),
    var(
        "CLEAVE_RC4_TABLE_FIXTURE",
        Testing,
        "Private sample for an ignored test.",
    ),
    var(
        "CLEAVE_RC4_TABLE_MEMBERS",
        Testing,
        "Private sample for an ignored test.",
    ),
    var(
        "CLEAVE_SKC3_FIXTURE",
        Testing,
        "Private sample for an ignored test.",
    ),
    var(
        "CLEAVE_SCRATCH_LIFETIME_TEST_CHILD",
        Testing,
        "Marks a test's child process.",
    ),
    var(
        "CLEAVE_TEST_SECRET",
        Testing,
        "A value tests check is scrubbed from tools' environment.",
    ),
];

/// The boolean value of `name`: `None` when unset, otherwise
/// [`truthy`] of its value.
#[must_use]
pub fn bool_var(name: &str) -> Option<bool> {
    let value = std::env::var(name).ok()?;
    let on = truthy(&value);
    if on.is_none() {
        tracing::warn!(
            variable = name,
            value,
            "unrecognized boolean; treating as false"
        );
    }
    Some(on.unwrap_or(false))
}

/// `1`/`true`/`yes`/`on` (any case) are true; `0`/`false`/`no`/`off` and
/// empty are false; anything else is `None`.
#[must_use]
pub fn truthy(value: &str) -> Option<bool> {
    let value = value.trim();
    let is = |words: &[&str]| words.iter().any(|w| value.eq_ignore_ascii_case(w));
    if is(&["1", "true", "yes", "on"]) {
        Some(true)
    } else if value.is_empty() || is(&["0", "false", "no", "off"]) {
        Some(false)
    } else {
        None
    }
}

/// Whether `name` is set to a true value (see [`bool_var`]).
#[must_use]
pub fn flag(name: &str) -> bool {
    bool_var(name).unwrap_or(false)
}

/// `name` parsed as `T`, or `None` when it is unset or does not parse (the
/// latter is logged).
#[must_use]
pub fn parse<T: std::str::FromStr>(name: &str) -> Option<T> {
    let value = std::env::var(name).ok()?;
    let parsed = value.trim().parse().ok();
    if parsed.is_none() {
        tracing::warn!(
            variable = name,
            value,
            "unparsable value; using the default"
        );
    }
    parsed
}

#[cfg(test)]
mod tests {
    use super::{Group, VARIABLES, truthy};

    /// Every `"CLEAVE_..."` literal in the crate's sources names a registered
    /// variable, so a new knob cannot appear without being documented.
    #[test]
    #[allow(clippy::expect_used)]
    fn every_variable_read_is_registered() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let mut unregistered = std::collections::BTreeSet::new();
        let mut pending = vec![root.join("src"), root.join("crates")];
        while let Some(dir) = pending.pop() {
            for entry in std::fs::read_dir(&dir).expect("read source dir") {
                let path = entry.expect("dir entry").path();
                if path.is_dir() {
                    pending.push(path);
                    continue;
                }
                if path.extension().is_none_or(|e| e != "rs") {
                    continue;
                }
                let text = std::fs::read_to_string(&path).expect("read source");
                for (i, _) in text.match_indices("\"CLEAVE_") {
                    let name: String = text[i + 1..]
                        .chars()
                        .take_while(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || *c == '_')
                        .collect();
                    if name.len() > "CLEAVE_".len()
                        && text[i + 1 + name.len()..].starts_with('"')
                        && !VARIABLES.iter().any(|v| v.name == name)
                    {
                        unregistered.insert(format!("{name} ({})", path.display()));
                    }
                }
            }
        }
        assert!(
            unregistered.is_empty(),
            "register these in env::VARIABLES: {unregistered:?}"
        );
    }

    /// The README's configuration table lists exactly the supported variables.
    #[test]
    #[allow(clippy::expect_used)]
    fn readme_lists_the_configuration_variables() {
        let readme = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("README.md"),
        )
        .expect("read README");
        for v in VARIABLES.iter().filter(|v| v.group == Group::Configuration) {
            assert!(
                readme.contains(&format!("`{}`", v.name)),
                "README lacks {}",
                v.name
            );
        }
    }

    #[test]
    fn zero_and_false_mean_off() {
        for (value, expected) in [
            ("1", Some(true)),
            ("TRUE", Some(true)),
            ("yes", Some(true)),
            ("0", Some(false)),
            ("false", Some(false)),
            ("", Some(false)),
            ("off", Some(false)),
            ("maybe", None),
        ] {
            assert_eq!(truthy(value), expected, "{value:?}");
        }
    }
}
