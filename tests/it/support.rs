//! Shared support for the consolidated integration-test crate.
//!
//! Integration tests run one-process-per-test under nextest (fully isolated),
//! but the same binary can also run as threads in a single process under
//! `cargo test --test it` (the Phase 5 dual-runner path — see
//! `docs/FAST_SAFE_TESTING_PLAN.md`). Any test that mutates process-global state
//! — environment variables, the `traits_repo` override dir, the working
//! directory — must serialize through [`global_lock`] so a shared-process run
//! stays deterministic. Under nextest the lock is uncontended (one test per
//! process), so it costs nothing.

use std::sync::{Mutex, MutexGuard, OnceLock};

/// Test modules that mutate process-global state (env vars, the traits override
/// dir, or an analysis skip-override) and therefore MUST run isolated under
/// nextest — never in the shared `cargo test --test it` process, where their
/// leaked state corrupts other tests. Keep this in sync with the `--skip` list
/// in the Makefile `test` target. The [`shared_bucket_has_no_global_state_mutation`]
/// guard test fails if a non-listed module starts mutating global state.
pub(crate) const ISOLATED_MODULES: &[&str] = &[
    "archive_determinism_test",
    "archive_tmp_regression",
    "binary_traits_test",
    "embedded_code_detection_test",
    "subfile_pipeline_test",
    "symbol_extraction_test",
    "tiny_manifest_value_traits_test",
    "trait_migration_regression_test",
    "traits_override_isolation_test",
    "utf16_text_normalization_test",
    "yara_init_no_deadlock",
];

/// Acquire the process-wide lock guarding all global-state mutation.
///
/// Hold the returned guard for the whole window in which a global (env var,
/// traits override dir, cwd) is mutated *and* observed, so no other
/// global-state test in the same process can interleave. A poisoned lock (a
/// panicking test that held it) is recovered rather than propagated, so one
/// failing test doesn't cascade into every later one.
pub(crate) fn global_lock() -> MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Sets an environment variable for the lifetime of the guard, restoring the
/// previous value (or removing it) on drop. Pair with [`global_lock`] whenever
/// another test in the same process could read the variable concurrently.
pub(crate) struct EnvVarGuard {
    key: &'static str,
    prev: Option<std::ffi::OsString>,
}

impl EnvVarGuard {
    /// Set `key` to `value`, remembering the prior value for restoration.
    pub(crate) fn set(key: &'static str, value: &str) -> Self {
        let prev = std::env::var_os(key);
        // SAFETY: edition-2024 `set_var` is `unsafe`; callers serialize through
        // `global_lock`, so no other thread races this mutation.
        unsafe { std::env::set_var(key, value) };
        Self { key, prev }
    }
}

impl Drop for EnvVarGuard {
    fn drop(&mut self) {
        // SAFETY: same contract as `set` — mutation happens under the caller's
        // `global_lock` guard.
        unsafe {
            match self.prev.take() {
                Some(v) => std::env::set_var(self.key, v),
                None => std::env::remove_var(self.key),
            }
        }
    }
}

/// Self-policing guard for the dual-runner partition.
///
/// The Makefile runs the shared (non-[`ISOLATED_MODULES`]) test modules in a
/// single `cargo test --test it` process for speed. A module that mutates
/// process-global state there silently corrupts sibling tests. This scans every
/// sibling test file and fails if a *non-isolated* module calls a global-state
/// setter — so the partition can't rot as new tests land: the author is told to
/// add the module to [`ISOLATED_MODULES`] (and the Makefile `--skip` list) or
/// drop the mutation. Runs in the shared bucket itself (it only reads files).
#[test]
fn shared_bucket_has_no_global_state_mutation() {
    // Substrings covering every process-global mutation vector. `_override(`
    // catches all `set_*_override(` library setters (traits/cache/yara/builtin),
    // including ones added later; `set_override_dir(` is the odd name out; the
    // env/cwd setters and the sanctioned `EnvVarGuard` helper cover the rest.
    // `Command::env(...)` on a spawned child is NOT matched (it sets the child's
    // environment, not this process's), so CLI subprocess tests stay shared.
    const SETTERS: &[&str] = &[
        "_override(",
        "set_override_dir(",
        "env::set_var(",
        "env::remove_var(",
        "set_current_dir(",
        "EnvVarGuard",
    ];
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/it");
    // Packaged CI may lack the source tree; nothing to police there.
    let Ok(entries) = std::fs::read_dir(&dir) else {
        return;
    };
    let mut offenders = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("rs") {
            continue;
        }
        let Some(stem) = path.file_stem().and_then(|s| s.to_str()) else {
            continue;
        };
        // `main` wires the modules; `support` owns the sanctioned EnvVarGuard.
        if stem == "main" || stem == "support" || ISOLATED_MODULES.contains(&stem) {
            continue;
        }
        let Ok(src) = std::fs::read_to_string(&path) else {
            continue;
        };
        for setter in SETTERS {
            if src.contains(setter) {
                offenders.push(format!("{stem} calls `{setter}`"));
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "shared-bucket test modules mutate process-global state and will corrupt the \
         shared `cargo test --test it` run. Add each to `support::ISOLATED_MODULES` AND \
         the Makefile `test` target's `--skip` list, or remove the mutation:\n  {}",
        offenders.join("\n  "),
    );
}

/// The `IT_ISOLATED` module list declared by the Makefile `test` target.
///
/// Parses the `IT_ISOLATED := ...` assignment, following `\`-continued lines.
/// Returns `None` when the Makefile isn't readable (packaged CI without the
/// source tree), so callers can skip rather than fail.
fn makefile_isolated_modules() -> Option<Vec<String>> {
    let makefile = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("Makefile");
    let src = std::fs::read_to_string(makefile).ok()?;
    let start = src.find("\nIT_ISOLATED :=")? + 1;
    let mut modules = Vec::new();
    for line in src[start..].lines() {
        let continued = line.ends_with('\\');
        let names = line
            .trim_end_matches('\\')
            .trim_start_matches("IT_ISOLATED :=");
        modules.extend(names.split_whitespace().map(str::to_string));
        if !continued {
            break;
        }
    }
    Some(modules)
}

/// The Makefile `--skip` list and [`ISOLATED_MODULES`] must name the same
/// modules.
///
/// Both comments claim they are "kept in sync", but nothing checked it: the
/// `shared_bucket_has_no_global_state_mutation` guard only polices the opposite
/// direction (a shared module that starts mutating globals). A module added to
/// one list and not the other runs in the shared process and corrupts its
/// siblings — the failure lands in *other* modules and shifts with thread
/// scheduling, so it reads as flakiness rather than as a partition bug.
#[test]
fn isolated_module_list_matches_makefile() {
    let Some(mut from_makefile) = makefile_isolated_modules() else {
        skip_missing("Makefile (source tree unavailable)");
        return;
    };
    let mut declared: Vec<String> = ISOLATED_MODULES.iter().map(|m| (*m).to_string()).collect();
    from_makefile.sort();
    declared.sort();
    assert_eq!(
        declared, from_makefile,
        "`support::ISOLATED_MODULES` and the Makefile `IT_ISOLATED` list have drifted. \
         Every module that mutates process-global state must appear in BOTH, or it runs \
         in the shared `cargo test --test it` process and corrupts sibling modules."
    );
}

/// A shared-process run must skip every [`ISOLATED_MODULES`] module.
///
/// `make test` passes `--skip <module>::` for each one (Phase 1) and runs them
/// one-process-each under nextest (Phase 2). A bare `cargo test --test it`
/// passes no skips, so the isolated modules run as threads beside everything
/// else: whichever loads traits first wins the process-global mapper and cache
/// fingerprint, and the rest evaluate against the wrong rules. The resulting
/// failures land in unrelated modules and move between runs.
///
/// Worse, the damage outlives the run. An analysis cached under another
/// module's traits fingerprint persists in the on-disk cache, so a later
/// *correct* run can still be served the poisoned entry — which is why
/// `make test` also exports `CLEAVE_SKIP_CACHE=1`.
///
/// A filtered invocation (`cargo test --test it <filter>`, or nextest's
/// per-test `--exact`) is left alone: the caller has named what to run.
#[test]
fn shared_run_skips_isolated_modules() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    // Any positional filter, or nextest's per-test invocation, means the caller
    // chose the test set explicitly.
    let filtered = args
        .iter()
        .any(|a| a == "--exact" || (!a.starts_with('-') && a != "--"));
    if filtered || std::env::var_os("NEXTEST").is_some() {
        return;
    }
    let missing: Vec<&str> = ISOLATED_MODULES
        .iter()
        .filter(|m| !args.iter().any(|a| a == &format!("{m}::")))
        .copied()
        .collect();
    assert!(
        missing.is_empty(),
        "this is an unpartitioned `cargo test --test it` run: {} global-state module(s) \
         are executing as threads beside the shared tests and will corrupt them \
         (first missing: {}).\n\
         Run `make test` instead — it skips these in the shared process and runs each \
         in its own process under nextest.\n\
         If a run like this already happened, its findings may have been cached under \
         the wrong traits fingerprint; re-run with CLEAVE_SKIP_CACHE=1 to bypass the \
         poisoned entries.",
        missing.len(),
        missing[0],
    );
}

/// Report that a test is skipping because a fixture the host doesn't have is
/// missing. Callers `return` (or fall through an `else`) immediately after.
///
/// Every skip goes through here for two reasons. It prints one greppable marker,
/// so `cargo test -- --nocapture 2>&1 | grep SKIP:` is an honest inventory of
/// what the suite did *not* check on this host. And `CLEAVE_TEST_REQUIRE_FIXTURES=1`
/// turns every skip into a failure, so a machine that is supposed to have the
/// fixtures (CI, a release box) cannot quietly lose coverage when one goes
/// missing.
///
/// This exists because skips used to be bare `eprintln!` + `return`, which makes
/// a skipped test indistinguishable from a passing one. When the sibling traits
/// checkout moved, six tests stopped asserting anything and the suite still
/// reported green — a day went into chasing "flaky" behaviour that was really
/// tests blinking in and out of existence. Prefer removing the external
/// dependency outright (see `tiny_manifest_value_traits_test`, which now writes
/// its own trait fixtures) over skipping; skip only for genuinely
/// unredistributable inputs such as malware samples.
pub(crate) fn skip_missing(what: &str) {
    assert!(
        std::env::var("CLEAVE_TEST_REQUIRE_FIXTURES").as_deref() != Ok("1"),
        "required fixture missing: {what} (CLEAVE_TEST_REQUIRE_FIXTURES=1)",
    );
    eprintln!("SKIP: {what}");
}
