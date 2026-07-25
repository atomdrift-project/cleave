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

/// Resolve the sibling traits checkout that fixture-driven tests analyze against.
///
/// Checked in order: `CLEAVE_TEST_TRAITS_DIR`, `../traits-dev`, `../cleave-traits`
/// (the pre-2026-07 name). Returns `None` only when none exists — a real
/// situation on a packaged-crate build, where these tests cannot run.
///
/// Prefer [`require_traits_dir`] at a test's first line. A bare `None` check that
/// returns early makes a skipped test indistinguishable from a passing one: when
/// this directory moved to `../traits-dev`, six tests silently stopped asserting
/// anything and the suite still reported green, which cost a day of chasing
/// "flaky" behaviour that was really tests blinking in and out of existence.
pub(crate) fn traits_dir() -> Option<std::path::PathBuf> {
    if let Ok(dir) = std::env::var("CLEAVE_TEST_TRAITS_DIR") {
        let p = std::path::PathBuf::from(dir);
        return p.is_dir().then_some(p);
    }
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    ["../traits-dev", "../cleave-traits"]
        .iter()
        .map(|rel| root.join(rel))
        .find(|p| p.is_dir())
}

/// The traits checkout, or a loud failure naming where it was looked for.
///
/// Set `CLEAVE_TEST_ALLOW_NO_TRAITS=1` to downgrade to a skip — for packaged-crate
/// CI, where the sibling repo genuinely is not on disk. That is an explicit opt-out
/// rather than the default, so a checkout that moves on a developer's machine
/// breaks the build instead of quietly hollowing out the tests that need it.
pub(crate) fn require_traits_dir() -> Option<std::path::PathBuf> {
    if let Some(dir) = traits_dir() {
        return Some(dir);
    }
    assert!(
        std::env::var("CLEAVE_TEST_ALLOW_NO_TRAITS").as_deref() == Ok("1"),
        "traits checkout not found (looked for $CLEAVE_TEST_TRAITS_DIR, \
         ../traits-dev, ../cleave-traits relative to {}). These tests assert against \
         real traits and cannot run without it. Clone it, point \
         CLEAVE_TEST_TRAITS_DIR at it, or set CLEAVE_TEST_ALLOW_NO_TRAITS=1 to skip.",
        env!("CARGO_MANIFEST_DIR"),
    );
    eprintln!("skipping: no traits checkout (CLEAVE_TEST_ALLOW_NO_TRAITS=1)");
    None
}
