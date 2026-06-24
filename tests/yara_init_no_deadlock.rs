//! Regression test for the YARA-init-on-rayon-worker deadlock.
//!
//! The bug: `shared_resources::yara_engine()` initializes lazily via `OnceLock`,
//! and `YaraEngine::load_all_rules` uses `par_iter` internally. If the first
//! caller to win `OnceLock::get_or_init` is itself a rayon worker, peers also
//! calling `yara_engine()` park on the OnceLock mutex — starving the very pool
//! the winner's `par_iter` is dispatching into. Any task the winner steals
//! while waiting can re-enter `get_or_init` on the same thread and self-lock.
//!
//! The invariant: even if a caller forgets to prefetch and the first YARA
//! initialization happens on a rayon worker, cold rule loading must not start
//! nested rayon work that can starve the pool. Prefetch is still desirable for
//! startup latency, but correctness cannot depend on every caller remembering
//! it.
//!
//! Each cargo integration test file runs as its own test binary, so the
//! `OnceLock` statics are fresh for this process regardless of other tests.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use rayon::prelude::*;

/// Wall-clock ceiling. Cold compile with `CLEAVE_BUILTIN_YARA_ONLY=1` should
/// finish in well under this; anything close to the bound indicates real
/// progress stalled (the bug), not slow compilation.
const WATCHDOG_TIMEOUT: Duration = Duration::from_secs(120);

#[test]
fn yara_init_does_not_deadlock_under_concurrent_rayon_load() {
    // Force the cold-compile path so the deadlock-prone code actually runs.
    // Without this, the cache returns in ~25 ms and never touches the par_iter.
    cleave::cache::set_skip_yara_cache_override(Some(true));
    // Keep third-party rules out so compile is fast enough to fit the budget.
    // The deadlock manifests on any cold compile regardless of rule count —
    // restricting to built-in rules keeps the test responsive without
    // changing the code path under test.
    cleave::yara_engine::set_builtin_yara_only_override(Some(true));

    // Watchdog: a deadlocked main thread cannot panic its way out. Abort the
    // process from an independent thread so cargo records the test as failed.
    let done = Arc::new(AtomicBool::new(false));
    {
        let done = Arc::clone(&done);
        std::thread::Builder::new()
            .name("yara-init-watchdog".into())
            .spawn(move || {
                std::thread::sleep(WATCHDOG_TIMEOUT);
                if !done.load(Ordering::SeqCst) {
                    eprintln!(
                        "yara_init_does_not_deadlock_under_concurrent_rayon_load: \
                         timed out after {:?} — process appears deadlocked",
                        WATCHDOG_TIMEOUT,
                    );
                    std::process::abort();
                }
            })
            .expect("spawn watchdog");
    }

    // Simulate the observed production scenario without any prior warmup:
    // multiple concurrent rayon workers each call `analyze_bytes`, so one
    // worker wins the global YARA OnceLock cold init while peers block on it.
    // The initializer must complete without spawning nested rayon work.
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(8)
        .thread_name(|i| format!("yara-deadlock-test-{i}"))
        .build()
        .expect("build test rayon pool");

    pool.install(|| {
        (0..32).into_par_iter().for_each(|i| {
            let payload = format!("sample-{i}\n").into_bytes();
            let filename = format!("sample-{i}.bin");
            let _ = cleave::analyze_bytes(&payload, &filename, &cleave::AnalysisOptions::default());
        });
    });

    // Signal the watchdog that we finished legitimately.
    done.store(true, Ordering::SeqCst);
}
