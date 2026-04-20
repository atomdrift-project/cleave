//! Regression test for the YARA-init-on-rayon-worker deadlock.
//!
//! The bug: `shared_resources::yara_engine()` initializes lazily via `OnceLock`,
//! and `YaraEngine::load_all_rules` uses `par_iter` internally. If the first
//! caller to win `OnceLock::get_or_init` is itself a rayon worker, peers also
//! calling `yara_engine()` park on the OnceLock mutex — starving the very pool
//! the winner's `par_iter` is dispatching into. Any task the winner steals
//! while waiting can re-enter `get_or_init` on the same thread and self-lock.
//!
//! The contract: warm YARA from a non-rayon thread (`prefetch_shared_resources`
//! or an equivalent `std::thread::spawn + join`) before any rayon worker calls
//! into analysis. This test exercises that contract under cold-compile
//! conditions where the deadlock would reproduce without it.
//!
//! Each cargo integration test file runs as its own test binary, so the
//! `OnceLock` statics are fresh for this process regardless of other tests.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
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
    std::env::set_var("CLEAVE_SKIP_YARA_CACHE", "1");
    // Keep third-party rules out so compile is fast enough to fit the budget.
    // The deadlock manifests on any cold compile regardless of rule count —
    // restricting to built-in rules keeps the test responsive without
    // changing the code path under test.
    std::env::set_var("CLEAVE_BUILTIN_YARA_ONLY", "1");

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

    // Warm YARA from a non-rayon thread, and synchronously wait for the
    // initializer to complete. Using `join` rather than
    // `prefetch_shared_resources` removes the "does prefetch finish before
    // the par_iter starts?" race from the test itself — the contract under
    // test is "first init must not happen on a rayon worker," and a joined
    // `std::thread` trivially satisfies it.
    let warmup = std::thread::spawn(|| {
        // Any analyze call triggers the same `yara_engine()` code path that
        // the deadlock hits in production. The payload is intentionally
        // trivial — we care about the init path, not the scan.
        let _ = cleave::analyze_bytes(b"warmup", "warmup.bin", &cleave::AnalysisOptions::default());
    });
    warmup.join().expect("warmup thread panicked");

    // Now simulate the observed production scenario: multiple concurrent
    // rayon workers each calling `analyze_bytes`. With the contract
    // satisfied above, every call hits the OnceLock fast path. Without it,
    // this block would deadlock.
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
