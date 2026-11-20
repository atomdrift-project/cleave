//! Regression test for the pipelined-tarball deadlock.
//!
//! An xz or bzip2 tarball is decoded on one thread while a helper thread
//! analyzes the windows it has filled, on the rayon pool. The bug: a tarball
//! nested in another archive is decoded by a pool worker, which then blocked
//! on its helper while the helper waited for a free worker. With as many
//! nested tarballs in flight as the pool has workers, every worker waited on
//! a helper and every helper on a worker: a scan of a directory stopped
//! for good, with no CPU in use.
//!
//! The invariant: a pool worker never waits on a thread that needs the pool.
//!
//! Each isolated integration test runs in its own process, so the abort
//! below takes nothing else down with it.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::io::Write as _;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

/// Wall-clock ceiling. The analysis takes about a second; reaching this
/// means it stopped.
const WATCHDOG_TIMEOUT: Duration = Duration::from_secs(120);

/// Members per nested tarball: enough that a nested archive fans its members
/// out across the pool instead of walking them on one thread.
const NESTED_MEMBERS: usize = 80;

fn tarball(members: impl Iterator<Item = (String, Vec<u8>)>) -> Vec<u8> {
    let mut archive = tar::Builder::new(Vec::new());
    for (name, body) in members {
        let mut header = tar::Header::new_gnu();
        header.set_size(body.len() as u64);
        header.set_mode(0o644);
        archive
            .append_data(&mut header, name, body.as_slice())
            .unwrap();
    }
    archive.into_inner().unwrap()
}

#[test]
fn nested_xz_tarballs_do_not_deadlock_the_pool() {
    // A deadlocked analysis cannot panic its way out. Abort the process from
    // an independent thread so cargo records the test as failed.
    let done = Arc::new(AtomicBool::new(false));
    {
        let done = Arc::clone(&done);
        std::thread::Builder::new()
            .name("nested-xz-watchdog".into())
            .spawn(move || {
                std::thread::sleep(WATCHDOG_TIMEOUT);
                if !done.load(Ordering::SeqCst) {
                    eprintln!(
                        "nested_xz_tarballs_do_not_deadlock_the_pool: timed out after \
                         {WATCHDOG_TIMEOUT:?} — process appears deadlocked",
                    );
                    std::process::abort();
                }
            })
            .expect("spawn watchdog");
    }

    // Several nested tarballs per pool worker, so every worker is decoding
    // one at the same moment.
    let nested = rayon::current_num_threads() * 4;
    let outer = tarball((0..nested).map(|n| {
        let inner = tarball((0..NESTED_MEMBERS).map(|i| {
            (
                format!("pkg-{n}/file-{i:03}.txt"),
                format!("member {n}.{i}\n").into_bytes(),
            )
        }));
        let mut encoder = xz2::write::XzEncoder::new(Vec::new(), 1);
        encoder.write_all(&inner).unwrap();
        (format!("vendor/pkg-{n}.tar.xz"), encoder.finish().unwrap())
    }));

    let report = cleave::analyze_bytes(&outer, "bundle.tar", &cleave::AnalysisOptions::default())
        .expect("analysis completes");
    done.store(true, Ordering::SeqCst);

    let members = report
        .files
        .iter()
        .filter(|file| file.path.ends_with(".txt"))
        .count();
    assert_eq!(
        members,
        nested * NESTED_MEMBERS,
        "every nested member is reported"
    );
}
