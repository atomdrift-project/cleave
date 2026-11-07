//! Archive content analysis functions.
//!
//! This module contains the core analysis logic for different archive types:
//! - JAR/WAR/APK archives (Java bytecode optimized)
//! - Generic archives (all other formats)
//! - Individual extracted file analysis
//! - File type routing to appropriate analyzers
//!
//! # JAR Analysis Optimization
//!
//! JAR archives often contain thousands of .class files. Decompiling all of them
//! is prohibitively expensive, so we use a three-phase approach:
//! 1. YARA scan ALL classes in parallel (fast, just pattern matching)
//! 2. Full analysis on interesting classes (main class, YARA hits, samples)
//! 3. Analyze non-class files (scripts, configs, manifests)
//!
//! This balances thoroughness with performance.
//!
//! # Parallelism
//!
//! Archive member analysis runs on the global rayon thread pool, so the
//! per-thread YARA scanner caches are not duplicated across pools. Multiple
//! concurrent archives compete for the same rayon threads, so individual
//! member analyses must be bounded to avoid stalling the entire pool.

#[path = "pyarmor_members.rs"]
mod pyarmor_members;
#[path = "rc4_members.rs"]
mod rc4_members;

use super::ArchiveAnalyzer;
use super::guards::{
    CancellableReader, ExtractionGuard, HostileArchiveReason, LimitedReader, MAX_FILE_SIZE,
    MAX_PATH_COMPONENT_LEN, sanitize_entry_path, symlink_escapes,
};
use super::utils::{calculate_sha256, find_main_class, is_benign_java_path};
use crate::analyzers::{AnalysisInput, FileType, FileTypeExt, declared_file_type_from_name};
use crate::composite_rules::traits::nest_host;
use crate::types::{
    ARCHIVE_DELIMITER, AnalysisReport, ArchiveEntry, ENCODING_DELIMITER, FileAnalysis, Finding,
    TargetInfo, YaraMatch, encode_archive_path,
};
use crate::yara_engine::YaraScan;
use anyhow::{Context, Result};
use rayon::prelude::*;
use std::collections::{HashMap, HashSet};
use std::io::Read;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use tracing::debug;

mod member;

mod formats;

mod tempdir;

// Archive analysis now runs on the global rayon pool instead of a separate pool.
// This halves the number of YARA scanner cache instances (each ~50-100MB per wasmtime VM)
// since scanners are thread-local and a separate pool doubled the thread count.
// The global pool's work-stealing scheduler naturally balances archive and non-archive work.

/// Archive member identity is POSIX (`usr/bin/hello`) on every host. Walking
/// an extracted tree through `Path` would otherwise emit `usr\bin\hello` on
/// Windows and break path assertions plus any rule that matches on `/`.
fn posix_relative_path(path: &Path, root: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

/// Cheap constant-pool salience score used to choose the bounded set of JAR
/// classes that receive full analysis. Archive order is attacker-controlled;
/// taking the first twenty non-library classes lets a payload hide behind
/// inert padding classes even though the payload contains conspicuous APIs.
fn jar_class_triage_score(data: &[u8]) -> usize {
    const MARKERS: &[&[u8]] = &[
        b"java/lang/ProcessBuilder",
        b"java/lang/Runtime",
        b"java/net/http/HttpClient",
        b"java/net/HttpURLConnection",
        b"okhttp3/MultipartBody",
        b"javax/net/ssl/X509TrustManager",
        b"com/sun/jna/",
        b"java/awt/Robot",
        b"java/awt/datatransfer/Clipboard",
        b"java/util/zip/ZipOutputStream",
        b"java/io/FileOutputStream",
        b"java/nio/file/Files",
        b"javax/crypto/Cipher",
        b"java/lang/invoke/ConstantCallSite",
        // Memory-only staging and credential handoff must compete with
        // ordinary file/process APIs in the bounded archive class sample.
        b"java/util/jar/JarInputStream",
        b"java/lang/reflect/Method",
        b"getAccessToken",
        b"javax/net/ssl/SSLSocket",
        b"javax/net/ssl/SNIHostName",
        b"/dns-query?name=",
        b"Content-Length:",
    ];

    static MATCHER: std::sync::OnceLock<Option<aho_corasick::AhoCorasick>> =
        std::sync::OnceLock::new();
    let Some(matcher) = MATCHER
        .get_or_init(|| aho_corasick::AhoCorasick::new(MARKERS).ok())
        .as_ref()
    else {
        return 0;
    };

    let mut seen = [false; MARKERS.len()];
    let mut score = 0usize;
    for hit in matcher.find_iter(data) {
        let pattern = hit.pattern().as_usize();
        if !seen[pattern] {
            seen[pattern] = true;
            score += 1;
        }
        if score == MARKERS.len() {
            break;
        }
    }
    score
}

/// Keep selected JVM nests intact. A small anonymous implementation (for
/// example, an empty X509TrustManager) can carry the decisive evidence while
/// scoring below the class sample cutoff. Use the same host identity as
/// nest-scoped composites, and do not spend additional seed slots on siblings.
fn jar_nest_companion_indices<'a>(
    paths: &[String],
    selected: impl Iterator<Item = &'a str>,
) -> Vec<usize> {
    let selected: HashSet<&str> = selected.collect();
    let hosts: HashSet<&str> = selected.iter().map(|path| nest_host(path)).collect();
    let mut companions: Vec<usize> = paths
        .iter()
        .enumerate()
        .filter(|(_, path)| !selected.contains(path.as_str()) && hosts.contains(nest_host(path)))
        .map(|(index, _)| index)
        .collect();
    companions.sort_unstable_by(|left, right| paths[*left].cmp(&paths[*right]));
    companions
}

/// Informational inline YARA must not turn the bounded class sample into a
/// full walk. Alert definitions only make a class eligible for full analysis;
/// they are evaluated again there with scope, exclusions and normal evidence.
fn jar_inline_alert_ids(definitions: &[crate::composite_rules::TraitDefinition]) -> HashSet<&str> {
    definitions
        .iter()
        .filter(|definition| definition.crit >= crate::types::Criticality::Suspicious)
        .map(|definition| definition.id.as_str())
        .collect()
}

fn jar_should_retain_class(scan: &YaraScan, alert_ids: &HashSet<&str>) -> bool {
    !scan.matches.is_empty()
        || scan.inline_traits.keys().any(|namespace| {
            namespace
                .strip_prefix("inline.")
                .is_some_and(|id| alert_ids.contains(id))
        })
}

/// The cheap prepass decides retention; full analysis evaluates the traits.
struct JarClassTriage {
    index: usize,
    score: usize,
    retain: bool,
    matches: Vec<YaraMatch>,
}

/// Keep the best `limit` entries in linear time, then order only that bounded
/// prefix for deterministic analysis/output order.
fn keep_top_ranked<T>(
    items: &mut Vec<T>,
    limit: usize,
    mut compare: impl FnMut(&T, &T) -> std::cmp::Ordering,
) {
    if items.len() > limit {
        items.select_nth_unstable_by(limit, &mut compare);
        items.truncate(limit);
    }
    items.sort_unstable_by(compare);
}

/// Read one in-memory archive member into `out`, keeping whatever decoded when
/// the member's stream fails partway.
///
/// Returns the byte count read, or `None` when the member produced nothing at
/// all — the caller skips those, since there is no content to analyze. A
/// genuinely empty member returns `Some(0)` and is kept.
///
/// Corrupt and truncated members are the norm in a malware corpus, and the
/// in-memory container paths hold every member in RAM rather than on disk, so
/// there is nothing for `analyze_archive_with_data`'s partial-extraction
/// fallback to recover if one bad member aborts the walk.
fn read_member_tolerant<R: Read>(
    reader: &mut R,
    relative_path: &str,
    guard: &ExtractionGuard,
    out: &mut Vec<u8>,
) -> Option<u64> {
    let mut buf = [0u8; 65536];
    loop {
        match reader.read(&mut buf) {
            Ok(0) => return Some(out.len() as u64),
            Ok(n) => out.extend_from_slice(&buf[..n]),
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => {
                guard.add_extraction_note(format!(
                    "{relative_path}: member stream failed after {} bytes ({e})",
                    out.len()
                ));
                return (!out.is_empty()).then_some(out.len() as u64);
            }
        }
    }
}

// Member analyses currently on this thread's stack (see
// `ArchiveAnalyzer::member_may_wait`).

/// Members at or above the single-flight wait floor stay on their lane
/// thread in a parallel member window (see `par_filter_fold_members`).
/// How many heavy members one archive analyzes at a time
/// (`CLEAVE_HEAVY_MEMBER_PARALLEL`, default 32; 1 restores the serial walk).
/// Wider is faster on archives of many large bundles, at a modest cost in
/// peak RSS.
fn heavy_member_parallelism() -> usize {
    static N: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    *N.get_or_init(|| {
        crate::env::parse::<usize>("CLEAVE_HEAVY_MEMBER_PARALLEL")
            .filter(|&n| n > 0)
            .unwrap_or(32)
    })
}

fn prioritized_heavy_members() -> bool {
    static ENABLED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ENABLED.get_or_init(|| crate::env::flag("CLEAVE_PRIORITY_HEAVY_MEMBERS"))
}

/// Native analysis includes a long external disassembly pass. Start those
/// members before source bundles, then prefer larger members in each class.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum MemberDispatch {
    WholeMember(usize),
    // Claim or wait for the member flight off-pool, then enter the source
    // pool inside analyze_extracted_member_with_flight. Entering it earlier
    // would disable safe duplicate waits and repeat identical large bundles.
    SourceAnalysis,
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct MemberPriority {
    native: bool,
    bytes: usize,
    dispatch: Option<MemberDispatch>,
}

fn member_priority(member: &MemoryArchiveMember) -> Option<MemberPriority> {
    if member.data.len() < FLIGHT_WAIT_MIN_BYTES {
        return None;
    }
    let native = matches!(member.file_type, FileType::Elf | FileType::Pe);
    let dispatch = if native && member.data.len() >= 16 * 1024 * 1024 {
        native_member_threads().map(MemberDispatch::WholeMember)
    } else if member.file_type.is_source_code() && member.data.len() >= source_leaf_min_bytes() {
        static EARLY: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
        if *EARLY.get_or_init(|| crate::env::flag("CLEAVE_SOURCE_EARLY_DISPATCH")) {
            source_leaf_threads().map(|_| MemberDispatch::SourceAnalysis)
        } else {
            None
        }
    } else {
        None
    };
    Some(MemberPriority {
        native,
        bytes: member.data.len(),
        dispatch,
    })
}

/// Pull from the ranked queue when a worker becomes available. Parallel
/// iterator splitting alone can admit a low-priority half before the second
/// expensive member. Each invocation still belongs to its original index,
/// so callers can deliver results in archive order.
fn for_each_priority_member(indices: &[usize], f: impl Fn(usize) + Sync + Send) {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let next = AtomicUsize::new(0);
    let workers = indices.len().min(rayon::current_num_threads());
    (0..workers).into_par_iter().for_each(|_| {
        while let Some(&index) = indices.get(next.fetch_add(1, Ordering::Relaxed)) {
            f(index);
        }
    });
}

fn native_member_threads() -> Option<usize> {
    static THREADS: std::sync::OnceLock<Option<usize>> = std::sync::OnceLock::new();
    *THREADS.get_or_init(|| {
        crate::env::parse::<usize>("CLEAVE_NATIVE_MEMBER_THREADS").filter(|&n| n > 0)
    })
}

fn source_leaf_threads() -> Option<usize> {
    static THREADS: std::sync::OnceLock<Option<usize>> = std::sync::OnceLock::new();
    *THREADS
        .get_or_init(|| crate::env::parse::<usize>("CLEAVE_SOURCE_LEAF_THREADS").filter(|&n| n > 0))
}

/// Minimum source member size for the optional private leaf pool. Medium
/// bundles can also spend most of their wall time waiting on unrelated work
/// stolen by nested joins; allow measuring that boundary independently of
/// the number of workers in the private pool.
fn source_leaf_min_bytes() -> usize {
    static MIN: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    *MIN.get_or_init(|| {
        crate::env::parse::<usize>("CLEAVE_SOURCE_LEAF_MIN_KB")
            .filter(|&kb| kb > 0)
            .unwrap_or(4096)
            .saturating_mul(1024)
    })
}

/// Start isolated leaf members without waiting for a free scan worker. A
/// source pool created only inside its member task cannot help when that task
/// sits behind unrelated nested joins. The caller supplies one bounded heavy
/// group; results still use original indices and ordinary work stays on Rayon.
fn for_each_group_with_isolated_members(
    indices: &[usize],
    dispatch: impl Fn(usize) -> Option<MemberDispatch>,
    f: impl Fn(usize) + Sync + Send,
) {
    std::thread::scope(|scope| {
        let mut ordinary = Vec::new();
        for &index in indices {
            if let Some(dispatch) = dispatch(index) {
                let f = &f;
                scope.spawn(move || match dispatch {
                    MemberDispatch::WholeMember(threads) => {
                        crate::rayon_nest::with_isolated_leaf_pool(threads, || f(index))
                    }
                    MemberDispatch::SourceAnalysis => f(index),
                });
            } else {
                ordinary.push(index);
            }
        }
        for_each_priority_member(&ordinary, &f);
    });
}

/// Smallest member a busy single-flight is worth waiting for; smaller
/// duplicates are analyzed independently.
const FLIGHT_WAIT_MIN_BYTES: usize = 256 << 10;
thread_local! {
    static MEMBER_ANALYSIS_DEPTH: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// Retain the caller's bounded Rayon ownership while providing stack headroom.
/// A joined std::thread lost that thread-local context, leaving nested archives
/// serial while multiple top-level reports remained resident. Stack growth
/// stays on the same thread and cannot create an extra parallel owner.
fn with_nested_archive_stack<T>(work: impl FnOnce() -> Result<T>) -> Result<T> {
    const RED_ZONE: usize = 8 * 1024 * 1024;
    const STACK_SIZE: usize = 16 * 1024 * 1024;
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        stacker::maybe_grow(RED_ZONE, STACK_SIZE, work)
    }))
    .map_err(|error| {
        let message = error
            .downcast_ref::<String>()
            .map(String::as_str)
            .or_else(|| error.downcast_ref::<&str>().copied())
            .unwrap_or("unknown panic payload");
        anyhow::anyhow!("Nested archive analysis panicked: {message}")
    })?
}

/// Filter-map `items` in parallel for the top archive, sequentially for nested
/// archives.
///
/// `parallel` is [`ArchiveAnalyzer::members_run_parallel`]. The top archive fans its
/// members across the rayon pool so an idle worker can steal member work via
/// rayon's work-stealing — that is "parallel when slots are free, serial when
/// they're not", and it fills the long tail of a directory scan when only one
/// big archive remains (the other scan threads would otherwise sit idle). It
/// does *not* depend on being the outermost rayon context: under `cleave scan`'s
/// `par_bridge` walk (or an embedding host's slot pool) the top archive is already inside a
/// rayon thread, yet still benefits from fanning members out to drain the tail.
///
/// Nested archives (`depth >= 1`) stay serial: their members already run inside
/// a parallel member task, so a second fan-out level only deepens rayon nesting
/// — extra deadlock pressure on small pools (an embedding host runs 4-thread slots sized
/// precisely for the recursion chain) — without exposing usable parallelism.
fn par_filter_map_members<T, U, F>(items: &[T], parallel: bool, f: F) -> Vec<U>
where
    T: Sync,
    U: Send,
    F: Fn(&T) -> Option<U> + Sync + Send,
{
    // Stack-overflow guard: a rayon worker blocked in a nested join (e.g. a
    // member's scan_bytes par_iter) steals whatever task is pending — on a
    // shared pool that includes *other* in-flight analyses' member tasks — and
    // runs it on top of its current stack. Each stolen task can block and
    // steal again, so frames from independent deep analyses compound without
    // bound; no fixed thread stack survives that (an embedding host overflowed 64 MB
    // with 4 large archives in flight). maybe_grow moves the member task onto
    // a fresh heap-allocated stack segment whenever headroom is low, making
    // the compounding harmless. The red zone must cover one member's full
    // sequential chain (including in-place nested-archive recursion, capped at
    // depth 3) since the next check only happens at the next member boundary.
    // When headroom is fine the call is a thread-local read and a compare.
    const MEMBER_RED_ZONE: usize = 64 * 1024 * 1024;
    const MEMBER_GROWN_STACK: usize = 128 * 1024 * 1024;
    let f = |item: &T| stacker::maybe_grow(MEMBER_RED_ZONE, MEMBER_GROWN_STACK, || f(item));
    if !parallel {
        return items.iter().filter_map(f).collect();
    }
    // One window at a time. A rayon worker drains its own deque before it
    // looks at the shared injector, so one unbounded `par_iter` over tens of
    // thousands of members keeps every worker until it finishes, and every
    // other analysis's join waits behind it — h2o.jar's 70k classes held the
    // whole pool for 34 minutes. Windows the size the fold path already uses
    // bound that wait to one window.
    items
        .chunks(member_window_count().max(1))
        .flat_map(|window| window.par_iter().filter_map(&f).collect::<Vec<_>>())
        .collect()
}

/// Streaming sibling of [`par_filter_map_members`]: fold each produced value
/// into the accumulator the moment its producer finishes, instead of
/// collecting the whole batch first. On member-heavy windows the collect held
/// every member's full pre-fold report co-resident until the serial fold loop
/// drained it — several hundred MB to ~1 GB of pure peak on a big window
/// (memprofile: 1.9 GB net-live in the analyze phase). With streaming, at
/// at most one bounded scheduling window of reports in flight. The fold is
/// orders of magnitude cheaper than the analysis that feeds it, so lock
/// contention is noise.
// The state lock intentionally remains held while folding the contiguous
// prefix: releasing it would let another producer advance and fold a later
// item concurrently, breaking the input-order guarantee.
#[allow(clippy::significant_drop_tightening)]
///
/// `priority` classifies heavy members and ranks them when prioritized
/// admission is enabled. Heavy members run in bounded groups; light members
/// can run concurrently with that group. Folding always follows input order.
fn par_filter_fold_members<T, U, F>(
    items: &[T],
    parallel: bool,
    priority: impl Fn(&T) -> Option<MemberPriority> + Sync,
    f: F,
    mut fold: impl FnMut(U) + Send,
) where
    T: Sync,
    U: Send,
    F: Fn(&T) -> Option<U> + Sync + Send,
{
    const MEMBER_RED_ZONE: usize = 64 * 1024 * 1024;
    const MEMBER_GROWN_STACK: usize = 128 * 1024 * 1024;
    let f = |item: &T| stacker::maybe_grow(MEMBER_RED_ZONE, MEMBER_GROWN_STACK, || f(item));
    let mut items = items;
    if !parallel {
        // Serial walk, re-checked per member: the scan may enter its drain
        // phase (see `rayon_nest::toplevel_draining`) while a whale is
        // still walking, at which point the remaining members fan out
        // instead of finishing one by one on an otherwise idle pool.
        let mut upgraded = false;
        for (i, item) in items.iter().enumerate() {
            if i > 0 && items.len() - i > 1 && crate::rayon_nest::inner_work_parallel() {
                items = &items[i..];
                upgraded = true;
                break;
            }
            if let Some(u) = f(item) {
                fold(u);
            }
        }
        if !upgraded {
            return;
        }
    }
    // Ordered streaming fold: results are folded in ITEM order (identical to
    // the old collect-then-fold — member record order, rollup tie-breaks and
    // YARA dedup order are all arrival-order-sensitive), but each result is
    // folded as soon as the order allows instead of after the whole batch.
    // Out-of-order completions buffer until their predecessors fold, so the
    // co-resident set is bounded by completion skew (typically ~#threads)
    // rather than the window size.
    struct Ordered<U> {
        next: usize,
        pending: std::collections::BTreeMap<usize, Option<U>>,
    }
    let fold = std::sync::Mutex::new(fold);
    // A single early straggler can otherwise let every later completion pile
    // into `pending`; on the generic disk-walk path that means up to 100,000
    // full member reports despite the function being described as streaming.
    // Sequential bounded chunks preserve exact item order while retaining the
    // measured 2,048-member scheduling window.
    // Under live host-memory pressure (see `mem_pressure`) a chunk runs
    // serially on this thread instead of fanning out — no new member working
    // set stacks onto a host with no room for it — and the walk resumes
    // parallel on the next chunk once memory frees. Pressured chunks are
    // short so that re-check comes quickly. Deliberately not a lock: a member
    // that is itself an archive waits on its own nested walk, and a
    // process-wide mutex held across that wait would deadlock the pool.
    const PRESSURED_CHUNK: usize = 16;
    let mut start = 0;
    while start < items.len() {
        let pressured = crate::mem_pressure::under_pressure();
        let len = if pressured {
            PRESSURED_CHUNK
        } else {
            member_window_count().max(1)
        };
        let end = start.saturating_add(len).min(items.len());
        let chunk = &items[start..end];
        start = end;
        if pressured {
            for u in chunk.iter().filter_map(f) {
                let mut g = fold
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                g(u);
            }
            continue;
        }
        let state = std::sync::Mutex::new(Ordered {
            next: 0,
            pending: std::collections::BTreeMap::new(),
        });
        let deliver = |i: usize, u: Option<U>| {
            let mut st = state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            st.pending.insert(i, u);
            // Drain the contiguous prefix. Holding `state` while folding
            // keeps drains single-threaded; producers only block here when
            // they have nothing left to analyze anyway.
            loop {
                let next = st.next;
                match st.pending.first_entry() {
                    Some(entry) if *entry.key() == next => {
                        let (_, u) = entry.remove_entry();
                        st.next += 1;
                        if let Some(u) = u {
                            let mut g = fold
                                .lock()
                                .unwrap_or_else(std::sync::PoisonError::into_inner);
                            g(u);
                        }
                    }
                    _ => break,
                }
            }
        };
        let (mut heavy_items, light_items): (Vec<usize>, Vec<usize>) =
            (0..chunk.len()).partition(|&i| priority(&chunk[i]).is_some());
        let prioritized = prioritized_heavy_members();
        if prioritized {
            heavy_items.sort_by_key(|&i| std::cmp::Reverse(priority(&chunk[i])));
        }
        // `join`'s left side runs here; the right side is the only stealable
        // job. Heavy members run a bounded number at a time rather than one
        // after another: an archive of dozens of multi-MB minified bundles
        // otherwise spends most of its wall on one thread while the pool
        // idles. The bound keeps the concurrent working set of big
        // members — each holds its strings, parse tree and regex scratch —
        // from multiplying across every archive in flight.
        rayon::join(
            || {
                for group in heavy_items.chunks(heavy_member_parallelism()) {
                    if group
                        .iter()
                        .any(|&i| priority(&chunk[i]).is_some_and(|p| p.dispatch.is_some()))
                    {
                        for_each_group_with_isolated_members(
                            group,
                            |i| priority(&chunk[i]).and_then(|p| p.dispatch),
                            |i| deliver(i, f(&chunk[i])),
                        );
                    } else if prioritized {
                        for_each_priority_member(group, |i| deliver(i, f(&chunk[i])));
                    } else {
                        group.par_iter().for_each(|&i| deliver(i, f(&chunk[i])));
                    }
                }
            },
            || {
                light_items
                    .par_iter()
                    .for_each(|&i| deliver(i, f(&chunk[i])));
            },
        );
    }
    // Filtered items (f returned None) still advance `next` via the None
    // entries above, so every Some folds exactly once, in order.
}

/// Consume member buffers as each analysis finishes, before ordered result
/// delivery can wait for a slower predecessor. Scheduling and fold order are
/// shared with the borrowed path; only the input lifetime differs.
fn par_filter_fold_owned_members<T, U>(
    items: impl IntoIterator<Item = T>,
    parallel: bool,
    priority: impl Fn(&T) -> Option<MemberPriority>,
    analyze: impl Fn(&T) -> Option<U> + Sync + Send,
    fold: impl FnMut(U) + Send,
) where
    T: Send,
    U: Send,
{
    // The scheduler borrows its input slice. Each slot transfers ownership to
    // its one analysis invocation; the lock is released before analysis (and
    // any recursive archive work), and is never contended.
    let slots: Vec<_> = items
        .into_iter()
        .map(|item| (priority(&item), parking_lot::Mutex::new(Some(item))))
        .collect();
    par_filter_fold_members(
        &slots,
        parallel,
        |slot| slot.0,
        |slot| {
            let item = slot.1.lock().take()?;
            analyze(&item)
        },
        fold,
    );
}

/// Result of analyzing a single archive member, collected lock-free during par_iter
/// and aggregated single-threaded afterwards.
struct MemberAnalysisResult {
    go_source: Option<String>,
    entry_path: String,
    archive_location: String,
    entry_metadata: ArchiveEntry,
    report: Option<AnalysisReport>,
}

struct MemoryArchiveMember {
    relative_path: String,
    data: super::member_data::MemberData,
    file_type: FileType,
    sha256: String,
    container_kind: Option<String>,
}

fn archive_entry_metadata(
    entry_path: String,
    logical_path: &Path,
    file_type: &FileType,
    sha256: String,
    data: &[u8],
    container_kind: Option<String>,
) -> ArchiveEntry {
    let declared_file_type = declared_file_type_from_name(logical_path);
    let declared_type =
        (declared_file_type != FileType::Unknown).then(|| declared_file_type.report_file_type());
    let extension_type_mismatch = declared_type.is_some() && declared_file_type != *file_type;

    ArchiveEntry {
        path: entry_path,
        file_type: file_type.report_file_type(),
        sha256,
        size_bytes: data.len() as u64,
        declared_type,
        extension_type_mismatch,
        entropy: (!data.is_empty())
            .then(|| (crate::entropy::shannon(data) * 1000.0).round() / 1000.0),
        magic_prefix: magic_prefix(data),
        container_kind,
        ..ArchiveEntry::default()
    }
}

fn magic_prefix(data: &[u8]) -> Option<String> {
    if data.is_empty() {
        return None;
    }

    let mut out = String::with_capacity(data.len().min(8) * 2);
    for byte in data.iter().take(8) {
        use std::fmt::Write;
        let _ = write!(&mut out, "{byte:02x}");
    }
    Some(out)
}

fn pyinstaller_entry_kind(kind: pyinstx::EntryKind) -> &'static str {
    match kind {
        pyinstx::EntryKind::PySource => "py-source",
        pyinstx::EntryKind::PyModule => "py-module",
        pyinstx::EntryKind::PyzMember => "pyz-member",
        pyinstx::EntryKind::Splash => "splash",
        pyinstx::EntryKind::Binary => "binary",
    }
}

fn push_optional_string(
    obj: &mut serde_json::Map<String, serde_json::Value>,
    key: &str,
    value: &Option<String>,
) {
    if let Some(value) = value {
        obj.insert(key.to_string(), serde_json::Value::String(value.clone()));
    }
}

fn archive_entry_json(entry: &ArchiveEntry) -> serde_json::Value {
    let mut obj = serde_json::Map::new();
    obj.insert("path".into(), serde_json::Value::String(entry.path.clone()));
    obj.insert(
        "type".into(),
        serde_json::Value::String(entry.file_type.clone()),
    );
    obj.insert(
        "sha256".into(),
        serde_json::Value::String(entry.sha256.clone()),
    );
    obj.insert(
        "size_bytes".into(),
        serde_json::Value::Number(entry.size_bytes.into()),
    );
    push_optional_string(&mut obj, "declared_type", &entry.declared_type);
    if entry.extension_type_mismatch {
        obj.insert(
            "extension_type_mismatch".into(),
            serde_json::Value::Bool(true),
        );
    }
    if let Some(entropy) = entry.entropy
        && let Some(number) = serde_json::Number::from_f64(entropy)
    {
        obj.insert("entropy".into(), serde_json::Value::Number(number));
    }
    push_optional_string(&mut obj, "magic_prefix", &entry.magic_prefix);
    push_optional_string(&mut obj, "container_kind", &entry.container_kind);
    serde_json::Value::Object(obj)
}

/// Streaming accumulator for per-member analysis results.
///
/// Rebuild a folded member's retained record into fresh allocations, dropping
/// the analysis-time graph whole (see the fold-site comment for why in-place
/// field releases do not reduce peak RSS). The retained slice is everything
/// the finalize passes and compact emission still read:
/// - findings: slim clones — id/desc/mbc/attack are shared `Istr`s (refcount
///   clones), `trait_refs` kept (end-strip referenced union + per-file
///   summary scoring), evidence replaced by precomputed emission spans
///   (derived through the same dedup pipeline finalize would apply);
///   evidence appended later (inheritance, aggregate attribution) unions in
///   via `finding_spans`.
/// - context windows (composite-source lines + emission), precompacted facts, folded kv,
///   filefacts references (link_flagged_references), identity/scalars.
fn rebuild_slim_member(mut file: FileAnalysis, engine: &crate::Engine) -> FileAnalysis {
    let container_refs = engine.rules().container_ref_index();
    for finding in &mut file.findings {
        // A finding some loaded rule references stays full: container-scope
        // composite evaluation runs AFTER the fold over the folded member
        // findings, and offset conditions (`near_bytes`) and value conditions
        // read this evidence. Slimming one was measured to silently kill a
        // container proximity composite (gist-api deaddrop on a tar.gz),
        // whose death then cascaded through the end-strip's `referenced` set
        // and deleted the component findings from every member. The oracle is
        // the TraitRefIndex restricted to container-scope-capable rules — the
        // full index exempted most member findings and gave back the entire
        // memory win (member components exist largely to feed composites).
        if container_refs.possibly_referenced(&finding.id) {
            continue;
        }
        if finding.precomputed_spans.is_none() {
            // Materialize emission spans through the finalize-time evidence
            // pipeline (tuple-dedup + cap) before dropping the evidence.
            if finding.evidence.len() > 1 {
                let ev = std::mem::take(&mut finding.evidence);
                finding.evidence = crate::types::traits_findings::deduplicate_evidence(ev);
                finding
                    .evidence
                    .truncate(crate::types::traits_findings::MAX_EVIDENCE_PER_TRAIT);
            }
            finding.precomputed_spans = Some(crate::types::traits_findings::finding_spans(finding));
        }
        finding.evidence = Vec::new();
    }
    // One deep clone of the now-slim graph into fresh allocations, then drop
    // the original: its pages — shared with the analysis-time evidence and
    // strings freed above — empty out and purge.
    let slim = file.clone();
    drop(file);
    slim
}

/// Folds each member's result into deduplicated aggregate state and drops the
/// (large) member `AnalysisReport` immediately. This lets an archive's members
/// be analyzed in bounded byte-windows without ever holding every member's
/// report resident at once — the dominant per-archive memory term on
/// member-heavy archives (e.g. a 4 MB wheel with thousands of members).
#[derive(Default)]
struct MemberAccumulator {
    go_sources: Vec<(String, String)>,
    go_source_bytes: usize,
    go_incomplete: bool,
    /// Distinct finding ids seen across all members. Reported as both the trait
    /// and capability tally (the two are identical — every finding id counts as
    /// one of each), kept once rather than in two parallel sets.
    distinct_finding_ids: HashSet<String>,
    collected_traits: HashMap<String, Finding>,
    collected_yara: Vec<YaraMatch>,
    collected_archive_entries: Vec<ArchiveEntry>,
    collected_files: Vec<FileAnalysis>,
    files_analyzed: usize,
}

impl MemberAccumulator {
    /// Fold one member's result into the aggregate, consuming and dropping it.
    /// Member order is preserved because callers fold windows sequentially and
    /// each window's `par_iter` collect is index-ordered.
    fn fold(&mut self, result: MemberAnalysisResult, engine: &crate::Engine) {
        if let Some(source) = result.go_source {
            if source.is_empty() {
                self.go_incomplete = true;
            }
            if self.go_source_bytes + source.len() <= 8 * 1024 * 1024 && self.go_sources.len() < 512
            {
                self.go_source_bytes += source.len();
                self.go_sources.push((result.entry_path.clone(), source));
            } else {
                self.go_incomplete = true;
            }
        }
        let _aggregate = crate::mem_profile::phase(crate::mem_profile::Phase::Aggregate);
        self.collected_archive_entries.push(result.entry_metadata);
        let Some(file_report) = result.report else {
            return;
        };
        self.files_analyzed += 1;

        // Aggregate member YARA matches from the report *before* conversion:
        // `into_file_analysis` does not carry `yara_matches` onto the
        // FileAnalysis, so reading it post-conversion would silently see none.
        for yara_match in &file_report.yara_matches {
            if self.collected_yara.len() >= 1_000 {
                break;
            }
            if !self
                .collected_yara
                .iter()
                .any(|m| m.rule == yara_match.rule)
            {
                self.collected_yara.push(yara_match.clone());
            }
        }

        let (mut file_entry, nested_files, archive_contents) =
            file_report.into_file_analysis(0, engine);
        file_entry.path = result.entry_path.clone();
        file_entry.depth = 1;
        file_entry.compute_summary();

        for f in &file_entry.findings {
            self.distinct_finding_ids.insert(f.id.clone().to_string());
            let mut new_finding = f.clone();
            for evidence in &mut new_finding.evidence {
                match &evidence.location {
                    None => evidence.location = Some(result.archive_location.clone()),
                    Some(loc) if !loc.starts_with("archive:") => {
                        evidence.location = Some(format!("{}:{}", result.archive_location, loc));
                    }
                    _ => {}
                }
            }
            self.collected_traits
                .entry(new_finding.id.clone().to_string())
                .and_modify(|existing| {
                    if (new_finding.crit, new_finding.conf.total_cmp(&existing.conf))
                        > (existing.crit, std::cmp::Ordering::Equal)
                    {
                        *existing = new_finding.clone();
                    }
                })
                .or_insert(new_finding);
        }

        // Member strings (URLs/IPs/base64) are deliberately NOT hoisted onto the
        // parent. Matching has already materialized every useful result as a
        // finding, so clear_unserialized_member_fields dropped the extracted
        // strings before this fold. Pulling them up made the parent's `type:
        // text` evaluation re-match member content with no way to attribute it
        // back, producing findings on the archive itself (e.g. a
        // `jsonkeeper.com` URL decoded from a member) with member-relative
        // offsets meaningless in the archive's byte space. Only traits roll up
        // to the parent — carrying their member `from`.
        // Compact-retained members are REBUILT into fresh allocations
        // (`rebuild_slim_member`) and the original analysis graph dropped
        // whole — in-place field releases were measured a no-op for peak RSS
        // because a member's eval-time allocations interleave on shared
        // allocator pages. Runs AFTER the rollup loop above (the rollup
        // representatives clone member evidence and keep the full form).
        // Wrapper nodes — members that contain the nested files below — stay
        // full: finalize's aggregate attribution rewrites `archive:`-located
        // evidence on wrappers after the fold, and slimming them froze
        // pre-rewrite spans (measured: 223 findings lost spans on the
        // 54k-member manifest). Wrappers are rare, so keeping them costs
        // little.
        if engine.compact_members() && nested_files.is_empty() {
            file_entry = rebuild_slim_member(file_entry, engine);
        }
        self.collected_files.push(file_entry);
        self.collected_archive_entries
            .extend(archive_contents.into_iter().map(|mut entry| {
                entry.path = rebase_nested_archive_entry_path(&result.entry_path, &entry.path);
                entry
            }));
        let mut nested: Vec<FileAnalysis> = Vec::with_capacity(nested_files.len());
        for mut nested_file in nested_files {
            nested_file.path = rebase_nested_file_path(&result.entry_path, &nested_file.path);
            nested_file.depth += 1;
            nested.push(nested_file);
        }
        if engine.compact_members() {
            // A record stays full when finalize still re-reads its evidence:
            // - wrappers (another path extends this one at a `!` or `##`
            //   boundary): aggregate attribution rewrites their evidence, and
            //   inheritance stamps the findings they receive by it.
            // - decoded-layer records themselves (`##` in the path): their
            //   findings, evidence included, are what inheritance copies into
            //   the parent file.
            let exempt: Vec<bool> = (0..nested.len())
                .map(|i| {
                    let path = &nested[i].path;
                    if path.contains(crate::types::file_analysis::ENCODING_DELIMITER) {
                        return true;
                    }
                    nested.iter().any(|f| {
                        f.path.len() > path.len()
                            && f.path.starts_with(path.as_str())
                            && (f.path.as_bytes().get(path.len()) == Some(&b'!')
                                || f.path.as_bytes()[path.len()..].starts_with(b"##"))
                    })
                })
                .collect();
            for (i, is_exempt) in exempt.into_iter().enumerate() {
                if !is_exempt {
                    let f = std::mem::take(&mut nested[i]);
                    nested[i] = rebuild_slim_member(f, engine);
                }
            }
        }
        self.collected_files.extend(nested);
    }

    /// Merge another accumulator's state after this one's — the pipelined
    /// window driver appends any inline-folded remainder (consumer-death
    /// fallback, or a fully inline run) to the consumer's aggregate, with the
    /// same per-id max-crit/conf and YARA dedup rules as [`Self::fold`].
    fn absorb(&mut self, other: MemberAccumulator) {
        self.go_incomplete |= other.go_incomplete;
        for (path, source) in other.go_sources {
            if self.go_source_bytes + source.len() <= 8 * 1024 * 1024 && self.go_sources.len() < 512
            {
                self.go_source_bytes += source.len();
                self.go_sources.push((path, source));
            } else {
                self.go_incomplete = true;
            }
        }
        use std::collections::hash_map::Entry;
        self.distinct_finding_ids.extend(other.distinct_finding_ids);
        for ym in other.collected_yara {
            if self.collected_yara.len() >= 1_000 {
                break;
            }
            if !self.collected_yara.iter().any(|m| m.rule == ym.rule) {
                self.collected_yara.push(ym);
            }
        }
        for (id, f) in other.collected_traits {
            match self.collected_traits.entry(id) {
                Entry::Occupied(mut entry) => {
                    let existing = entry.get_mut();
                    if (f.crit, f.conf.total_cmp(&existing.conf))
                        > (existing.crit, std::cmp::Ordering::Equal)
                    {
                        *existing = f;
                    }
                }
                Entry::Vacant(entry) => {
                    entry.insert(f);
                }
            }
        }
        self.collected_archive_entries
            .extend(other.collected_archive_entries);
        self.collected_files.extend(other.collected_files);
        self.files_analyzed += other.files_analyzed;
    }

    /// Sort the collected member files by descending peak severity, then cap the
    /// count. Generic archives surface their most severe members first under a
    /// hard ceiling; formats that keep insertion order simply don't call this.
    fn sort_files_by_severity(&mut self, limit: usize) {
        // `cached_key` computes each file's peak once rather than on every
        // comparison; `Reverse` gives descending order while staying stable.
        self.collected_files.sort_by_cached_key(|f| {
            std::cmp::Reverse(f.findings.iter().map(|f| f.crit).max().unwrap_or_default())
        });
        self.collected_files.truncate(limit);
    }

    /// Drain the deduplicated aggregate into the parent report, returning the
    /// tallies each archive type folds into its own summary line. Writes no
    /// metadata — callers append their format-specific summary and tools after.
    fn merge_into(self, report: &mut AnalysisReport) -> MemberCounts {
        super::source_context::attach_go(report, &self.go_sources, self.go_incomplete);
        let distinct = self.distinct_finding_ids.len();
        let counts = MemberCounts {
            files_analyzed: self.files_analyzed,
            trait_count: distinct,
            capability_count: distinct,
        };
        // Dedup against what the container already holds via sets, not a linear
        // rescan per item (archives can carry thousands of distinct findings).
        let mut seen_ids: HashSet<crate::types::Istr> =
            report.findings.iter().map(|f| f.id.clone()).collect();
        for (_, t) in self.collected_traits {
            if seen_ids.insert(t.id.clone().to_string().into()) {
                report.findings.push(t);
            }
        }
        let mut seen_rules: HashSet<String> =
            report.yara_matches.iter().map(|m| m.rule.clone()).collect();
        for ym in self.collected_yara {
            if seen_rules.insert(ym.rule.clone()) {
                report.yara_matches.push(ym);
            }
        }
        report
            .archive_contents
            .extend(self.collected_archive_entries);
        report.files.extend(self.collected_files);
        counts
    }

    /// Merge the deduplicated aggregate into the parent report and write the
    /// generic archive-level metadata. Called once per archive after all members
    /// fold (the windowed ZIP/ASAR path); JAR and generic archives build their
    /// own summary lines from [`MemberAccumulator::merge_into`] instead.
    fn finalize(
        self,
        report: &mut AnalysisReport,
        start: std::time::Instant,
        archive_label: &'static str,
        tools_used: Vec<String>,
        total_files: usize,
    ) {
        let MemberCounts {
            files_analyzed,
            trait_count,
            capability_count,
        } = self.merge_into(report);
        report.metadata.errors.push(format!(
            "{archive_label}: {total_files} members, {files_analyzed} analyzed, \
             {trait_count} traits and {capability_count} capabilities detected"
        ));
        report.metadata.analysis_duration_ms = start.elapsed().as_millis() as u64;
        report.metadata.tools_used = tools_used;
    }
}

/// Rebase a child's file-analysis path beneath the member path known by its
/// parent.
///
/// Nested analyzers only know their local root (`setup.exe!!payload.dll`), while
/// the enclosing archive knows the complete path (`bundle.zip!!setup.exe`).
/// Replacing that local root retains every deeper segment without losing the
/// outer provenance chain.
fn rebase_nested_file_path(parent: &str, child: &str) -> String {
    // ArchiveEntry paths use the legacy single-`!` separator, whereas the flat
    // FileAnalysis tree uses `!!`. Reports folded from nested analyzers can
    // therefore arrive in either spelling; canonicalize both before rebasing.
    let parent = parent
        .split('!')
        .filter(|segment| !segment.is_empty())
        .collect::<Vec<_>>()
        .join(ARCHIVE_DELIMITER);
    let child = child
        .split('!')
        .filter(|segment| !segment.is_empty())
        .collect::<Vec<_>>()
        .join(ARCHIVE_DELIMITER);
    let complete_prefix = format!("{parent}{ARCHIVE_DELIMITER}");
    if child.starts_with(&complete_prefix) {
        return child;
    }

    // A member analyzer may return decoded layers with a local path such as
    // `setup.exe##base64@123`. That path names the already selected member;
    // append the decoder suffix to the archive-qualified parent instead of
    // treating it as a nested archive member (`setup.exe!!setup.exe##...`).
    let parent_member = parent.rsplit(ARCHIVE_DELIMITER).next().unwrap_or(&parent);
    if let Some((child_source, decoder_suffix)) = child.split_once(ENCODING_DELIMITER)
        && (parent_member == child_source
            || parent_member.ends_with(&format!("/{child_source}"))
            || parent_member.ends_with(&format!("\\{child_source}")))
    {
        return format!("{parent}{ENCODING_DELIMITER}{decoder_suffix}");
    }

    let local_child = child
        .split_once(ARCHIVE_DELIMITER)
        .map_or(child.as_str(), |(_, nested)| nested);
    encode_archive_path(&parent, local_child)
}

/// Rebase archive inventory metadata, whose nested-path separator is a single
/// `!`. Embedded PE analyzers expose `!!` paths, so normalize those at the
/// archive boundary as well.
fn rebase_nested_archive_entry_path(parent: &str, child: &str) -> String {
    let parent = parent
        .split('!')
        .filter(|segment| !segment.is_empty())
        .collect::<Vec<_>>()
        .join("!");
    let child = child
        .split('!')
        .filter(|segment| !segment.is_empty())
        .collect::<Vec<_>>()
        .join("!");
    let complete_prefix = format!("{parent}!");
    if child.starts_with(&complete_prefix) {
        return child;
    }

    let local_child = child
        .split_once('!')
        .map_or(child.as_str(), |(_, nested)| nested);
    format!("{parent}!{local_child}")
}

/// Per-archive tallies returned by [`MemberAccumulator::merge_into`] — each
/// archive format folds these into its own summary line.
struct MemberCounts {
    files_analyzed: usize,
    trait_count: usize,
    capability_count: usize,
}

/// Resident-byte budget for one member window. Caps how much decompressed
/// member data co-resides; tunable via `CLEAVE_MEMBER_WINDOW_MB`.
///
/// Window sizing is a memory/straggler tradeoff: every window ends by waiting
/// on its slowest member, so the idle cost of that straggler is paid once per
/// window. Small windows spend a large fraction of wall waiting — on a
/// 16k-member TypeScript corpus (8 cores) the old 256-member/32 MB
/// windows held the whole scan to 4.3 of 8 cores, and raising the caps to
/// 2048/256 MB cut wall 40% (777 s -> 464 s) with identical output and +3%
/// RSS. The count cap is the binding one for small-member archives (2048 of
/// those members ≈ 31 MB); the byte budget only doubles so worker fleets with
/// dozens of concurrent archive scans don't gain 8x transients.
fn member_window_bytes() -> usize {
    static BYTES: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    *BYTES.get_or_init(|| {
        if let Some(mb) = crate::env::parse::<usize>("CLEAVE_MEMBER_WINDOW_MB").filter(|mb| *mb > 0)
        {
            return mb.saturating_mul(1024 * 1024);
        }
        // Scale with the host: the window is the decompressed member bytes
        // co-resident during one parallel batch, and a fixed 64 MB serialises
        // an archive's whales. A 95 MB ELF fills a window alone and the
        // 10 MB bundle beside it waits for the next one — measured as the
        // 52 s critical path of a 55 s corpus scan on a 31 GB host, where
        // both could have run side by side. 1/64 of RAM, clamped to the old
        // floor and a 512 MB ceiling, keeps small hosts exactly where they
        // were.
        const FLOOR_MB: usize = 64;
        const CEIL_MB: usize = 512;
        let from_ram = crate::memory_tracker::total_memory()
            .map(|total| (total / 64) as usize / (1024 * 1024))
            .unwrap_or(FLOOR_MB);
        from_ram
            .clamp(FLOOR_MB, CEIL_MB)
            .saturating_mul(1024 * 1024)
    })
}

/// Minimum batch size at which a *nested* archive's members fan out across the
/// rayon pool; smaller batches run serially on the analysis's own task. The
/// member window caps batches at [`member_window_count`] (256), so member-heavy
/// nested archives hit this threshold window after window while small wheels
/// and condas never do.
const NESTED_PARALLEL_MIN_MEMBERS: usize = 64;

/// Non-class members sampled from a Java archive, where the remainder are
/// incidental resources. Raised from 100 once it was measured truncating real
/// archives: a hundred is fewer entries than an ordinary JAR's resource tree,
/// so the sample was cutting into content rather than trimming a long tail.
const JAR_RESOURCE_SAMPLE: usize = 1_000;

/// Rank a member by how much its absence would change a verdict, lowest first.
/// Used to order members before a cap truncates them, so the files a verdict
/// actually rests on survive a sample taken for size reasons.
fn member_signal_rank(path: &std::path::Path) -> u8 {
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    // Package manifests: they carry install hooks, dependencies and entrypoint
    // declarations, and every ecosystem keeps exactly one at a known name.
    const MANIFESTS: [&str; 12] = [
        "package.json",
        "manifest.mf",
        "androidmanifest.xml",
        "setup.py",
        "pyproject.toml",
        "cargo.toml",
        "composer.json",
        "build.gradle",
        "pom.xml",
        "bower.json",
        "gemspec",
        "extension.vsixmanifest",
    ];
    if MANIFESTS.contains(&name.as_str()) {
        return 0;
    }
    // Conventional entrypoints -- the file a manifest's `main` or install hook
    // most often names, and so the usual home of an install-time payload.
    if matches!(
        name.as_str(),
        "index.js" | "main.js" | "install.js" | "setup.js" | "preinstall.js" | "postinstall.js"
    ) {
        return 1;
    }
    2
}

/// Maximum members held in one window. Caps the per-window report transient
/// (each window's `par_iter` collects this many full reports before folding)
/// independent of member size; tunable via `CLEAVE_MEMBER_WINDOW_COUNT`.
fn member_window_count() -> usize {
    const DEFAULT: usize = 2048;
    crate::env::parse::<usize>("CLEAVE_MEMBER_WINDOW_COUNT")
        .filter(|n| *n > 0)
        .unwrap_or(DEFAULT)
}

/// Whether window flushes hand off to a pipelined consumer thread. Requires at
/// least two rayon workers: the producer is usually itself a pool worker, and
/// while it is parked in a channel send it cannot steal work — on a 1-thread
/// pool the consumer's par_iter would then never be executed and both sides
/// would wait forever. Kill switch: `CLEAVE_PIPELINE_MEMBER_WINDOWS=0` (also
/// how a single binary A/Bs the pipeline in benchmarks).
fn pipeline_member_windows() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| {
        // Opt-in (=1), not opt-out: measured on the typed corpus,
        // handing windows to the consumer thread was a wash at 63k members and
        // 24% SLOWER at 16k — the consumer is an external thread rayon won't
        // run pool work on, and the producer parked in a channel send is a
        // worker the pool loses outright. The window-size defaults above are
        // what actually recover the barrier idle; revisit this gate only with
        // fresh numbers showing a win.
        crate::env::flag("CLEAVE_PIPELINE_MEMBER_WINDOWS") && rayon::current_num_threads() >= 2
    })
}

/// The pipelined half of a [`MemberWindow`]: a consumer thread (scoped, so it
/// may borrow the analyzer) that analyzes each window it receives and folds
/// the results in arrival order — which is send order, so member order is
/// preserved exactly as in the inline path.
struct WindowPipeline<'scope> {
    tx: std::sync::mpsc::SyncSender<Vec<MemoryArchiveMember>>,
    handle: std::thread::ScopedJoinHandle<'scope, MemberAccumulator>,
}

/// Byte-windowed member analysis driver.
///
/// Members are pushed in; when the resident window exceeds the byte budget or
/// the member-count cap, the window is analyzed in parallel, folded into the
/// accumulator, and dropped. This bounds both resident decompressed bytes and
/// the per-window report transient, replacing the old all-members-resident
/// depth-0 path (which held every member's data and report at once) and the
/// fully-serial depth>=1 path with one memory-bounded, parallel path.
///
/// With a scope (see [`MemberWindow::new_in`]) the flush is pipelined: a
/// consumer thread analyzes and folds window N while the producer inflates
/// window N+1. Decompression is inherently serial per archive, and the
/// blocking flush made it strictly alternate with analysis — the pool sat
/// idle while the producer inflated and vice versa, which on a 63k-member
/// archive left ~30% of even an 8-core box unused (typed
/// benchmark). The bounded channel keeps at most one window in flight, so
/// resident bytes stay within one window budget of the inline path.
struct MemberWindow<'a, 'scope> {
    analyzer: &'a ArchiveAnalyzer,
    acc: MemberAccumulator,
    window: Vec<MemoryArchiveMember>,
    window_bytes: usize,
    budget_bytes: usize,
    max_count: usize,
    total: usize,
    slow_log_label: &'static str,
    pipeline: Option<WindowPipeline<'scope>>,
}

impl<'a: 'scope, 'scope> MemberWindow<'a, 'scope> {
    fn new(analyzer: &'a ArchiveAnalyzer, slow_log_label: &'static str) -> Self {
        Self {
            analyzer,
            acc: MemberAccumulator::default(),
            window: Vec::new(),
            window_bytes: 0,
            budget_bytes: member_window_bytes(),
            max_count: member_window_count(),
            total: 0,
            slow_log_label,
            pipeline: None,
        }
    }

    /// Like [`MemberWindow::new`], but flushes hand windows to a consumer
    /// thread spawned on `scope` (when pipelining is enabled), overlapping the
    /// producer's decompression with member analysis. The caller's producer
    /// loop simply runs inside `std::thread::scope(|s| ...)`; every early exit
    /// drops this struct and with it the channel sender, so the consumer
    /// always terminates and the scope never hangs on join.
    fn new_in(
        scope: &'scope std::thread::Scope<'scope, '_>,
        analyzer: &'a ArchiveAnalyzer,
        slow_log_label: &'static str,
    ) -> Self {
        let mut this = Self::new(analyzer, slow_log_label);
        if !pipeline_member_windows() {
            return this;
        }
        let (tx, rx) = std::sync::mpsc::sync_channel::<Vec<MemoryArchiveMember>>(1);
        let handle = scope.spawn(move || {
            let mut acc = MemberAccumulator::default();
            while let Ok(batch) = rx.recv() {
                let parallel = analyzer.members_run_parallel(batch.len());
                par_filter_fold_owned_members(
                    batch,
                    parallel,
                    member_priority,
                    |member| analyzer.analyze_one_member(member, slow_log_label),
                    |result| acc.fold(result, &analyzer.engine),
                );
            }
            acc
        });
        this.pipeline = Some(WindowPipeline { tx, handle });
        this
    }

    /// Add a member, flushing the window first if it is already full.
    fn push(&mut self, member: MemoryArchiveMember) {
        self.total += 1;
        self.window_bytes += member.data.len();
        self.window.push(member);
        if self.window_bytes >= self.budget_bytes || self.window.len() >= self.max_count {
            self.flush();
        }
    }

    /// Analyze the current window in parallel, fold results, drop the buffers.
    /// Pipelined: hand the window to the consumer (blocking while one window
    /// is already in flight — that backpressure is the memory bound). Inline:
    /// analyze and fold here, exactly the pre-pipeline behavior.
    fn flush(&mut self) {
        if self.window.is_empty() {
            return;
        }
        if let Some(pipeline) = &self.pipeline {
            let batch = std::mem::take(&mut self.window);
            self.window_bytes = 0;
            if let Err(send_err) = pipeline.tx.send(batch) {
                // Consumer died (panicked). Fold this window inline so the
                // scan still completes; the join in finalize propagates the
                // panic for visibility.
                self.window = send_err.0;
                self.pipeline = None;
            } else {
                return;
            }
        }
        let analyzer = self.analyzer;
        let label = self.slow_log_label;
        let parallel = analyzer.members_run_parallel(self.window.len());
        let acc = &mut self.acc;
        par_filter_fold_owned_members(
            self.window.drain(..),
            parallel,
            member_priority,
            |member| analyzer.analyze_one_member(member, label),
            |result| acc.fold(result, &analyzer.engine),
        );
        self.window.clear();
        self.window_bytes = 0;
    }

    /// Flush any remainder and merge the aggregate into the parent report.
    fn finalize(
        mut self,
        report: &mut AnalysisReport,
        start: std::time::Instant,
        archive_label: &'static str,
        tools_used: Vec<String>,
    ) {
        self.flush();
        let mut acc = match self.pipeline.take() {
            Some(WindowPipeline { tx, handle }) => {
                drop(tx); // consumer's recv loop ends
                match handle.join() {
                    Ok(acc) => acc,
                    Err(panic) => std::panic::resume_unwind(panic),
                }
            }
            None => MemberAccumulator::default(),
        };
        // Inline-path folds (non-pipelined runs, or a fallback after consumer
        // death) merge after the pipelined ones; in normal operation exactly
        // one of the two accumulators is non-empty.
        acc.absorb(self.acc);
        acc.finalize(report, start, archive_label, tools_used, self.total);
    }
}

fn find_main_class_in_members(members: &[MemoryArchiveMember]) -> Option<String> {
    let manifest = members
        .iter()
        .find(|m| m.relative_path.eq_ignore_ascii_case("META-INF/MANIFEST.MF"))?;
    super::utils::main_class_from_manifest(&manifest.data)
}

fn is_interesting_jar_non_class(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    !lower.contains("meta-inf/") || lower.ends_with("manifest.mf") || lower.ends_with(".xml")
}

/// Keep nested archives in the JAR resource candidate set even when they live
/// below `META-INF/`. That directory is normally full of low-value Java
/// metadata, but a nested JAR is a real analysis container: dropping it here
/// prevents `analyze_extracted_member` from recursing into it and loses every
/// trait from its classes/resources. Both paths pass the member's detected
/// type — never one guessed from its name — so a nested archive is recognized
/// by what it is, whatever it is called.
fn is_nested_archive_member(file_type: &FileType) -> bool {
    file_type.is_archive()
}

fn is_interesting_jar_resource(path: &std::path::Path, file_type: &FileType) -> bool {
    is_nested_archive_member(file_type) || is_interesting_jar_non_class(&path.to_string_lossy())
}

/// Total number of successful archive member analyses (cumulative, for logging)
static SUCCESSFUL_ANALYSES: AtomicU64 = AtomicU64::new(0);

/// Total number of failed archive member analyses
static FAILED_ANALYSES: AtomicU64 = AtomicU64::new(0);

/// Warn when a single archive member analysis exceeds this threshold.
const SLOW_ARCHIVE_MEMBER_ANALYSIS_MS: u128 = 30_000;

/// Emit a progress log every N members or every T seconds, whichever comes
/// first. The atomic ensures only one thread emits per window, so the log is
/// safe to call from a `par_iter` body. Returns `true` if a log should fire.
fn should_log_progress(
    done: usize,
    total: usize,
    elapsed_ms: u64,
    last_log_ms: &AtomicU64,
) -> bool {
    const EVERY_N_MEMBERS: usize = 10;
    const EVERY_T_MS: u64 = 10_000;
    if done == total || done.is_multiple_of(EVERY_N_MEMBERS) {
        last_log_ms.store(elapsed_ms, Ordering::Relaxed);
        return true;
    }
    let last = last_log_ms.load(Ordering::Relaxed);
    if elapsed_ms.saturating_sub(last) >= EVERY_T_MS
        && last_log_ms
            .compare_exchange(last, elapsed_ms, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
    {
        return true;
    }
    false
}

struct ThreadLocalCacheClearGuard;

impl Drop for ThreadLocalCacheClearGuard {
    fn drop(&mut self) {
        crate::composite_rules::evaluators::clear_thread_local_caches();
    }
}

/// Log archive analysis statistics.
pub(crate) fn log_archive_analysis_stats() {
    let successful = SUCCESSFUL_ANALYSES.load(Ordering::Relaxed);
    let failed = FAILED_ANALYSES.load(Ordering::Relaxed);
    tracing::info!(
        successful_analyses = successful,
        failed_analyses = failed,
        "Archive analysis statistics"
    );
}

impl ArchiveAnalyzer {
    /// Analyze the managed members of a native .NET single-file host through
    /// the normal bounded member pipeline. Packaging alone is not suspicious.
    pub(crate) fn analyze_dotnet_bundle(&self, data: &[u8], report: &mut AnalysisReport) -> bool {
        let guard = ExtractionGuard::with_budget(self.cancelled.clone(), self.budget.clone());
        let bundle = match super::dotnet_bundle::parse(data) {
            Ok(Some(bundle)) => bundle,
            Ok(None) => return false,
            Err(error) => {
                guard.add_extraction_note(format!(".NET bundle manifest: {error:#}"));
                super::drain_extraction_notes(report, &guard);
                return false;
            }
        };
        report.merge_kv_subtree(
            "dotnet_bundle",
            serde_json::json!({
                "version": format!("{}.{}", bundle.major, bundle.minor),
                "members": bundle.entries.len(),
            }),
        );
        for note in &bundle.notes {
            guard.add_extraction_note(note.clone());
        }
        if self.current_depth >= self.max_depth {
            guard.add_extraction_note(".NET bundle: maximum archive depth reached".to_string());
            super::drain_extraction_notes(report, &guard);
            return true;
        }
        let start = std::time::Instant::now();
        let saved_tools = report.metadata.tools_used.clone();
        let mut window = MemberWindow::new(self, "memory .NET bundle");
        let fake_root = Path::new("/__cleave_bundle__");
        let mut total = 0u64;
        for entry in &bundle.entries {
            if self.is_cancelled() {
                guard.add_extraction_note(".NET bundle analysis cancelled".to_string());
                break;
            }
            if !guard.check_file_count() {
                break;
            }
            let Some(safe_path) = sanitize_entry_path(&entry.path, fake_root) else {
                guard.add_hostile_reason(HostileArchiveReason::PathTraversal(entry.path.clone()));
                continue;
            };
            // Analyze every occurrence, even identical or case-variant paths;
            // otherwise an inert first entry can conceal a later payload.
            let relative_path = posix_relative_path(&guard.claim_output_path(safe_path), fake_root);
            let limit = self.max_memory_file_size.min(MAX_FILE_SIZE);
            if entry.size > limit {
                guard.add_extraction_note(format!(
                    "{relative_path}: bundle member exceeds memory limit ({limit} bytes)"
                ));
                continue;
            }
            if entry.size > super::dotnet_bundle::MAX_BUNDLE_BYTES.saturating_sub(total) {
                guard.add_extraction_note(
                    ".NET bundle stopped at 512 MiB expanded byte cap".to_string(),
                );
                break;
            }
            // Charge declared output before decoding, including failures.
            total += entry.size;
            let file_data = match super::dotnet_bundle::read_member(data, &bundle, entry, limit) {
                Ok(bytes) => bytes,
                Err(error) => {
                    guard.add_extraction_note(format!("{relative_path}: {error:#}"));
                    continue;
                }
            };
            if !guard.check_bytes(file_data.len() as u64, &relative_path) {
                break;
            }
            let file_type =
                crate::analyzers::detect_file_type_from_data(Path::new(&relative_path), &file_data);
            let sha256 = calculate_sha256(&file_data);
            guard.record_member_metadata(super::guards::ExtractedMemberMetadata {
                archive_path: relative_path.clone(),
                compressed_size: Some(if entry.compressed == 0 {
                    entry.size
                } else {
                    entry.compressed
                }),
                compression_method: Some(
                    if entry.compressed == 0 {
                        "stored"
                    } else {
                        "deflate"
                    }
                    .to_string(),
                ),
                entry_type: Some("regular".to_string()),
                ..Default::default()
            });
            window.push(MemoryArchiveMember {
                relative_path,
                data: file_data.into(),
                file_type,
                sha256,
                container_kind: None,
            });
        }
        window.finalize(report, start, ".NET single-file bundle", saved_tools);
        if !report
            .metadata
            .tools_used
            .iter()
            .any(|tool| tool == "dotnet_bundle")
        {
            report.metadata.tools_used.push("dotnet_bundle".to_string());
        }
        super::merge_archive_member_metadata(report, guard.take_member_metadata());
        super::drain_extraction_notes(report, &guard);
        super::push_archive_hostile_findings(
            report,
            guard.take_reasons(),
            Path::new("bundle.exe"),
            "dotnet_bundle",
            false,
        );
        true
    }

    fn has_wrapped_binary(&self, file_type: &FileType, data: &[u8]) -> bool {
        *file_type == FileType::Unknown
            && data.len() <= 32 * 1024 * 1024
            && (memchr::memmem::find(data, b"MZ").is_some()
                || memchr::memmem::find(data, b"\x7fELF").is_some()
                || memchr::memmem::find(data, b"TVq").is_some())
            && !crate::analyzers::embedded_binary_detector::scan_for_embedded_binaries(
                data,
                self.cancelled.as_deref(),
            )
            .is_empty()
    }

    fn archive_member_analysis_skip_reason(
        &self,
        file_type: &FileType,
        path: &str,
    ) -> Option<&'static str> {
        if filefacts::package_context::has_named_reference_metadata(Path::new(path)) {
            return None;
        }
        if self
            .analysis_options
            .as_ref()
            .is_some_and(|opts| opts.all_files)
        {
            return None;
        }

        // Allow file types that carry identity-signal facts (Markdown
        // exposes `markdown.first_heading` / `markdown.github_repos[]`,
        // PkgInfo carries `Name:` / `Version:` headers). These are
        // technically `!is_program()` but the cross-file value
        // matchers depend on their values being reachable from
        // archive-scope evaluation.
        //
        // HTML is here for a stronger reason: `is_program()` excludes only
        // `Unknown | Html | Markdown | Odf`, and HTML is the one of those that
        // carries executable code. A `<script>` block is a JavaScript program
        // whether it arrives as `payload.js` or inlined in `index.html`, and
        // cleave ships a full HTML analyzer plus the `documents` trait group to
        // read it. Skipping HTML members meant an archive whose ENTIRE payload
        // is a web page analyzed as though it were empty: the npm-as-free-CDN
        // campaigns publish a package whose only file is `index.html` — a fake
        // Cloudflare "Just a moment" Turnstile page with an obfuscated
        // completion handler — and cleave reported only the `package.json`,
        // reaching none of the phishing traits that fire when the same file is
        // scanned directly. The same blind spot covers browser-extension
        // popups, `.crx`/`.xpi` UI pages, and HTML droppers stapled into a zip.
        if matches!(
            file_type,
            FileType::Markdown | FileType::PkgInfo | FileType::Html
        ) {
            return None;
        }

        if !file_type.is_analyzed() {
            return Some("non-program archive member and all_files is false");
        }

        None
    }

    fn archive_member_yara_skip_reason(
        relative_path: &str,
        file_type: &FileType,
        size_bytes: usize,
    ) -> Option<&'static str> {
        // Skip the YARA pass for an unidentified member: with no bucket it
        // would scan with a `None` filter and hit EVERY tier, materializing all
        // per-filetype rule sets (the cold-start blow-up). Identified members
        // scan only their own label bucket plus fallback. The member's string /
        // trait / encoded-payload analysis still runs either way.
        if Self::archive_member_yara_filetypes(file_type).is_empty() {
            return Some("no targeted YARA tier for file type");
        }

        let lower_path = relative_path.to_ascii_lowercase();
        let file_name = Path::new(relative_path)
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or(relative_path)
            .to_ascii_lowercase();

        if lower_path.ends_with(".asar") {
            return Some("archive-like asar container");
        }

        // A YARA rule file *is* a list of the strings and hex patterns that YARA
        // rules search for, so scanning one with the YARA engine is guaranteed
        // self-detection: any packaged rule corpus lights up the third-party
        // tiers and reports the rule's own subject as a hostile hit. The
        // member's string/trait analysis still runs; only the YARA pass is
        // skipped. The traits side already handles the first-party half of this
        // via `metadata/file/extension/identity::yara-extension`.
        if lower_path.ends_with(".yar") || lower_path.ends_with(".yara") {
            return Some("YARA rule source");
        }

        if size_bytes >= 512 * 1024 && lower_path.ends_with(".map") {
            return Some("large source map");
        }

        let is_licenseish = file_name.starts_with("license")
            || file_name.starts_with("licenses")
            || file_name.starts_with("copying")
            || file_name.starts_with("notice");
        if size_bytes >= 128 * 1024
            && is_licenseish
            && matches!(
                file_type,
                FileType::Html | FileType::Markdown | FileType::Unknown
            )
        {
            return Some("large license/notice document");
        }

        None
    }

    fn archive_member_yara_filetypes(file_type: &FileType) -> Vec<&'static str> {
        file_type.yara_filetypes()
    }

    fn nested_archive_analyzer(&self, relative_path: &str) -> ArchiveAnalyzer {
        let nested_prefix = match &self.archive_path_prefix {
            Some(prefix) => format!("{}!{}", prefix, relative_path),
            None => relative_path.to_string(),
        };

        let mut nested = ArchiveAnalyzer::new()
            .with_depth(self.current_depth + 1)
            .with_archive_prefix(nested_prefix);
        nested.budget = self.budget.clone();

        nested = nested.with_engine(self.engine.clone());
        if let Some(ref engine) = self.yara_engine {
            nested = nested.with_yara_arc(engine.clone());
        }
        if !self.zip_passwords.is_empty() {
            nested = nested.with_zip_passwords_arc(self.zip_passwords.clone());
        }
        if let Some(ref flag) = self.cancelled {
            nested = nested.with_cancellation(flag.clone());
        }
        if let Some(ref opts) = self.analysis_options {
            nested = nested.with_analysis_options(opts.clone());
        }

        nested
    }

    /// Whether this archive's members should be analyzed in parallel.
    ///
    /// The top archive (`depth == 0`) fans its members across the rayon pool, so
    /// an idle scan worker steals member work via work-stealing — parallel when
    /// slots are free, effectively serial when they're not — which drains the
    /// long tail of a directory scan when only one big archive remains. Memory
    /// is not a reason to serialize here: a single top-level analysis has RAM to
    /// spare, and an embedding host bounds the memory of *concurrent* top-level analyses
    /// with its admission controller, not by streaming one member at a time.
    ///
    /// Nested archives (`depth >= 1`) fan out only
    /// for member-heavy batches: the most member-dense packages are
    /// containers in containers (src.rpm → tar, deb → data.tar), and a serial
    /// walk leaves one thread holding an indivisible chunk while the rest
    /// idle. Small nested archives (wheels, condas) stay serial, where fan-out
    /// costs more in scheduling and per-thread scanner caches than it saves.
    /// Work-stealing joins on the shared pool cannot deadlock, the `stacker`
    /// red zone absorbs stolen-frame stack growth, and the member window
    /// bounds in-flight bytes.
    fn members_run_parallel(&self, member_count: usize) -> bool {
        // When sibling top-level files are already occupying independent
        // blocking workers, keep each archive's member walk on that worker.
        // Letting every one of 24 top-level archives enqueue an ordered member
        // fan-out into the same Rayon pool recreates the same head-of-line
        // starvation that the trait/AC/YARA guard prevents: producers from
        // later archives occupy the pool while each archive waits for an early
        // member before it can drain. A single top-level analysis still gets
        // the full pool, including its large nested containers.
        if !crate::rayon_nest::inner_work_parallel() {
            return false;
        }
        if self.current_depth == 0 {
            return true;
        }
        member_count >= NESTED_PARALLEL_MIN_MEMBERS
    }

    /// Whether a member whose single-flight is busy may wait for the owner.
    ///
    /// Only when this thread holds nothing another thread's rayon join is
    /// waiting for: the member must be a top-level one executed directly by
    /// the archive's own lane thread, with no member analysis already on
    /// this thread's stack. A job that was stolen — a member, or a trait
    /// chunk that led here through a nested payload — sits on top of some
    /// owner's join; parking there while that owner waits for it is the
    /// wait cycle a process dump showed as a multi-minute stall (owners
    /// asleep in `wait_until_cold`, their halves under a waiting frame).
    fn member_may_wait(&self) -> bool {
        self.current_depth == 0
            && !crate::rayon_nest::on_isolated_leaf_pool()
            && MEMBER_ANALYSIS_DEPTH.with(std::cell::Cell::get) == 0
            && rayon::current_thread_index()
                .is_some_and(|t| t == self.lane_thread.load(std::sync::atomic::Ordering::Relaxed))
    }
}

#[cfg(test)]
mod tests;
