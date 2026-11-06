//! Scanning many paths: directory walks, file lists and their scheduling.

// Split out of the parent module for size; it shares the parent's namespace.
#[allow(clippy::wildcard_imports)]
use super::*;

/// An event emitted during [`scan_directory`].
#[derive(Debug)]
pub enum ScanEvent {
    /// Emitted exactly once before analysis begins.
    ///
    /// `total` is `None` because the scan streams the directory walk: analysis
    /// starts as soon as the first path is yielded, so the final count is not
    /// known upfront. The final count is available on `ScanSummary.total`
    /// returned from [`scan_directory`] once the scan completes.
    Start {
        /// Total number of files that will be analyzed, if known upfront.
        total: Option<usize>,
    },
    /// Emitted for each file as its analysis completes. May arrive from any rayon worker thread.
    File {
        /// Path to the analyzed file.
        path: std::path::PathBuf,
        /// Analysis result, or an error if analysis failed.
        result: Box<Result<AnalysisReport>>,
    },
}

/// Summary returned by [`scan_directory`] after all files have been processed.
#[derive(Debug, Clone, Default)]
pub struct ScanSummary {
    /// Total files submitted for analysis (passed the type filter).
    pub total: usize,
    /// Files successfully analyzed.
    pub analyzed: usize,
    /// Files that failed analysis.
    pub errors: usize,
}

/// Load the CapabilityMapper and YARA engine once for a parallel scan.
///
/// Both are wrapped in `Arc` so every rayon worker shares a single instance via
/// cheap clones rather than reloading per file. Shared by [`scan_directory`]
/// and [`scan_files`].
pub(super) fn load_scan_resources(options: &AnalysisOptions) -> Result<Engine> {
    // Surface this pre-pipeline step in the phase tracker. It runs before
    // `analyze_file_with_resources_at_depth` reaches its first `set_phase`.
    if let Some(ref tracker) = options.phase {
        tracker.set("cleave:resources");
    }
    // Both are process-wide caches after the first load: a warm call is a
    // lock read. This used to hand the two lookups to `rayon::join`, which
    // put the start of every analysis behind whatever the pool was busy with
    // — thirty-minute `cleave:resources` phases while one jar held every
    // worker. A cold load runs here, on the caller's own thread.
    shared_resources::engine_for_options(options)
}

/// Above this file count the work-list is left in directory order and the
/// largest-first sort is skipped: the sort needs one upfront `stat` per file
/// (the walk only yields `d_type`, not size), and on huge trees that serial
/// stat storm costs more than the tail-latency win it buys.
pub(super) const MAX_SORT_FILES: usize = 50_000;

/// Order a work-list largest-file-first for longest-processing-time-first
/// scheduling: per-file analysis cost rises with size, so dispatching the
/// largest binaries first overlaps them with the long tail of small files
/// instead of leaving one giant binary running alone on a single core at the
/// end of the scan. A no-op above [`MAX_SORT_FILES`] (see its rationale).
pub(super) fn sort_largest_first(paths: &mut [std::path::PathBuf]) {
    if paths.len() <= MAX_SORT_FILES {
        paths.sort_by_cached_key(|p| std::cmp::Reverse(scheduling_size(p)));
    }
}

/// The size that predicts a path's analysis cost: its length on disk, or
/// for a compressed container the larger of that and what it inflates to.
/// A 100 KB `.tgz` holding a 5 MB single-expression JavaScript bundle is
/// the most expensive path in a QA corpus by far, yet its compressed size
/// queued it behind 400 smaller files, so it started at t=50 s of a 100 s
/// scan and was the last to finish; an 18 KB zip around a 2.2 MB script did
/// the same at t=39 s of 52 s. gzip reports its uncompressed size in the
/// trailer (`ISIZE`, modulo 2^32); zip in each central-directory entry.
/// Only paths small enough to be worth the question are opened: a file this
/// size is cheap to inflate-probe, and above the cap the on-disk length
/// already ranks it near the front.
pub(super) fn scheduling_size(path: &std::path::Path) -> u64 {
    const PROBE_MAX_BYTES: u64 = 16 << 20;
    let on_disk = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
    if !(22..=PROBE_MAX_BYTES).contains(&on_disk) {
        return on_disk;
    }
    inflated_size(path, on_disk).map_or(on_disk, |n| n.max(on_disk))
}

/// What a gzip or zip at `path` inflates to, read from the gzip trailer
/// (`ISIZE`, modulo 2^32) or summed over the zip central directory; `None`
/// for any other container, an unreadable one, or one the directory walk
/// declines (see `zip_inflated_size`). Costs one open plus a tail read.
pub(super) fn inflated_size(path: &std::path::Path, on_disk: u64) -> Option<u64> {
    use std::io::{Read, Seek, SeekFrom};
    if on_disk < 22 {
        return None;
    }
    let mut file = std::fs::File::open(path).ok()?;
    let mut magic = [0u8; 4];
    file.read_exact(&mut magic).ok()?;
    match magic {
        [0x1f, 0x8b, _, _] => {
            file.seek(SeekFrom::End(-4)).ok()?;
            let mut trailer = [0u8; 4];
            file.read_exact(&mut trailer).ok()?;
            Some(u64::from(u32::from_le_bytes(trailer)))
        }
        [b'P', b'K', 3, 4] => zip_inflated_size(&mut file, on_disk),
        [b'M', b'S', b'C', b'F'] => cab_inflated_size(&mut file, on_disk),
        _ => None,
    }
}

/// Sum of the uncompressed sizes a cabinet's CFFILE table records. A 23 KB
/// `.cab` around one 826 KB script cost 15 CPU-seconds yet queued by its
/// on-disk size behind every larger file, starting at t=75 s of an 80 s
/// hostile-corpus scan and finishing last. `None` for a truncated header or
/// table, or more entries than are worth reading for a scheduling hint.
pub(super) fn cab_inflated_size(file: &mut std::fs::File, on_disk: u64) -> Option<u64> {
    use std::io::{Read, Seek, SeekFrom};
    const HEADER_LEN: usize = 36;
    const MAX_FILES: usize = 20_000;
    // CFFILE: cbFile u32, uoffFolderStart u32, iFolder u16, date u16, time u16,
    // attribs u16, then a NUL-terminated name of at most 256 bytes.
    const MAX_ENTRY_LEN: usize = 16 + 257;
    file.seek(SeekFrom::Start(0)).ok()?;
    let mut header = [0u8; HEADER_LEN];
    file.read_exact(&mut header).ok()?;
    let u16_at = |at: usize| u16::from_le_bytes([header[at], header[at + 1]]);
    let files_offset = u64::from(u32::from_le_bytes([
        header[16], header[17], header[18], header[19],
    ]));
    let entries = usize::from(u16_at(28));
    if entries == 0 || entries > MAX_FILES || files_offset >= on_disk {
        return None;
    }
    let table_len = (entries * MAX_ENTRY_LEN).min(usize::try_from(on_disk - files_offset).ok()?);
    file.seek(SeekFrom::Start(files_offset)).ok()?;
    let mut table = vec![0u8; table_len];
    file.read_exact(&mut table).ok()?;
    let mut at = 0usize;
    let mut total = 0u64;
    for _ in 0..entries {
        let size = table.get(at..at + 4)?;
        total = total.saturating_add(u64::from(u32::from_le_bytes([
            size[0], size[1], size[2], size[3],
        ])));
        let name_start = at + 16;
        let name_len = memchr::memchr(0, table.get(name_start..)?)?;
        at = name_start + name_len + 1;
    }
    Some(total)
}

/// What the memory gate can learn about `path` from its magic alone: that
/// it is a flat image — an executable (PE, ELF, Mach-O) or an OLE compound
/// file (MSI) — whose footprint tracks its own size rather than an unknown
/// container expansion. Anything else, an unreadable file included, stays
/// `Unknown`.
pub(super) fn footprint_hint(path: &std::path::Path) -> scan_mem_gate::FootprintHint {
    use scan_mem_gate::FootprintHint;
    use std::io::Read;
    let mut magic = [0u8; 8];
    let read = std::fs::File::open(path).and_then(|mut f| f.read_exact(&mut magic));
    if read.is_err() {
        return FootprintHint::Unknown;
    }
    match magic {
        [b'M', b'Z', ..]
        | [0x7f, b'E', b'L', b'F', ..]
        | [0xfe, 0xed, 0xfa, 0xce | 0xcf, ..]
        | [0xce | 0xcf, 0xfa, 0xed, 0xfe, ..]
        | [0xca, 0xfe, 0xba, 0xbe, ..]
        | [0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1] => FootprintHint::Flat,
        _ => FootprintHint::Unknown,
    }
}

/// Sum of the uncompressed sizes a zip's central directory records. `None`
/// for a zip64 directory, a truncated one, or one with more entries than
/// are worth walking for a scheduling hint; the on-disk size then stands.
pub(super) fn zip_inflated_size(file: &mut std::fs::File, on_disk: u64) -> Option<u64> {
    use std::io::{Read, Seek, SeekFrom};
    const EOCD_MIN: u64 = 22;
    const EOCD_SEARCH_MAX: u64 = EOCD_MIN + 0xFFFF;
    const MAX_ENTRIES: usize = 20_000;
    let tail_len = on_disk.min(EOCD_SEARCH_MAX);
    file.seek(SeekFrom::End(-(tail_len as i64))).ok()?;
    let mut tail = vec![0u8; tail_len as usize];
    file.read_exact(&mut tail).ok()?;
    let eocd = tail
        .windows(4)
        .rposition(|w| w == [b'P', b'K', 5, 6])
        .filter(|&at| at + 22 <= tail.len())?;
    let u16_at = |at: usize| u16::from_le_bytes([tail[at], tail[at + 1]]);
    let u32_at =
        |at: usize| u32::from_le_bytes([tail[at], tail[at + 1], tail[at + 2], tail[at + 3]]);
    let entries = usize::from(u16_at(eocd + 10));
    let dir_len = u64::from(u32_at(eocd + 12));
    let dir_offset = u64::from(u32_at(eocd + 16));
    if entries == 0 || entries > MAX_ENTRIES || entries == 0xFFFF || dir_offset == 0xFFFF_FFFF {
        return None;
    }
    if dir_offset.checked_add(dir_len)? > on_disk {
        return None;
    }
    file.seek(SeekFrom::Start(dir_offset)).ok()?;
    let mut dir = vec![0u8; usize::try_from(dir_len).ok()?];
    file.read_exact(&mut dir).ok()?;
    let mut at = 0usize;
    let mut total = 0u64;
    for _ in 0..entries {
        if at + 46 > dir.len() || dir[at..at + 4] != [b'P', b'K', 1, 2] {
            return None;
        }
        let field32 = |o: usize| {
            u32::from_le_bytes([
                dir[at + o],
                dir[at + o + 1],
                dir[at + o + 2],
                dir[at + o + 3],
            ])
        };
        let field16 = |o: usize| u16::from_le_bytes([dir[at + o], dir[at + o + 1]]);
        let uncompressed = field32(24);
        if uncompressed == 0xFFFF_FFFF {
            return None;
        }
        total = total.saturating_add(u64::from(uncompressed));
        at += 46 + usize::from(field16(28)) + usize::from(field16(30)) + usize::from(field16(32));
    }
    Some(total)
}

/// Run `f` over `paths` on the rayon pool, admitting them strictly in
/// order: one worker per pool thread pulls the next index from a shared
/// counter.
///
/// `paths.into_par_iter().for_each` looks like the same thing but is not:
/// rayon splits the vector in halves as work is stolen, so the sixteen
/// jobs that start first are indices 0, 256, 128, 384, … and index 2 — the
/// third-largest archive after `sort_largest_first` — waits behind a
/// sequential run of its first-half chunk. Measured on a 510-archive npm
/// corpus: an 11 MB installer that costs 40 CPU-seconds began at t=42 s of
/// a 55 s scan and was the last file to finish. Nested member parallelism
/// is unaffected: it is stolen by whichever pull-loop thread is idle
/// exactly as before.
pub(super) fn for_each_ordered<T, F>(items: &[T], f: &F)
where
    T: Sync,
    F: Fn(&T) + Sync,
{
    use rayon::prelude::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    if items.len() <= 1 {
        for item in items {
            f(item);
        }
        return;
    }
    let next = AtomicUsize::new(0);
    // `CLEAVE_SCAN_LANES=N` (experiment): admit paths on N lanes and leave
    // the other pool threads free to steal inner work (whale member and
    // trait chunks) for the whole scan.
    let lanes = crate::env::parse::<usize>("CLEAVE_SCAN_LANES")
        .filter(|&n| n > 0)
        .unwrap_or_else(rayon::current_num_threads)
        .max(1)
        .min(items.len());
    let pending = crate::rayon_nest::PendingPaths::new(items.len());
    let pull = || -> bool {
        let i = next.fetch_add(1, Ordering::Relaxed);
        let Some(item) = items.get(i) else {
            return false;
        };
        pending.admit();
        f(item);
        true
    };
    let started = AtomicUsize::new(0);
    (0..lanes).into_par_iter().for_each(|_| {
        // A lane that finds a member's analysis already in flight on another
        // thread (seven archives carrying one 10 MB bundle start in the same
        // wave) pulls the next path from this queue instead of idling until
        // the owner finishes — see `ReportFlight::wait_yielding`.
        crate::rayon_nest::with_wait_work(&pull, || {
            started.fetch_add(1, Ordering::AcqRel);
            loop {
                // Once every lane runs (no lane job is left in any queue to be
                // stolen and nested), finish inner work already in flight — a
                // whale's member and trait chunks — before admitting another
                // path. A 45 CPU-second bundle otherwise runs on its lane alone
                // while sixteen lanes stay busy with paths that could wait.
                if started.load(Ordering::Acquire) >= lanes {
                    while rayon::yield_now() == Some(rayon::Yield::Executed) {}
                }
                if !pull() {
                    break;
                }
            }
        });
    });
}

/// Analyze a single already-discovered file under the shared scan pipeline:
/// honor cancellation, gate concurrent memory, apply the size and program-type
/// filters (unless `all_files`), then analyze and deliver the result through
/// `callback`. A caught analyzer panic surfaces as a [`ScanEvent::File`] with an
/// `Err` rather than poisoning the rayon pool.
///
/// Shared by [`scan_directory`], [`scan_paths`] and [`scan_files`] so all three
/// tally and report identically — they differ only in how the path list is
/// produced and whether the filters apply.
#[allow(clippy::too_many_arguments)]
pub(super) fn analyze_one_path<F>(
    file_path: &Path,
    options: &AnalysisOptions,
    engine: &Engine,
    all_files: bool,
    max_scan_size: u64,
    mem_gate: &scan_mem_gate::ScanMemGate,
    analyzed: &std::sync::atomic::AtomicUsize,
    skipped: &std::sync::atomic::AtomicUsize,
    errors: &std::sync::atomic::AtomicUsize,
    callback: &F,
) where
    F: Fn(ScanEvent) + Sync,
{
    use std::sync::atomic::Ordering;

    // Cancellation fast path: once SIGINT has flipped the flag, every remaining
    // slot returns instantly so the scan drains work already in-flight rather
    // than starting new files. Inner analyzers (YARA, tree-sitter) also
    // observe the flag via options.cancellation for sub-file granularity.
    if options
        .cancellation
        .as_ref()
        .is_some_and(|c| c.load(Ordering::Relaxed))
    {
        skipped.fetch_add(1, Ordering::Relaxed);
        return;
    }

    // Bound concurrent memory: a burst of large archives serialises instead of
    // co-residing and OOM-killing the host. Held until this file is done.
    let file_len = std::fs::metadata(file_path).map(|m| m.len()).unwrap_or(0);
    let gate_wait = std::time::Instant::now();
    let _mem_permit = mem_gate.acquire_hinted(file_len, footprint_hint(file_path));
    let gate_wait_ms = gate_wait.elapsed().as_millis() as u64;
    let started = std::time::Instant::now();

    // Catch panics from any analyzer so one malformed file doesn't poison the
    // rayon thread pool and kill the entire scan.
    let panic_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        // Skip files exceeding the size limit (avoids mmap'ing huge ISOs/disk images).
        if max_scan_size > 0
            && let Ok(meta) = std::fs::metadata(file_path)
            && meta.len() > max_scan_size
        {
            tracing::debug!(
                path = %file_path.display(),
                size_mb = meta.len() / (1024 * 1024),
                limit_mb = max_scan_size / (1024 * 1024),
                "skipping file exceeding the directory-scan size limit"
            );
            skipped.fetch_add(1, Ordering::Relaxed);
            return;
        }

        // File-type filtering: read the file once and check type from loaded
        // data, then hand the same bytes to the analyzer to avoid a second read.
        if !all_files {
            let Ok(file_data) = file_io::read_file_smart(file_path) else {
                tracing::debug!(path = %file_path.display(), "Skipping unreadable file");
                skipped.fetch_add(1, Ordering::Relaxed);
                return;
            };
            let ft = analyzers::detect_file_type_from_data(file_path, file_data.as_slice());
            if !analyzers::is_analyzable(file_path, &ft) {
                tracing::debug!(path = %file_path.display(), file_type = ?ft, "Skipping non-analyzable file");
                skipped.fetch_add(1, Ordering::Relaxed);
                return;
            }
            let result =
                analyze_file_with_engine(file_path, options, engine, Some(file_data), None);
            match &result {
                Ok(_) => {
                    analyzed.fetch_add(1, Ordering::Relaxed);
                }
                Err(_) => {
                    errors.fetch_add(1, Ordering::Relaxed);
                }
            }
            callback(ScanEvent::File {
                path: file_path.to_path_buf(),
                result: Box::new(result),
            });
            // Release wasmtime Scanner VMs on this thread to prevent non-jemalloc
            // memory accumulation. Each Scanner holds mmap'd VM regions
            // (~50-100MB) that macOS keeps resident even after munmap (MADV_FREE).
            composite_rules::evaluators::clear_thread_local_caches();
            return;
        }

        let result = analyze_file_with_engine(file_path, options, engine, None, None);
        match &result {
            Ok(_) => {
                analyzed.fetch_add(1, Ordering::Relaxed);
            }
            Err(_) => {
                errors.fetch_add(1, Ordering::Relaxed);
            }
        }
        callback(ScanEvent::File {
            path: file_path.to_path_buf(),
            result: Box::new(result),
        });
        composite_rules::evaluators::clear_thread_local_caches();
    }));
    // One line per top-level path: where a directory scan's wall clock went
    // (`RUST_LOG=cleave=info`). `gate_wait_ms` is time spent queued on the
    // memory gate before analysis began.
    static SCAN_EPOCH: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();
    let epoch = *SCAN_EPOCH.get_or_init(|| started);
    tracing::info!(
        path = %file_path.display(),
        size = file_len,
        gate_wait_ms,
        start_ms = started.duration_since(epoch).as_millis() as u64,
        elapsed_ms = started.elapsed().as_millis() as u64,
        "path analyzed"
    );
    if panic_result.is_err() {
        tracing::error!(path = %file_path.display(), "panic during file analysis (caught)");
        errors.fetch_add(1, Ordering::Relaxed);
        callback(ScanEvent::File {
            path: file_path.to_path_buf(),
            result: Box::new(Err(anyhow::anyhow!("analysis panicked"))),
        });
    }
}

/// Scan a directory, invoking `callback` for each file as its analysis completes.
///
/// Results stream out of the parallel workers as they finish rather than being
/// collected into a `Vec`. This makes it suitable for progress reporting,
/// streaming output, and processing large directories without accumulating all
/// results in memory — the only viable entry point at 10M-file scale.
///
/// The callback first receives a [`ScanEvent::Start`] with the total file count,
/// then a [`ScanEvent::File`] for every file attempted, including failures. The
/// `Start` event is always delivered before any `File` events.
///
/// Resources (CapabilityMapper and YARA engine) are loaded once and shared across
/// all parallel workers, avoiding the per-file reload overhead of calling
/// [`analyze_file`] in a loop.
///
/// Hidden files and non-program file types are silently skipped unless
/// `options.all_files` is set.
///
/// # Errors
///
/// Returns `Err` only for setup failures (path is not a directory, resource load
/// failure). Per-file errors are delivered through the callback as
/// [`ScanEvent::File`] with an `Err` result.
pub fn scan_directory<P, F>(path: P, options: &AnalysisOptions, callback: F) -> Result<ScanSummary>
where
    P: AsRef<Path>,
    F: Fn(ScanEvent) + Sync,
{
    use std::sync::atomic::{AtomicUsize, Ordering};
    use walkdir::WalkDir;

    let path = path.as_ref();
    if !path.is_dir() {
        anyhow::bail!("path is not a directory: {}", path.display());
    }

    // Maintain the filefacts disk cache (which holds binform's recovery) in
    // the background: prune old schema versions, evict past the item cap,
    // and retire the legacy `re/` tree. Self-detaching, so it never blocks
    // startup.
    cache::maintain_filefacts_cache();

    // Load shared resources once; all rayon workers share them via cheap Arc clones.
    let engine = load_scan_resources(options)?;

    let all_files_flag = options.all_files;

    // Counters shared across the walk producer and analyzer consumers.
    // The walk runs inside `par_bridge`, which serializes `next()` across
    // worker threads, so these are touched from multiple threads (one at a
    // time inside the bridge's mutex). Atomic fetch_add is still the right
    // primitive — it's what the Drop-time summary and ScanSummary read.
    let walked = AtomicUsize::new(0);
    let walk_errors = AtomicUsize::new(0);
    let dirs_entered = AtomicUsize::new(0);

    // Total is not known until the walk finishes. Downstream progress UIs
    // should listen for the final count on the returned ScanSummary.
    callback(ScanEvent::Start { total: None });

    let analyzed = AtomicUsize::new(0);
    let skipped = AtomicUsize::new(0);
    let errors = AtomicUsize::new(0);

    let max_scan_size = options.max_scan_file_size;

    let analyze_files = || {
        // Collect the work-list up front, then dispatch with indexed
        // work-stealing (`into_par_iter`). The previous `par_bridge()` drove
        // `next()` from worker threads behind an internal mutex; profiling a
        // directory of binaries showed rayon workers parked ~1/3 of wall time
        // (`Sleep::sleep <- WorkerThread::wait_until_cold <- bridge_unindexed`)
        // because that mutex serialized hand-off faster than workers drained
        // it. A materialized Vec removes the mutex and, for trees small enough
        // to sort, lets us order work largest-first. Collecting the paths costs
        // ~100 bytes each — negligible even for the 200k-file trees — so the
        // streaming-to-bound-memory rationale no longer outweighs the stall.
        let mut paths: Vec<std::path::PathBuf> = WalkDir::new(path)
            .follow_links(false)
            .into_iter()
            // Skip only the object store, a directory named exactly `.git`. A
            // `.git` prefix also hid `.github/workflows`, `.gitlab-ci.yml`,
            // `.gitmodules` and `.gitattributes` (filter drivers), which is
            // where a supply-chain change to CI lands.
            .filter_entry(|e| {
                let object_store = e.file_type().is_dir() && e.file_name() == ".git";
                if object_store {
                    tracing::debug!(path = %e.path().display(), "Skipping .git directory");
                }
                !object_store
            })
            .filter_map(|entry| match entry {
                Ok(e) => Some(e),
                Err(e) => {
                    walk_errors.fetch_add(1, Ordering::Relaxed);
                    tracing::warn!(error = %e, "Failed to read directory entry");
                    None
                }
            })
            .filter(|e| {
                if e.file_type().is_dir() {
                    dirs_entered.fetch_add(1, Ordering::Relaxed);
                    return false;
                }
                if !e.file_type().is_file() {
                    tracing::debug!(path = %e.path().display(), "Skipping non-file entry");
                    return false;
                }
                walked.fetch_add(1, Ordering::Relaxed);
                true
            })
            .map(|e| e.path().to_path_buf())
            .collect();

        sort_largest_first(&mut paths);

        let mem_gate = scan_mem_gate::ScanMemGate::new();
        for_each_ordered(&paths, &|file_path: &std::path::PathBuf| {
            analyze_one_path(
                file_path,
                options,
                &engine,
                all_files_flag,
                max_scan_size,
                &mem_gate,
                &analyzed,
                &skipped,
                &errors,
                &callback,
            );
        });
    };

    crate::mem_profile::start_sampler();
    analyze_files();

    crate::mem_profile::report_scan_stats();
    crate::composite_rules::evaluators::log_regex_cache_stats();
    crate::analysis_cache::log_analysis_memo_stats();

    let total = walked.load(Ordering::Relaxed);
    let final_analyzed = analyzed.load(Ordering::Relaxed);
    let final_skipped = skipped.load(Ordering::Relaxed);
    let final_errors = errors.load(Ordering::Relaxed);
    tracing::info!(
        walked = total,
        dirs = dirs_entered.load(Ordering::Relaxed),
        walk_errors = walk_errors.load(Ordering::Relaxed),
        analyzed = final_analyzed,
        skipped = final_skipped,
        errors = final_errors,
        "Directory scan complete"
    );

    Ok(ScanSummary {
        total,
        analyzed: final_analyzed,
        errors: final_errors,
    })
}

/// Analyze a caller-supplied list of already-discovered file paths under the
/// same pipeline as [`scan_directory`] — the program-type and size filters are
/// applied and non-analyzable files are silently skipped — but without walking a
/// directory. The caller owns discovery (typically its own `walkdir` pass),
/// which lets it report the total file count to a progress UI before analysis
/// starts: `ScanEvent::Start` carries `Some(paths.len())`, whereas the streamed
/// [`scan_directory`] walk reports `None` because its total is known only once
/// the walk finishes.
///
/// This is distinct from [`scan_files`], which analyzes every path exactly as
/// given (no program-type or size filter) for explicitly-named files. Use
/// `scan_paths` when the paths came from a directory traversal and should be
/// filtered as if `scan_directory` had walked them itself.
///
/// Resources (CapabilityMapper and YARA engine) are loaded once and shared
/// across workers; results stream through `callback` as each file completes, in
/// size-descending order (longest-processing-time-first scheduling).
///
/// # Errors
///
/// Returns `Err` only for setup failures (resource load). Per-file errors,
/// including caught panics, are delivered through the callback as a
/// [`ScanEvent::File`] carrying an `Err` result.
pub fn scan_paths<F>(
    paths: Vec<std::path::PathBuf>,
    options: &AnalysisOptions,
    callback: F,
) -> Result<ScanSummary>
where
    F: Fn(ScanEvent) + Sync,
{
    scan_list(paths, options, true, callback)
}

/// Analyze an explicit set of file paths in parallel, invoking `callback` for
/// each as its analysis completes.
///
/// This is the multi-file analog of [`scan_directory`]: the CapabilityMapper and
/// YARA engine are loaded once and shared across all rayon workers, and results
/// stream out through the callback under the same [`ScanEvent`] contract — minus
/// the directory walk. `ScanEvent::Start` carries the path count, which is known
/// upfront here (unlike the streamed directory walk).
///
/// Unlike [`scan_directory`], paths are analyzed exactly as given: directories
/// are not recursed (a directory path surfaces as a `ScanEvent::File` error),
/// and the program-type and size filters are not applied — an explicitly named
/// file is always analyzed. Use [`scan_directory`] to recurse a tree. Otherwise
/// it is [`scan_paths`]: same ordering, memory gate, and cache maintenance.
///
/// # Errors
///
/// Returns `Err` only for setup failures (resource load). Per-file errors,
/// including caught panics, are delivered through the callback as a
/// [`ScanEvent::File`] carrying an `Err` result.
pub fn scan_files<F>(
    paths: &[std::path::PathBuf],
    options: &AnalysisOptions,
    callback: F,
) -> Result<ScanSummary>
where
    F: Fn(ScanEvent) + Sync,
{
    scan_list(paths.to_vec(), options, false, callback)
}

/// The pipeline behind [`scan_paths`] and [`scan_files`]. `filtered` applies
/// the size and program-type filters a directory walk would (honoring
/// `options.all_files`); unfiltered lists analyze every path as given.
pub(super) fn scan_list<F>(
    mut paths: Vec<std::path::PathBuf>,
    options: &AnalysisOptions,
    filtered: bool,
    callback: F,
) -> Result<ScanSummary>
where
    F: Fn(ScanEvent) + Sync,
{
    use std::sync::atomic::{AtomicUsize, Ordering};

    // Maintain the filefacts disk cache in the background, exactly as
    // scan_directory does.
    cache::maintain_filefacts_cache();

    let engine = load_scan_resources(options)?;

    let total = paths.len();
    // Total is known upfront here (the caller already enumerated the paths), so
    // a progress UI can render a determinate bar from the first File event.
    callback(ScanEvent::Start { total: Some(total) });

    let analyzed = AtomicUsize::new(0);
    let skipped = AtomicUsize::new(0);
    let errors = AtomicUsize::new(0);
    let (all_files, max_scan_size) = if filtered {
        (options.all_files, options.max_scan_file_size)
    } else {
        (true, 0)
    };

    sort_largest_first(&mut paths);

    crate::mem_profile::start_sampler();
    let mem_gate = scan_mem_gate::ScanMemGate::new();
    for_each_ordered(&paths, &|file_path: &std::path::PathBuf| {
        analyze_one_path(
            file_path,
            options,
            &engine,
            all_files,
            max_scan_size,
            &mem_gate,
            &analyzed,
            &skipped,
            &errors,
            &callback,
        );
    });
    crate::mem_profile::report_scan_stats();
    crate::composite_rules::evaluators::log_regex_cache_stats();
    crate::analysis_cache::log_analysis_memo_stats();

    let final_analyzed = analyzed.load(Ordering::Relaxed);
    let final_skipped = skipped.load(Ordering::Relaxed);
    let final_errors = errors.load(Ordering::Relaxed);
    tracing::info!(
        provided = total,
        filtered,
        analyzed = final_analyzed,
        skipped = final_skipped,
        errors = final_errors,
        "Path-list scan complete"
    );

    Ok(ScanSummary {
        total,
        analyzed: final_analyzed,
        errors: final_errors,
    })
}
