//! Archive analyzers that extract to a temporary directory: PyInstaller, JAR and generic archives.

// Split out of the parent module for size; it shares the parent's namespace.
#[allow(clippy::wildcard_imports)]
use super::*;

impl ArchiveAnalyzer {
    /// Analyze a PyInstaller-bundled executable entirely in memory. Decodes
    /// every CArchive entry and PYZ contents via `unpack::pyinstaller`, then
    /// feeds each as a [`MemoryArchiveMember`] into the same per-member
    /// pipeline used for ZIP archives.
    pub(in super::super) fn analyze_pyinstaller_archive_in_memory(
        &self,
        data: &[u8],
        archive_path: &Path,
        report: &mut AnalysisReport,
        start: std::time::Instant,
    ) -> Result<()> {
        let mem = unpack::pyinstaller::extract_to_memory(data)
            .map_err(|e| anyhow::anyhow!("PyInstaller extract: {e}"))?;

        let members: Vec<MemoryArchiveMember> = mem
            .entries
            .into_iter()
            .map(|entry| {
                let logical = Path::new(&entry.name);
                let file_type = crate::analyzers::detect_file_type_from_data(logical, &entry.data);
                let sha256 = calculate_sha256(&entry.data);
                MemoryArchiveMember {
                    relative_path: entry.name,
                    data: entry.data.into(),
                    file_type,
                    sha256,
                    container_kind: Some(pyinstaller_entry_kind(entry.kind).to_string()),
                }
            })
            .collect();

        let mut pyarmor = pyarmor_members::Collector::default();
        for member in &members {
            pyarmor.observe(member);
        }
        let mut members = members;
        members.extend(pyarmor.recover(
            |message| {
                report
                    .analysis_gaps
                    .record(crate::types::AnalysisGap::EmbeddedSourceIncomplete);
                report.metadata.errors.push(message);
            },
            || self.is_cancelled(),
        ));

        self.analyze_in_memory_members(
            members,
            archive_path,
            report,
            start,
            "PyInstaller archive",
            "memory PyInstaller",
            vec!["archive_analyzer".to_string(), "pyinstx".to_string()],
        );

        // The interpreter version is filefacts' `binary.installer.python_version`.
        Ok(())
    }

    /// Analyze JAR-like archives (JAR, WAR, EAR, APK, AAR) with optimized class file handling.
    ///
    /// JAR analysis is optimized with a three-phase approach:
    /// 1. YARA scan ALL .class files in parallel (fast)
    /// 2. Full analysis on interesting classes (main class, YARA-flagged, sample)
    /// 3. Analyze non-class files (scripts, configs, manifests)
    ///
    /// This avoids full decompilation of thousands of benign library classes while
    /// ensuring suspicious classes are thoroughly analyzed.
    ///
    /// # Arguments
    /// * `temp_dir` - Extracted archive directory
    /// * `report` - Mutable report to aggregate findings into
    /// * `start` - Analysis start time for duration tracking
    pub(in super::super) fn analyze_jar_archive(
        &self,
        temp_dir: &Path,
        report: &mut AnalysisReport,
        start: std::time::Instant,
    ) {
        // Find main class from MANIFEST.MF
        let main_class = find_main_class(temp_dir);
        if let Some(ref mc) = main_class {
            debug!("Main-Class: {}", mc);
        }

        // `jar.*` kv comes from filefacts's dual emission in the
        // capability mapper — no temp-dir walk needed here.

        // Collect all files
        let all_files = extracted_files(temp_dir, report);

        // Separate class files from non-class files
        let (class_files, other_files): (Vec<_>, Vec<_>) = all_files
            .into_iter()
            .partition(|e| e.path().extension().is_some_and(|ext| ext == "class"));

        let total_class_files = class_files.len();
        debug!("Found {} .class files", total_class_files);

        // Phase 1: score every class and optionally run class-bucket YARA in
        // the same read, so salience ranking does not add a second archive walk.
        let yara_start = std::time::Instant::now();
        let triage_results =
            self.triage_jar_classes(self.yara_engine.as_deref(), &class_files, |entry| {
                match std::fs::read(entry.path()) {
                    Ok(data) => Some(std::borrow::Cow::Owned(data)),
                    Err(e) => {
                        debug!("Failed to read {}: {}", entry.path().display(), e);
                        None
                    }
                }
            });
        debug!(
            "JAR class triage completed in {:.2}s",
            yara_start.elapsed().as_secs_f64()
        );

        let mut flagged_classes = HashSet::new();
        let mut collected_yara_matches = Vec::with_capacity(50);
        let mut class_scores = vec![0usize; class_files.len()];
        for triage in triage_results {
            class_scores[triage.index] = triage.score;
            if triage.retain {
                flagged_classes.insert(class_files[triage.index].path().to_path_buf());
            }
            for ym in triage.matches {
                if !collected_yara_matches
                    .iter()
                    .any(|m: &YaraMatch| m.rule == ym.rule)
                {
                    collected_yara_matches.push(ym);
                }
            }
        }

        // Add collected YARA matches to report
        for ym in collected_yara_matches {
            if !report.yara_matches.iter().any(|m| m.rule == ym.rule) {
                report.yara_matches.push(ym);
            }
        }

        debug!("{} classes flagged by YARA", flagged_classes.len());

        // Phase 2: Run full JavaClassAnalyzer only on interesting classes
        // - Main class
        // - YARA-flagged classes
        // - A sample ranked by salient APIs. A package name is chosen by
        //   whoever built the jar, so a library-looking one earns no pass.
        let interesting_classes: Vec<_> = class_files
            .iter()
            .filter(|e| {
                let path = e.path();
                let path_str = path.to_string_lossy();

                // Always analyze main class
                if let Some(ref mc) = main_class {
                    let class_path = mc.replace('.', "/") + ".class";
                    if path_str.ends_with(&class_path) {
                        return true;
                    }
                }

                // Always analyze YARA-flagged classes; the rest compete
                // for the ranked sample below.
                flagged_classes.contains(path)
            })
            .collect();

        // Also include a bounded sample of non-flagged classes,
        // prioritizing classes with salient APIs rather than attacker-controlled
        // archive order. Exclude main/YARA classes already selected.
        let interesting_paths: HashSet<&Path> = interesting_classes
            .iter()
            .map(|entry| entry.path())
            .collect();
        let mut sample_classes: Vec<(usize, u64, _)> = class_files
            .iter()
            .enumerate()
            .filter(|(_, entry)| !interesting_paths.contains(entry.path()))
            .map(|(index, entry)| {
                let len = entry.metadata().map_or(0, |meta| meta.len());
                (index, len, entry)
            })
            .collect();
        keep_top_ranked(
            &mut sample_classes,
            20,
            |(left_idx, left_len, left), (right_idx, right_len, right)| {
                class_scores[*right_idx]
                    .cmp(&class_scores[*left_idx])
                    .then_with(|| right_len.cmp(left_len))
                    .then_with(|| left.path().cmp(right.path()))
            },
        );

        let mut classes_to_analyze: Vec<_> = interesting_classes
            .into_iter()
            .chain(sample_classes.into_iter().map(|(_, _, entry)| entry))
            .collect();
        let class_paths: Vec<String> = class_files
            .iter()
            .map(|entry| posix_relative_path(entry.path(), temp_dir))
            .collect();
        let selected_paths: Vec<String> = classes_to_analyze
            .iter()
            .map(|entry| posix_relative_path(entry.path(), temp_dir))
            .collect();
        let companions =
            jar_nest_companion_indices(&class_paths, selected_paths.iter().map(String::as_str));
        classes_to_analyze.extend(companions.into_iter().map(|index| &class_files[index]));

        debug!("Full analysis on {} classes", classes_to_analyze.len());

        // Run full analysis on selected classes and stream completed results
        // into one accumulator. The class and non-class phases share it so the
        // JAR's tallies span every analyzed member without retaining both full
        // result vectors until the end.
        let expected_count = classes_to_analyze.len();
        let mut acc = MemberAccumulator::default();

        let members_done = std::sync::atomic::AtomicUsize::new(0);
        let last_progress_ms = AtomicU64::new(0);
        let jar_display = self
            .archive_path_prefix
            .as_deref()
            .unwrap_or(report.target.path.as_str());

        par_filter_fold_members(
            &classes_to_analyze,
            self.members_run_parallel(classes_to_analyze.len()),
            |_| None,
            |entry| {
                let _thread_local_cache_clear_guard = ThreadLocalCacheClearGuard;
                if self.is_cancelled() {
                    return None;
                }
                let relative_path = posix_relative_path(entry.path(), temp_dir);
                let entry_path = self.format_entry_path(&relative_path);
                let archive_location = self.format_evidence_location(&relative_path);

                // Map large members instead of reading them. This closure runs
                // on every rayon worker at once and nothing bounds how much
                // member data is resident here — unlike the in-memory path,
                // which meters itself through `member_window_bytes`. A read is
                // anonymous dirty memory the kernel cannot reclaim, and
                // installers carry members far larger than that budget (see
                // MEMORY_EXPERIMENTS.md: one sample held ~1.4 GB of member
                // `Vec<u8>` live at once). `read_file_smart` maps above 10 MiB
                // and reads smaller members inline; it does NOT normalize
                // encoding, so the bytes — and with them the sha256 and the
                // detected type — are identical to the previous `fs::read`.
                let member_data = {
                    let _extract = crate::mem_profile::phase(crate::mem_profile::Phase::Extract);
                    match crate::file_io::read_file_smart(entry.path()) {
                        Ok(data) => data,
                        Err(e) => {
                            debug!("Failed to read archive member {}: {}", entry_path, e);
                            return None;
                        }
                    }
                };
                let file_data: &[u8] = member_data.as_slice();
                let file_type =
                    crate::analyzers::detect_file_type_from_data(entry.path(), file_data);
                let sha256 = calculate_sha256(file_data);

                let entry_metadata = archive_entry_metadata(
                    entry_path.clone(),
                    &file_type,
                    sha256.clone(),
                    file_data,
                    None,
                );

                let member_start = std::time::Instant::now();

                let _analyze = crate::mem_profile::phase(crate::mem_profile::Phase::Analyze);
                let report = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    self.analyze_extracted_member(
                        entry.path(),
                        &relative_path,
                        file_data,
                        &file_type,
                        &sha256,
                    )
                })) {
                    Ok(Ok(Some(mut r))) => {
                        // Matching is done; drop the fields nothing downstream
                        // reads so they don't pile up across the archive's
                        // members — the same release the windowed member path
                        // performs. These disk-walk paths never did, so every
                        // member of a jar/generic archive kept its traits,
                        // strings, structure, YARA matches, syscalls, paths,
                        // directories and env vars live until the whole scan
                        // finished (57 857 members on the MiniMax sample).
                        r.clear_unserialized_member_fields();
                        Some(r)
                    }
                    Ok(Ok(None)) => None,
                    Ok(Err(e)) => {
                        debug!("Failed to analyze archive member {}: {}", entry_path, e);
                        None
                    }
                    Err(_panic) => {
                        tracing::error!(
                            path = %entry_path,
                            "panic during archive member analysis (caught)"
                        );
                        FAILED_ANALYSES.fetch_add(1, Ordering::Relaxed);
                        None
                    }
                };

                let member_elapsed = member_start.elapsed();
                tracing::debug!(
                    relative_path,
                    file_type = %file_type.report_file_type(),
                    size_bytes = file_data.len(),
                    elapsed_ms = member_elapsed.as_millis() as u64,
                    rayon_thread = ?rayon::current_thread_index(),
                    "archive member timing",
                );
                if member_elapsed.as_millis() > SLOW_ARCHIVE_MEMBER_ANALYSIS_MS {
                    tracing::warn!(
                        relative_path,
                        file_type = %file_type.report_file_type(),
                        size_bytes = file_data.len(),
                        elapsed_ms = member_elapsed.as_millis() as u64,
                        rayon_thread = ?rayon::current_thread_index(),
                        "Slow archive member analysis (JAR)",
                    );
                }

                let done = members_done.fetch_add(1, Ordering::Relaxed) + 1;
                let elapsed_ms = start.elapsed().as_millis() as u64;
                if should_log_progress(done, expected_count, elapsed_ms, &last_progress_ms) {
                    tracing::info!(
                        archive = jar_display,
                        progress = %format!("{done}/{expected_count}"),
                        total_elapsed_ms = elapsed_ms,
                        "jar member analysis progress",
                    );
                }

                Some(MemberAnalysisResult {
                    go_source: None,
                    entry_path,
                    archive_location,
                    entry_metadata,
                    report,
                })
            },
            |result| acc.fold(result, &self.engine),
        );

        // Phase 3: Analyze non-class files (scripts, configs, etc.)
        //
        // The cap here samples a Java archive's incidental resources --
        // images, properties, XML -- and only archives that actually carry
        // bytecode now reach this function; `contains_java_members` sends the
        // rest to the generic path. Before that split every zip-shaped format
        // landed here, which made an npm package's *entire* payload
        // "non-class files" and truncated it in walkdir order -- dropping
        // whatever sorted late, manifests included.
        //
        // Ordering by signal before the cap is the second half: a sample taken
        // for size should never be what decides a verdict, so the members a
        // verdict rests on sort to the front and survive it.
        // Type each member from its bytes, as the in-memory path does.
        let mut non_class_files: Vec<_> = other_files
            .into_iter()
            .filter(|e| {
                let path = e.path();
                let file_type =
                    crate::analyzers::detect_file_type(path).unwrap_or(FileType::Unknown);
                is_interesting_jar_resource(path, &file_type)
            })
            .collect();
        // Path breaks rank ties so the selection is reproducible; walkdir
        // order is filesystem order, which is not.
        non_class_files
            .sort_by_cached_key(|e| (member_signal_rank(e.path()), e.path().to_path_buf()));
        non_class_files.truncate(JAR_RESOURCE_SAMPLE);

        let member_count = non_class_files.len();
        let members_done = std::sync::atomic::AtomicUsize::new(0);
        let last_progress_ms = AtomicU64::new(0);
        let analysis_start = std::time::Instant::now();

        let archive_display: &str = self
            .archive_path_prefix
            .as_deref()
            .unwrap_or(report.target.path.as_str());

        tracing::info!(
            archive = archive_display,
            members = member_count,
            depth = self.current_depth,
            "starting parallel archive member analysis",
        );

        par_filter_fold_members(
            &non_class_files,
            self.members_run_parallel(non_class_files.len()),
            |_| None,
            |entry| {
                let _thread_local_cache_clear_guard = ThreadLocalCacheClearGuard;
                if self.is_cancelled() {
                    return None;
                }
                let relative_path = posix_relative_path(entry.path(), temp_dir);
                let entry_path = self.format_entry_path(&relative_path);
                let archive_location = self.format_evidence_location(&relative_path);

                // Map large members instead of reading them. This closure runs
                // on every rayon worker at once and nothing bounds how much
                // member data is resident here — unlike the in-memory path,
                // which meters itself through `member_window_bytes`. A read is
                // anonymous dirty memory the kernel cannot reclaim, and
                // installers carry members far larger than that budget (see
                // MEMORY_EXPERIMENTS.md: one sample held ~1.4 GB of member
                // `Vec<u8>` live at once). `read_file_smart` maps above 10 MiB
                // and reads smaller members inline; it does NOT normalize
                // encoding, so the bytes — and with them the sha256 and the
                // detected type — are identical to the previous `fs::read`.
                let member_data = {
                    let _extract = crate::mem_profile::phase(crate::mem_profile::Phase::Extract);
                    match crate::file_io::read_file_smart(entry.path()) {
                        Ok(data) => data,
                        Err(e) => {
                            debug!("Failed to read archive member {}: {}", entry_path, e);
                            return None;
                        }
                    }
                };
                let file_data: &[u8] = member_data.as_slice();
                let file_type =
                    crate::analyzers::detect_file_type_from_data(entry.path(), file_data);
                let sha256 = calculate_sha256(file_data);

                let entry_metadata = archive_entry_metadata(
                    entry_path.clone(),
                    &file_type,
                    sha256.clone(),
                    file_data,
                    None,
                );

                let member_start = std::time::Instant::now();

                let _analyze = crate::mem_profile::phase(crate::mem_profile::Phase::Analyze);
                let report = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    self.analyze_extracted_member(
                        entry.path(),
                        &relative_path,
                        file_data,
                        &file_type,
                        &sha256,
                    )
                })) {
                    Ok(Ok(Some(mut r))) => {
                        // Matching is done; drop the fields nothing downstream
                        // reads so they don't pile up across the archive's
                        // members — the same release the windowed member path
                        // performs. These disk-walk paths never did, so every
                        // member of a jar/generic archive kept its traits,
                        // strings, structure, YARA matches, syscalls, paths,
                        // directories and env vars live until the whole scan
                        // finished (57 857 members on the MiniMax sample).
                        r.clear_unserialized_member_fields();
                        Some(r)
                    }
                    Ok(Ok(None)) => None,
                    Ok(Err(e)) => {
                        debug!("Failed to analyze archive member {}: {}", entry_path, e);
                        None
                    }
                    Err(_panic) => {
                        tracing::error!(
                            path = %entry_path,
                            "panic during archive member analysis (caught)"
                        );
                        FAILED_ANALYSES.fetch_add(1, Ordering::Relaxed);
                        None
                    }
                };

                let done = members_done.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
                let member_ms = member_start.elapsed().as_millis();
                tracing::debug!(
                    relative_path = %entry_path,
                    file_type = %file_type.report_file_type(),
                    size_bytes = file_data.len(),
                    elapsed_ms = member_ms as u64,
                    rayon_thread = ?rayon::current_thread_index(),
                    "archive member timing",
                );
                if member_ms > 5000 {
                    tracing::warn!(
                        archive = archive_display,
                        member = %entry_path,
                        file_type = %file_type.report_file_type(),
                        size_kb = file_data.len() / 1024,
                        elapsed_ms = member_ms,
                        progress = %format!("{done}/{member_count}"),
                        rayon_thread = rayon::current_thread_index().unwrap_or(usize::MAX),
                        "slow archive member analysis",
                    );
                } else {
                    let elapsed_ms = analysis_start.elapsed().as_millis() as u64;
                    if should_log_progress(done, member_count, elapsed_ms, &last_progress_ms) {
                        tracing::info!(
                            archive = archive_display,
                            progress = %format!("{done}/{member_count}"),
                            total_elapsed_ms = elapsed_ms,
                            "archive member analysis progress",
                        );
                    }
                }

                Some(MemberAnalysisResult {
                    go_source: None,
                    entry_path,
                    archive_location,
                    entry_metadata,
                    report,
                })
            },
            |result| acc.fold(result, &self.engine),
        );

        // Merge JAR collected results into the report
        let MemberCounts {
            files_analyzed,
            trait_count,
            capability_count,
        } = acc.merge_into(report);

        // Add metadata about archive contents
        report.metadata.errors.push(format!(
            "JAR archive: {} total classes, {} YARA-flagged, {} fully analyzed, {} traits and {} capabilities detected",
            total_class_files,
            flagged_classes.len(),
            files_analyzed,
            trait_count,
            capability_count
        ));

        report.metadata.analysis_duration_ms = start.elapsed().as_millis() as u64;
        report.metadata.tools_used = vec![
            "archive_analyzer".to_string(),
            "yara".to_string(),
            "java_class_analyzer".to_string(),
        ];
    }

    /// Analyze generic archives (non-JAR formats).
    ///
    /// Performs comprehensive analysis of all extracted files including:
    /// - YARA scanning for known malicious patterns
    /// - File-type-specific analysis (scripts, binaries, configs)
    /// - Archive entry metadata collection
    /// - Nested archive handling
    ///
    /// Files are analyzed in parallel for performance, with progress tracking
    /// for large archives.
    ///
    /// # Arguments
    /// * `temp_dir` - Extracted archive directory
    /// * `report` - Mutable report to aggregate findings into
    /// * `start` - Analysis start time for duration tracking
    pub(in super::super) fn analyze_generic_archive(
        &self,
        temp_dir: &Path,
        report: &mut AnalysisReport,
        start: std::time::Instant,
    ) {
        debug!(
            "Analyzing generic archive, scanning temp dir: {:?}",
            temp_dir
        );

        // Collect all files to analyze
        let files = extracted_files(temp_dir, report);

        let total_files = files.len();
        debug!("Found {} files to analyze", total_files);

        // Stream results into the accumulator in bounded, ordered windows.
        let mut acc = MemberAccumulator::default();

        // Analyze files in parallel — no shared Mutexes. Nested rayon calls
        // (analyze_extracted_member → rayon::join, scan_bytes → par_iter) are
        // handled by work-stealing; the outer worker participates in inner tasks.
        tracing::debug!(
            file_count = total_files,
            on_rayon_thread = rayon::current_thread_index().is_some(),
            "Starting parallel archive member analysis"
        );
        par_filter_fold_members(
            &files,
            self.members_run_parallel(files.len()),
            |_| None,
            |entry| {
                let _thread_local_cache_clear_guard = ThreadLocalCacheClearGuard;
                if self.is_cancelled() {
                    return None;
                }

                let relative_path = posix_relative_path(entry.path(), temp_dir);
                let entry_path = self.format_entry_path(&relative_path);
                let archive_location = self.format_evidence_location(&relative_path);

                // Map large members instead of reading them. This closure runs
                // on every rayon worker at once and nothing bounds how much
                // member data is resident here — unlike the in-memory path,
                // which meters itself through `member_window_bytes`. A read is
                // anonymous dirty memory the kernel cannot reclaim, and
                // installers carry members far larger than that budget (see
                // MEMORY_EXPERIMENTS.md: one sample held ~1.4 GB of member
                // `Vec<u8>` live at once). `read_file_smart` maps above 10 MiB
                // and reads smaller members inline; it does NOT normalize
                // encoding, so the bytes — and with them the sha256 and the
                // detected type — are identical to the previous `fs::read`.
                let member_data = {
                    let _extract = crate::mem_profile::phase(crate::mem_profile::Phase::Extract);
                    match crate::file_io::read_file_smart(entry.path()) {
                        Ok(data) => data,
                        Err(e) => {
                            debug!("Failed to read archive member {}: {}", entry_path, e);
                            return None;
                        }
                    }
                };
                let file_data: &[u8] = member_data.as_slice();
                let file_type =
                    crate::analyzers::detect_file_type_from_data(entry.path(), file_data);
                let sha256 = calculate_sha256(file_data);

                let entry_metadata = archive_entry_metadata(
                    entry_path.clone(),
                    &file_type,
                    sha256.clone(),
                    file_data,
                    None,
                );

                let member_start = std::time::Instant::now();

                let _analyze = crate::mem_profile::phase(crate::mem_profile::Phase::Analyze);
                let report = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    self.analyze_extracted_member(
                        entry.path(),
                        &relative_path,
                        file_data,
                        &file_type,
                        &sha256,
                    )
                })) {
                    Ok(Ok(Some(mut r))) => {
                        // Matching is done; drop the fields nothing downstream
                        // reads so they don't pile up across the archive's
                        // members — the same release the windowed member path
                        // performs. These disk-walk paths never did, so every
                        // member of a jar/generic archive kept its traits,
                        // strings, structure, YARA matches, syscalls, paths,
                        // directories and env vars live until the whole scan
                        // finished (57 857 members on the MiniMax sample).
                        r.clear_unserialized_member_fields();
                        Some(r)
                    }
                    Ok(Ok(None)) => None,
                    Ok(Err(e)) => {
                        debug!("Failed to analyze archive member {}: {}", entry_path, e);
                        None
                    }
                    Err(_panic) => {
                        tracing::error!(
                            path = %entry_path,
                            "panic during archive member analysis (caught)"
                        );
                        FAILED_ANALYSES.fetch_add(1, Ordering::Relaxed);
                        None
                    }
                };

                let member_elapsed = member_start.elapsed();
                tracing::debug!(
                    relative_path,
                    file_type = %file_type.report_file_type(),
                    size_bytes = file_data.len(),
                    elapsed_ms = member_elapsed.as_millis() as u64,
                    rayon_thread = ?rayon::current_thread_index(),
                    "archive member timing",
                );
                if member_elapsed.as_millis() > SLOW_ARCHIVE_MEMBER_ANALYSIS_MS {
                    tracing::warn!(
                        relative_path,
                        file_type = %file_type.report_file_type(),
                        size_bytes = file_data.len(),
                        elapsed_ms = member_elapsed.as_millis() as u64,
                        rayon_thread = ?rayon::current_thread_index(),
                        "Slow archive member analysis (generic)",
                    );
                }

                Some(MemberAnalysisResult {
                    go_source: (file_type == FileType::Go).then(|| {
                        if file_data.len() <= 2 * 1024 * 1024 {
                            String::from_utf8_lossy(file_data).into_owned()
                        } else {
                            String::new()
                        }
                    }),
                    entry_path,
                    archive_location,
                    entry_metadata,
                    report,
                })
            },
            |result| {
                let _aggregate = crate::mem_profile::phase(crate::mem_profile::Phase::Aggregate);
                acc.fold(result, &self.engine);
            },
        );

        // Surface the most severe members first under a hard ceiling, then drain
        // the aggregate into the report.
        acc.sort_files_by_severity(100_000);
        let MemberCounts {
            files_analyzed,
            trait_count,
            capability_count,
        } = acc.merge_into(report);

        report.prune_archive_directories();

        // Add metadata about archive contents
        report.metadata.errors.push(format!(
            "Archive contains {files_analyzed} files analyzed, {trait_count} traits and \
             {capability_count} capabilities detected"
        ));

        report.metadata.analysis_duration_ms = start.elapsed().as_millis() as u64;
        report.metadata.tools_used = vec!["archive_analyzer".to_string(), "walkdir".to_string()];
    }
}

/// The regular files extracted under `temp_dir`, at most
/// [`MAX_ARCHIVE_MEMBER_DEPTH`](super::super::guards::MAX_ARCHIVE_MEMBER_DEPTH)
/// directories deep and [`MAX_FILE_COUNT`](super::super::guards::MAX_FILE_COUNT)
/// in number. What the walk leaves out is recorded on `report`: a payload
/// buried deeper, behind padding files, or under an unreadable directory
/// shows as a cut in the analysis rather than as nothing at all.
pub(super) fn extracted_files(
    temp_dir: &Path,
    report: &mut AnalysisReport,
) -> Vec<walkdir::DirEntry> {
    use super::super::guards::{MAX_ARCHIVE_MEMBER_DEPTH, MAX_FILE_COUNT};

    let mut files = Vec::new();
    let (mut too_deep, mut unreadable, mut over_count) = (0usize, 0usize, 0usize);
    // One level past the cap, so entries beyond it are seen and counted.
    for entry in walkdir::WalkDir::new(temp_dir)
        .min_depth(1)
        .max_depth(MAX_ARCHIVE_MEMBER_DEPTH + 1)
    {
        match entry {
            Ok(entry) if entry.depth() > MAX_ARCHIVE_MEMBER_DEPTH => too_deep += 1,
            Ok(entry) if entry.file_type().is_file() => {
                if files.len() < MAX_FILE_COUNT {
                    files.push(entry);
                } else {
                    over_count += 1;
                }
            }
            Ok(_) => {}
            Err(_) => unreadable += 1,
        }
    }
    for (count, what) in [
        (
            too_deep,
            format!("entries deeper than {MAX_ARCHIVE_MEMBER_DEPTH} directories not analyzed"),
        ),
        (
            over_count,
            format!("files past the first {MAX_FILE_COUNT} not analyzed"),
        ),
        (
            unreadable,
            "extracted entries could not be read".to_string(),
        ),
    ] {
        if count > 0 {
            report.metadata.errors.push(format!("{count} {what}"));
            report
                .analysis_gaps
                .record(crate::types::AnalysisGap::EmbeddedSourceIncomplete);
        }
    }
    files
}
