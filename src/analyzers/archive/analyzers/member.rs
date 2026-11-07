//! Analysis of one extracted archive member: caching, single-flight and pool placement.

// Split out of the parent module for size; it shares the parent's namespace.
#[allow(clippy::wildcard_imports)]
use super::*;

impl ArchiveAnalyzer {
    /// The report for a nested archive past the depth cap. It is not unpacked,
    /// but it is reported with that said, rather than as an error its caller
    /// drops: otherwise one more level of nesting hides whatever it holds.
    fn depth_capped_member(
        file_path: &Path,
        relative_path: &str,
        size_bytes: usize,
        file_type: &FileType,
        sha256: &str,
        depth: usize,
        max_depth: usize,
    ) -> AnalysisReport {
        let mut report = AnalysisReport::new(crate::types::TargetInfo {
            path: file_path.display().to_string(),
            file_type: file_type.report_file_type(),
            size_bytes: size_bytes as u64,
            sha256: sha256.to_string(),
            architectures: None,
        });
        report.findings.push(super::super::findings::archive_finding(
            "anti-analysis/archive/excessive-nesting",
            format!(
                "Nested archive past the {max_depth}-level unpacking limit; its members were not analyzed"
            ),
            "cleave",
            vec![crate::types::Evidence {
                method: "archive_extraction".to_string(),
                source: "cleave".to_string(),
                value: format!("depth={depth}"),
                location: Some(relative_path.to_string()),
                ..Default::default()
            }],
            1,
        ));
        report
            .analysis_gaps
            .record(crate::types::AnalysisGap::EmbeddedSourceIncomplete);
        report
    }

    pub(super) fn analyze_extracted_member(
        &self,
        file_path: &Path,
        relative_path: &str,
        data: &[u8],
        file_type: &FileType,
        sha256: &str,
    ) -> Result<Option<AnalysisReport>> {
        // Archive members do not pass through `analyze_file`, so the
        // toplevel SHA cache cannot deduplicate them. Reuse the cross-context
        // FileAnalysis cache where safe, and single-flight the first analysis
        // when duplicate members arrive concurrently (within one archive or
        // from two archives in a diff).
        let default_options;
        let options = if let Some(options) = self.analysis_options.as_deref() {
            options
        } else {
            default_options = crate::AnalysisOptions::default();
            &default_options
        };
        // Unknown members are normally skipped, but a validated embedded PE or
        // ELF is executable content even when a wrapper obscures its file ID.
        let wrapped_binary = self.has_wrapped_binary(file_type, data);
        if let Some(reason) = self.archive_member_analysis_skip_reason(file_type, relative_path)
            && !wrapped_binary
        {
            tracing::debug!(
                relative_path,
                file_type = %file_type.report_file_type(),
                reason,
                "Skipping archive member analysis"
            );
            return Ok(None);
        }
        let is_archive = file_type.is_archive();
        // Decided before the caches and the single flight: both key on the
        // member's bytes, not on how deep it sits, and a report cut short by
        // depth must never stand in for the same archive found shallower.
        if is_archive && self.current_depth + 1 >= self.max_depth {
            return Ok(Some(Self::depth_capped_member(
                file_path,
                relative_path,
                data.len(),
                file_type,
                sha256,
                self.current_depth + 1,
                self.max_depth,
            )));
        }
        let file_type_key = file_type.label();
        // The settings this member is analyzed under: the engine's. They key
        // the cache and the in-process sharing below.
        let member_settings = self.engine.settings().clone();
        let report_type_key = crate::analysis_cache::report_type_key(
            file_type_key,
            std::path::Path::new(relative_path),
        );
        if !is_archive {
            // A member can emit decoded child files (`##base64`,
            // `##unicode-escape`, ...). Only the full report cache carries
            // that child inventory; `file_analysis_cache_store` refuses any
            // report with children, so the compact fallback below can never
            // resurrect a member with its decoded children stripped. Both
            // lookups validate the member path themselves and refuse a hit
            // whose evaluation origin is not equivalent to this one.
            if let Some(mut report) = crate::analysis_cache::report_cache_lookup(
                sha256,
                &report_type_key,
                options,
                &member_settings,
                relative_path,
                Some(self.engine.rules().as_ref()),
            ) {
                report.analysis_timestamp = Some(chrono::Utc::now());
                tracing::debug!(
                    sha256,
                    relative_path,
                    "Archive member full-report cache hit"
                );
                return Ok(Some(report));
            }

            if let Some(fa) = crate::analysis_cache::file_analysis_cache_lookup(
                sha256,
                file_type_key,
                options,
                &member_settings,
                relative_path,
                Some(self.engine.rules().as_ref()),
            ) {
                let mut report = crate::report_from_file_analysis(fa, relative_path.to_string());
                crate::restamp_path_derived_values(&mut report, Path::new(relative_path));
                tracing::debug!(sha256, relative_path, "Archive member cache hit");
                return Ok(Some(report));
            }
        }

        let flight = crate::analysis_cache::acquire_member_flight(
            sha256,
            file_type_key,
            options,
            &member_settings,
        );
        flight.set_label(relative_path);
        if !flight.is_owner() {
            let on_pool = rayon::current_thread_index().is_some();
            let isolated_wait = flight.can_wait_for_isolated_owner();
            if on_pool
                && !isolated_wait
                && (crate::analysis_cache::owns_any_flight() || !self.member_may_wait())
            {
                // This thread is inside an analysis it owns (a nested
                // archive, or a job stolen while its own `join` waited).
                // Blocking here can deadlock — the flight it waits on may
                // need this very stack to unwind — so it analyzes
                // independently, as every pool waiter did before
                // `wait_yielding` existed.
                tracing::debug!(
                    sha256,
                    relative_path,
                    "Archive member flight busy while owning another; analyzing independently"
                );
                crate::rayon_nest::note_independent_member_analysis();
                return flight.run_independently(|| {
                    self.analyze_extracted_member_uncached(
                        file_path,
                        relative_path,
                        data,
                        file_type,
                        sha256,
                    )
                });
            }
            // Only a member worth deduplicating is worth waiting for. The
            // owner of a small member's flight can be diverted for tens of
            // seconds — a rayon `join` inside its analysis steals whatever
            // is pending, a 30 s bundle included — and seven lanes then sat
            // 180 s on a README.md flight. Below the floor the
            // duplicate is cheaper than any wait.
            if on_pool && data.len() < FLIGHT_WAIT_MIN_BYTES {
                tracing::debug!(
                    sha256,
                    relative_path,
                    bytes = data.len(),
                    "Archive member flight busy; member below the wait floor, analyzing independently"
                );
                crate::rayon_nest::note_independent_member_analysis();
                return flight.run_independently(|| {
                    self.analyze_extracted_member_uncached(
                        file_path,
                        relative_path,
                        data,
                        file_type,
                        sha256,
                    )
                });
            }
            // On a pool worker, wait by running this lane's own pending jobs
            // rather than parking (or, as before, re-analyzing the same
            // bytes) — see `ReportFlight::wait_yielding`. Waiters are capped
            // at half the pool so the owner's nested parallelism always has
            // free workers; past the cap a duplicate is analyzed on its own.
            static WAITERS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
            /// Members below this many bytes wait at most [`SMALL_MEMBER_WAIT`]
            /// for a single-flight owner before analyzing independently.
            const SMALL_MEMBER_WAIT_BYTES: usize = 256 * 1024;
            const SMALL_MEMBER_WAIT: std::time::Duration = std::time::Duration::from_secs(1);
            // How long a wait is worth depends on what duplicating the work
            // would cost. For a big member (the 10 MB bundle case above) that
            // is CPU-seconds, so wait up to the analysis wall deadline. For a
            // small one it is milliseconds, and the wait can be far longer
            // than that: the owner may be a worker in another pool (a whale
            // on its private pool, whose members share a LICENSE or vendored
            // file with everyone) that is saturated with its own heavy
            // members. Measured on a scan server at concurrency
            // 8: three unrelated small packages each stalled 15–18 s on a
            // member the whale in flight owned, then finished within 0.4 s
            // of each other — on a pool worker and off it alike.
            let deadline = if data.len() < SMALL_MEMBER_WAIT_BYTES {
                SMALL_MEMBER_WAIT
            } else {
                std::time::Duration::from_secs(180)
            };
            let waited = if isolated_wait {
                tracing::info!(target: "cleave::source_flights", relative_path, sha256, "waiting for isolated member");
                match flight.wait_isolated(deadline) {
                    Some(report) => report,
                    None => {
                        return flight.run_independently(|| {
                            self.analyze_extracted_member_uncached(
                                file_path,
                                relative_path,
                                data,
                                file_type,
                                sha256,
                            )
                        });
                    }
                }
            } else if on_pool {
                // Half the pool, and never the last two workers: an owner's
                // spawned nested job needs a free worker to run on.
                // A path pulled during another wait (`rayon_nest::run_wait_work`)
                // is exempt: its lane already holds a waiter slot, it cannot
                // pull further work, and its wait resolves through an owner
                // that never waits — so it is counted with its lane, not as
                // a second idle worker.
                let threads = rayon::current_num_threads();
                let cap = (threads / 2).min(threads.saturating_sub(2));
                let counted = !crate::rayon_nest::in_wait_work();
                if counted && WAITERS.fetch_add(1, std::sync::atomic::Ordering::AcqRel) >= cap {
                    WAITERS.fetch_sub(1, std::sync::atomic::Ordering::AcqRel);
                    tracing::debug!(
                        sha256,
                        relative_path,
                        "Archive member flight busy; waiter cap reached, analyzing independently"
                    );
                    crate::rayon_nest::note_independent_member_analysis();
                    return flight.run_independently(|| {
                        self.analyze_extracted_member_uncached(
                            file_path,
                            relative_path,
                            data,
                            file_type,
                            sha256,
                        )
                    });
                }
                let w = flight.wait_yielding(deadline);
                if counted {
                    WAITERS.fetch_sub(1, std::sync::atomic::Ordering::AcqRel);
                }
                match w {
                    Some(w) => w,
                    None => {
                        crate::rayon_nest::note_independent_member_analysis();
                        return flight.run_independently(|| {
                            self.analyze_extracted_member_uncached(
                                file_path,
                                relative_path,
                                data,
                                file_type,
                                sha256,
                            )
                        });
                    }
                }
            } else {
                match flight.wait_bounded(deadline) {
                    Some(w) => w,
                    None => {
                        crate::rayon_nest::note_independent_member_analysis();
                        return flight.run_independently(|| {
                            self.analyze_extracted_member_uncached(
                                file_path,
                                relative_path,
                                data,
                                file_type,
                                sha256,
                            )
                        });
                    }
                }
            };
            if let Some(mut report) = waited {
                // Same guard as the persistent caches above: a report
                // carrying path-derived findings (or decoded children whose
                // paths hang off the member path) is only valid under the
                // path it was evaluated for. Sharing it across paths let
                // `testing/harness` basename findings from one archive
                // surface on another's container record.
                if !crate::shared_resources::adopt_report_under(
                    &mut report,
                    relative_path,
                    self.engine.rules(),
                ) {
                    // Refused, so the report still carries its owner's path.
                    let owner_path = report.target.path.as_str();
                    tracing::debug!(
                        sha256,
                        relative_path,
                        owner_path,
                        children = report.files.len() + report.archive_contents.len(),
                        differing = ?self.engine.rules().paths_inequivalent_inputs(owner_path, relative_path),
                        "Archive member single-flight hit is path-bound; analyzing independently"
                    );
                    drop(report);
                    if isolated_wait {
                        tracing::info!(target: "cleave::source_flights", relative_path, sha256, "isolated result is path-bound; analyzing independently");
                    }
                    return flight.run_independently(|| {
                        self.analyze_extracted_member_uncached(
                            file_path,
                            relative_path,
                            data,
                            file_type,
                            sha256,
                        )
                    });
                }
                crate::restamp_path_derived_values(&mut report, Path::new(relative_path));
                if isolated_wait {
                    tracing::info!(target: "cleave::source_flights", relative_path, sha256, "reused isolated member");
                }
                tracing::debug!(sha256, relative_path, "Archive member single-flight hit");
                return Ok(Some(report));
            }
            // The owner failed before publishing a report. Retry once through
            // the normal path so a waiter is not turned into a false success.
            return flight.run_independently(|| {
                self.analyze_extracted_member(file_path, relative_path, data, file_type, sha256)
            });
        }

        let result = self.analyze_extracted_member_with_flight(
            file_path,
            relative_path,
            data,
            file_type,
            sha256,
            Some(&flight),
        );
        match &result {
            Ok(Some(report)) => {
                // Archive reports contain nested members whose paths depend on
                // the containing archive, so retain only ordinary members in
                // the persistent cross-context cache. The in-process flight
                // still shares full archive reports between simultaneous users.
                if !is_archive {
                    // The revision the member was actually evaluated under, so
                    // a traits reload landing mid-archive cannot file this
                    // member's verdict under the new rules' fingerprint.
                    let traits_revision = self.engine.rules().traits_revision();
                    if !report.files.is_empty() || !report.archive_contents.is_empty() {
                        crate::analysis_cache::report_cache_store(
                            sha256,
                            &report_type_key,
                            options,
                            &member_settings,
                            report,
                            traits_revision,
                        );
                    }
                    let mut fa = report.to_file_analysis(0, &self.engine);
                    // Negative path matches are path-dependent too. Keep the
                    // origin so the cache can check equivalence on every hit.
                    fa.path = relative_path.to_string();
                    fa.id = 0;
                    fa.parent_id = None;
                    fa.depth = 0;
                    crate::analysis_cache::file_analysis_cache_store(
                        sha256,
                        file_type_key,
                        options,
                        &member_settings,
                        &fa,
                        report,
                        traits_revision,
                    );
                }
                flight.complete(Some(report));
            }
            Ok(None) | Err(_) => flight.complete(None),
        }
        result
    }

    pub(super) fn analyze_extracted_member_uncached(
        &self,
        file_path: &Path,
        relative_path: &str,
        data: &[u8],
        file_type: &FileType,
        sha256: &str,
    ) -> Result<Option<AnalysisReport>> {
        self.analyze_extracted_member_with_flight(
            file_path,
            relative_path,
            data,
            file_type,
            sha256,
            None,
        )
    }

    pub(super) fn analyze_extracted_member_with_flight(
        &self,
        file_path: &Path,
        relative_path: &str,
        data: &[u8],
        file_type: &FileType,
        sha256: &str,
        flight: Option<&crate::analysis_cache::ReportFlight>,
    ) -> Result<Option<AnalysisReport>> {
        let work = || {
            static WAIT: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
            if *WAIT.get_or_init(|| crate::env::flag("CLEAVE_SOURCE_FLIGHT_WAIT"))
                && let Some(flight) = flight
            {
                flight.mark_isolated_owner();
            }
            self.analyze_extracted_member_on_current_pool(
                file_path,
                relative_path,
                data,
                file_type,
                sha256,
            )
        };
        if file_type.is_source_code()
            && data.len() >= source_leaf_min_bytes()
            && let Some(threads) = source_leaf_threads()
        {
            return crate::rayon_nest::with_isolated_leaf_pool(threads, work);
        }
        work()
    }

    pub(super) fn analyze_extracted_member_on_current_pool(
        &self,
        file_path: &Path,
        relative_path: &str,
        data: &[u8],
        file_type: &FileType,
        sha256: &str,
    ) -> Result<Option<AnalysisReport>> {
        if self.is_cancelled() {
            anyhow::bail!("Analysis cancelled");
        }
        // Depth of member analyses on this thread's stack (see
        // `member_may_wait`). Restored on every exit path.
        struct DepthGuard;
        impl Drop for DepthGuard {
            fn drop(&mut self) {
                MEMBER_ANALYSIS_DEPTH.with(|d| d.set(d.get().saturating_sub(1)));
            }
        }
        MEMBER_ANALYSIS_DEPTH.with(|d| d.set(d.get() + 1));
        let _depth_guard = DepthGuard;

        // Breadcrumb so a wedge dump can name which member this pool thread is
        // analyzing. This is the universal per-member chokepoint (every archive
        // path and the nested-archive recursion routes through it), so the top
        // archive's members — fanned across the whole rayon pool — are all named.
        let _breadcrumb = crate::breadcrumb::scope("member", relative_path);

        let wrapped_binary = self.has_wrapped_binary(file_type, data);
        if let Some(reason) = self.archive_member_analysis_skip_reason(file_type, relative_path)
            && !wrapped_binary
        {
            tracing::debug!(
                relative_path,
                file_type = %file_type.report_file_type(),
                reason,
                "Skipping archive member analysis"
            );
            return Ok(None);
        }

        if !file_type.is_archive()
            && let Some(ref yara_engine) = self.yara_engine
            && Self::archive_member_yara_skip_reason(relative_path, file_type, data.len()).is_none()
        {
            let yara_engine = yara_engine.clone();
            let yara_filetypes = Self::archive_member_yara_filetypes(file_type);
            rayon::spawn(move || {
                if yara_filetypes.is_empty() {
                    yara_engine.prewarm_filetypes(None);
                } else {
                    yara_engine.prewarm_filetypes(Some(&yara_filetypes));
                }
            });
        }

        let result = if file_type.is_archive() {
            if self.current_depth + 1 >= self.max_depth {
                Ok(Some(Self::depth_capped_member(
                    file_path,
                    relative_path,
                    data.len(),
                    file_type,
                    sha256,
                    self.current_depth + 1,
                    self.max_depth,
                )))
            } else {
                let nested = self.nested_archive_analyzer(relative_path);
                let path = file_path.to_path_buf();
                let nested_depth = self.current_depth + 1;

                // If we're already running on a rayon worker, run the nested
                // archive analysis directly on this thread. Rayon workers are
                // configured with a large stack by the caller (an embedding host installs
                // a 256 MB global pool), and par_filter_map_members grows onto
                // a fresh heap segment when headroom runs low, so we don't
                // need the 8 MB std::thread for stack headroom.
                //
                // Critically, spawning a std::thread and join()ing it from a
                // rayon worker causes a deadlock cycle: the rayon worker
                // blocks in pthread_join waiting for the std::thread, while
                // the std::thread calls par_iter inside cleave, which
                // submits work to the rayon pool via `in_worker_cold` and
                // blocks on a LockLatch waiting for a rayon worker to pick it
                // up — but every rayon worker is already blocked in join.
                // Off-pool callers also stay on their calling thread, growing
                // its stack when necessary. A joined std::thread gave them
                // headroom but lost their top-level parallel-owner context.
                let nested_result = if rayon::current_thread_index().is_some() {
                    tracing::debug!(
                        relative_path,
                        nested_depth,
                        file_size_bytes = data.len(),
                        "Analyzing nested archive in-place on rayon worker"
                    );
                    nested.analyze_archive_with_data(data, &path).map(Some)
                } else {
                    tracing::debug!(
                        relative_path,
                        nested_depth,
                        file_size_bytes = data.len(),
                        "Analyzing nested archive on caller's guarded stack"
                    );
                    with_nested_archive_stack(|| nested.analyze_archive_with_data(data, &path))
                        .map(Some)
                };

                match nested_result {
                    Ok(report) => Ok(report),
                    Err(archive_error) => {
                        // A valid format signature can sit in front of a
                        // script (or other recognized file) whose archive
                        // header is malformed. Do not let the failed nested
                        // parser hide the member's behavior: retry using its
                        // path-derived type, while keeping the parse failure
                        // visible in the fallback report.
                        let fallback_type =
                            crate::analyzers::declared_file_type_from_name(file_path);
                        if fallback_type == FileType::Unknown
                            || fallback_type == *file_type
                            || fallback_type.is_archive()
                        {
                            Err(archive_error)
                        } else {
                            tracing::debug!(
                                relative_path,
                                archive_type = %file_type.report_file_type(),
                                fallback_type = %fallback_type.report_file_type(),
                                error = %archive_error,
                                "Retrying malformed archive member using its path-derived type"
                            );
                            self.analyze_extracted_member_uncached(
                                file_path,
                                relative_path,
                                data,
                                &fallback_type,
                                sha256,
                            )
                            .map(|report| {
                                if let Some(mut report) = report {
                                    report.metadata.errors.push(format!(
                                        "Nested archive parsing failed; analyzed using {}: {archive_error}",
                                        fallback_type.report_file_type()
                                    ));
                                    Some(report)
                                } else {
                                    None
                                }
                            })
                        }
                    }
                }
            }
        } else if let Some(analyzer) = {
            // The generic factory intentionally creates PE analyzers with
            // standalone defaults. Archive-member PEs need the enclosing
            // request's archive settings so an installer nested inside a ZIP
            // inherits --all-files, memory limits, YARA,
            // and cancellation for its own payloads.
            if wrapped_binary {
                Some(Box::new(
                    crate::analyzers::generic::GenericAnalyzer::new(FileType::Unknown)
                        .with_engine(self.engine.clone()),
                ) as Box<dyn crate::analyzers::Analyzer>)
            } else if *file_type == FileType::Pe {
                let mut pe = crate::analyzers::pe::PEAnalyzer::new()
                    .with_engine(self.engine.clone())
                    .with_cancellation(self.cancelled.clone())
                    .with_archive_config(self.child_archive_config());
                if let Some(yara) = self.yara_engine.clone() {
                    pe = pe.with_yara_arc(yara);
                }
                Some(Box::new(pe) as Box<dyn crate::analyzers::Analyzer>)
            } else {
                crate::analyzers::analyzer_for_file_type_arc(file_type, &self.engine)
            }
        } {
            let extract_payloads =
                crate::analyzers::unified::UnifiedSourceAnalyzer::for_file_type(file_type)
                    .is_some();

            // Archive members get the SAME string-extraction treatment as a
            // standalone file (`lib.rs` uses `stng_analysis_opts` for every
            // non-archive input). The previous code downgraded text/script
            // members to `stng_text_opts`, which sets `FormatHint::Text` and
            // SKIPS stng's XOR scan — silently dropping XOR-obfuscated payload
            // detection on exactly the files attackers bury inside archives
            // (npm tarballs, zips, jars). XOR/base64 detection parity with the
            // standalone path matters far more than the per-member scan cost;
            // an inconsistency that weakens detection only for archived content
            // is a security hole.
            crate::memory_tracker::set_current_phase(format!("strings on {relative_path}"));
            // Normalize UTF-16 (LE/BE BOM) member content to UTF-8 before string
            // extraction and trait matching, mirroring the standalone path in
            // `lib.rs`. Without this a UTF-16 script inside an archive is
            // null-interleaved at the byte level (`E\0x\0e\0c\0...`) and no
            // `type: text` trait matches. The member SHA is computed separately
            // from the original bytes, so identity is unchanged.
            let normalized_member = crate::file_io::normalize_text_encoding(data);
            let data: &[u8] = normalized_member.as_ref();
            let logical_path = Path::new(relative_path);
            // filefacts is the string authority and the parser: open the
            // member once and thread it into the analyzer (below) so it is
            // parsed a single time, regardless of member type. The analyzer
            // reuses this parse (`with_parsed_ctx`) rather than opening the
            // member again.
            let member_ctx = crate::analysis_context::AnalysisContext::open_with(
                crate::engine::filefacts_options(self.engine.settings()),
                logical_path,
                data,
            );
            let stng_strings = member_ctx.text_rows();
            crate::memory_tracker::clear_current_phase();
            let mut payloads = if extract_payloads {
                crate::extractors::encoded_payload::extract_encoded_payloads(stng_strings)
            } else {
                Vec::new()
            };
            payloads.extend(crate::extractors::encoded_payload::xor_encoded_pe(
                member_ctx.parsed.fileid(),
                data,
            ));
            if matches!(
                file_type,
                FileType::Gif | FileType::Jpeg | FileType::Png | FileType::Bmp | FileType::Webp
            ) {
                payloads.extend(crate::extractors::encoded_payload::extract_media_base64_pes(data));
                payloads.extend(crate::extractors::encoded_payload::extract_media_xor_pes(
                    data,
                ));
            }
            // Binary recovery must not depend on the source/string-decoding
            // gate: a packed PE needs the same child analysis in an archive.
            if *file_type == FileType::Pe {
                payloads.extend(crate::extractors::encoded_payload::nrv8_encoded_pes(data));
            }
            if extract_payloads {
                payloads.extend(crate::extractors::encoded_payload::xor_encoded_machos(
                    data,
                    stng_strings,
                ));
            }
            let mut input = AnalysisInput::with_payloads(
                logical_path,
                data,
                stng_strings,
                &payloads,
                *file_type,
            )
            .with_backing_path(file_path)
            .with_sha256(sha256.to_string())
            .at_depth((self.current_depth + 1) as u32)
            .with_parsed_ctx(&member_ctx);
            input.cancellation = self.cancelled.clone();

            tracing::debug!(
                relative_path,
                file_type = %file_type.report_file_type(),
                string_count = stng_strings.len(),
                payload_count = payloads.len(),
                payload_mode = if extract_payloads { "enabled" } else { "skipped" },
                payload_reason = if extract_payloads {
                    "unified source analyzer consumes encoded payloads"
                } else {
                    "non-unified analyzer path does not consume encoded payloads"
                },
                "Analyzing archive member via unified AnalysisInput path"
            );

            // A top-level archive fans members onto Rayon, but binary members
            // can each spend many minutes in serial trait evaluation after
            // that fan-out. On uruk-hai a 4.53 MiB Go ELF member took 996,725
            // ms while 110/128 Rayon workers were idle. Admit only a bounded
            // number of members to one additional parallel level; the guard
            // is thread-local, so their Rayon children cannot recursively fan
            // out again.
            let _nested_parallel = crate::rayon_nest::try_enter_nested_member_parallelism();
            let mut report = analyzer.analyze_input(&input)?;

            // Attach identity and the filefacts view for member analyzers that didn't,
            // reusing the member context opened above (no re-parse) — so a
            // member's declared references (e.g. a package.json's dependencies)
            // are never lost to an analyzer that forgets. Mirrors the standalone
            // safety net in `analyze`. Gated on `is_none` so analyzers that
            // already attach keep theirs.
            if let Some(ctx) = input.parsed_ctx {
                if report.identity.is_none() {
                    report.identity = ctx.identity();
                }
                if report.filefacts.is_none() {
                    let view = crate::types::FilefactsView::of(ctx, self.engine.compact_members());
                    if !view.is_empty() {
                        report.filefacts = Some(view);
                    }
                }
            }

            // Run the SAME encoded-payload analysis the standalone path runs
            // (`process_encoded_payloads` in lib.rs): emit the
            // `metadata/encoded-payload/*` finding for each payload and
            // recursively analyze the decoded bytes, merging decoded
            // traits/findings back. Without this an obfuscated payload inside an
            // archive member (npm tarball, zip, jar) silently lost its
            // encoded-payload finding and every trait derived from the decoded
            // content — detection that the same file gets when scanned
            // standalone. Guarded on the options the recursion needs;
            // `payloads` was extracted above (empty when extract_payloads=false,
            // making this a no-op). `payloads` is moved — `input` (which
            // borrowed it) is no longer used after `analyze_input` above.
            if !payloads.is_empty()
                && let Some(opts) = self.analysis_options.as_ref()
            {
                crate::process_encoded_payloads(
                    payloads,
                    &mut report,
                    logical_path,
                    data,
                    *file_type,
                    (self.current_depth + 1) as u32,
                    opts,
                    &self.engine,
                );
            }

            // Dedicated analyzers use the shared engine stage. Only an
            // analyzer that has not run YARA needs this fallback; it must
            // evaluate inline traits as well as materialize regular hits.
            if !report
                .metadata
                .tools_used
                .iter()
                .any(|tool| tool == "yara-x")
                && self.yara_engine.is_some()
                && Self::archive_member_yara_skip_reason(relative_path, file_type, data.len())
                    .is_none()
            {
                self.engine.evaluate_and_merge_findings_with_precomputed(
                    &mut report,
                    data,
                    crate::capabilities::AnalysisBorrow::new(None),
                    None,
                    None,
                    None,
                    self.cancelled.as_deref(),
                );
                self.engine
                    .rules()
                    .apply_retroactive_unless_suppression_to_findings(&mut report.findings, None);
            }

            // Capture this member's context windows from its OWN bytes, mirroring
            // the standalone path (lib.rs, after dedupe). The member's evidence
            // offsets index these decompressed bytes, not the container's, so
            // without a per-member capture the member would carry findings but no
            // byte/line context. Rides up into `files[].context` via
            // `into_file_analysis`.
            report.suppress_scanner_catalog_self_hits();
            report.dedupe_findings();
            // The container's end-of-analysis low-value filter has not run yet,
            // so resolve what it will delete and keep those out of the windows.
            let doomed = self.engine.rules().doomed_low_value_ids(&report.findings);
            crate::context::capture(&mut report, data, *file_type, &doomed);
            Ok(Some(report))
        } else if self
            .analysis_options
            .as_ref()
            .is_some_and(|opts| opts.all_files)
            || filefacts::package_context::has_named_reference_metadata(Path::new(relative_path))
        {
            // `all_files` promises analysis, not merely a path ledger. Treat an
            // unclassified blob as generic data so data-oriented facts and
            // traits can inspect decompressed payloads that have no extension.
            // This is especially important for single-stream archives: their
            // decoded child often has a bare stem even when it contains the
            // interesting structure.
            let effective_type = if *file_type == FileType::Unknown {
                FileType::Data
            } else {
                *file_type
            };
            let target = TargetInfo {
                path: relative_path.to_string(),
                file_type: effective_type.report_file_type(),
                size_bytes: data.len() as u64,
                sha256: sha256.to_string(),
                architectures: None,
            };
            let mut report = AnalysisReport::new(target);
            let logical_path = Path::new(relative_path);
            let ctx = Some(crate::analysis_context::AnalysisContext::open_with(
                self.engine.filefacts_options(),
                logical_path,
                data,
            ));
            if let Some(ctx) = ctx.as_ref() {
                report.strings = crate::strings::StringExtractor::default()
                    .convert_stng_strings(ctx.text_rows());
                let view = crate::types::FilefactsView::of(ctx, self.engine.compact_members());
                if !view.is_empty() {
                    report.filefacts = Some(view);
                }
                report.identity = ctx.identity();
                crate::capabilities::merge_filefacts_context(&mut report, ctx);
            }
            self.engine.evaluate_and_merge_findings_with_precomputed(
                &mut report,
                data,
                crate::capabilities::AnalysisBorrow::with_filefacts(None, ctx.as_ref()),
                None,
                None,
                None,
                self.cancelled.as_deref(),
            );
            report.dedupe_findings();
            let doomed = self.engine.rules().doomed_low_value_ids(&report.findings);
            crate::context::capture(&mut report, data, effective_type, &doomed);
            Ok(Some(report))
        } else {
            Err(anyhow::anyhow!("Unsupported file type: {:?}", file_type))
        };

        match &result {
            Ok(Some(_)) => {
                SUCCESSFUL_ANALYSES.fetch_add(1, Ordering::Relaxed);
            }
            Ok(None) => {}
            Err(_) => {
                FAILED_ANALYSES.fetch_add(1, Ordering::Relaxed);
            }
        }

        result
    }
}
