//! The single-file analysis pipeline.

// Split out of the parent module for size; it shares the parent's namespace.
#[allow(clippy::wildcard_imports)]
use super::*;

/// Maximum recursion depth for nested payload analysis.
/// Each level adds a full analysis stack frame; 8 levels is generous for
/// legitimate multi-layer encoding while preventing stack overflows from
/// adversarial nesting (e.g., base64-in-hex-in-base64 ad infinitum).
pub(super) const MAX_ANALYSIS_DEPTH: u32 = 8;

/// Extract a human-readable message from a panic payload (`String` or `&str`).
///
/// `std::panic::catch_unwind` hands back the payload as `Box<dyn Any + Send>`;
/// the standard panic machinery boxes either a `String` (from `format!`-style
/// panics) or a `&'static str`, so those two cases cover every panic we raise.
pub(crate) fn panic_payload_message(payload: &Box<dyn std::any::Any + Send>) -> String {
    if let Some(s) = payload.downcast_ref::<String>() {
        s.clone()
    } else if let Some(s) = payload.downcast_ref::<&str>() {
        (*s).to_string()
    } else {
        "unknown panic".to_string()
    }
}

/// Analyze one file under `engine`: the core every single-file entry point
/// converges on. `preloaded` and `precomputed_sha256` let a caller that
/// already read and hashed the file for a cache lookup skip doing it twice,
/// a non-trivial cost on large inputs. The report carries `engine`, so a
/// later [`AnalysisReport::finalize`] folds it under the same rules.
pub(super) fn analyze_file_with_engine<P: AsRef<Path>>(
    path: P,
    options: &AnalysisOptions,
    engine: &Engine,
    preloaded: Option<file_io::FileData>,
    precomputed_sha256: Option<String>,
) -> Result<AnalysisReport> {
    let path = path.as_ref();
    // Every public single-file entry point converges here, including workers
    // that call `analyze_file` concurrently from independent blocking tasks.
    // Keeping the top-level counter only in directory-scan wrappers missed
    // exactly that worker case: the counter stayed at zero, so all 24 analyses
    // independently enabled nested trait/YARA/AC `par_iter`s over the same
    // global Rayon pool. Besides severe head-of-line starvation, each Rayon
    // thread then retained regex scratch from many unrelated analyses.
    let _in_flight = crate::rayon_nest::enter_toplevel_analysis_on(options.dedicated_pool);

    // Catch panics from any analyzer so a single malformed or adversarial file
    // (e.g. a header offset pointing past EOF that trips unchecked slice
    // indexing) can't unwind across the caller's thread boundary — a rayon
    // worker or a tokio `spawn_blocking` task — and take down unrelated work.
    // Library callers instead get a plain `Err` they can classify and log. The
    // per-frame `ThreadLocalCacheClearGuard` inside the analysis still runs
    // during the unwind, so thread-local caches are left clean before we return.
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        analyze_file_with_resources_at_depth(
            path,
            options,
            engine,
            preloaded,
            precomputed_sha256,
            0,
        )
    }));

    // Tree-sitter queries first compile during analysis; keep what they
    // taught the derivation memo so the next process can skip them.
    crate::capabilities::derivation_memo::persist();
    match outcome {
        Ok(result) => result.map(|mut report| {
            report.engine = Some(engine.clone());
            report
        }),
        Err(payload) => {
            let message = panic_payload_message(&payload);
            tracing::error!(
                path = %path.display(),
                panic = %message,
                "analyzer panicked; recovered as error",
            );
            Err(anyhow::anyhow!(
                "analysis panicked for {}: {message}",
                path.display()
            ))
        }
    }
}

/// Re-stamp path-derived values on a cache-hit report.
///
/// The analysis cache is keyed by content hash, so a hit may originate from an
/// identical-bytes file with a *different name*; `file.basename`/`file.stem`
/// in the cached values tree describe the cache donor, not the file being
/// analyzed. Observed symptom: `cleave diff` of two identical files reported a
/// phantom `file.basename` change against an unrelated donor's name.
pub(crate) fn restamp_path_derived_values(report: &mut AnalysisReport, path: &Path) {
    let name = path.file_name().and_then(|n| n.to_str());
    let stem = path.file_stem().and_then(|s| s.to_str());

    // Reports reconstructed from the cross-context FileAnalysis cache carry
    // only flattened member kv; their values_tree was intentionally dropped.
    // Re-stamp that representation too, otherwise identical bytes reused under
    // another archive path retain the cache donor's name and create a phantom
    // kv diff.
    if let Some(kv) = report.cached_member_kv.as_mut() {
        if let Some(name) = name
            && let Some(basename) = kv.get_mut("file.basename")
        {
            *basename = serde_json::Value::String(name.to_string());
        }
        if let Some(stem) = stem
            && let Some(value) = kv.get_mut("file.stem")
        {
            *value = serde_json::Value::String(stem.to_string());
        }
    }

    let Some(file_values) = report
        .values_tree
        .as_deref_mut()
        .and_then(|tree| tree.get_mut("file"))
        .and_then(serde_json::Value::as_object_mut)
    else {
        return;
    };
    if let Some(name) = name
        && let Some(basename) = file_values.get_mut("basename")
    {
        *basename = serde_json::Value::String(name.to_string());
    }
    // `Path::file_stem` matches the extractor's stem convention: leading-dot
    // names keep the dot, and only the last extension is stripped.
    if let Some(s) = stem
        && let Some(stem) = file_values.get_mut("stem")
    {
        *stem = serde_json::Value::String(s.to_string());
    }
}

/// Synthesize an `AnalysisReport` from a cached `FileAnalysis` (cross-context file cache hit).
pub(crate) fn report_from_file_analysis(
    fa: types::FileAnalysis,
    path: String,
) -> types::AnalysisReport {
    use types::TargetInfo;
    // Exhaustive on purpose: a new `FileAnalysis` field is a compile error
    // here until someone decides whether a cache replay restores it.
    let types::FileAnalysis {
        file_type,
        size,
        sha256,
        arch,
        traits,
        findings,
        suppressions,
        context,
        structure,
        strings,
        imports,
        exports,
        functions,
        sections,
        syscalls,
        yara_matches,
        filefacts,
        analysis_gaps,
        filefacts_metrics,
        identity,
        paths,
        directories,
        env_vars,
        kv,
        // Placement and derived output, recomputed when the report is folded
        // back into a file entry.
        id: _,
        path: _,
        parent_id: _,
        depth: _,
        rel: _,
        via: _,
        role: _,
        score: _,
        counts: _,
        encoding: _,
        formula: _,
        composite_sources: _,
        precompact_facts: _,
        precompact_refs: _,
    } = fa;
    let target = TargetInfo {
        path,
        file_type,
        size_bytes: size,
        sha256,
        architectures: arch.map(|a| vec![a]),
    };
    let mut report = types::AnalysisReport::new(target);
    // Every caller synthesizes from a file-analysis cache entry, so the report
    // is a replay rather than a fresh pass.
    report.cache_hit = true;
    report.traits = traits;
    report.findings = findings;
    report.suppressions = suppressions;
    report.context = context;
    report.structure = structure;
    report.strings = strings;
    report.imports = imports;
    report.exports = exports;
    report.functions = functions;
    report.sections = sections;
    report.syscalls = syscalls;
    report.yara_matches = yara_matches;
    report.filefacts = filefacts;
    report.analysis_gaps = analysis_gaps;
    report.filefacts_metrics = filefacts_metrics;
    report.identity = identity;
    report.paths = paths;
    report.directories = directories;
    report.env_vars = env_vars;
    // The compact member cache stores kv already flattened (no `values_tree`).
    // Carry it through so `into_file_analysis` restores it verbatim rather than
    // yielding empty kv — the diff reads both `identity` and `kv`, and dropping
    // them made an unchanged cached member read as changed. See
    // `AnalysisReport::cached_member_kv`.
    if !kv.is_empty() {
        report.cached_member_kv = Some(kv);
    }
    let actual_path = report.target.path.clone();
    restamp_path_derived_values(&mut report, Path::new(&actual_path));
    report
}

/// Rebase a decoded child's absolute or basename-relative temporary path.
pub(super) fn rebase_decoded_child_path(
    path: &str,
    temporary: &std::path::Path,
    decoded: &str,
) -> String {
    let full = temporary.to_string_lossy();
    let name = temporary
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("");
    let suffix = path.strip_prefix(full.as_ref()).or_else(|| {
        if name.is_empty() {
            None
        } else {
            path.strip_prefix(name)
        }
    });
    match suffix {
        Some(suffix)
            if suffix.is_empty() || suffix.starts_with("!!") || suffix.starts_with("##") =>
        {
            format!("{decoded}{suffix}")
        }
        _ => path.to_string(),
    }
}

mod binary;
#[cfg(test)]
mod decoded_child_path_tests;

/// Process encoded payloads discovered during string extraction: emit the
/// `metadata/encoded-payload/*` finding for each and recursively analyze the
/// decoded bytes (depth-limited), merging the decoded traits/findings back.
///
/// Factored out of `analyze_file_with_resources_at_depth` so the archive
/// member path can run the SAME payload analysis — previously only top-level
/// files got it, so an obfuscated payload inside an archive (npm/zip/jar) lost
/// its encoded-payload finding and every trait derived from the decoded
/// content. Detection must not depend on whether a file was scanned standalone
/// or as an archive member.
pub(crate) fn process_encoded_payloads(
    encoded_payloads: Vec<types::ExtractedPayload>,
    report: &mut types::AnalysisReport,
    path: &std::path::Path,
    source: &[u8],
    file_type: FileType,
    analysis_depth: u32,
    options: &AnalysisOptions,
    engine: &Engine,
) {
    let has_mime = encoded_payloads
        .iter()
        .any(|p| p.encoding_chain.as_slice() == ["mime-base64"]);
    for payload in encoded_payloads {
        if options
            .cancellation
            .as_ref()
            .is_some_and(|f| f.load(std::sync::atomic::Ordering::Relaxed))
        {
            break;
        }
        if let Some(reason) = payload_filter::skip_reason(file_type, &payload, source, report) {
            tracing::debug!(reason, preview = %payload.preview, "skipping decoded payload");
            continue;
        }

        // Add finding for the encoded payload
        let is_unknown_unicode_escape = payload.detected_type == FileType::Unknown
            && payload
                .encoding_chain
                .iter()
                .any(|encoding| encoding == "unicode-escape");
        // minisign/signify signatures; judged by the decoded text, not by the
        // file name, which the author chooses.
        let is_detached_signature_data = payload.detected_type == FileType::Unknown
            && payload
                .preview
                .to_ascii_lowercase()
                .starts_with("untrusted comment: signature");
        let crit = if is_unknown_unicode_escape || is_detached_signature_data {
            types::Criticality::Baseline
        } else if payload.encoding_chain.as_slice() == ["nrv2b-8"] {
            // Static decompression is neutral; infer intent from child analysis.
            types::Criticality::Notable
        } else {
            match payload.detected_type {
                FileType::Python
                | FileType::Shell
                | FileType::Elf
                | FileType::MachO
                | FileType::Pe => types::Criticality::Suspicious,
                _ => types::Criticality::Notable,
            }
        };
        let desc = if is_detached_signature_data {
            "Encoded detached signature data".to_string()
        } else if is_unknown_unicode_escape {
            "Decoded unicode-escape content".to_string()
        } else if payload.detected_type == FileType::Pe
            && payload.encoding_chain.as_slice() == ["nrv2b-8"]
        {
            "NRV2B-8 compressed PE image recovered".to_string()
        } else if payload.detected_type == FileType::Pe
            && payload.encoding_chain.as_slice() == ["xor"]
        {
            "XOR-encoded PE image recovered".to_string()
        } else if payload.detected_type == FileType::Pe
            && payload.encoding_chain.as_slice() == ["media-xor-pe"]
        {
            "XOR-encoded PE recovered from image".to_string()
        } else if payload.detected_type == FileType::Pe
            && payload.encoding_chain.as_slice() == ["media-base64-pe"]
        {
            "Base64-encoded PE recovered from image".to_string()
        } else if payload.encoding_chain.as_slice() == ["url"] {
            "Percent-encoded content decoded".to_string()
        } else if payload.detected_type == FileType::Unknown {
            // Successful decoding alone does not establish an embedded payload.
            // Uniform padding, identifiers and arbitrary data can also decode.
            format!(
                "Candidate bytes decoded: {}",
                payload.encoding_chain.join(" → ")
            )
        } else {
            format!(
                "Encoded content decoded: {}",
                payload.encoding_chain.join(" → ")
            )
        };

        report.findings.push(types::Finding {
            precomputed_spans: None,
            src: None,
            id: format!(
                "metadata/encoded-payload/{}",
                payload.encoding_chain.join("-")
            )
            .into(),
            kind: types::FindingKind::Structural,
            desc: desc.into(),
            conf: 0.9,
            crit,
            mbc: None,
            attack: None,
            trait_refs: vec![],
            evidence: vec![types::Evidence {
                method: "pattern".to_string(),
                source: "cleave".to_string(),
                value: format!("{} <{}>", payload.preview, payload.encoding_chain.join("+")),
                location: Some(format!("offset:{}", payload.original_offset)),
                ..Default::default()
            }],
            match_count: 0,
            source_file: None,
            downgraded: false,
        });

        // Unknown-type payloads have no analyzer and would immediately bail — skip
        // the expensive temp-file write + full pipeline call.  The encoded-payload
        // finding was already pushed above so the discovery is still recorded.
        if payload.detected_type == FileType::Unknown {
            tracing::debug!(
                encoding = %payload.encoding_chain.join("+"),
                preview = %payload.preview,
                "Skipping recursive analysis for unrecognized payload type"
            );
            continue;
        }

        // Analyze the decoded payload (with depth limit to prevent stack overflow)
        if analysis_depth >= MAX_ANALYSIS_DEPTH {
            tracing::warn!(
                depth = analysis_depth,
                path = %path.display(),
                "Encoded payload analysis depth limit reached ({MAX_ANALYSIS_DEPTH}), skipping deeper analysis"
            );
            report.findings.push(types::Finding {
                precomputed_spans: None,
                src: None,
                id: "objectives/anti-static/obfuscation/multi-layer/deep-nesting"
                    .to_string()
                    .into(),
                kind: types::FindingKind::Indicator,
                desc: format!(
                    "Encoded payload nesting exceeds {MAX_ANALYSIS_DEPTH} layers, \
                     a technique used to resist automated analysis"
                )
                .into(),
                conf: 0.95,
                crit: types::Criticality::Suspicious,
                mbc: Some("OB0002".into()),
                attack: Some("T1027".into()),
                trait_refs: vec![],
                evidence: vec![types::Evidence {
                    method: "structural".to_string(),
                    source: "cleave".to_string(),
                    value: format!("depth={analysis_depth}"),
                    location: None,
                    ..Default::default()
                }],
                match_count: 0,
                source_file: None,
                downgraded: false,
            });
            break;
        }
        if let Ok(mut temp_file) = tempfile::NamedTempFile::new() {
            let _ = std::io::Write::write_all(&mut temp_file, &payload.data);
            if let Ok(mut payload_report) = analyze_file_with_resources_at_depth(
                temp_file.path(),
                options,
                engine,
                None,
                None,
                analysis_depth + 1,
            ) {
                // MIME attachments and recovered media executables are real
                // child files. Keep their attribution rather than claiming the
                // enclosing mail or image directly implements PE behavior.
                if payload.encoding_chain.as_slice() == ["mime-base64"]
                    || payload.encoding_chain.as_slice() == ["media-base64-pe"]
                    || payload.encoding_chain.as_slice() == ["media-xor-pe"]
                {
                    let virtual_path = types::encode_decoded_path(
                        &path.display().to_string(),
                        &payload.encoding_chain,
                        payload.original_offset,
                    );
                    payload_report.target.path = virtual_path.clone();
                    let (mut entry, mut children, _) = payload_report.into_file_analysis(0, engine);
                    entry.path = virtual_path.clone();
                    entry.depth = 1;
                    entry.encoding = Some(payload.encoding_chain.clone());
                    for child in &mut children {
                        child.path =
                            rebase_decoded_child_path(&child.path, temp_file.path(), &virtual_path);
                        child.depth += 1;
                        for finding in &mut child.findings {
                            if let Some(source) = &mut finding.source_file {
                                *source = rebase_decoded_child_path(
                                    source,
                                    temp_file.path(),
                                    &virtual_path,
                                );
                            }
                        }
                    }
                    for finding in &mut entry.findings {
                        if let Some(source) = &mut finding.source_file {
                            *source =
                                rebase_decoded_child_path(source, temp_file.path(), &virtual_path);
                        }
                    }
                    report.files.push(entry);
                    report.files.extend(children);
                    continue;
                }
                // Merge traits from payload analysis
                for mut trait_item in payload_report.traits {
                    // Prefix trait offset with encoding chain
                    if let Some(ref offset) = trait_item.offset {
                        trait_item.offset =
                            Some(format!("{}!{}", payload.encoding_chain.join("+"), offset));
                    } else {
                        trait_item.offset = Some(format!("{}!", payload.encoding_chain.join("+")));
                    }
                    report.traits.push(trait_item);
                }

                // Merge findings from payload analysis
                let existing: std::collections::HashSet<crate::types::Istr> =
                    report.findings.iter().map(|f| f.id.clone()).collect();
                for finding in payload_report.findings {
                    if !existing.contains(finding.id.as_str()) {
                        report.findings.push(finding);
                    }
                }
            }
        }
    }
    if has_mime {
        let mut origins: rustc_hash::FxHashMap<String, composite_rules::TypeMask> =
            rustc_hash::FxHashMap::default();
        let root_bit = composite_rules::FileType::from_str(&report.target.file_type).type_bit();
        for finding in &report.findings {
            *origins.entry(finding.id.to_string()).or_default() |= root_bit;
        }
        let mut nested = Vec::new();
        for child in &report.files {
            let bit = composite_rules::FileType::from_str(&child.file_type).type_bit();
            for finding in &child.findings {
                *origins.entry(finding.id.to_string()).or_default() |= bit;
                nested.push(finding);
            }
        }
        let added = engine.rules().evaluate_container_composites(
            report,
            source,
            nested,
            &report.target.file_type,
            Some(&origins),
        );
        report.findings.extend(added);
    }
}

/// An XOR "payload" whose evidence sits in ELF metadata that is never loaded
/// (comments, symbol and string tables, debug info) is not an encoded blob.
fn drop_xor_hits_in_elf_metadata(report: &mut AnalysisReport) {
    let sections = &report.sections;
    report.findings.retain(|finding| {
        finding.id != "metadata/encoded-payload/xor"
            || !finding.evidence.iter().any(|evidence| {
                evidence
                    .location
                    .as_deref()
                    .and_then(|location| location.strip_prefix("offset:"))
                    .and_then(|value| value.parse::<usize>().ok())
                    .is_some_and(|offset| payload_filter::is_elf_metadata_offset(offset, sections))
            })
    });
}

/// Payloads encoded inside the file (hex, base64, XOR, packed executables,
/// MIME attachments), found from its strings and bytes.
fn encoded_payloads(
    file_type: FileType,
    file_data: &[u8],
    stng_strings: &[stng::ExtractedString],
    file_ctx: Option<&crate::analysis_context::AnalysisContext<'_>>,
) -> Vec<types::ExtractedPayload> {
    let mut payloads = if stng_strings.is_empty() {
        Vec::new()
    } else {
        extractors::encoded_payload::extract_encoded_payloads(stng_strings)
    };
    payloads.extend(extractors::encoded_payload::extract_nibble_table_payloads(
        file_data,
    ));
    payloads.extend(extractors::encoded_payload::extract_mime_attachments(
        file_data,
    ));
    if matches!(
        file_type,
        FileType::Gif | FileType::Jpeg | FileType::Png | FileType::Bmp | FileType::Webp
    ) {
        payloads.extend(extractors::encoded_payload::extract_media_base64_pes(
            file_data,
        ));
        payloads.extend(extractors::encoded_payload::extract_media_xor_pes(
            file_data,
        ));
    }
    payloads.extend(file_ctx.and_then(|ctx| {
        extractors::encoded_payload::xor_encoded_pe(ctx.parsed.fileid(), file_data)
    }));
    payloads.extend(extractors::encoded_payload::xor_encoded_machos(
        file_data,
        stng_strings,
    ));

    if file_type == FileType::Pe {
        payloads.extend(extractors::encoded_payload::nrv8_encoded_pes(file_data));
    }
    payloads
}

/// A finished report for these bytes from the analysis caches: the
/// whole-report cache first, then the per-file cache shared with archive
/// members.
fn cached_report(
    sha256: &str,
    report_type_key: &str,
    file_type_key: &str,
    options: &AnalysisOptions,
    engine: &Engine,
    path: &Path,
) -> Option<AnalysisReport> {
    let path_string = path.display().to_string();
    if let Some(mut report) = analysis_cache::report_cache_lookup(
        sha256,
        report_type_key,
        options,
        engine.settings(),
        &path_string,
        Some(engine.rules().as_ref()),
    ) {
        report.target.path = path_string;
        report.analysis_timestamp = Some(chrono::Utc::now());
        report.cache_hit = true;
        restamp_path_derived_values(&mut report, path);
        tracing::debug!(sha256, "analysis cache hit (report)");
        return Some(report);
    }
    let fa = analysis_cache::file_analysis_cache_lookup(
        sha256,
        file_type_key,
        options,
        engine.settings(),
        &path_string,
        Some(engine.rules().as_ref()),
    )?;
    tracing::debug!(sha256, "analysis cache hit (file, cross-context)");
    Some(report_from_file_analysis(fa, path_string))
}

pub(super) fn analyze_file_with_resources_at_depth<P: AsRef<Path>>(
    path: P,
    options: &AnalysisOptions,
    engine: &Engine,
    preloaded: Option<file_io::FileData>,
    precomputed_sha256: Option<String>,
    analysis_depth: u32,
) -> Result<AnalysisReport> {
    let capability_mapper = engine.rules();
    let yara_engine = engine.yara();
    // Every file this analysis parses goes through these: the engine's cache
    // settings, and the request's cancellation flag.
    let facts_options = match options.cancellation.as_deref() {
        Some(flag) => engine.filefacts_options().cancellation(flag),
        None => engine.filefacts_options(),
    };
    struct ThreadLocalCacheClearGuard;

    impl Drop for ThreadLocalCacheClearGuard {
        fn drop(&mut self) {
            crate::composite_rules::evaluators::clear_thread_local_caches();
        }
    }

    let path = path.as_ref();
    // Clear thread-local UTF-8 / scanner caches after every analysis frame,
    // including nested payload decoding (analysis_depth > 0). Leaving entries
    // in the LRU across depth levels let a deep decoding chain pin multiple
    // multi-hundred-MB UTF-8 caches on a single worker thread.
    let _thread_local_cache_clear_guard = ThreadLocalCacheClearGuard;
    let span = tracing::info_span!("analyze", path = %path.display());
    let _enter = span.enter();

    // Report fine-grained progress through the phase tracker so a stuck
    // analysis says something more useful than `cleave:init` for ten minutes.
    let set_phase = |p: &str| {
        if let Some(ref tracker) = options.phase {
            tracker.set(p);
        }
    };

    // Log BEFORE processing to ensure we capture what file causes OOM crashes
    tracing::debug!("Starting analysis");

    // Read file once — reuse pre-loaded data if available (e.g. from analyze_bytes
    // or the fast-path cache check). When data is preloaded the path may be synthetic
    // and not exist on disk, so skip the filesystem checks.
    set_phase("cleave:read");
    let file_data_wrapper = match preloaded {
        Some(data) => data,
        None => {
            if !path.exists() {
                anyhow::bail!("Path does not exist: {}", path.display());
            }
            if path.is_dir() {
                anyhow::bail!(
                    "Path is a directory, use scan_directory instead: {}",
                    path.display()
                );
            }
            file_io::read_file_smart(path)?
        }
    };
    let file_data = file_data_wrapper.as_slice();
    let path_label = path.to_str().unwrap_or("unknown");

    // Detect file type from already-loaded data (no extra read)
    set_phase("cleave:detect");
    tracing::debug!("Detecting file type for: {}", path.display());
    let file_type = analyzers::detect_file_type_from_data(path, file_data);
    let file_type_key = file_type.label();
    let report_type_key = analysis_cache::report_type_key(file_type_key, path);
    tracing::debug!(
        "Detected file type: {:?} for: {}",
        file_type,
        path.display()
    );

    // Explicit file analysis should still run for unknown top-level inputs so callers can
    // inspect ad hoc files directly. Directory scans keep their own pre-filtering logic.

    // Get file size for memory tracking (from loaded data, avoiding a metadata syscall)
    let file_size = file_data.len() as u64;

    // Log memory state before processing
    memory_tracker::log_before_file_processing(path_label, file_size);

    let analysis_start = std::time::Instant::now();

    // Track file read for memory monitoring
    memory_tracker::global_tracker().record_file_read(file_size, path_label);

    // Reuse a precomputed hash when the caller already hashed these bytes for a
    // fast-path cache lookup; otherwise compute it here. Skipping the recompute
    // matters for large inputs — SHA256 of a 100 MB archive is ~200 ms.
    let sha256_hex =
        precomputed_sha256.unwrap_or_else(|| analyzers::utils::calculate_sha256(file_data));

    // Caller skip hook: consulted with the sha256 right after hashing, before any
    // analysis. A `true` short-circuits to a minimal target-only report — the
    // caller (e.g. an embedding host's known-good bloom filter) already has a verdict and
    // recognizes the skip by re-checking the sha. Cheaper than the cache lookup,
    // and bloom-agnostic.
    if let Some(predicate) = &options.skip_predicate
        && (predicate.0)(&sha256_hex, path)
    {
        return Ok(AnalysisReport::new(types::TargetInfo {
            path: path.display().to_string(),
            file_type: String::new(),
            size_bytes: file_size,
            sha256: sha256_hex,
            architectures: None,
        }));
    }

    set_phase("cleave:cache_lookup");
    if let Some(report) = cached_report(
        &sha256_hex,
        &report_type_key,
        file_type_key,
        options,
        engine,
        path,
    ) {
        memory_tracker::log_after_file_processing(path_label, file_size, analysis_start.elapsed());
        return Ok(report);
    }

    // Two sides of a directory/archive diff commonly reach this point with
    // the same SHA256 at the same time. The persistent cache cannot prevent
    // that first-wave race, so single-flight identical analyses in-process.
    let flight = loop {
        let flight = analysis_cache::acquire_report_flight(
            &sha256_hex,
            &report_type_key,
            options,
            engine.settings(),
        );
        if flight.is_owner() {
            break Some(flight);
        }
        if let Some(mut report) = flight.wait() {
            // A report with path-derived findings or decoded children is
            // bound to the path it was evaluated under (same guard as the
            // archive-member flight); fall through to a fresh analysis.
            let path_string = path.display().to_string();
            if !shared_resources::adopt_report_under(&mut report, &path_string, engine.rules()) {
                tracing::debug!(
                    sha256 = %sha256_hex,
                    "Analysis single-flight hit is path-bound; analyzing independently"
                );
                break None;
            }
            report.analysis_timestamp = Some(chrono::Utc::now());
            restamp_path_derived_values(&mut report, path);
            tracing::debug!(sha256 = %sha256_hex, "Analysis single-flight hit");
            memory_tracker::log_after_file_processing(
                path_label,
                file_size,
                analysis_start.elapsed(),
            );
            return Ok(report);
        }
        if rayon::current_thread_index().is_some() {
            tracing::debug!(
                sha256 = %sha256_hex,
                "Analysis flight busy on Rayon worker; analyzing independently"
            );
            break None;
        }
        // The owner failed. Its Drop released the slot; retry so this caller
        // can provide the normal error (or successful fallback) itself.
    };

    // Recheck persistent caches after becoming owner. A non-overlapping
    // caller may have completed between the first lookup and acquisition.
    if let Some(report) = cached_report(
        &sha256_hex,
        &report_type_key,
        file_type_key,
        options,
        engine,
        path,
    ) {
        if let Some(flight) = flight {
            flight.complete(None);
        }
        return Ok(report);
    }

    // Extension/content mismatch is emitted by YAML traits under
    // objectives/evasion/masquerade/extension-mismatch/ (consuming the
    // filefacts consistency.extension_content_mismatch metric).

    // Normalize text encoding (UTF-16 LE/BE BOM -> UTF-8) before string
    // extraction, metrics, and trait matching.
    //
    // Why: `type: text` on source/text file types is evaluated by `eval_raw()`
    // against the file content (so cross-line regexes like `[\s\S]{0,N}` keep
    // working — ~950 traits depend on that). A UTF-16 script is null-interleaved
    // at the byte level (`E\0x\0e\0c\0...`), so without normalization no text
    // pattern matches and the file looks empty (e.g. a UTF-16 VBS dropper). We
    // normalize the content the matcher reads rather than reroute `type: text`
    // to the per-line stng strings, which would lose those cross-line patterns.
    //
    // Normalization mirrors `file_io::read_file_normalized`. A BOM is the easy
    // case; BOM-less UTF-16 is recognized by the NUL-interleaving itself, which
    // no binary or archive format survives (it needs ~95% of one byte of every
    // pair to be NUL and ~90% of the other to be printable text). SHA and
    // file-type detection above already ran on the original bytes, so file
    // identity is unchanged either way.
    let normalized_data: Option<file_io::FileData> =
        match file_io::normalize_text_encoding(file_data) {
            std::borrow::Cow::Owned(decoded) => Some(file_io::FileData::Owned(decoded)),
            std::borrow::Cow::Borrowed(_) => None,
        };
    let file_data: &[u8] = normalized_data
        .as_ref()
        .map_or(file_data, file_io::FileData::as_slice);

    // For binary types (PE, ELF, MachO) run the YARA scan concurrently with stng extraction.
    // Both only need file_data and are independent of each other, so they can overlap.
    // On production runs where recovery output is cached, YARA (~270ms) otherwise sits between
    // stng (~290ms) and structural (~50ms), adding to the critical path.  Running them in
    // parallel eliminates that 270ms from the wall-clock total.
    let binary_yara_ftypes: Option<&[&str]> = if yara_engine.is_none() {
        None
    } else {
        match file_type {
            FileType::Pe => Some(&["pe", "exe", "dll", "bat", "ps1"]),
            FileType::Elf => Some(&["elf", "so", "ko"]),
            FileType::MachO => Some(&["macho", "dylib", "kext"]),
            _ => None,
        }
    };

    // Extract strings with stng ONCE - used for encoded payloads and passed to analyzers.
    // Skip extraction for archive files themselves as they are expected to contain
    // binary noise and their contents will be analyzed separately.
    // For binary types, overlap stng with YARA scan (both need only file_data).
    set_phase(if binary_yara_ftypes.is_some() {
        "cleave:stng+yara"
    } else {
        "cleave:stng"
    });
    let cancel_for_yara = options.cancellation.clone();
    // filefacts is the single string-extraction authority. lib.rs opens the
    // full-file context ONCE here (overlapping parse+scan with the YARA
    // prefetch for binaries) and harvests `text()`. PE/ELF additionally
    // thread this context into their arm for structural facts; Mach-O opens a
    // per-arch slice for structure but still sources its strings from here.
    // Types whose analyzer reads from a filefacts `AnalysisContext`: open it
    // once here and thread it through `AnalysisInput` so the file is parsed a
    // single time. Source code (unified/generic) plus the image analyzers
    // (jpeg/png) and Java bytecode qualify; binaries take the dedicated arms
    // above, and Office types with their own parser are intentionally excluded.
    let threads_ctx = file_type.is_source_code()
        || matches!(
            file_type,
            FileType::Jpeg
                | FileType::Png
                | FileType::Font
                | FileType::Wav
                | FileType::Aiff
                | FileType::Mp3
                | FileType::Mp4
                | FileType::Avif
                | FileType::Tiff
                | FileType::Ico
                | FileType::Gif
                | FileType::Bmp
                | FileType::Webp
                | FileType::Wasm
                | FileType::Dex
                | FileType::JavaClass
        );
    let yara_prefetch = |ftypes: &[&str]| {
        if cancel_for_yara
            .as_ref()
            .is_some_and(|c| c.load(std::sync::atomic::Ordering::Relaxed))
        {
            return None;
        }
        yara_engine
            .filter(|e| e.is_loaded())
            .map(|e| e.scan_bytes(file_data, Some(ftypes)))
    };
    // Open filefacts on the full file and harvest its `text()` rows — the same
    // string scan cleave used to run standalone, but now sourced from the one
    // authority. The rows are extracted here, inside the timed (and possibly
    // YARA-overlapped) closure, and borrowed from the context below; the
    // caller threads the same context into the analyzer (avoiding a second
    // parse). Mirrors `stng_scan`'s `(_, elapsed)`.
    let open_ctx_strings = || {
        let t = std::time::Instant::now();
        let ctx = crate::analysis_context::AnalysisContext::open_with(
            facts_options.clone(),
            path,
            file_data,
        );
        let _ = ctx.text_rows();
        (Some(ctx), t.elapsed().as_millis() as u64)
    };
    let (file_ctx, stage_stng_ms, prefetched_yara) = if file_type.is_archive() {
        (None, 0u64, None)
    } else if let Some(ftypes) = binary_yara_ftypes {
        // A lone binary benefits from overlapping filefacts with YARA. In a
        // worker, however, every top-level analysis already runs on its own
        // blocking thread. Letting all of them enter `rayon::join` adds two
        // runnable trees per file on top of those coordinators (48 analyses on
        // uruk-hai drove 111/128 cores while completing fewer files than 24).
        // Keep the overlap only on the single-analysis fast path.
        if crate::rayon_nest::inner_work_parallel() {
            let ((ctx, ms), yara) = rayon::join(open_ctx_strings, || yara_prefetch(ftypes));
            (ctx, ms, yara)
        } else {
            let (ctx, ms) = open_ctx_strings();
            let yara = yara_prefetch(ftypes);
            (ctx, ms, yara)
        }
    } else {
        // Every other type sources strings from the same filefacts view.
        // Source + image types additionally thread the context into their
        // analyzer (below) so the file is parsed a single time.
        let (ctx, ms) = open_ctx_strings();
        (ctx, ms, None)
    };
    let stng_strings = file_ctx
        .as_ref()
        .map_or(&[][..], crate::analysis_context::AnalysisContext::text_rows);

    let encoded_payloads = encoded_payloads(file_type, file_data, stng_strings, file_ctx.as_ref());

    // Create unified analysis input - all analyzers receive the same pre-extracted data
    let mut input = analyzers::AnalysisInput::with_payloads(
        path,
        file_data,
        stng_strings,
        &encoded_payloads,
        file_type,
    )
    .with_sha256(sha256_hex.clone());
    input.cancellation = options.cancellation.clone();

    // Hand the source/image analyzer the context we already opened so it
    // reuses the filefacts parse instead of opening its own. Binary arms use
    // `file_ctx` directly (below), so only the threaded path lends it to the
    // input.
    if threads_ctx && let Some(ctx) = file_ctx.as_ref() {
        input = input.with_parsed_ctx(ctx);
    }

    // Bail early if already cancelled before starting expensive structural analysis
    if options
        .cancellation
        .as_ref()
        .is_some_and(|f| f.load(std::sync::atomic::Ordering::Relaxed))
    {
        anyhow::bail!("Analysis cancelled before structural phase");
    }

    // Route to appropriate analyzer.
    // Binary analyzers (MachO, Elf, Pe) use parallel YARA for performance.
    // All other analyzers use analyze_input() for unified data flow.
    let structural_start = std::time::Instant::now();
    // Default structural phase for every file type. The specialized arms below
    // (binary struct+yara, archive) refine it; the office / java-class /
    // package-manifest arms set no phase of their own, so without this they would
    // report the prior `cleave:stng` phase for their entire structural pass.
    set_phase(&format!("analyze:{}", file_type.report_file_type()));
    let compact_nested_values = engine.compact_members();
    let mut report = match file_type {
        FileType::MachO => Ok(binary::analyze_macho(
            binary::BinaryInput {
                path,
                data: file_data,
                sha256: &sha256_hex,
                ctx: file_ctx.as_ref(),
                options,
                engine,
                prefetched_yara,
            },
            stng_strings,
            &facts_options,
            analysis_depth,
        )),
        FileType::Elf => Ok(binary::analyze_elf(binary::BinaryInput {
            path,
            data: file_data,
            sha256: &sha256_hex,
            ctx: file_ctx.as_ref(),
            options,
            engine,
            prefetched_yara,
        })),
        FileType::Pe => binary::analyze_pe(binary::BinaryInput {
            path,
            data: file_data,
            sha256: &sha256_hex,
            ctx: file_ctx.as_ref(),
            options,
            engine,
            prefetched_yara,
        }),
        FileType::JavaClass => analyzers::java_class::JavaClassAnalyzer::new()
            .with_engine(engine.clone())
            .analyze_input(&input),
        FileType::OleDoc | FileType::Msi | FileType::Ooxml => {
            analyzers::office::OfficeAnalyzer::new()
                .with_engine(engine.clone())
                .with_cancellation(options.cancellation.clone())
                .analyze_input(&input)
        }
        ref ft if ft.is_archive() => {
            set_phase(&format!("archive:{}", ft.report_file_type()));
            let mut analyzer = analyzers::archive::ArchiveAnalyzer::new()
                .with_engine(engine.clone())
                .with_zip_passwords(options.zip_passwords.clone())
                .with_max_memory_file_size(options.max_memory_file_size)
                .with_analysis_options(Arc::new(options.clone()));
            if let Some(engine) = yara_engine {
                analyzer = analyzer.with_yara_arc(engine.clone());
            }
            if let Some(ref flag) = options.cancellation {
                analyzer = analyzer.with_cancellation(flag.clone());
            }
            analyzer.analyze_input(&input)
        }
        FileType::PackageJson => analyzers::package_json::PackageJsonAnalyzer::new()
            .with_engine(engine.clone())
            .analyze_input(&input),
        FileType::PackageLockJson => analyzers::generic::GenericAnalyzer::new(file_type)
            .with_engine(engine.clone())
            .analyze_input(&input),
        FileType::VsixManifest => analyzers::vsix_manifest::VsixManifestAnalyzer::new()
            .with_engine(engine.clone())
            .analyze_input(&input),
        // All source code languages use the unified analyzer (or generic fallback)
        _ => {
            if let Some(analyzer) = analyzers::analyzer_for_file_type_arc(&file_type, engine) {
                analyzer.analyze_input(&input)
            } else {
                // No dedicated analyzer — return a minimal report with basic metadata.
                // This allows callers (analyze_file, scan_directory with all_files=true)
                // to handle files of any type without erroring.
                let target = types::TargetInfo {
                    path: path.display().to_string(),
                    file_type: file_type.report_file_type(),
                    size_bytes: file_data.len() as u64,
                    sha256: sha256_hex.clone(),
                    architectures: None,
                };
                Ok(types::AnalysisReport::new(target))
            }
        }
    }?;

    // Identity and the filefacts view are normalized the same way for every
    // file. Most analyzers attach them from the context they already opened;
    // for the rest (documents, images, the no-dedicated-analyzer path) attach
    // them here so no analyzer can silently drop them — losing, e.g., a
    // manifest's declared dependencies. Gated on `is_none` so a path that
    // already attached pays nothing, and the single open serves both.
    if report.identity.is_none() || report.filefacts.is_none() {
        // Reuse the context already opened for this file (binary/source/generic
        // paths all opened one above). Its extraction — recovery included — is
        // cached on the `ParsedFile`, so deriving identity here is free.
        // Re-`open`ing instead, as this used to, re-ran the *entire*
        // extraction pipeline (a second recovery per binary) just to recompute
        // an identity that is empty for stripped/unsigned files. Only open a
        // fresh context only for paths that never opened one (archives).
        let fresh = if file_ctx.is_none() && input.parsed_ctx.is_none() {
            Some(crate::analysis_context::AnalysisContext::open_with(
                facts_options.clone(),
                path,
                file_data,
            ))
        } else {
            None
        };
        let ctx = file_ctx.as_ref().or(input.parsed_ctx).or(fresh.as_ref());
        if let Some(ctx) = ctx {
            if report.identity.is_none() {
                report.identity = ctx.identity();
            }
            if report.filefacts.is_none() {
                let view = crate::types::FilefactsView::of(ctx, compact_nested_values);
                if !view.is_empty() {
                    report.filefacts = Some(view);
                }
            }
        }
    }
    // `AnalysisInput` borrows the decoded payload list. Structural analysis is
    // complete, so end that borrow before the payloads are consumed below.
    drop(input);
    let stage_structural_ms = structural_start.elapsed().as_millis() as u64;

    // Process encoded payloads and analyze them
    let payloads_start = std::time::Instant::now();
    if !encoded_payloads.is_empty() {
        set_phase("payloads");
    }
    process_encoded_payloads(
        encoded_payloads,
        &mut report,
        path,
        file_data,
        file_type,
        analysis_depth,
        options,
        engine,
    );
    let stage_payloads_ms = payloads_start.elapsed().as_millis() as u64;

    // Bail early if cancelled — skip YARA and remaining phases
    if options
        .cancellation
        .as_ref()
        .is_some_and(|f| f.load(std::sync::atomic::Ordering::Relaxed))
    {
        anyhow::bail!("Analysis cancelled before YARA phase");
    }

    // Run YARA for file types that didn't handle it internally.
    // Binary types (MachO, Elf, Pe) and archives already ran YARA with parallel scanning above.
    set_phase("yara");
    let yara_start = std::time::Instant::now();
    let handled_yara_internally =
        matches!(file_type, FileType::MachO | FileType::Elf | FileType::Pe)
            || file_type.is_archive();
    // A YARA rule file lists the strings and hex patterns that YARA rules match
    // on, so scanning one with the YARA engine self-detects: the rule's own
    // subject is reported as a hostile hit on the corpus that documents it.
    // Rule files are classified as PHP/Python/Kotlin/shell-like source, so they
    // reach this arm as ordinary programs. Mirrors
    // `archive_member_yara_skip_reason`, which does the same for members.
    let is_yara_rule_source = file_type == FileType::Yara
        || AsRef::<Path>::as_ref(&path)
            .extension()
            .and_then(|e| e.to_str())
            .is_some_and(|e| e.eq_ignore_ascii_case("yar") || e.eq_ignore_ascii_case("yara"));
    if !handled_yara_internally
        && !report
            .metadata
            .tools_used
            .iter()
            .any(|tool| tool == "yara-x")
        && !is_yara_rule_source
        && yara_engine.is_some_and(|yara| yara.is_loaded())
        && file_type.is_analyzed()
    {
        // This fallback also uses the shared stage, so inline results support
        // traits instead of being discarded by a late findings-only scan.
        engine.evaluate_and_merge_findings_with_precomputed(
            &mut report,
            file_data,
            crate::capabilities::AnalysisBorrow::new(None),
            None,
            None,
            None,
            options.cancellation.as_deref(),
        );
        capability_mapper
            .apply_retroactive_unless_suppression_to_findings(&mut report.findings, None);
    }
    let stage_yara_ms = yara_start.elapsed().as_millis() as u64;
    set_phase("done");

    if file_type == FileType::Elf {
        drop_xor_hits_in_elf_metadata(&mut report);
    }

    // Filter low-value composite "any" rules (needs=1) before caching: they add
    // nothing over the underlying trait that matched — UNLESS a composite depends
    // on one. A trait referenced by a composite is, by definition, not low value:
    // it's what ties that composite to the file (and offset) it fired on, so
    // dropping it would erase the composite's cross-file provenance. Nor is one
    // that outranks every leg it fired on: that wrapper *is* the verdict, not a
    // restatement of it — see `drops_as_low_value`.
    // Parent-scoped downgrades use each child's exact immediate parent. This
    // also covers nested decoded/container files without admitting siblings or
    // more distant ancestors as context.
    capability_mapper.reeval_parent_scope_in_file_tree(
        &mut report,
        file_data,
        crate::composite_rules::FileType::from(file_type),
    );

    let removed = capability_mapper.filter_low_value(&mut report);
    if removed > 0 {
        tracing::debug!("Filtered {} low-value composite 'any' rules", removed);
    }

    let total_ms = analysis_start.elapsed().as_millis() as u64;

    // Identify the slowest stage for quick bottleneck spotting
    let slowest = [
        ("stng", stage_stng_ms),
        ("structural", stage_structural_ms),
        ("payloads", stage_payloads_ms),
        ("yara", stage_yara_ms),
    ]
    .into_iter()
    .max_by_key(|(_, ms)| *ms)
    .map(|(name, _)| name)
    .unwrap_or("none");

    // Per-file stage timing summary — debug! because this fires for every
    // file and serializes on the tracing writer mutex at info level. At 10M
    // files × 24 workers, the mutex cost dominates the log itself.
    tracing::debug!(
        total_ms,
        stng_ms = stage_stng_ms,
        structural_ms = stage_structural_ms,
        payloads_ms = stage_payloads_ms,
        yara_ms = stage_yara_ms,
        slowest,
        file_type = ?file_type,
        size_kb = file_size / 1024,
        findings = report.findings.len(),
        traits = report.traits.len(),
        "Analysis complete",
    );

    // Log memory state after processing
    memory_tracker::log_after_file_processing(path_label, file_size, analysis_start.elapsed());

    // Universal file-level metrics — guaranteed populated regardless of
    // which analyzer ran, so consumers (cleave diff in particular) can
    // rely on `file.size` for every analyzed file. Writes directly into
    // the flat metric map; the typed `FileMetrics` struct is retired
    // (#41).
    {
        use crate::types::MetricsExt;
        let size = report.target.size_bytes;
        report
            .filefacts_metrics
            .get_or_insert_with(Default::default)
            .set_u("file.size", size);
    }

    // A standalone scanner binary is finalized here. Archive containers are
    // not: their findings are the member rollup, and a sibling member's
    // signature hits must survive when one member is the scanner.
    if !file_type.is_archive() {
        report.suppress_scanner_catalog_self_hits();
    }

    // Collapse duplicate findings (same id) before anything downstream sees
    // the report. Some analyzers emit one finding per match site; consumers
    // (diff, ML feature extraction, JSON viewers) want one logical finding
    // per id with merged evidence.
    report.dedupe_findings();

    // Capture merged, render-ready context windows from the findings while the
    // file bytes are still in scope. This is the LLM/output surface that
    // replaces raw per-finding evidence; it rides the report into both caches.
    // Findings here are already final — the low-value filter ran above.
    crate::context::capture(&mut report, file_data, file_type, &Default::default());

    // Store result in per-file cache (cross-context: shared with archive member analysis)
    {
        let mut fa = report.to_file_analysis(0, engine);
        // Keep the origin even when no path-dependent rule matched: negative
        // matches must also be checked before sharing with another path.
        fa.path = path.display().to_string();
        fa.id = 0;
        fa.parent_id = None;
        fa.depth = 0;
        analysis_cache::file_analysis_cache_store(
            &sha256_hex,
            file_type_key,
            options,
            engine.settings(),
            &fa,
            &report,
            capability_mapper.traits_revision(),
        );
    }

    // Store result in analysis cache for future lookups
    // Key on the mapper this analysis ran with, not on the process-global
    // traits scan: a reload (`/reload`, scan's renewal task) can have replaced
    // the latter while this file was being analyzed.
    analysis_cache::report_cache_store(
        &sha256_hex,
        &report_type_key,
        options,
        engine.settings(),
        &report,
        capability_mapper.traits_revision(),
    );
    if let Some(flight) = flight {
        flight.complete(Some(&report));
    }

    Ok(report)
}
