//! Structural analysis for the native binary formats (Mach-O, ELF, PE).
//!
//! Each arm reuses what the pipeline already did for the whole file: the
//! filefacts context opened to harvest strings and the YARA scan that ran
//! alongside it. It adds structure, then evaluates traits over the result.
#[allow(clippy::wildcard_imports)]
use super::*;

/// What every binary arm starts from.
pub(super) struct BinaryInput<'a, 'd> {
    pub(super) path: &'d Path,
    pub(super) data: &'d [u8],
    pub(super) sha256: &'a str,
    /// The full-file context the pipeline opened for strings. Borrowed, not
    /// consumed: the identity fallback after dispatch reuses it, so the file's
    /// extraction (recovery included) runs exactly once.
    pub(super) ctx: Option<&'a crate::analysis_context::AnalysisContext<'d>>,
    pub(super) options: &'a AnalysisOptions,
    pub(super) engine: &'a Engine,
    /// The YARA scan run concurrently with string extraction.
    pub(super) prefetched_yara: Option<Result<yara_engine::YaraScan>>,
}

fn set_phase(options: &AnalysisOptions, phase: &str) {
    if let Some(tracker) = &options.phase {
        tracker.set(phase);
    }
}

/// Mach-O: structure comes from the preferred arch slice; strings, raw
/// matching and YARA cover the whole (possibly fat) file.
pub(super) fn analyze_macho(
    b: BinaryInput<'_, '_>,
    stng_strings: &[stng::ExtractedString],
    facts_options: &filefacts::OpenOptions<'_>,
    analysis_depth: u32,
) -> AnalysisReport {
    let BinaryInput {
        path,
        data: file_data,
        sha256,
        ctx: file_ctx,
        options,
        engine,
        prefetched_yara,
    } = b;
    set_phase(options, "macho:struct+yara");
    let rules = engine.rules();
    // Mach-O's structural context is a per-arch slice, so it cannot
    // self-source full-file strings the way PE/ELF do.
    let analyzer = analyzers::macho::MachOAnalyzer::new()
        .with_cancellation(options.cancellation.clone())
        .with_engine(engine.clone())
        .with_preextracted_strings(
            strings::StringExtractor::new().convert_stng_strings(stng_strings),
        );
    // The slice table comes from the full-file parse already opened for
    // strings, so no helper reparses the fat binary.
    let slices = analyzers::macho::FatSlices::of(file_data, file_ctx, facts_options);
    let range = analyzer.preferred_arch_range(file_data, &slices);
    let arch_data = &file_data[range.clone()];
    let labeled_ranges = analyzer.labeled_arch_ranges(file_data, &slices);
    let is_fat = labeled_ranges.len() > 1;
    let eval_data = if is_fat { file_data } else { arch_data };
    // Open filefacts on the preferred-arch slice so the analyzer reads dyld
    // imports and export-trie entries from the typed view.
    let ctx =
        crate::analysis_context::AnalysisContext::open_with(facts_options.clone(), path, arch_data);
    let mut report =
        analyzer.analyze_structural_with_ctx(path, arch_data, Some(sha256.to_owned()), &ctx);
    let raw_regex = rules.precompute_raw_regex_matches(eval_data, &rules.detect_file_type("macho"));
    report.filefacts = Some(crate::types::FilefactsView::of(
        &ctx,
        engine.compact_members(),
    ));
    report.identity = ctx.identity();
    analyzer.apply_fat_metadata(&mut report, file_data, &slices);

    if is_fat {
        // The preferred slice was parsed at base 0, so its structural offsets
        // are slice-relative. Strings, raw matching, YARA, and the hex view
        // all use full-file coordinates; rebase before any of them run.
        analyzers::macho::MachOAnalyzer::rebase_slice_offsets(&mut report, range.start as u64);
        // Union every other slice's imports/exports into the report, so
        // malware in a non-preferred arch (a malicious x86_64 slice beside a
        // benign arm64 one) cannot escape filefacts-derived traits.
        analyzer.union_supplementary_arches(&mut report, file_data, range.start, &slices);
    }

    let archive_config = analyzers::archive::ArchiveAnalyzerConfig::from_analysis_options(options)
        .with_depth(analysis_depth as usize);
    analyzer.analyze_nuitka_payload(
        path,
        arch_data,
        &mut report,
        &archive_config,
        engine.yara().cloned(),
    );

    let inline_yara = process_yara_result(
        &mut report,
        prefetched_yara,
        engine.yara().map(AsRef::as_ref),
    );
    analyzers::binary_extractors::augment_report(&mut report, eval_data);
    set_phase(options, "macho:traits");
    rules.evaluate_and_merge_findings_with_precomputed(
        &mut report,
        eval_data,
        crate::capabilities::AnalysisBorrow::with_filefacts(None, (!is_fat).then_some(&ctx)),
        Some(&inline_yara),
        Some(raw_regex),
        is_fat.then_some(labeled_ranges.as_slice()),
        options.cancellation.as_deref(),
    );
    report
}

/// ELF: the full-file context supplies both structure and strings. When
/// filefacts could not open the bytes, the analyzer's bytes-only entry point
/// still surfaces the malformed signal.
pub(super) fn analyze_elf(b: BinaryInput<'_, '_>) -> AnalysisReport {
    let BinaryInput {
        path,
        data: file_data,
        sha256,
        ctx: file_ctx,
        options,
        engine,
        prefetched_yara,
    } = b;
    set_phase(options, "elf:struct+yara");
    tracing::debug!(
        on_rayon_thread = rayon::current_thread_index().is_some(),
        data_bytes = file_data.len(),
        "ELF: entering structural analysis (YARA already prefetched)"
    );
    let rules = engine.rules();
    let mut analyzer = analyzers::elf::ElfAnalyzer::new()
        .with_cancellation(options.cancellation.clone())
        .with_engine(engine.clone());
    if let Some(yara) = engine.yara() {
        analyzer = analyzer.with_yara_arc(yara);
    }
    let mut report = match file_ctx {
        Some(ctx) => analyzer.analyze_structural_with_ctx(path, file_data, Some(sha256), ctx),
        None => analyzer.analyze_structural(path, file_data, Some(sha256)),
    };
    let raw_regex = rules.precompute_raw_regex_matches(file_data, &rules.detect_file_type("elf"));
    report.filefacts =
        file_ctx.map(|ctx| crate::types::FilefactsView::of(ctx, engine.compact_members()));
    report.identity = file_ctx.and_then(crate::analysis_context::AnalysisContext::identity);
    let inline_yara = process_yara_result(
        &mut report,
        prefetched_yara,
        engine.yara().map(AsRef::as_ref),
    );
    // Format-specific extractors (.comment, DWARF) layer on top of the
    // `report.filefacts.values.elf.*` facts trait authors read.
    analyzers::binary_extractors::augment_report(&mut report, file_data);
    set_phase(options, "elf:traits");
    rules.evaluate_and_merge_findings_with_precomputed(
        &mut report,
        file_data,
        crate::capabilities::AnalysisBorrow::with_filefacts(None, file_ctx),
        Some(&inline_yara),
        Some(raw_regex),
        None,
        options.cancellation.as_deref(),
    );
    path_mapper::analyze_and_link_paths(&mut report);
    env_mapper::analyze_and_link_env_vars(&mut report);
    report
}

/// PE: the full-file context supplies sections, imports, exports, values,
/// metrics and strings, with no second parser pass. `.bat`/`.ps1` scripts
/// also reach the PE-tier YARA rules through the prefetched scan.
pub(super) fn analyze_pe(b: BinaryInput<'_, '_>) -> Result<AnalysisReport> {
    let BinaryInput {
        path,
        data: file_data,
        sha256,
        ctx: file_ctx,
        options,
        engine,
        prefetched_yara,
    } = b;
    set_phase(options, "pe:struct+yara");
    tracing::debug!(
        on_rayon_thread = rayon::current_thread_index().is_some(),
        data_bytes = file_data.len(),
        "PE: entering structural analysis (YARA already prefetched)"
    );
    // A PE that filefacts cannot open is unanalyzable.
    let ctx = file_ctx.ok_or_else(|| anyhow::anyhow!("filefacts open failed for PE"))?;
    let rules = engine.rules();
    let mut analyzer = analyzers::pe::PEAnalyzer::new()
        .with_cancellation(options.cancellation.clone())
        .with_archive_config(
            analyzers::archive::ArchiveAnalyzerConfig::from_analysis_options(options),
        )
        .with_engine(engine.clone());
    // Overlay and embedded payload analysis scan with YARA.
    if let Some(yara) = engine.yara() {
        analyzer = analyzer.with_yara_arc(yara.clone());
    }
    let mut report = analyzer.analyze_structural_with_ctx(path, file_data, Some(sha256), ctx);
    let raw_regex = rules.precompute_raw_regex_matches(file_data, &rules.detect_file_type("pe"));
    report.filefacts = Some(crate::types::FilefactsView::of(
        ctx,
        engine.compact_members(),
    ));
    report.identity = ctx.identity();
    let inline_yara = process_yara_result(
        &mut report,
        prefetched_yara,
        engine.yara().map(AsRef::as_ref),
    );
    // VERSIONINFO, Rich header and imphash layer on top of the
    // `report.filefacts.values.pe.*` facts trait authors read.
    analyzers::binary_extractors::augment_report(&mut report, file_data);
    set_phase(options, "pe:traits");
    rules.evaluate_and_merge_findings_with_precomputed(
        &mut report,
        file_data,
        crate::capabilities::AnalysisBorrow::with_filefacts(None, Some(ctx)),
        Some(&inline_yara),
        Some(raw_regex),
        None,
        options.cancellation.as_deref(),
    );
    Ok(report)
}
