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

/// Mach-O: structure comes from a fat file's primary slice; strings, raw
/// matching and YARA cover the whole file. One parse of the file gives both.
pub(super) fn analyze_macho<'d>(
    b: BinaryInput<'_, 'd>,
    stng_strings: &[stng::ExtractedString],
    facts_options: &filefacts::OpenOptions<'d>,
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
    let analyzer = analyzers::macho::MachOAnalyzer::new()
        .with_cancellation(options.cancellation.clone())
        .with_engine(engine.clone())
        .with_preextracted_strings(
            strings::StringExtractor::new().convert_stng_strings(stng_strings),
        );
    // One parse of the whole file serves the slice table, the structure of
    // the image it describes (a thin binary, or a fat one's primary slice),
    // the other slices' imports and exports, and trait evaluation: the one
    // the pipeline opened for strings, or one opened here when it has none.
    let opened;
    let ctx = match file_ctx {
        Some(ctx) => ctx,
        None => {
            opened = crate::analysis_context::AnalysisContext::open_with(
                facts_options.clone(),
                path,
                file_data,
            );
            &opened
        }
    };
    let slices = analyzers::macho::FatSlices::of(file_data, Some(ctx), facts_options);
    let range = analyzer.preferred_arch_range(file_data, &slices);
    let arch_data = &file_data[range.clone()];
    let labeled_ranges = analyzer.labeled_arch_ranges(file_data, &slices);
    let is_fat = labeled_ranges.len() > 1;
    let mut report =
        analyzer.analyze_structural_with_ctx(path, arch_data, Some(sha256.to_owned()), ctx);
    let raw_regex =
        rules.precompute_raw_regex_matches(file_data, &rules.detect_file_type("macho"), false);
    report.filefacts = Some(crate::types::FilefactsView::of(
        ctx,
        engine.compact_members(),
    ));
    report.identity = ctx.identity();
    analyzer.apply_fat_metadata(&mut report, file_data, &slices);

    if is_fat {
        // The primary slice's symbols and load-command offsets count from
        // the slice. Strings, raw matching, YARA, and the hex view all use
        // full-file coordinates; rebase before any of them run.
        analyzers::macho::MachOAnalyzer::rebase_slice_offsets(&mut report, range.start as u64);
        // Union every other slice's imports/exports into the report, so
        // malware in another arch (a malicious x86_64 slice beside a benign
        // arm64 one) cannot escape filefacts-derived traits.
        analyzer.union_supplementary_arches(&mut report, file_data, ctx, &slices);
    }

    let archive_config = analyzers::archive::ArchiveAnalyzerConfig::from_analysis_options(options)
        .with_depth(analysis_depth as usize);
    analyzer.analyze_python_bundle_payload(
        path,
        arch_data,
        Some(ctx.parsed.values()),
        &mut report,
        &archive_config,
        engine.yara().cloned(),
    );

    let inline_yara = process_yara_result(
        &mut report,
        prefetched_yara,
        engine.yara().map(AsRef::as_ref),
    );
    set_phase(options, "macho:traits");
    rules.evaluate_and_merge_findings_with_precomputed(
        &mut report,
        file_data,
        crate::capabilities::AnalysisBorrow::with_filefacts(None, Some(ctx)),
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
    let raw_regex =
        rules.precompute_raw_regex_matches(file_data, &rules.detect_file_type("elf"), false);
    report.filefacts =
        file_ctx.map(|ctx| crate::types::FilefactsView::of(ctx, engine.compact_members()));
    report.identity = file_ctx.and_then(crate::analysis_context::AnalysisContext::identity);
    let inline_yara = process_yara_result(
        &mut report,
        prefetched_yara,
        engine.yara().map(AsRef::as_ref),
    );
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
    let raw_regex =
        rules.precompute_raw_regex_matches(file_data, &rules.detect_file_type("pe"), false);
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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::analysis_context::AnalysisContext;
    use crate::analyzers::AnalysisInput;

    type Rows = (
        Vec<(String, Option<String>, Option<String>)>,
        Vec<(String, Option<String>)>,
        Vec<(String, Option<u64>, u64)>,
        Vec<(String, Option<String>)>,
        Option<Vec<String>>,
        u64,
    );

    fn rows(r: &AnalysisReport) -> Rows {
        (
            r.imports
                .iter()
                .map(|i| (i.symbol.clone(), i.library.clone(), i.offset.clone()))
                .collect(),
            r.exports
                .iter()
                .map(|e| (e.symbol.clone(), e.offset.clone()))
                .collect(),
            r.sections
                .iter()
                .map(|s| (s.name.clone(), s.offset, s.size))
                .collect(),
            r.functions
                .iter()
                .map(|f| (f.name.clone(), f.offset.clone()))
                .collect(),
            r.target.architectures.clone(),
            r.target.size_bytes,
        )
    }

    /// A Mach-O scanned as a file is analysed from the one parse the pipeline
    /// opened for its strings, fat or thin: no slice, and no second copy of
    /// the file, is opened. Its report holds what the archive-member path
    /// builds from the same parse, so a binary reads the same inside an
    /// archive and outside one.
    #[test]
    fn a_macho_file_is_analysed_from_the_pipelines_parse() {
        let fat = crate::test_samples::read("testdata/xor/gapi-update.macho");
        let thin = std::fs::read("tests/fixtures/test.macho").unwrap();
        let engine = Engine::empty();
        let options = AnalysisOptions::default();
        let facts = filefacts::OpenOptions::new();
        for (name, data) in [("gapi-update.macho", &fat), ("test.macho", &thin)] {
            let path = Path::new(name);
            let ctx = AnalysisContext::open_with(facts.clone(), path, data);
            let input = |ctx| BinaryInput {
                path,
                data,
                sha256: "sha",
                ctx,
                options: &options,
                engine: &engine,
                prefetched_yara: None,
            };
            let report = analyze_macho(input(Some(&ctx)), ctx.text_rows(), &facts, 0);
            assert_eq!(ctx.parsed.parse_count(), 1, "{name}: one extraction");
            assert!(!report.imports.is_empty(), "{name}");
            assert!(!report.sections.is_empty(), "{name}");
            assert!(report.filefacts.is_some(), "{name}");

            let member = analyzers::macho::MachOAnalyzer::new()
                .with_engine(engine.clone())
                .analyze_input(
                    &AnalysisInput::new(path, data, crate::FileType::MachO).with_parsed_ctx(&ctx),
                )
                .unwrap();
            assert_eq!(rows(&report), rows(&member), "{name}");

            // With no parse from the pipeline, one is opened here.
            let alone = analyze_macho(input(None), ctx.text_rows(), &facts, 0);
            assert_eq!(rows(&alone), rows(&report), "{name}");
        }
    }
}
