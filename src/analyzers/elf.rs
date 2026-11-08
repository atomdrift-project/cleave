//! ELF binary analyzer for Linux executables.
//!
//! Every ELF-internal helper takes a non-optional
//! `AnalysisContext`: structural data
//! (sections, segments, dynamic-section facts, notes) is read from
//! `filefacts`'s typed views; this analyzer never parses the file itself.

// Parses attacker-controlled bytes: index and offset arithmetic must be
// checked, so a forged header is a parse error rather than a panic.
#![warn(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use crate::analyzers::{AnalysisInput, Analyzer};
use crate::entropy::EntropyLevel;
use crate::strings::StringExtractor;
use crate::types::{
    AnalysisReport, Criticality, Evidence, Finding, FindingKind, Section, StructuralFeature,
    SyscallInfo, TargetInfo,
};
use crate::yara_engine::YaraEngine;
use anyhow::{Context, Result};
use std::fs;
use std::path::Path;
use std::sync::Arc;

type Ctx<'a> = crate::analysis_context::AnalysisContext<'a>;

/// Analyzer for Linux ELF binaries (executables, shared objects, kernel modules).
///
/// Function CFG fields and recovered symbols for stripped binaries arrive
/// through `filefacts::open` on `ctx.parsed.symbols()` (filtered by kind)
/// and `sections()`; recovery runs in-process inside filefacts.
#[derive(Debug)]
pub(crate) struct ElfAnalyzer {
    engine: crate::Engine,
    string_extractor: StringExtractor,
    yara_engine: Option<Arc<YaraEngine>>,
    /// When true, skip scanning for embedded PE/ELF binaries (prevents recursion in sub-analysis).
    skip_embedded_scan: bool,
    /// Per-request cancellation flag.
    cancellation: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
}

impl ElfAnalyzer {
    /// Creates a new ELF analyzer with default configuration
    #[must_use]
    pub(crate) fn new() -> Self {
        Self {
            engine: crate::Engine::empty(),
            string_extractor: StringExtractor::new(),
            yara_engine: None,
            skip_embedded_scan: false,
            cancellation: None,
        }
    }

    /// Disable embedded binary scanning (used when analyzing extracted sub-files).
    #[must_use]
    pub(crate) fn without_embedded_scan(mut self) -> Self {
        self.skip_embedded_scan = true;
        self
    }

    /// Set per-request cancellation flag.
    #[must_use]
    pub(crate) fn with_cancellation(
        mut self,
        flag: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
    ) -> Self {
        self.cancellation = flag;
        self
    }

    fn is_cancelled(&self) -> bool {
        self.cancellation
            .as_ref()
            .is_some_and(|c| c.load(std::sync::atomic::Ordering::Relaxed))
    }

    /// Create analyzer with shared YARA engine
    #[must_use]
    pub(crate) fn with_yara_arc(
        mut self,
        yara_engine: &Arc<crate::yara_engine::YaraEngine>,
    ) -> Self {
        self.yara_engine = Some(yara_engine.clone());
        self
    }

    /// Analyze under `engine`: its rules and settings.
    #[must_use]
    pub(crate) fn with_engine(mut self, engine: crate::Engine) -> Self {
        self.yara_engine = engine.yara().cloned();
        self.engine = engine;
        self
    }

    /// Core ELF analysis logic. Strings and structure both come from the
    /// caller's `AnalysisContext` (filefacts) — the single extraction authority.
    fn analyze_elf_core<'a>(
        &self,
        logical_path: &Path,
        analysis_path: &Path,
        data: &'a [u8],
        precomputed_sha256: Option<&str>,
        ctx: &Ctx<'a>,
    ) -> AnalysisReport {
        let start = std::time::Instant::now();
        let sha256 = precomputed_sha256
            .map(ToString::to_string)
            .unwrap_or_else(|| crate::analyzers::utils::calculate_sha256(data));

        // Create target info with default/empty values for fields that require parsing
        let target = TargetInfo {
            path: logical_path.display().to_string(),
            file_type: "elf".to_string(),
            size_bytes: data.len() as u64,
            sha256,
            architectures: None,
        };
        if !data.starts_with(b"\x7fELF") {
            return AnalysisReport::new(target);
        }

        let mut report = AnalysisReport::new(target);
        let mut tools_used = vec![];

        // Filefacts's ELF parse status drives the analyzer. A successful
        // parse populates `elf.machine`; a failed/panicked parse leaves
        // it absent and instead sets `elf.parse_failed` /
        // `elf.parse_panicked`. We branch on that single signal.
        let parsed_values = ctx.parsed.values();
        let parsed_metrics = ctx.parsed.metrics();
        // filefacts salvages `elf.machine` from the raw header even when the
        // parse fails, so success is the absence of the failure metrics.
        let parse_panicked = parsed_metrics.get("elf.parse_panicked").is_some();
        let filefacts_ok = !parse_panicked
            && parsed_metrics.get("elf.parse_failed").is_none()
            && parsed_values.get("elf.machine").is_some();

        if filefacts_ok {
            tools_used.push("filefacts".to_string());
            report.target.architectures = Some(vec![
                parsed_values
                    .get("elf.machine")
                    .and_then(|v| v.as_str())
                    .map(str::to_string)
                    .unwrap_or_else(|| "unknown".to_string()),
            ]);

            let struct_start = std::time::Instant::now();
            self.fill_structure_from_ctx(ctx, &mut report);
            self.fill_dynamic_symbols_from_ctx(ctx, &mut report);
            self.fill_sections_from_ctx(ctx, &mut report);
            self.fill_syscalls_from_ctx(ctx, &mut report);
            let struct_ms = struct_start.elapsed().as_millis();
            tracing::info!(
                path = %analysis_path.display(),
                rayon_thread = ?rayon::current_thread_index(),
                scope_struct_ms = struct_ms as u64,
                "ELF structural phase timings",
            );

            // Functions come from filefacts — `aflj`-derived CFG fields
            // land on `Function::complexity` / `basic_blocks` / `edges`
            // / `calls` already. Symbol-table-only entries leave the
            // CFG block on the cleave mirror `None`.
            report.functions = ctx
                .parsed
                .symbols()
                .iter_kind(filefacts::SymbolKind::Function)
                .filter_map(crate::analysis_context::project_filefacts_function)
                .collect();
            // An archive appended past the ELF image, as filefacts measured
            // and named it (an AppImage's squashfs is identified, not unpacked).
            let overlay_size = ctx
                .parsed
                .metrics()
                .get("binary.overlay_size")
                .map(|size| size as usize);
            if let Some(archive_type) = ctx
                .parsed
                .values()
                .get("binary.overlay_archive")
                .and_then(serde_json::Value::as_str)
                .filter(|kind| *kind != "squashfs")
                && let Some(overlay) =
                    overlay_size.and_then(|size| data.get(data.len().saturating_sub(size)..))
                && let Ok(ov) = crate::analyzers::overlay::analyze_overlay(
                    overlay,
                    archive_type,
                    &report.target.path,
                    &self.engine,
                    None,
                    None,
                )
            {
                report.findings.extend(ov.extraction_failure);
                report.findings.extend(ov.archive_report.findings);
                report.files.extend(ov.archive_report.files);
            }
        } else {
            // filefacts's ELF parse failed; the traits judge the failure
            // (`elf.parse_failed`, `elf.parse_error`) and the architecture
            // comes from the header fields filefacts salvaged.
            let err_msg = ctx
                .parsed
                .errors()
                .iter()
                .find(|e| e.stage == filefacts::Stage::ElfParse)
                .map(|e| e.message.clone())
                .unwrap_or_default();
            report.target.architectures = parsed_values
                .get("elf.machine")
                .and_then(serde_json::Value::as_str)
                .map(|machine| vec![machine.to_string()]);

            report.metadata.errors.push(format!(
                "ELF parse {}: {}",
                if parse_panicked { "panicked" } else { "error" },
                if err_msg.is_empty() {
                    "filefacts could not parse ELF"
                } else {
                    err_msg.as_str()
                },
            ));

            // Recovery is owned by `filefacts::open`: when goblin's ELF
            // parse comes back empty, binform fills the unified `Symbols`
            // view with Function records (plus Imports / Exports) before
            // we ever look at them. Projecting from
            // `ctx.parsed.symbols()` here mirrors the happy path
            // and avoids duplicating the cache-key plumbing.
            report.functions = ctx
                .parsed
                .symbols()
                .iter_kind(filefacts::SymbolKind::Function)
                .filter_map(crate::analysis_context::project_filefacts_function)
                .collect();
        }

        // --- Shared post-processing (strings, embedded code, metrics, overlay) ---

        // Strings come from filefacts's byte-scan `text()` — the single
        // string-extraction authority (cleave no longer scans). The raw stng
        // rows also feed embedded-child analysis below.
        let raw_stng_strings = ctx.text_rows();
        // Keep the binary's own symbol names ahead of the cap (Go pclntab
        // names in a large binary), then record what the caps left.
        self.string_extractor.prioritize_report_symbols(&report);
        report.strings = self.string_extractor.convert_stng_strings(raw_stng_strings);
        self.string_extractor.record_count_metrics(
            report
                .filefacts_metrics
                .get_or_insert_with(Default::default),
        );

        // Embedded ELF / PE images filefacts located (it skips core dumps,
        // whose memory holds the images they ran), analyzed as children.
        if !self.skip_embedded_scan {
            let host_name = std::path::Path::new(&report.target.path)
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("binary.elf")
                .to_string();
            for image in
                crate::analyzers::embedded_images::EmbeddedImage::from_values(parsed_values)
            {
                if self.is_cancelled() {
                    break;
                }
                let Some(bytes) = image.bytes(data) else {
                    continue;
                };
                if let Some(files) = crate::analyzers::utils::analyze_embedded_as_child(
                    &bytes,
                    &host_name,
                    &image.family,
                    &image.display_kind(),
                    image.offset,
                    self.engine.clone(),
                    None, // YARA handled by child
                ) {
                    report.files.extend(files);
                }
            }
        }

        // Report string truncation if limits were hit
        if self
            .string_extractor
            .truncated
            .load(std::sync::atomic::Ordering::SeqCst)
        {
            report.findings.push(Finding {
                precomputed_spans: None,
                src: None,
                id: "metadata/strings-truncated".to_string().into(),
                kind: FindingKind::Structural,
                desc: self.string_extractor.truncation_desc().into(),
                conf: 1.0,
                crit: Criticality::Notable,
                mbc: None,
                attack: None,
                trait_refs: vec![],
                evidence: vec![],
                match_count: 0,
                source_file: None,
                downgraded: false,
            });
        }
        tools_used.push("stng".to_string());

        // Analyze embedded code in strings
        let (encoded_layers, plain_findings) =
            crate::analyzers::embedded_code_detector::process_all_strings(
                &logical_path.display().to_string(),
                &report.strings,
                &self.engine,
                0,
                Some(&crate::FileType::Elf),
                self.cancellation.as_deref(),
            );
        report.files.extend(encoded_layers);
        report.findings.extend(plain_findings);

        // Emit recursive-scan counters. Mirrors pe.rs — embedded
        // payload discovery is cleave-side recursive work, not
        // filefacts's parse-time view.
        report.metadata.analysis_duration_ms = start.elapsed().as_millis() as u64;
        report.metadata.tools_used = tools_used;

        // Free excess vector capacity to reduce memory footprint
        report.shrink_to_fit();

        report
    }

    /// `analyze_structure`'s filefacts-backed counterpart. Synthesises the
    /// same `binary/format/elf`, `binary/arch/*`, `binary/stripped` and
    /// `binary/pie` features but pulls every input from filefacts's view of
    /// the file.
    fn fill_structure_from_ctx(&self, ctx: &Ctx<'_>, report: &mut AnalysisReport) {
        let parsed = &ctx.parsed;
        let metrics = parsed.metrics();
        let values = parsed.values();

        report.structure.push(StructuralFeature {
            id: "binary/format/elf".to_string(),
            desc: "ELF binary format".to_string(),
            evidence: vec![Evidence {
                method: "magic".to_string(),
                source: "filefacts".to_string(),
                value: "0x7f".to_string(), // ELF magic byte 0
                location: Some("0x0".to_string()),
                ..Default::default()
            }],
        });

        // Architecture comes from filefacts's `elf.machine` string (e.g.
        // "x86_64"). Fall back to "unknown" when filefacts couldn't
        // identify the machine.
        let arch = values
            .get("elf.machine")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        report.structure.push(StructuralFeature {
            id: format!("binary/arch/{}", arch),
            desc: format!("{} architecture", arch),
            evidence: vec![Evidence {
                method: "header".to_string(),
                source: "filefacts".to_string(),
                value: format!("elf.machine={}", arch),
                location: Some("0x0".to_string()),
                ..Default::default()
            }],
        });

        // Full symbol-table absence is observable even in a header-only
        // member. It does not establish that symbols were removed by a tool.
        if metrics
            .get("binary.full_symbol_table_absent_or_empty")
            .unwrap_or(0.0)
            > 0.0
        {
            report.structure.push(StructuralFeature {
                id: "binary/full-symbol-table-absent-or-empty".to_string(),
                desc: "Full symbol table absent or empty".to_string(),
                evidence: vec![Evidence {
                    method: "symbols".to_string(),
                    source: "filefacts".to_string(),
                    value: "no_symtab".to_string(),
                    location: Some("0x0".to_string()),
                    ..Default::default()
                }],
            });
        }

        // PIE detection: filefacts flags `binary.is_pie = 1.0` for
        // dynamically-linked ET_DYN executables (shared libraries that
        // are also ET_DYN don't count).
        if metrics.get("binary.is_pie").unwrap_or(0.0) > 0.0 {
            report.structure.push(StructuralFeature {
                id: "binary/pie".to_string(),
                desc: "Position Independent Executable".to_string(),
                evidence: vec![Evidence {
                    method: "header".to_string(),
                    source: "filefacts".to_string(),
                    value: "ET_DYN".to_string(),
                    location: Some("0x0".to_string()),
                    ..Default::default()
                }],
            });
        }
    }

    /// Project filefacts's typed Imports / Exports into the report. Symbol
    /// traits match these through the trait engine's symbol index. Exports come
    /// from `.dynsym` only — filefacts's typed view doesn't surface `.symtab`
    /// exports today.
    fn fill_dynamic_symbols_from_ctx(&self, ctx: &Ctx<'_>, report: &mut AnalysisReport) {
        use std::collections::HashSet;
        report.imports.extend(ctx.imports_from_filefacts());
        // Dedup exports via a set, not O(n²) linear rescans — `.dynsym` can
        // carry thousands of entries.
        let mut export_symbols: HashSet<String> =
            report.exports.iter().map(|e| e.symbol.clone()).collect();
        for exp in ctx.exports_from_filefacts() {
            if export_symbols.insert(exp.symbol.clone()) {
                report.exports.push(exp);
            }
        }
        // STT_GNU_IFUNC names are surfaced by filefacts as `elf.ifuncs`.
    }

    /// Walk the section table from filefacts's typed `Sections` view,
    /// reading each section's entropy directly off the typed field (the same
    /// value PE/Mach-O use via `sections_from_filefacts`).
    fn fill_sections_from_ctx(&self, ctx: &Ctx<'_>, report: &mut AnalysisReport) {
        let parsed = &ctx.parsed;
        for section in parsed.sections().iter() {
            if section.file_size == 0 {
                continue;
            }
            let entropy = section.entropy.unwrap_or(0.0);
            report.sections.push(Section {
                name: section.name.clone(),
                address: Some(section.vaddr),
                offset: Some(section.file_offset),
                size: section.file_size,
                entropy,
                permissions: Some(
                    section
                        .flags
                        .iter()
                        .map(|f| f.as_str())
                        .collect::<Vec<_>>()
                        .join(","),
                ),
                flags: crate::analysis_context::section_flag_names(&section.flags),
            });

            let level = EntropyLevel::from_value(entropy);
            if level == EntropyLevel::High {
                report.structure.push(StructuralFeature {
                    id: "entropy/high".to_string(),
                    desc: "High entropy section (possibly packed/encrypted)".to_string(),
                    evidence: vec![Evidence {
                        method: "entropy".to_string(),
                        source: "entropy_analyzer".to_string(),
                        value: format!("{:.2}", entropy),
                        location: Some(section.name.clone()),
                        ..Default::default()
                    }],
                });
            }
        }
    }

    /// Project filefacts's direct-syscall inventory (`elf.syscalls_direct[]`,
    /// resolved from raw `syscall`/`svc` instructions that bypass the libc
    /// wrapper) into `report.syscalls`, which the `type: syscall` trait matcher
    /// reads. Each record is `{name, number, args}`; `args` carries the resolved
    /// immediate argument values (`null` where non-constant) so an `arg:`
    /// predicate can match a flag like `PROT_EXEC`. Syscall numbers are
    /// arch-specific, so a `number:` rule should pin `arch:` alongside it.
    /// `offset` is the file offset of the record's first call site, which is
    /// what anchors a syscall finding to real bytes; only `desc` has no source.
    ///
    /// The caps below are defence in depth, not redundancy: filefacts bounds its
    /// own site set, but every record here costs three heap allocations, and the
    /// input is a hostile binary. A parser bound that regresses upstream must not
    /// become unbounded scanner memory downstream.
    fn fill_syscalls_from_ctx(&self, ctx: &Ctx<'_>, report: &mut AnalysisReport) {
        /// Matches filefacts's own per-binary candidate budget.
        const MAX_SITES: usize = 4096;
        /// Linux syscall ABI argument count.
        const MAX_ARGS: usize = 6;

        let values = ctx.parsed.values();
        let Some(records) = values.get("elf.syscalls_direct").and_then(|v| v.as_array()) else {
            return;
        };
        if records.len() > MAX_SITES {
            tracing::warn!(
                found = records.len(),
                kept = MAX_SITES,
                "elf.syscalls_direct exceeded the ingest cap; truncating"
            );
        }
        let arch = values
            .get("elf.syscalls_arch")
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        report
            .syscalls
            .extend(records.iter().take(MAX_SITES).filter_map(|rec| {
                Some(SyscallInfo {
                    // Both absent on records cached before the producer emitted
                    // them; 0 then means "unknown", exactly as it did before.
                    address: rec
                        .get("offset")
                        .and_then(serde_json::Value::as_u64)
                        .unwrap_or(0),
                    number: rec
                        .get("number")
                        .and_then(serde_json::Value::as_u64)
                        .and_then(|n| u32::try_from(n).ok())
                        .unwrap_or(0),
                    name: rec.get("name")?.as_str()?.to_string(),
                    desc: String::new(),
                    arch: arch.to_string(),
                    args: rec
                        .get("args")
                        .and_then(|v| v.as_array())
                        .map(|a| {
                            a.iter()
                                .take(MAX_ARGS)
                                .map(serde_json::Value::as_u64)
                                .collect()
                        })
                        .unwrap_or_default(),
                })
            }));
    }
}

impl Default for ElfAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl ElfAnalyzer {
    /// Convenience wrapper that opens an `AnalysisContext` against
    /// `data` and forwards to [`Self::analyze_structural_with_ctx`].
    /// Production paths (`cleave::lib`) plumb a shared ctx through
    /// directly; this entry point exists for the legacy
    /// `Analyzer::analyze` pathway and tests that don't have a ctx
    /// already.
    pub(crate) fn analyze_structural(
        &self,
        file_path: &Path,
        data: &[u8],
        precomputed_sha256: Option<&str>,
    ) -> AnalysisReport {
        let ctx = crate::analysis_context::AnalysisContext::open_with(
            self.engine.filefacts_options(),
            file_path,
            data,
        );
        self.analyze_structural_with_ctx(file_path, data, precomputed_sha256, &ctx)
    }

    /// Structural analysis driven entirely by an
    /// [`AnalysisContext`]. The ctx must borrow the same bytes
    /// passed in `data`; downstream helpers source sections,
    /// imports, exports, segments, dynamic-section facts, and notes
    /// from `ctx.parsed` rather than re-walking goblin.
    ///
    /// Handles UPX decompression internally — unpacked content
    /// becomes a separate `FileAnalysis` entry in `report.files`
    /// with `encoding: ["upx"]`. The unpacked layer opens its own
    /// `AnalysisContext` against the decompressed bytes.
    pub(crate) fn analyze_structural_with_ctx<'a>(
        &self,
        file_path: &'a Path,
        data: &'a [u8],
        precomputed_sha256: Option<&str>,
        ctx: &Ctx<'a>,
    ) -> AnalysisReport {
        self.analyze_structural_with_backing_ctx(
            file_path,
            file_path,
            data,
            precomputed_sha256,
            ctx,
        )
    }

    // Preserve logical paths while external tools reopen the backing file.
    fn analyze_structural_with_backing_ctx<'a>(
        &self,
        file_path: &'a Path,
        backing_path: &'a Path,
        data: &'a [u8],
        precomputed_sha256: Option<&str>,
        ctx: &Ctx<'a>,
    ) -> AnalysisReport {
        use crate::types::file_analysis::encode_upx_path;
        use crate::upx::UPXDecompressor;

        if !UPXDecompressor::is_upx_packed(data) {
            return self.analyze_elf_core(file_path, backing_path, data, precomputed_sha256, ctx);
        }

        // UPX-packed: structural analysis of packed binary first
        let mut report =
            self.analyze_elf_core(file_path, backing_path, data, precomputed_sha256, ctx);

        report.findings.push(
            Finding::structural(
                "anti-static/packer/upx".to_string(),
                "Binary contains a UPX packing marker".to_string(),
                1.0,
            )
            .with_criticality(Criticality::Notable),
        );

        // A UPX-disabled engine reports the same as a missing tool: the
        // unpacked image was not analyzed.
        if !self.engine.upx() || !UPXDecompressor::is_available() {
            report.findings.push(
                Finding::structural(
                    "anti-static/packer/upx/tool-missing".to_string(),
                    "UPX binary not found in PATH - unpacked analysis skipped".to_string(),
                    1.0,
                )
                .with_criticality(Criticality::Suspicious),
            );
            return report;
        }

        if self.is_cancelled() {
            return report;
        }

        match UPXDecompressor::decompress(data) {
            Ok(unpacked_data) => {
                if let Ok(temp_file) = tempfile::NamedTempFile::new()
                    && std::fs::write(temp_file.path(), &unpacked_data).is_ok()
                {
                    // UPX-unpacked bytes differ from the caller's
                    // bytes; open a fresh context on the
                    // decompressed payload so the downstream
                    // helpers see a self-consistent view (and supply the
                    // unpacked strings via its `text()`).
                    let unpacked_ctx = crate::analysis_context::AnalysisContext::open_with(
                        self.engine.filefacts_options(),
                        temp_file.path(),
                        &unpacked_data,
                    );
                    let unpacked_report = self.analyze_elf_core(
                        temp_file.path(),
                        temp_file.path(),
                        &unpacked_data,
                        None,
                        &unpacked_ctx,
                    );
                    let mut unpacked_report = unpacked_report;
                    self.engine.evaluate_and_merge_findings_with_precomputed(
                        &mut unpacked_report,
                        &unpacked_data,
                        crate::capabilities::AnalysisBorrow::with_filefacts(
                            None,
                            Some(&unpacked_ctx),
                        ),
                        None,
                        None,
                        None,
                        None,
                    );
                    crate::path_mapper::analyze_and_link_paths(&mut unpacked_report);
                    crate::env_mapper::analyze_and_link_env_vars(&mut unpacked_report);

                    // Create separate FileAnalysis for unpacked layer
                    let unpacked_sha256 = crate::analyzers::utils::calculate_sha256(&unpacked_data);
                    let virtual_path = encode_upx_path(&file_path.display().to_string());

                    let (mut unpacked_file, unpacked_nested, _) =
                        unpacked_report.into_file_analysis(0, &self.engine);
                    unpacked_file.path = virtual_path;
                    unpacked_file.sha256 = unpacked_sha256;
                    unpacked_file.size = unpacked_data.len() as u64;
                    unpacked_file.depth = 1;
                    unpacked_file.parent_id = Some(0);
                    unpacked_file.encoding = Some(vec!["upx".to_string()]);
                    unpacked_file.compute_summary();

                    // The packed wrapper represents the executable users see, so
                    // its findings include the behavior exposed by the UPX layer
                    // while the child retains layer-specific attribution.
                    for finding in &unpacked_file.findings {
                        report.push_finding_capped(finding.clone());
                    }

                    // Add nested files from unpacked analysis (e.g., embedded code)
                    report.files.extend(unpacked_nested);
                    report.files.push(unpacked_file);

                    report.metadata.tools_used.push("upx".to_string());
                }
            }
            Err(e) => {
                // The raw `upx` stderr names the temp file we handed it, so it
                // is not reproducible run to run; keep it in the log and put a
                // fixed reason in the finding. See `upx::classify_failure`.
                tracing::debug!("UPX decompression failed: {}", e);
                let failure = crate::upx::classify_failure(&e);
                if let Some(finding) = crate::upx::standard_unpack_refusal(&e) {
                    report.findings.push(finding);
                }
                report.findings.push(
                    Finding::structural(
                        "metadata/binary/layout/compression::upx-decompression-failed".to_string(),
                        failure.description.to_string(),
                        1.0,
                    )
                    .with_criticality(Criticality::Notable),
                );
                // Artifact-specific integrity failure, distinct from missing tools,
                // timeouts and size limits. The finding states the evidence rather
                // than asserting a particular payload or malware family.
                if failure.invalid_image {
                    report.findings.push(
                        Finding::structural(
                            "metadata/binary/layout/compression::upx-invalid-packed-image"
                                .to_string(),
                            "UPX-like image has invalid or non-packed structure".to_string(),
                            1.0,
                        )
                        .with_criticality(Criticality::Suspicious),
                    );
                }
                if failure.checksum_mismatch {
                    report.findings.push(
                        Finding::structural(
                            "metadata/binary/layout/compression::upx-checksum-mismatch".to_string(),
                            "UPX-packed image fails checksum validation".to_string(),
                            1.0,
                        )
                        .with_criticality(Criticality::Suspicious),
                    );
                }
            }
        }

        report
    }
}

impl Analyzer for ElfAnalyzer {
    fn analyze_input(&self, input: &AnalysisInput<'_>) -> Result<AnalysisReport> {
        // Open filefacts-side parse once so analyze_elf_core's helpers
        // read structural data straight from filefacts — including its
        // byte-scan `text()`, the single string-extraction authority. When
        // filefacts can't open the bytes, we still produce a report so tamper
        // findings and recovered functions surface for triage. Reuse the parse
        // a caller threaded in (an archive member's): opening again repeats
        // the whole extraction.
        let opened;
        let ctx = match input.parsed_ctx {
            Some(ctx) => ctx,
            None => {
                opened = input.open_ctx_with(self.engine.filefacts_options());
                &opened
            }
        };
        let mut report = self.analyze_structural_with_backing_ctx(
            input.path,
            input.backing_path(),
            input.data,
            input.sha256.as_deref(),
            ctx,
        );

        // Post-processing
        self.engine.evaluate_and_merge_findings_with_precomputed(
            &mut report,
            input.data,
            crate::capabilities::AnalysisBorrow::with_filefacts(None, Some(ctx)),
            None,
            None,
            None,
            None,
        );
        crate::path_mapper::analyze_and_link_paths(&mut report);
        crate::env_mapper::analyze_and_link_env_vars(&mut report);
        Ok(report)
    }

    fn analyze(&self, file_path: &Path) -> Result<AnalysisReport> {
        let data = fs::read(file_path).context("Failed to read file")?;
        // filefacts is the string-extraction authority; open the context once
        // and thread it into the input so analyze_input reuses this parse.
        let ctx = crate::analysis_context::AnalysisContext::open_with(
            self.engine.filefacts_options(),
            file_path,
            &data,
        );
        let strings = ctx.text_rows();
        let input =
            AnalysisInput::with_strings(file_path, &data, strings, crate::analyzers::FileType::Elf)
                .with_parsed_ctx(&ctx);
        self.analyze_input(&input)
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]
mod tests;
