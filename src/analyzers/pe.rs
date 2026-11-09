//! PE (Portable Executable) analyzer for Windows binaries.
//!
//! Every PE-internal helper takes a non-optional
//! `AnalysisContext`: structural data
//! (sections, imports, exports, characteristics) is read from
//! `filefacts`'s typed views; this analyzer never parses the file itself.
// Parses attacker-controlled bytes: index and offset arithmetic must be
// checked, so a forged header is a parse error rather than a panic.
#![warn(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use crate::analyzers::{AnalysisInput, Analyzer};
use crate::strings::StringExtractor;
use crate::types::{
    AnalysisReport, Criticality, Export, Finding, FindingKind, Import, Section, TargetInfo,
};
use crate::yara_engine::YaraEngine;
use anyhow::{Context, Result};
use std::fs;
use std::path::Path;
use std::sync::Arc;

type Ctx<'a> = crate::analysis_context::AnalysisContext<'a>;

mod recovered;

/// Analyzer for Windows PE binaries (executables, DLLs, drivers).
///
/// All deep-binary signal — function CFG fields, sections recovered
/// from packed binaries, the recovered import table — now flows in
/// through `filefacts::open`. The analyzer projects from
/// `ctx.parsed.symbols()` (filtered by kind) / `sections()`; recovery
/// runs in-process inside filefacts.
#[derive(Debug)]
pub struct PEAnalyzer {
    engine: crate::Engine,
    string_extractor: StringExtractor,
    yara_engine: Option<Arc<YaraEngine>>,
    archive_config: crate::analyzers::archive::ArchiveAnalyzerConfig,
    /// When true, skip scanning for embedded PE/ELF binaries (prevents recursion in sub-analysis).
    skip_embedded_scan: bool,
    /// Per-request cancellation flag.
    cancellation: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
}

/// The host's file name, which members it carries are filed under.
fn host_file_name(report: &AnalysisReport) -> String {
    std::path::Path::new(&report.target.path)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("binary.exe")
        .to_string()
}

/// File an inner archive's member inventory under the host PE, which is the
/// members' immediate provenance parent. The complete inventory is kept,
/// including data files not promoted to separate analyses.
fn adopt_member_inventory(report: &mut AnalysisReport, entries: Vec<crate::types::ArchiveEntry>) {
    use crate::types::file_analysis::{ARCHIVE_DELIMITER, encode_archive_path};
    let host = host_file_name(report);
    for mut entry in entries {
        if !entry.path.contains(ARCHIVE_DELIMITER) {
            entry.path = encode_archive_path(&host, &entry.path);
        }
        report.archive_contents.push(entry);
    }
}

fn adopt_tools(tools_used: &mut Vec<String>, tools: Vec<String>) {
    for tool in tools {
        if !tools_used.contains(&tool) {
            tools_used.push(tool);
        }
    }
}

/// Merge the analysis of an archive appended to the PE (an SFX overlay) into
/// the host report, its evidence locations rewritten to name the host.
fn adopt_overlay(
    report: &mut AnalysisReport,
    tools_used: &mut Vec<String>,
    overlay: crate::analyzers::overlay::OverlayAnalysis,
) {
    use crate::types::file_analysis::ARCHIVE_DELIMITER;
    let host = host_file_name(report);
    report.findings.extend(overlay.extraction_failure);
    let archive = overlay.archive_report;
    for mut finding in archive.findings {
        for evidence in &mut finding.evidence {
            if let Some(loc) = &evidence.location {
                let member = loc.strip_prefix("archive:");
                if member.is_some() || !loc.contains(ARCHIVE_DELIMITER) {
                    evidence.location = Some(format!(
                        "archive:{host}{ARCHIVE_DELIMITER}{}",
                        member.unwrap_or(loc)
                    ));
                }
            }
        }
        report.findings.push(finding);
    }
    adopt_member_inventory(report, archive.archive_contents);
    report.files.extend(archive.files);
    report.strings.extend(archive.strings);
    adopt_tools(tools_used, archive.metadata.tools_used);
}

impl PEAnalyzer {
    /// Project filefacts's typed `Imports` view into `Vec<Import>`. Symbol
    /// names are pre-normalised inside `imports_from_filefacts`; symbol traits
    /// match them through the trait engine's symbol index.
    fn pe_imports(&self, ctx: &Ctx<'_>) -> Vec<Import> {
        ctx.imports_from_filefacts()
    }

    /// Project filefacts's typed `Exports` view and the
    /// `pe.aliased_export_count` metric. Aliased exports are stub
    /// chains where multiple exported names land at the same target;
    /// filefacts's `aliased_exports` walker emits the count, so cleave
    /// doesn't disassemble locally.
    fn pe_exports(&self, ctx: &Ctx<'_>) -> (Vec<Export>, Option<u32>) {
        let exports = ctx.exports_from_filefacts();
        let aliased = if exports.len() < 2 {
            None
        } else {
            let count = ctx
                .parsed
                .metrics()
                .get("pe.aliased_export_count")
                .map(|v| v as u32)
                .unwrap_or(0);
            (count > 0).then_some(count)
        };
        (exports, aliased)
    }

    /// Project filefacts's typed `Sections` view into `Vec<Section>`.
    /// Per-section entropy comes from filefacts's metric map (no second
    /// scan over the section bytes).
    fn pe_sections(&self, ctx: &Ctx<'_>) -> Vec<Section> {
        ctx.sections_from_filefacts()
    }
    /// Creates a new PE analyzer with default configuration
    #[must_use]
    pub fn new() -> Self {
        Self {
            engine: crate::Engine::empty(),
            string_extractor: StringExtractor::new(),
            yara_engine: None,
            archive_config: crate::analyzers::archive::ArchiveAnalyzerConfig::default(),
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
        self.archive_config = self.archive_config.clone().with_cancellation(flag.clone());
        self.cancellation = flag;
        self
    }

    #[must_use]
    pub(crate) fn with_archive_config(
        mut self,
        config: crate::analyzers::archive::ArchiveAnalyzerConfig,
    ) -> Self {
        self.archive_config = config.with_cancellation(self.cancellation.clone());
        self
    }

    fn is_cancelled(&self) -> bool {
        self.cancellation
            .as_ref()
            .is_some_and(|c| c.load(std::sync::atomic::Ordering::Relaxed))
    }

    /// Create analyzer with shared YARA engine
    #[must_use]
    pub(crate) fn with_yara_arc(mut self, yara_engine: Arc<YaraEngine>) -> Self {
        self.yara_engine = Some(yara_engine);
        self
    }

    /// Analyze under `engine`: its rules and settings.
    #[must_use]
    pub(crate) fn with_engine(mut self, engine: crate::Engine) -> Self {
        self.yara_engine = engine.yara().cloned();
        self.engine = engine;
        self
    }

    /// Structural analysis of a PE binary (no main YARA scan, no trait evaluation).
    /// Overlay analysis (self-extracting archives) still runs and uses the YARA engine
    /// stored in this analyzer if set. Callers are responsible for running the main YARA
    /// scan and calling `evaluate_and_merge_findings` on the returned report.
    ///
    /// Handles UPX decompression internally - unpacked content becomes a separate FileAnalysis
    /// entry in `report.files` with `encoding: ["upx"]`.
    ///
    /// Convenience wrapper that opens an `AnalysisContext` against
    /// `data` and forwards to
    /// [`Self::analyze_structural_with_ctx`]. Production paths
    /// (`cleave::lib`) plumb a shared ctx through directly; this
    /// entry point exists for the legacy `Analyzer::analyze`
    /// pathway and tests that don't have a ctx already.
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
    /// imports, exports, signatures, and resource metadata from
    /// `ctx.parsed` rather than re-walking goblin.
    ///
    /// Handles UPX decompression internally — unpacked content
    /// becomes a separate `FileAnalysis` entry in `report.files`
    /// with `encoding: ["upx"]`. The unpacked layer opens its own
    /// `AnalysisContext` against the decompressed bytes.
    /// Analyze each embedded PE/ELF image as a child and report a Notable
    /// marker for it; trait rules decide what the marker means in context.
    /// Images inside the certificate table are signature data, not payloads.
    /// Returns how many were found.
    fn analyze_embedded_binaries(
        &self,
        report: &mut AnalysisReport,
        pe_data: &[u8],
        embedded: &[crate::analyzers::embedded_images::EmbeddedImage],
    ) {
        let host_name = std::path::Path::new(&report.target.path)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("binary.exe")
            .to_string();
        for image in embedded {
            if self.is_cancelled() {
                break;
            }
            let Some(bytes) = image.bytes(pe_data) else {
                continue;
            };
            if let Some(files) = crate::analyzers::utils::analyze_embedded_as_child(
                &bytes,
                &host_name,
                &image.family,
                &image.display_kind(),
                image.offset,
                self.engine.clone(),
                self.yara_engine.clone(),
            ) {
                report.files.extend(files);
            }
        }
    }

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

        if !unpack::upx::is_packed(data) {
            return self.analyze_structural_with_strings(
                file_path,
                backing_path,
                data,
                precomputed_sha256,
                ctx,
            );
        }

        // UPX-packed: structural analysis of packed binary first
        let mut report = self.analyze_structural_with_strings(
            file_path,
            backing_path,
            data,
            precomputed_sha256,
            ctx,
        );

        crate::upx::record_packed(&mut report);

        // A UPX-disabled engine reports the same as a missing tool: the
        // unpacked image was not analyzed.
        if !self.engine.upx() || !UPXDecompressor::is_available() {
            crate::upx::record_tool_missing(&mut report);
            return report;
        }

        if self.is_cancelled() {
            return report;
        }

        let initial = UPXDecompressor::decompress(data);
        if let Err(error) = &initial {
            crate::upx::record_attempt_failure(&mut report, error);
        }
        let recovered = if initial
            .as_ref()
            .err()
            .is_some_and(|e| crate::upx::classify_failure(e).checksum_mismatch)
        {
            unpack::upx::repair_checksums(data)
                .and_then(|copy| UPXDecompressor::decompress(&copy).ok())
        } else {
            None
        };
        let unpacked = if let Some(bytes) = recovered {
            crate::upx::record_checksum_repaired(&mut report);
            Ok(bytes)
        } else {
            initial
        };
        match unpacked {
            Ok(unpacked_data) => {
                if let Ok(temp_file) = tempfile::NamedTempFile::new()
                    && fs::write(temp_file.path(), &unpacked_data).is_ok()
                {
                    // UPX-unpacked bytes differ from the caller's
                    // bytes; open a fresh context on the
                    // decompressed payload so the downstream
                    // helpers see a self-consistent view — including
                    // its filefacts-extracted strings.
                    let unpacked_ctx = crate::analysis_context::AnalysisContext::open_with(
                        self.engine.filefacts_options(),
                        temp_file.path(),
                        &unpacked_data,
                    );
                    let mut unpacked_report = self.analyze_structural_with_strings(
                        temp_file.path(),
                        temp_file.path(),
                        &unpacked_data,
                        None, // Hash will change after decompression
                        &unpacked_ctx,
                    );
                    // Keep inline matches alongside ordinary YARA findings: trait
                    // evaluation needs the inline namespace evidence on this layer.
                    // Evaluate composites against the unpacked layer so that
                    // objective-level findings (infostealers, etc.) appear in the child.
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
                crate::upx::record_failure(&mut report, &e);
            }
        }

        report
    }

    /// Structural analysis with optional pre-extracted strings.
    /// The caller provides an `AnalysisContext` borrowing `data`;
    /// every PE-internal helper reads from filefacts's typed views via
    /// that ctx (no goblin re-parse).
    fn analyze_structural_with_strings<'a>(
        &self,
        logical_path: &Path,
        analysis_path: &Path,
        data: &'a [u8],
        precomputed_sha256: Option<&str>,
        ctx: &Ctx<'a>,
    ) -> AnalysisReport {
        let start = std::time::Instant::now();

        // Bytes prepended before `MZ` (filefacts' `pe.header.mz_offset`)
        // are peeled off for the overlay and embedded-binary passes. The
        // ctx still describes the original layout, which is what traits
        // see: the prefix itself is the signal.
        let prefix = ctx
            .parsed
            .values()
            .get("pe.header.mz_offset")
            .and_then(serde_json::Value::as_u64)
            .and_then(|offset| usize::try_from(offset).ok())
            .unwrap_or(0);
        let pe_data = data.get(prefix..).unwrap_or(data);

        self.analyze_pe(
            logical_path,
            analysis_path,
            data,
            pe_data,
            start,
            precomputed_sha256,
            ctx,
        )
    }

    /// Unified PE analysis driven by an `AnalysisContext`. Structure,
    /// imports, exports, sections, and per-format metrics all flow
    /// from filefacts's typed views, including the functions and
    /// disassembly-derived metrics (function counts, complexity) binform
    /// recovers, and the sections and imports it reads when goblin cannot
    /// (e.g. corrupted import directories).
    ///
    /// `pe_data` is the image from its `MZ`; `original_data` is the
    /// caller's bytes verbatim. The two diverge only when bytes were
    /// prepended before `MZ` — overlay extraction and embedded-binary scanning
    /// operate on `pe_data`, while file-size metrics use
    /// `original_data`.
    #[allow(clippy::too_many_arguments)]
    fn analyze_pe<'a>(
        &self,
        logical_path: &Path,
        analysis_path: &Path,
        original_data: &[u8],
        pe_data: &'a [u8],
        start: std::time::Instant,
        precomputed_sha256: Option<&str>,
        ctx: &Ctx<'a>,
    ) -> AnalysisReport {
        // `filefacts_ok` is true whenever filefacts identified the bytes as
        // PE and emitted at least the COFF header. The fallback path
        // (no PE values present) still produces a report so that
        // tamper findings and recovered functions surface for triage.
        let filefacts_ok = ctx.parsed.values().get("pe.machine").is_some();
        let lazy_walker_panicked = ctx
            .parsed
            .metrics()
            .get("pe.resource_walk_panicked")
            .is_some();
        let parse_panicked = ctx.parsed.metrics().get("pe.parse_panicked").is_some();
        let partial_parse = ctx.parsed.values().get("pe.partial_parse").is_some();

        let any_lazy_panic = lazy_walker_panicked || parse_panicked;

        // Create target info
        let target = TargetInfo {
            path: logical_path.display().to_string(),
            file_type: "pe".to_string(),
            size_bytes: original_data.len() as u64,
            sha256: precomputed_sha256
                .map(ToString::to_string)
                .unwrap_or_else(|| crate::analyzers::utils::calculate_sha256(original_data)),
            architectures: filefacts_ok.then(|| vec![self.arch_name(ctx)]),
        };

        let mut report = AnalysisReport::new(target);
        let mut tools_used = Vec::new();
        if filefacts_ok {
            tools_used.push("filefacts".to_string());
        }

        // Project structural views from filefacts's typed accessors.
        // Recovery (for stripped / packed PEs) already ran inside
        // `filefacts::open` — `ctx.parsed.symbols()` / `imports()` /
        // `sections()` already carry what binform recovered.
        let scope_start = std::time::Instant::now();
        let mut struct_ms = 0u128;
        if filefacts_ok {
            let s_start = std::time::Instant::now();
            let pe_imports = self.pe_imports(ctx);
            let (pe_exports, _aliased_count) = self.pe_exports(ctx);
            let pe_sections = self.pe_sections(ctx);
            struct_ms = s_start.elapsed().as_millis();

            report.imports.extend(pe_imports);
            report.exports.extend(pe_exports);
            report.sections.extend(pe_sections);
        }
        let scope_ms = scope_start.elapsed().as_millis();
        if struct_ms > 0 {
            tracing::info!(
                path = %logical_path.display(),
                rayon_thread = ?rayon::current_thread_index(),
                scope_ms = scope_ms as u64,
                struct_ms = struct_ms as u64,
                "PE structural phase timings",
            );
        }

        // Functions come straight from filefacts: goblin-extracted entries
        // for symbols, plus binform-recovered ones (with CFG fields).
        report.functions = ctx
            .parsed
            .symbols()
            .iter_kind(filefacts::SymbolKind::Function)
            .filter_map(crate::analysis_context::project_filefacts_function)
            .collect();

        // A PE filefacts could not identify, or parsed only down to its
        // headers, is an analysis limit; the traits judge it from the
        // absence of `pe.machine` or the presence of `pe.partial_parse`.
        if !filefacts_ok {
            report
                .metadata
                .errors
                .push("PE could not be identified by filefacts".to_string());
        } else if partial_parse {
            report
                .metadata
                .errors
                .push("PE parsed with header-only fallback (downstream walker failed)".to_string());
        }

        // Surface "filefacts couldn't be trusted on this binary" via
        // `metadata.errors` only — the malformed-structure metric
        // bit lived on the retired typed projection.
        if any_lazy_panic && filefacts_ok && !partial_parse {
            report
                .metadata
                .errors
                .push("filefacts lazy walker panicked during PE metric extraction".to_string());
        }

        // --- Shared post-processing (strings, embedded code, metrics, overlay, SFX) ---

        // Strings come from filefacts's typed `text()` view — the single
        // string-extraction authority (cleave no longer scans). The raw
        // stng rows also feed embedded-child analysis below.
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

        // Embedded code in strings
        let (encoded_layers, plain_findings) =
            crate::analyzers::embedded_code_detector::process_all_strings(
                &logical_path.display().to_string(),
                &report.strings,
                &self.engine,
                0,
                Some(&crate::FileType::Pe),
                self.cancellation.as_deref(),
            );
        report.files.extend(encoded_layers);
        report.findings.extend(plain_findings);

        self.analyze_recovered_payloads(&mut report, pe_data, logical_path);

        // Signer findings, filed under how far the signature is trusted
        // (see `signature`). filefacts already folds the image-digest check
        // into its trust tier; `pe.signature_integrity` says which way a
        // signature that does not verify failed.
        if let Some(identity) = ctx.identity() {
            let failure = match ctx
                .parsed
                .values()
                .get("pe.signature_integrity")
                .and_then(|v| v.as_str())
            {
                Some("tampered") => Some(super::signature::Failure::Tampered),
                Some("invalid") => Some(super::signature::Failure::BadSignature),
                _ => None,
            };
            // The pinned CA that signed the leaf of the signature identity
            // was read from (`pe.signatures[0]`), if one did.
            let issuer = ctx
                .parsed
                .values()
                .get("pe.signatures")
                .and_then(|sigs| sigs.get(0))
                .and_then(super::signature::pinned_issuer);
            report.findings.extend(super::signature::findings(
                &identity,
                failure,
                issuer,
                "authenticode",
                None,
            ));
        }

        // Overlay analysis. The overlay extent comes from filefacts's
        // emitted `pe.overlay_offset` / `pe.overlay_end` metrics —
        // the same range the legacy "sections end → cert table"
        // derivation produced.
        let overlay_bounds = {
            let m = ctx.parsed.metrics();
            let start = m.get("pe.overlay_offset").map(|v| v as usize);
            let end = m.get("pe.overlay_end").map(|v| v as usize);
            match (start, end) {
                (Some(s), Some(e)) if e > s => Some((s, e)),
                _ => None,
            }
        };
        // Overlay extents flow through `filefacts.metrics` (pe.overlay_offset
        // / pe.overlay_end) — no cleave-side metric mirror needed now.

        // Overlay archive analysis
        if let Some((overlay_start, overlay_end)) = overlay_bounds
            && let Some(overlay_data) = pe_data.get(overlay_start..overlay_end)
            && let Some(archive_type) = ctx
                .parsed
                .values()
                .get("binary.overlay_archive")
                .and_then(serde_json::Value::as_str)
            && let Ok(overlay_analysis) = crate::analyzers::overlay::analyze_overlay(
                overlay_data,
                archive_type,
                &report.target.path,
                &self.engine,
                self.yara_engine.clone(),
                Some(&self.archive_config),
            )
        {
            adopt_overlay(&mut report, &mut tools_used, overlay_analysis);
        }

        // NSIS / Inno Setup detection
        // Discover embedded images once and use their validated spans when
        // identifying SFX markers. A nested Inno installer must be analyzed
        // as the embedded child; its marker must not make the host itself look
        // like an Inno setup or trigger extraction of the wrong byte range.
        // filefacts located images and installer markers in the whole file; a
        // junk prefix before the PE moves them by its length, and the host's
        // own header is not one of them.
        let prefix = (pe_data.as_ptr() as usize).saturating_sub(original_data.as_ptr() as usize);
        let embedded = if self.skip_embedded_scan {
            Vec::new()
        } else {
            crate::analyzers::embedded_images::EmbeddedImage::from_values(ctx.parsed.values())
                .into_iter()
                .filter_map(|mut image| {
                    image.offset = image.offset.checked_sub(prefix).filter(|&at| at > 0)?;
                    Some(image)
                })
                .collect()
        };
        if let Some((sfx_kind, marker_offset)) =
            crate::analyzers::sfx_detector::installer_from_values(ctx.parsed.values(), prefix)
        {
            let sfx_result = crate::analyzers::sfx_detector::analyze_sfx(
                analysis_path,
                sfx_kind,
                marker_offset,
                pe_data,
                &self.engine,
                self.yara_engine.clone(),
                Some(&self.archive_config),
            );
            report.findings.extend(sfx_result.extraction_findings);
            if let Some(archive_report) = sfx_result.archive_report {
                report.findings.extend(archive_report.findings);
                report.files.extend(archive_report.files);
                // Preserve the complete extracted-member inventory, including
                // data files that are not promoted to separate analyses unless
                // --all-files is enabled. Prefixing here records the installer
                // as the immediate provenance parent.
                adopt_member_inventory(&mut report, archive_report.archive_contents);
                // Merge the inner archive report's kv subtrees (e.g.
                // `archive.*`) into the host PE's values_tree so they surface
                // in the host's `k` field at finalize time.
                if let Some(inner_kv) = archive_report.values_tree
                    && let serde_json::Value::Object(map) = *inner_kv
                {
                    for (ns, value) in map {
                        report.merge_kv_subtree(&ns, value);
                    }
                }
                adopt_tools(&mut tools_used, archive_report.metadata.tools_used);
            }
        }

        // Embedded PE / ELF scanning
        if !self.skip_embedded_scan {
            let mut bundle_analyzer = self.archive_config.apply(
                crate::analyzers::archive::ArchiveAnalyzer::new().with_engine(self.engine.clone()),
            );
            if let Some(yara) = &self.yara_engine {
                bundle_analyzer = bundle_analyzer.with_yara_arc(yara.clone());
            }
            // filefacts read the manifest from the bytes the ctx was opened
            // on, so its offsets index `original_data`.
            bundle_analyzer.analyze_dotnet_bundle(original_data, ctx.parsed.values(), &mut report);
        }

        if !self.skip_embedded_scan {
            self.analyze_embedded_binaries(&mut report, pe_data, &embedded);
        }

        report.metadata.analysis_duration_ms = start.elapsed().as_millis() as u64;
        report.metadata.tools_used = tools_used;

        report
    }
    /// Canonical machine-type label for the parsed PE, read from
    /// filefacts's `pe.machine` (lowercase forms like `"x86_64"`,
    /// `"i386"`, `"arm64"`). Falls back to a literal `"unknown"`
    /// only when filefacts didn't identify the binary as PE — every
    /// successful PE parse emits the field.
    fn arch_name(&self, ctx: &Ctx<'_>) -> String {
        ctx.parsed
            .values()
            .get("pe.machine")
            .and_then(|x| x.as_str())
            .map(str::to_string)
            .unwrap_or_else(|| "unknown".to_string())
    }
}

impl Default for PEAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl Analyzer for PEAnalyzer {
    fn analyze_input(&self, input: &AnalysisInput<'_>) -> Result<AnalysisReport> {
        // Structural helpers (sections, imports, exports, signature
        // verification) and strings all source from filefacts's typed view.
        // Reuse the parse a caller threaded in (an archive member's): opening
        // again repeats the whole extraction, recovery included.
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
        Ok(report)
    }

    fn analyze(&self, file_path: &Path) -> Result<AnalysisReport> {
        let data = fs::read(file_path).context("Failed to read file")?;
        // Strings come from filefacts inside analyze_input — no local scan.
        let input = AnalysisInput::new(file_path, &data, crate::analyzers::FileType::Pe);
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
