//! PE (Portable Executable) analyzer for Windows binaries.
//!
//! Every PE-internal helper takes a non-optional
//! [`crate::analysis_context::AnalysisContext`]: structural data
//! (sections, imports, exports, characteristics) is read from
//! `expose`'s typed views rather than re-walked with goblin. The
//! analyzer no longer carries its own goblin parse path.
use crate::analyzers::{AnalysisInput, Analyzer};
use crate::capabilities::CapabilityMapper;
use crate::strings::StringExtractor;
use crate::types::{
    AnalysisReport, Criticality, Evidence, Export, Finding, FindingKind, Import, Section,
    StringInfo, StructuralFeature, TargetInfo,
};
use crate::yara_engine::YaraEngine;
use anyhow::{Context, Result};
use std::fs;
use std::path::Path;
use std::sync::Arc;

type Ctx<'a> = crate::analysis_context::AnalysisContext<'a>;

/// Analyzer for Windows PE binaries (executables, DLLs, drivers).
///
/// All deep-binary signal — function CFG fields, sections recovered
/// from packed binaries, the rizin import fallback — now flows in
/// through `expose::open`. The analyzer projects from
/// `ctx.parsed.functions()` / `imports()` / `sections()` rather than
/// spawning rizin itself.
#[derive(Debug)]
pub struct PEAnalyzer {
    capability_mapper: Arc<CapabilityMapper>,
    string_extractor: StringExtractor,
    yara_engine: Option<Arc<YaraEngine>>,
    /// Pre-extracted strings from stng (avoids redundant extraction)
    preextracted_strings: Option<Vec<StringInfo>>,
    /// When true, skip scanning for embedded PE/ELF binaries (prevents recursion in sub-analysis).
    skip_embedded_scan: bool,
    /// Per-request cancellation flag.
    cancellation: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
}

/// True when the PE has the IMAGE_FILE_DLL characteristic
/// (`0x2000`) set. Reads from expose's `pe.characteristics_raw`
/// emission, which always carries the raw COFF Characteristics u16.
fn is_dll_from_ctx(ctx: &Ctx<'_>) -> bool {
    ctx.parsed
        .values()
        .get("pe.characteristics_raw")
        .and_then(|v| v.as_u64())
        .is_some_and(|c| c & 0x2000 != 0)
}

/// Read the certificate-table range `(offset, end)` from expose's
/// emitted `pe.data_directories[]`. Returns `None` when the
/// directory is absent, empty, or extends past the file end.
fn pe_certificate_range_from_ctx(ctx: &Ctx<'_>, data: &[u8]) -> Option<(usize, usize)> {
    let arr = ctx.parsed.values().get("pe.data_directories")?.as_array()?;
    for node in arr {
        if node.get("name")?.as_str()? != "certificate" {
            continue;
        }
        let offset = node.get("rva")?.as_u64()? as usize;
        let size = node.get("size")?.as_u64()? as usize;
        if offset == 0 || size == 0 || offset.checked_add(size)? > data.len() {
            return None;
        }
        return Some((offset, offset + size));
    }
    None
}

fn looks_like_dos_executable(data: &[u8]) -> bool {
    if data.len() < 0x40 || !data.starts_with(b"MZ") {
        return false;
    }

    let pe_offset = u32::from_le_bytes([data[0x3c], data[0x3d], data[0x3e], data[0x3f]]) as usize;
    if pe_offset + 4 <= data.len() && &data[pe_offset..pe_offset + 4] == b"PE\x00\x00" {
        return false;
    }

    let last_page_bytes = u16::from_le_bytes([data[2], data[3]]) as usize;
    let page_count = u16::from_le_bytes([data[4], data[5]]) as usize;
    let header_paragraphs = u16::from_le_bytes([data[8], data[9]]) as usize;
    if page_count == 0 || header_paragraphs == 0 {
        return false;
    }

    let declared_size = (page_count.saturating_sub(1) * 512)
        + if last_page_bytes == 0 {
            512
        } else {
            last_page_bytes
        };
    let header_size = header_paragraphs * 16;
    declared_size >= header_size
        && declared_size <= data.len().saturating_add(512)
        && header_size < data.len()
}

fn dn_extract_cn(dn: &str) -> Option<String> {
    for raw in dn.split(',') {
        let seg = raw.trim();
        // Accept `CN=…` case-insensitively — RFC 4514 attributes are
        // case-insensitive and x509-cert canonicalises to upper-case
        // but we don't rely on the canonicalisation.
        if let Some(rest) = seg.strip_prefix("CN=").or_else(|| seg.strip_prefix("cn=")) {
            return Some(rest.trim().to_string());
        }
    }
    None
}

/// Pull the first O attribute from a DN string. Same comma-split as
/// `dn_extract_cn`; returns `None` when the DN doesn't carry one.
fn dn_extract_o(dn: &str) -> Option<String> {
    for raw in dn.split(',') {
        let seg = raw.trim();
        if let Some(rest) = seg.strip_prefix("O=").or_else(|| seg.strip_prefix("o=")) {
            return Some(rest.trim().to_string());
        }
    }
    None
}

impl PEAnalyzer {
    /// Emit the small list of structural-feature entries cleave's
    /// downstream consumers expect: `pe/header`, `pe/dll` (when the
    /// IMAGE_FILE_DLL characteristic is set), and `pe/optional_header`
    /// (when the optional header is present). All facts come from
    /// expose's emitted values — no goblin re-walk.
    fn structural_features(&self, ctx: &Ctx<'_>) -> Vec<StructuralFeature> {
        let mut features = Vec::new();
        let values = ctx.parsed.values();
        let machine = values
            .get("pe.machine")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        let subsystem = values
            .get("pe.subsystem")
            .and_then(|v| v.as_str())
            .map(str::to_string);
        features.push(StructuralFeature {
            id: "pe/header".to_string(),
            desc: format!("PE file (machine: {}, subsystem: {:?})", machine, subsystem),
            evidence: vec![Evidence {
                method: "header".to_string(),
                source: "expose".to_string(),
                value: "PE".to_string(),
                location: None,
                ..Default::default()
            }],
        });

        if is_dll_from_ctx(ctx) {
            features.push(StructuralFeature {
                id: "pe/dll".to_string(),
                desc: "Dynamic Link Library (DLL)".to_string(),
                evidence: vec![Evidence {
                    method: "header".to_string(),
                    source: "expose".to_string(),
                    value: "DLL".to_string(),
                    location: None,
                    ..Default::default()
                }],
            });
        }

        if values.get("pe.subsystem").is_some() {
            features.push(StructuralFeature {
                id: "pe/optional_header".to_string(),
                desc: "Has optional header (standard Windows executable)".to_string(),
                evidence: vec![Evidence {
                    method: "header".to_string(),
                    source: "expose".to_string(),
                    value: "OptionalHeader".to_string(),
                    location: None,
                    ..Default::default()
                }],
            });
        }
        features
    }

    /// Project expose's typed `Imports` view into `Vec<Import>` and
    /// run capability-mapper lookups over the symbol set. Symbol
    /// names are pre-normalised inside `imports_from_expose`.
    fn pe_imports(&self, ctx: &Ctx<'_>) -> (Vec<Import>, Vec<Finding>) {
        let imports = ctx.imports_from_expose();
        let mut findings = Vec::new();
        for imp in &imports {
            let normalized = crate::types::binary::normalize_symbol(&imp.symbol);
            if let Some(capability) = self.capability_mapper.lookup(&normalized, &imp.source) {
                findings.push(capability);
            }
        }
        (imports, findings)
    }

    /// Project expose's typed `Exports` view and the
    /// `pe.aliased_export_count` metric. Aliased exports are stub
    /// chains where multiple exported names land at the same target;
    /// expose's `aliased_exports` walker emits the count, so cleave
    /// doesn't disassemble locally.
    fn pe_exports(&self, ctx: &Ctx<'_>) -> (Vec<Export>, Option<u32>) {
        let exports = ctx.exports_from_expose();
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

    /// Project expose's typed `Sections` view into `Vec<Section>`.
    /// Per-section entropy comes from expose's metric map (no second
    /// scan over the section bytes).
    fn pe_sections(&self, ctx: &Ctx<'_>) -> Vec<Section> {
        ctx.sections_from_expose()
    }
    /// Creates a new PE analyzer with default configuration
    #[must_use]
    pub fn new() -> Self {
        Self {
            capability_mapper: Arc::new(CapabilityMapper::empty()),
            string_extractor: StringExtractor::new(),
            yara_engine: None,
            preextracted_strings: None,
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
    #[allow(dead_code)] // Used by binary target
    #[must_use]
    pub(crate) fn with_yara_arc(mut self, yara_engine: Arc<YaraEngine>) -> Self {
        self.yara_engine = Some(yara_engine);
        self
    }

    /// Create analyzer with pre-existing capability mapper (wraps in Arc)
    #[must_use]
    pub(crate) fn with_capability_mapper(mut self, capability_mapper: CapabilityMapper) -> Self {
        self.capability_mapper = Arc::new(capability_mapper);
        self
    }

    /// Create analyzer with shared capability mapper (avoids cloning)
    #[must_use]
    pub(crate) fn with_capability_mapper_arc(
        mut self,
        capability_mapper: Arc<CapabilityMapper>,
    ) -> Self {
        self.capability_mapper = capability_mapper;
        self
    }

    /// Set pre-extracted strings (avoids redundant stng/radare2 extraction)
    #[must_use]
    #[allow(dead_code)] // Used by binary target, not visible to library
    pub(crate) fn with_preextracted_strings(mut self, strings: Vec<StringInfo>) -> Self {
        self.preextracted_strings = Some(strings);
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
    /// If `stng_strings` is provided, uses those directly (avoids redundant extraction).
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
        precomputed_sha256: Option<String>,
    ) -> AnalysisReport {
        match crate::analysis_context::AnalysisContext::open(file_path, data) {
            Ok(ctx) => self.analyze_structural_with_ctx(file_path, data, precomputed_sha256, &ctx),
            Err(e) => {
                let mut report = AnalysisReport::new(TargetInfo {
                    path: file_path.display().to_string(),
                    file_type: "pe".to_string(),
                    size_bytes: data.len() as u64,
                    sha256: precomputed_sha256
                        .unwrap_or_else(|| crate::analyzers::utils::calculate_sha256(data)),
                    architectures: None,
                });
                report
                    .metadata
                    .errors
                    .push(format!("expose open failed: {e}"));
                report
            }
        }
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
    pub(crate) fn analyze_structural_with_ctx<'a>(
        &self,
        file_path: &'a Path,
        data: &'a [u8],
        precomputed_sha256: Option<String>,
        ctx: &Ctx<'a>,
    ) -> AnalysisReport {
        use crate::types::file_analysis::encode_upx_path;
        use crate::upx::{UPXDecompressor, UPXError};

        if !UPXDecompressor::is_upx_packed(data) {
            return self.analyze_structural_with_strings(
                file_path,
                file_path,
                data,
                None,
                true,
                precomputed_sha256,
                ctx,
            );
        }

        // UPX-packed: structural analysis of packed binary first
        let mut report = self.analyze_structural_with_strings(
            file_path,
            file_path,
            data,
            None,
            true,
            precomputed_sha256.clone(),
            ctx,
        );

        report.findings.push(
            Finding::structural(
                "anti-static/packer/upx".to_string(),
                "Binary contains a UPX packing marker".to_string(),
                1.0,
            )
            .with_criticality(Criticality::Suspicious),
        );

        if !UPXDecompressor::is_available() {
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

        match UPXDecompressor::decompress(file_path) {
            Ok(unpacked_data) => {
                if let Ok(temp_file) = tempfile::NamedTempFile::new() {
                    if fs::write(temp_file.path(), &unpacked_data).is_ok() {
                        let opts = crate::analyzers::stng_analysis_opts(4);
                        let unpacked_strings =
                            stng::extract_strings_with_options(&unpacked_data, &opts);
                        // UPX-unpacked bytes differ from the caller's
                        // bytes; open a fresh context on the
                        // decompressed payload so the downstream
                        // helpers see a self-consistent view.
                        let unpacked_ctx = match crate::analysis_context::AnalysisContext::open(
                            temp_file.path(),
                            &unpacked_data,
                        ) {
                            Ok(c) => c,
                            Err(_) => return report,
                        };
                        let mut unpacked_report = self.analyze_structural_with_strings(
                            temp_file.path(),
                            temp_file.path(),
                            &unpacked_data,
                            Some(&unpacked_strings),
                            true,
                            None, // Hash will change after decompression
                            &unpacked_ctx,
                        );
                        crate::analyzers::binary_extractors::augment_report(
                            &mut unpacked_report,
                            &unpacked_data,
                        );
                        if let Some(yara) = &self.yara_engine {
                            match yara.scan_bytes_to_findings(&unpacked_data, Some(&["pe"])) {
                                Ok((matches, findings)) => {
                                    unpacked_report.yara_matches = matches;
                                    for finding in findings {
                                        unpacked_report.push_finding_capped(finding);
                                    }
                                }
                                Err(e) => unpacked_report
                                    .metadata
                                    .errors
                                    .push(format!("yara(upx): {e:#}")),
                            }
                        }
                        // Evaluate composites against the unpacked layer so that
                        // objective-level findings (infostealers, etc.) appear in the child.
                        self.capability_mapper.evaluate_and_merge_findings(
                            &mut unpacked_report,
                            &unpacked_data,
                            None,
                            None,
                        );

                        // Create separate FileAnalysis for unpacked layer
                        let unpacked_sha256 =
                            crate::analyzers::utils::calculate_sha256(&unpacked_data);
                        let virtual_path = encode_upx_path(&file_path.display().to_string());

                        let mut unpacked_file = unpacked_report.to_file_analysis(0);
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
                        report.files.extend(unpacked_report.files);
                        report.files.push(unpacked_file);

                        report.metadata.tools_used.push("upx".to_string());
                    }
                }
            }
            Err(e) => {
                let description = match e {
                    UPXError::DecompressionFailed(msg) => {
                        format!("UPX decompression failed (possibly tampered): {}", msg)
                    }
                    _ => format!("UPX decompression failed: {}", e),
                };
                report.findings.push(
                    Finding::structural(
                        "anti-static/packer/upx/decompression-failed".to_string(),
                        description,
                        1.0,
                    )
                    .with_criticality(Criticality::Hostile),
                );
            }
        }

        report
    }

    /// Structural analysis with optional pre-extracted strings.
    /// The caller provides an `AnalysisContext` borrowing `data`;
    /// every PE-internal helper reads from expose's typed views via
    /// that ctx (no goblin re-parse).
    #[allow(clippy::too_many_arguments)]
    fn analyze_structural_with_strings<'a>(
        &self,
        logical_path: &Path,
        analysis_path: &Path,
        data: &'a [u8],
        stng_strings: Option<&[stng::ExtractedString]>,
        allow_rizin: bool,
        precomputed_sha256: Option<String>,
        ctx: &Ctx<'a>,
    ) -> AnalysisReport {
        let start = std::time::Instant::now();

        // Detect and handle tampered PE (junk prefix before MZ header).
        // The ctx was opened on `data`; when stripping moves the MZ
        // header, the ctx still describes the original layout (which
        // is what trait authors want to see — the tampering itself
        // is the signal). The bytes we hand to downstream helpers
        // remain `data`.
        let (pe_data, tamper_findings) = self.detect_and_strip_tampering(data);

        self.analyze_pe(
            logical_path,
            analysis_path,
            data,
            pe_data,
            tamper_findings,
            start,
            stng_strings,
            allow_rizin,
            precomputed_sha256,
            ctx,
        )
    }

    /// Unified PE analysis driven by an `AnalysisContext`. Structure,
    /// imports, exports, sections, and per-format metrics all flow
    /// from expose's typed views. Rizin runs in parallel for
    /// disassembly-derived metrics (function counts, complexity,
    /// strings) and as a fallback when expose surfaces no sections
    /// or imports (e.g. corrupted import directories).
    ///
    /// `pe_data` is the post-tamper-strip slice; `original_data` is
    /// the caller's bytes verbatim. The two diverge only when
    /// `detect_and_strip_tampering` peeled a junk prefix off the
    /// front — overlay extraction and embedded-binary scanning
    /// operate on `pe_data`, while file-size metrics use
    /// `original_data`.
    #[allow(clippy::unnecessary_wraps, clippy::too_many_arguments)]
    fn analyze_pe<'a>(
        &self,
        logical_path: &Path,
        analysis_path: &Path,
        original_data: &[u8],
        pe_data: &'a [u8],
        mut tamper_findings: Vec<Finding>,
        start: std::time::Instant,
        stng_strings: Option<&[stng::ExtractedString]>,
        allow_rizin: bool,
        precomputed_sha256: Option<String>,
        ctx: &Ctx<'a>,
    ) -> AnalysisReport {
        // `expose_ok` is true whenever expose identified the bytes as
        // PE and emitted at least the COFF header. The fallback path
        // (no PE values present) still produces a report so that
        // tamper findings and rizin disassembly surface for triage.
        let expose_ok = ctx.parsed.values().get("pe.machine").is_some();
        let lazy_walker_panicked = ctx
            .parsed
            .metrics()
            .get("pe.resource_walk_panicked")
            .is_some();
        let parse_panicked = ctx.parsed.metrics().get("pe.parse_panicked").is_some();
        let partial_parse = ctx.parsed.values().get("pe.partial_parse").is_some();

        let any_lazy_panic = lazy_walker_panicked || parse_panicked;

        let file_size = original_data.len() as u64;
        // Executable-code size sums every section flagged `executable`
        // on expose's typed Sections view, capped to the file extent.
        let code_size_from_ctx: u64 = ctx
            .parsed
            .sections()
            .iter()
            .filter(|s| s.flags.iter().any(|f| f == "executable"))
            .map(|s| {
                let raw_end = s.file_offset.saturating_add(s.file_size);
                if raw_end > file_size {
                    file_size.saturating_sub(s.file_offset)
                } else {
                    s.file_size
                }
            })
            .sum();

        // Create target info
        let target = TargetInfo {
            path: logical_path.display().to_string(),
            file_type: "pe".to_string(),
            size_bytes: original_data.len() as u64,
            sha256: precomputed_sha256
                .clone()
                .unwrap_or_else(|| crate::analyzers::utils::calculate_sha256(original_data)),
            architectures: expose_ok.then(|| vec![self.arch_name(ctx)]),
        };

        let mut report = AnalysisReport::new(target);
        let mut tools_used = Vec::new();
        let mut embedded_binary_count: u32 = 0;
        let mut embedded_archive_count: u32 = 0;
        if expose_ok {
            tools_used.push("expose".to_string());
        }

        // Add any tampering findings detected during preprocessing
        report.findings.append(&mut tamper_findings);
        let _ = (analysis_path, code_size_from_ctx, file_size, allow_rizin);

        // Project structural views from expose's typed accessors. The
        // rizin recovery (for stripped / packed PEs) already ran
        // inside `expose::open` — `ctx.parsed.functions()` /
        // `imports()` / `sections()` already carry the rizin-recovered
        // entries with `source: "rizin"`.
        let scope_start = std::time::Instant::now();
        let mut struct_ms = 0u128;
        if expose_ok {
            let s_start = std::time::Instant::now();
            let structural_features = self.structural_features(ctx);
            let (pe_imports, pe_import_findings) = self.pe_imports(ctx);
            let (pe_exports, _aliased_count) = self.pe_exports(ctx);
            let pe_sections = self.pe_sections(ctx);
            struct_ms = s_start.elapsed().as_millis();

            report.structure.extend(structural_features);
            report.imports.extend(pe_imports);
            for finding in pe_import_findings {
                if !report.findings.iter().any(|f| f.id == finding.id) {
                    report.findings.push(finding);
                }
            }
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

        // Detect inflated section headers (declared size extends
        // beyond EOF). Reads expose's typed Sections view.
        if expose_ok {
            let has_inflated = ctx
                .parsed
                .sections()
                .iter()
                .any(|s| s.file_offset.saturating_add(s.file_size) > file_size);
            if has_inflated {
                report.findings.push(
                    Finding::structural(
                        "metadata/binary/anomaly::inflated-section-headers".to_string(),
                        "PE section headers declare sizes beyond end of file".to_string(),
                        0.9,
                    )
                    .with_criticality(Criticality::Notable),
                );
            }
        }

        // Functions come straight from expose: goblin-extracted entries
        // for symbols, plus rizin-recovered ones (with CFG fields) when
        // expose's rizin fallback fired during `open`.
        report.functions = ctx
            .parsed
            .functions()
            .iter()
            .map(crate::analysis_context::project_expose_function)
            .collect();
        if ctx.parsed.functions().iter().any(|f| f.source == "rizin") {
            tools_used.push("radare2".to_string());
        }

        // String extraction no longer threads rizin's `izj` output
        // through stng: expose runs rizin once during `open`, and the
        // stng pre-population options (boundaries / function metadata /
        // connect-addrs / xor candidates) are sourced from there.
        let r2_strings: Option<Vec<stng::ExtractedString>> = None;

        // --- Corrupted-header findings (expose's PE parse fell back
        // to header-only, or failed entirely). The exact failure
        // detail isn't surfaced by expose's metrics; the absence of
        // `pe.machine` or presence of `pe.partial_parse` IS the
        // signal.
        if !expose_ok || partial_parse {
            let rizin_found_hidden_content =
                !report.sections.is_empty() || !report.imports.is_empty();
            let is_dos_executable = looks_like_dos_executable(pe_data);
            // Partial parse (header-only fallback) means the COFF
            // header was readable but a downstream walker failed;
            // resource-only DLLs and resource-table errors land
            // here. Treat as informational unless rizin found
            // something the parse missed.
            let (crit, conf) = if !expose_ok && !is_dos_executable {
                if rizin_found_hidden_content {
                    (Criticality::Suspicious, 0.8)
                } else {
                    (Criticality::Suspicious, 0.85)
                }
            } else {
                (Criticality::Baseline, 0.3)
            };

            let msg = if !expose_ok {
                "PE could not be identified by expose"
            } else {
                "PE parsed with header-only fallback (downstream walker failed)"
            };
            report.findings.push(Finding {
                id: "objectives/anti-analysis/pe-tampering/corrupted-header".to_string(),
                kind: FindingKind::Structural,
                desc: msg.to_string(),
                conf,
                crit,
                mbc: Some("B0001".to_string()),
                attack: Some("T1027".to_string()),
                trait_refs: vec![],
                evidence: vec![Evidence {
                    method: "parse-failure".to_string(),
                    source: "expose".to_string(),
                    value: msg.to_string(),
                    location: None,
                    ..Default::default()
                }],
                match_count: 1,
                source_file: None,
            });

            report.structure.push(StructuralFeature {
                id: "pe/corrupted".to_string(),
                desc: "Corrupted/tampered PE binary (header parsing failed)".to_string(),
                evidence: vec![Evidence {
                    method: "parse-failure".to_string(),
                    source: "expose".to_string(),
                    value: msg.to_string(),
                    location: None,
                    ..Default::default()
                }],
            });

            report.metadata.errors.push(msg.to_string());
        }

        // Surface "expose couldn't be trusted on this binary" via
        // `metadata.errors` only — the malformed-structure metric
        // bit lived on the retired typed projection.
        if any_lazy_panic && expose_ok && !partial_parse {
            report
                .metadata
                .errors
                .push("expose lazy walker panicked during PE metric extraction".to_string());
        }

        // --- Shared post-processing (strings, embedded code, metrics, overlay, SFX) ---

        // String extraction (preference: stng_strings > preextracted > extract_smart)
        let (report_strings, raw_stng_strings) = if let Some(strings) = stng_strings {
            (
                self.string_extractor.convert_stng_strings(strings),
                Some(strings.to_vec()),
            )
        } else if let Some(ref strings) = self.preextracted_strings {
            // If we have preextracted strings but they are already converted, we can't easily get back to raw.
            // But usually preextracted_strings are from stng-local path or similar.
            (strings.clone(), None)
        } else {
            let raw = self.string_extractor.extract_raw_smart(pe_data);
            (self.string_extractor.convert_stng_strings(&raw), Some(raw))
        };
        let _ = r2_strings;
        report.strings = report_strings;

        // Report string truncation if limits were hit
        if self
            .string_extractor
            .truncated
            .load(std::sync::atomic::Ordering::SeqCst)
        {
            report.findings.push(Finding {
                id: "metadata/strings-truncated".to_string(),
                kind: FindingKind::Structural,
                desc: format!(
                    "String extraction truncated due to limits (count: {}, total bytes: {} MB)",
                    crate::strings::MAX_STRINGS_PER_FILE,
                    crate::strings::MAX_TOTAL_STRING_BYTES / (1024 * 1024)
                )
                .to_string(),
                conf: 1.0,
                crit: Criticality::Notable,
                mbc: None,
                attack: None,
                trait_refs: vec![],
                evidence: vec![],
                match_count: 0,
                source_file: None,
            });
        }
        tools_used.push("stng".to_string());

        // Embedded code in strings
        let (encoded_layers, plain_findings) =
            crate::analyzers::embedded_code_detector::process_all_strings(
                &logical_path.display().to_string(),
                &report.strings,
                &self.capability_mapper,
                0,
                Some(&crate::FileType::Pe),
                self.cancellation.as_deref(),
            );
        report.files.extend(encoded_layers);
        report.findings.extend(plain_findings);

        // Emit signature findings directly from expose's
        // `pe.signatures[]` view. Each leaf cert subject CN becomes
        // a `metadata/signed/<type>::<cn>` finding; the very first
        // signature's CN is also emitted as a `metadata/signed/leaf::<cn>`
        // Notable so "who signed this" stands out from the chain.
        if let Some(sigs) = ctx
            .parsed
            .values()
            .get("pe.signatures")
            .and_then(|v| v.as_array())
        {
            for (idx, sig) in sigs.iter().enumerate() {
                let Some(subject) = sig.get("subject").and_then(|v| v.as_str()) else {
                    continue;
                };
                let Some(cn) = dn_extract_cn(subject) else {
                    continue;
                };
                let normalized = cn
                    .to_lowercase()
                    .replace(' ', "-")
                    .replace(',', "")
                    .replace("(", "")
                    .replace(")", "");
                report.findings.push(Finding {
                    id: format!("metadata/signed/unknown::{}", normalized),
                    kind: FindingKind::Capability,
                    desc: format!("Authenticode chain CN: {}", cn),
                    conf: 1.0,
                    crit: Criticality::Baseline,
                    mbc: None,
                    attack: None,
                    trait_refs: vec![],
                    evidence: vec![Evidence {
                        method: "authenticode".to_string(),
                        source: "expose".to_string(),
                        value: cn.clone(),
                        ..Default::default()
                    }],
                    match_count: 1,
                    source_file: None,
                });
                if idx == 0 {
                    // Prefer the O attribute when present (organisation
                    // signs more meaningfully than a person's CN).
                    let primary = dn_extract_o(subject).unwrap_or_else(|| cn.clone());
                    let primary_norm = primary
                        .to_lowercase()
                        .replace(' ', "-")
                        .replace(',', "")
                        .replace("(", "")
                        .replace(")", "");
                    report.findings.push(Finding {
                        id: format!("metadata/signed/leaf::{}", primary_norm),
                        kind: FindingKind::Capability,
                        desc: format!("Signed by {}", primary),
                        conf: 1.0,
                        crit: Criticality::Notable,
                        mbc: None,
                        attack: None,
                        trait_refs: vec![],
                        evidence: vec![Evidence {
                            method: "authenticode".to_string(),
                            source: "expose".to_string(),
                            value: primary,
                            ..Default::default()
                        }],
                        match_count: 1,
                        source_file: None,
                    });
                }
            }
        }
        let _ = original_data;

        // Overlay analysis. The overlay extent comes from expose's
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
        // Overlay extents flow through `expose.metrics` (pe.overlay_offset
        // / pe.overlay_end) — no cleave-side metric mirror needed now.

        // Overlay archive analysis
        if let Some((overlay_start, overlay_end)) = overlay_bounds {
            let overlay_data = &pe_data[overlay_start..overlay_end];
            if let Ok(Some(overlay_analysis)) = crate::analyzers::overlay::analyze_overlay(
                overlay_data,
                &report.target.path,
                Some(self.capability_mapper.clone()),
                self.yara_engine.clone(),
            ) {
                embedded_archive_count = embedded_archive_count.saturating_add(1);
                let pe_filename = std::path::Path::new(&report.target.path)
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("binary.exe");

                report.findings.push(overlay_analysis.sfx_finding);

                for mut finding in overlay_analysis.archive_report.findings {
                    for evidence in &mut finding.evidence {
                        if let Some(ref loc) = evidence.location {
                            if let Some(rest) = loc.strip_prefix("archive:") {
                                evidence.location = Some(format!(
                                    "archive:{}{}{}",
                                    pe_filename,
                                    crate::types::file_analysis::ARCHIVE_DELIMITER,
                                    rest
                                ));
                            } else if !loc.contains(crate::types::file_analysis::ARCHIVE_DELIMITER)
                            {
                                evidence.location = Some(format!(
                                    "archive:{}{}{}",
                                    pe_filename,
                                    crate::types::file_analysis::ARCHIVE_DELIMITER,
                                    loc
                                ));
                            }
                        }
                    }
                    report.findings.push(finding);
                }

                for mut entry in overlay_analysis.archive_report.archive_contents {
                    if !entry
                        .path
                        .contains(crate::types::file_analysis::ARCHIVE_DELIMITER)
                    {
                        entry.path = crate::types::file_analysis::encode_archive_path(
                            pe_filename,
                            &entry.path,
                        );
                    }
                    report.archive_contents.push(entry);
                }

                report.files.extend(overlay_analysis.archive_report.files);
                report
                    .strings
                    .extend(overlay_analysis.archive_report.strings);
                for tool in overlay_analysis.archive_report.metadata.tools_used {
                    if !tools_used.contains(&tool) {
                        tools_used.push(tool);
                    }
                }
            }
        }

        // NSIS / Inno Setup detection
        let detected_sfx_kind = crate::analyzers::sfx_detector::detect_sfx(pe_data);
        if let Some(sfx_kind) = detected_sfx_kind {
            let sfx_result = crate::analyzers::sfx_detector::analyze_sfx(
                analysis_path,
                sfx_kind,
                pe_data,
                Some(self.capability_mapper.clone()),
                self.yara_engine.clone(),
            );
            report.findings.push(sfx_result.sfx_finding);
            if let Some(archive_report) = sfx_result.archive_report {
                embedded_archive_count = embedded_archive_count.saturating_add(1);
                report.findings.extend(archive_report.findings);
                report.files.extend(archive_report.files);
                // Merge per-format kv subtrees from the inner archive report
                // (e.g. `pyinstaller.*`) into the host PE's kv_tree so they
                // surface in the host's `k` field at finalize time.
                if let Some(inner_kv) = archive_report.kv_tree {
                    if let serde_json::Value::Object(map) = *inner_kv {
                        for (ns, value) in map {
                            report.merge_kv_subtree(&ns, value);
                        }
                    }
                }
                for tool in archive_report.metadata.tools_used {
                    if !tools_used.contains(&tool) {
                        tools_used.push(tool);
                    }
                }
            }
        }

        // Embedded PE / ELF scanning
        if !self.skip_embedded_scan {
            let host_name = std::path::Path::new(&report.target.path)
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("binary.exe")
                .to_string();
            let cert_range = pe_certificate_range_from_ctx(ctx, pe_data);
            let embedded = crate::analyzers::embedded_binary_detector::scan_for_embedded_binaries(
                pe_data,
                self.cancellation.as_deref(),
            );
            for binary in &embedded {
                if self.is_cancelled() {
                    break;
                }
                if cert_range
                    .is_some_and(|(start, end)| binary.offset >= start && binary.offset < end)
                {
                    continue;
                }
                embedded_binary_count = embedded_binary_count.saturating_add(1);
                let mut finding = crate::analyzers::embedded_binary_detector::finding_for(
                    binary,
                    &report.target.path,
                );
                // Downgrade embedded binaries in .rsrc or .NET
                // managed resources to Notable (legitimate use —
                // e.g. resource-only DLLs, .NET assemblies bundling
                // drivers). Section lookup runs over expose's typed
                // Sections view.
                if expose_ok {
                    let in_rsrc = ctx.parsed.sections().iter().any(|s| {
                        if s.name != ".rsrc" {
                            return false;
                        }
                        let start = s.file_offset as usize;
                        let end = start + s.file_size as usize;
                        binary.offset >= start && binary.offset < end
                    });
                    // .NET assemblies store managed resources —
                    // including embedded native drivers — in the
                    // .text section, not .rsrc. Detect .NET via the
                    // CLR metadata root BSJB signature, which is
                    // present in every valid .NET assembly.
                    let is_dotnet = pe_data.windows(4).any(|w| w == b"BSJB");
                    let in_nsis_overlay =
                        matches!(
                            detected_sfx_kind,
                            Some(crate::analyzers::sfx_detector::SfxKind::Nsis)
                        ) && overlay_bounds.is_some_and(|(overlay_start, overlay_end)| {
                            binary.offset >= overlay_start && binary.offset < overlay_end
                        });
                    if std::env::var("DEBUG_CLEAVE_DOTNET").is_ok() {
                        eprintln!(
                            "[DEBUG] embedded PE check: in_rsrc={}, is_dotnet={}, in_nsis_overlay={}, data_len={}",
                            in_rsrc,
                            is_dotnet,
                            in_nsis_overlay,
                            pe_data.len()
                        );
                    }
                    // NSIS installers legitimately carry native
                    // plugin DLLs inside the overlay; those child
                    // binaries are still extracted and analyzed, so
                    // the host-level embedded-PE marker should be
                    // informational rather than suspicious.
                    //
                    // Platform-signed PEs (e.g. Microsoft Windows
                    // drivers) legitimately carry firmware blobs
                    // (Intel microcode, etc.) formatted as ELF
                    // inside non-standard sections like .drt.
                    let host_is_platform_signed = report
                        .findings
                        .iter()
                        .any(|f| f.id.starts_with("metadata/signed/platform::"));
                    if in_rsrc || is_dotnet || in_nsis_overlay || host_is_platform_signed {
                        finding.crit = Criticality::Notable;
                    }
                }

                if binary.offset >= pe_data.len() {
                    report.findings.push(finding);
                    continue;
                }
                // Decode base64-encoded payloads before recursing —
                // otherwise the child analyzer reads encoded text
                // and reports the dropper as a malformed binary.
                let decoded_storage: Vec<u8>;
                let embedded_bytes: &[u8] = if binary.encoding == Some("base64") {
                    let run_end = binary.offset
                        + pe_data[binary.offset..]
                            .iter()
                            .take_while(|&&b| {
                                b.is_ascii_alphanumeric() || b == b'+' || b == b'/' || b == b'='
                            })
                            .count();
                    let trimmed_end = run_end - (run_end - binary.offset) % 4;
                    match base64::Engine::decode(
                        &base64::engine::general_purpose::STANDARD,
                        &pe_data[binary.offset..trimmed_end],
                    ) {
                        Ok(b) => {
                            decoded_storage = b;
                            &decoded_storage[..]
                        }
                        Err(_) => {
                            report.findings.push(finding);
                            continue;
                        }
                    }
                } else {
                    let slice_end = (binary.offset + binary.estimated_size).min(pe_data.len());
                    &pe_data[binary.offset..slice_end]
                };
                let kind_str = binary.kind.as_str();
                let display_kind = binary.display_kind();
                if let Some(files) = crate::analyzers::utils::analyze_embedded_as_child(
                    embedded_bytes,
                    &host_name,
                    kind_str,
                    &display_kind,
                    binary.offset,
                    self.capability_mapper.clone(),
                    self.yara_engine.clone(),
                    raw_stng_strings.as_deref().unwrap_or(&[]),
                ) {
                    if finding.crit == Criticality::Suspicious
                        && files
                            .iter()
                            .flat_map(|file| &file.findings)
                            .any(|child_finding| {
                                child_finding.crit <= Criticality::Notable
                                    && child_finding.id.starts_with("metadata/signed/")
                            })
                    {
                        finding.crit = Criticality::Notable;
                    }
                    report.files.extend(files);
                }
                report.findings.push(finding);
            }
        }

        // Emit recursive-scan counters. Embedded-binary detection is
        // cleave's job (it spawns child analyses on each find), so
        // these counts live on cleave's flat metric map alongside the
        // expose-emitted `binary.*` keys.
        if embedded_binary_count > 0 || embedded_archive_count > 0 {
            use crate::types::core::MetricsExt;
            let flat = report.expose_metrics.get_or_insert_with(Default::default);
            if embedded_binary_count > 0 {
                flat.set_f(
                    "binary.embedded_binary_count",
                    f64::from(embedded_binary_count),
                );
                flat.set_f(
                    "binary.embedded_file_count",
                    f64::from(embedded_binary_count + embedded_archive_count),
                );
            }
            if embedded_archive_count > 0 {
                flat.set_f(
                    "binary.embedded_archive_count",
                    f64::from(embedded_archive_count),
                );
            }
        }

        report.metadata.analysis_duration_ms = start.elapsed().as_millis() as u64;
        report.metadata.tools_used = tools_used;

        report
    }
    /// Canonical machine-type label for the parsed PE, read from
    /// expose's `pe.machine` (lowercase forms like `"x86_64"`,
    /// `"i386"`, `"arm64"`). Falls back to a literal `"unknown"`
    /// only when expose didn't identify the binary as PE — every
    /// successful PE parse emits the field.
    fn arch_name(&self, ctx: &Ctx<'_>) -> String {
        ctx.parsed
            .values()
            .get("pe.machine")
            .and_then(|x| x.as_str())
            .map(str::to_string)
            .unwrap_or_else(|| "unknown".to_string())
    }

    fn detect_and_strip_tampering<'a>(&self, data: &'a [u8]) -> (&'a [u8], Vec<Finding>) {
        let mut findings = Vec::new();

        // Check if MZ is at offset 0
        if data.starts_with(b"MZ") {
            // Normal PE, but still check for other tampering
            self.detect_header_tampering(data, 0, &mut findings);
            return (data, findings);
        }

        // Search for MZ header within first 64 bytes
        let mz_offset = self.find_mz_offset(data, 64);

        if let Some(offset) = mz_offset {
            // Found MZ at non-zero offset - junk prefix detected
            let prefix = &data[..offset];
            let prefix_display = if prefix.len() <= 32 {
                String::from_utf8_lossy(prefix).to_string()
            } else {
                format!(
                    "{}... ({} bytes)",
                    String::from_utf8_lossy(&prefix[..32]),
                    prefix.len()
                )
            };

            findings.push(Finding {
                id: "objectives/anti-analysis/pe-tampering/junk-prefix".to_string(),
                kind: FindingKind::Structural,
                desc: format!(
                    "PE has {} bytes prepended before MZ header (anti-analysis)",
                    offset
                ),
                conf: 1.0,
                crit: Criticality::Hostile,
                mbc: Some("B0001".to_string()), // Executable Code Obfuscation
                attack: Some("T1027".to_string()), // Obfuscated Files or Information
                trait_refs: vec![],
                evidence: vec![Evidence {
                    method: "header-analysis".to_string(),
                    source: "cleave".to_string(),
                    value: format!("MZ at offset {:#x}, prefix: {:?}", offset, prefix_display),
                    location: Some(format!("0x0-{:#x}", offset)),
                    ..Default::default()
                }],
                match_count: 1,
                source_file: None,
            });

            // Check for additional tampering in the actual PE data
            let pe_data = &data[offset..];
            self.detect_header_tampering(pe_data, offset, &mut findings);

            return (pe_data, findings);
        }

        // No MZ found - check for BSJB (.NET) signature without valid PE
        if let Some(bsjb_offset) = self.find_signature(data, b"BSJB") {
            findings.push(Finding {
                id: "objectives/anti-analysis/pe-tampering/dotnet-invalid-pe".to_string(),
                kind: FindingKind::Structural,
                desc: ".NET assembly (BSJB signature) with corrupted/missing PE header".to_string(),
                conf: 0.95,
                crit: Criticality::Hostile,
                mbc: Some("B0001".to_string()),
                attack: Some("T1027".to_string()),
                trait_refs: vec![],
                evidence: vec![Evidence {
                    method: "signature".to_string(),
                    source: "cleave".to_string(),
                    value: format!("BSJB at offset {:#x}, no valid MZ header", bsjb_offset),
                    location: Some(format!("{:#x}", bsjb_offset)),
                    ..Default::default()
                }],
                match_count: 1,
                source_file: None,
            });
        }

        // Return original data (downstream parse will fail, which
        // is expected — the tampering finding already accompanies
        // the bytes).
        (data, findings)
    }

    /// Detect tampering within PE header area
    fn detect_header_tampering(
        &self,
        data: &[u8],
        base_offset: usize,
        findings: &mut Vec<Finding>,
    ) {
        if data.len() < 64 {
            return;
        }

        // Check for systematic byte injection (e.g., 0x20 padding)
        let header_area = &data[..data.len().min(512)];
        let mut byte_counts = [0u32; 256];
        for &b in header_area {
            byte_counts[b as usize] += 1;
        }

        let header_len = header_area.len() as u32;
        for (byte_val, &count) in byte_counts.iter().enumerate() {
            // Skip 0x00 (common in headers) and check if any byte is >40% of header
            if byte_val != 0 && count > header_len * 2 / 5 {
                findings.push(Finding {
                    id: "objectives/anti-analysis/pe-tampering/byte-injection".to_string(),
                    kind: FindingKind::Structural,
                    desc: format!(
                        "PE header has excessive 0x{:02X} bytes ({} of {} = {:.1}%)",
                        byte_val,
                        count,
                        header_len,
                        count as f32 / header_len as f32 * 100.0
                    ),
                    conf: 0.9,
                    crit: Criticality::Suspicious,
                    mbc: Some("B0001".to_string()),
                    attack: Some("T1027".to_string()),
                    trait_refs: vec![],
                    evidence: vec![Evidence {
                        method: "frequency-analysis".to_string(),
                        source: "cleave".to_string(),
                        value: format!("byte 0x{:02X} appears {} times in header", byte_val, count),
                        location: Some(format!("{:#x}-{:#x}", base_offset, base_offset + 512)),
                        ..Default::default()
                    }],
                    match_count: 1,
                    source_file: None,
                });
                break; // Only report the most prominent injection
            }
        }

        // Check the actual PE signature location from the DOS header, not the first
        // incidental `PE` byte sequence anywhere in the file.
        let pe_sig_offset =
            u32::from_le_bytes([data[0x3c], data[0x3d], data[0x3e], data[0x3f]]) as usize;
        if pe_sig_offset + 4 <= data.len() {
            let sig = &data[pe_sig_offset..pe_sig_offset + 4];
            if sig != b"PE\x00\x00" && !looks_like_dos_executable(data) {
                findings.push(Finding {
                    id: "objectives/anti-analysis/pe-tampering/pe-signature-corrupted".to_string(),
                    kind: FindingKind::Structural,
                    desc: format!(
                        "PE signature corrupted: expected PE\\x00\\x00, got {:02X} {:02X} {:02X} {:02X}",
                        sig[0], sig[1], sig[2], sig[3]
                    ),
                    conf: 0.85,
                    crit: Criticality::Suspicious,
                    mbc: Some("B0001".to_string()),
                    attack: Some("T1027".to_string()),
                    trait_refs: vec![],
                    evidence: vec![Evidence {
                        method: "signature".to_string(),
                        source: "cleave".to_string(),
                        value: format!("PE signature at {:#x}: {:?}", pe_sig_offset, sig),
                        location: Some(format!("{:#x}", base_offset + pe_sig_offset)),
                        ..Default::default()
                    }],
                    match_count: 1,
                    source_file: None,
                });
            }
        }

        // Detect .NET via BSJB signature
        if let Some(bsjb_offset) = self.find_signature(data, b"BSJB") {
            findings.push(Finding {
                id: "metadata/dotnet/bsjb-signature".to_string(),
                kind: FindingKind::Structural,
                desc: ".NET assembly detected via BSJB CLR metadata signature".to_string(),
                conf: 1.0,
                crit: Criticality::Baseline,
                mbc: None,
                attack: None,
                trait_refs: vec![],
                evidence: vec![Evidence {
                    method: "signature".to_string(),
                    source: "cleave".to_string(),
                    value: format!("BSJB at offset {:#x}", bsjb_offset),
                    location: Some(format!("{:#x}", base_offset + bsjb_offset)),
                    ..Default::default()
                }],
                match_count: 1,
                source_file: None,
            });
        }
    }

    /// Find MZ header within first max_offset bytes
    #[allow(clippy::manual_find)]
    fn find_mz_offset(&self, data: &[u8], max_offset: usize) -> Option<usize> {
        let limit = data.len().min(max_offset);
        for i in 0..limit.saturating_sub(1) {
            if data[i] == b'M' && data.get(i + 1) == Some(&b'Z') {
                return Some(i);
            }
        }
        None
    }

    /// Find a byte signature in data
    fn find_signature(&self, data: &[u8], needle: &[u8]) -> Option<usize> {
        data.windows(needle.len()).position(|w| w == needle)
    }
}

impl Default for PEAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl Analyzer for PEAnalyzer {
    fn analyze_input(&self, input: &AnalysisInput<'_>) -> Result<AnalysisReport> {
        // Use caller-provided strings when present; an empty slice means the
        // caller only supplied bytes, so the structural analyzer should extract.
        let strings = if input.strings.is_empty() {
            None
        } else {
            Some(input.strings)
        };
        // Open expose-side parse so structural helpers (sections,
        // imports, exports, signature verification) source from
        // expose's typed view.
        let ctx = crate::analysis_context::AnalysisContext::open(input.path, input.data)
            .map_err(|e| anyhow::anyhow!("expose open failed for PE: {e}"))?;
        let mut report = self.analyze_structural_with_strings(
            input.path,
            input.backing_path(),
            input.data,
            strings,
            !input.skip_rizin,
            input.sha256.clone(),
            &ctx,
        );

        // Post-processing
        self.capability_mapper
            .evaluate_and_merge_findings(&mut report, input.data, None, None);
        Ok(report)
    }

    fn analyze(&self, file_path: &Path) -> Result<AnalysisReport> {
        let data = fs::read(file_path).context("Failed to read file")?;
        let opts = crate::analyzers::stng_analysis_opts(4);
        let strings = stng::extract_strings_with_options(&data, &opts);
        tracing::debug!(
            path = %file_path.display(),
            strings = strings.len(),
            string_mode = "stng-local",
            reason = "legacy analyze() path without pre-extracted AnalysisInput",
            "PE analyzer extracting strings locally before analyze_input"
        );
        let input =
            AnalysisInput::with_strings(file_path, &data, &strings, crate::analyzers::FileType::Pe);
        self.analyze_input(&input)
    }

    fn can_analyze(&self, file_path: &Path) -> bool {
        // PE magic-byte check: `MZ` + valid `e_lfanew` pointing at `PE\0\0`.
        // A full expose parse just to gate analyzability is wasted
        // work — the actual parse happens once we commit to analyze().
        let Ok(mut file) = fs::File::open(file_path) else {
            return false;
        };
        use std::io::{Read, Seek, SeekFrom};
        let mut head = [0u8; 64];
        if file.read_exact(&mut head).is_err() || &head[0..2] != b"MZ" {
            return false;
        }
        let e_lfanew = u32::from_le_bytes([head[60], head[61], head[62], head[63]]) as u64;
        if file.seek(SeekFrom::Start(e_lfanew)).is_err() {
            return false;
        }
        let mut sig = [0u8; 4];
        file.read_exact(&mut sig).is_ok() && &sig == b"PE\0\0"
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn test_pe_path() -> PathBuf {
        PathBuf::from("tests/fixtures/test.exe")
    }

    #[test]
    fn test_can_analyze_pe() {
        let analyzer = PEAnalyzer::new();
        let test_file = test_pe_path();

        if test_file.exists() {
            assert!(analyzer.can_analyze(&test_file));
        }
    }

    #[test]
    fn test_cannot_analyze_non_pe() {
        let analyzer = PEAnalyzer::new();
        assert!(!analyzer.can_analyze(&PathBuf::from("/dev/null")));
        assert!(!analyzer.can_analyze(&PathBuf::from("tests/fixtures/test.elf")));
    }

    #[test]
    fn test_analyze_pe_file() {
        let analyzer = PEAnalyzer::new();
        let test_file = test_pe_path();

        if !test_file.exists() {
            return;
        }

        let result = analyzer.analyze(&test_file);
        assert!(result.is_ok());

        let report = result.unwrap();
        assert_eq!(report.target.file_type, "pe");
        assert!(report.target.size_bytes > 0);
        assert!(!report.target.sha256.is_empty());
    }

    #[test]
    fn test_pe_has_structure() {
        let analyzer = PEAnalyzer::new();
        let test_file = test_pe_path();

        if !test_file.exists() {
            return;
        }

        let report = analyzer.analyze(&test_file).unwrap();
        assert!(!report.structure.is_empty());
    }

    #[test]
    fn test_pe_architecture_detected() {
        let analyzer = PEAnalyzer::new();
        let test_file = test_pe_path();

        if !test_file.exists() {
            return;
        }

        let report = analyzer.analyze(&test_file).unwrap();
        let archs = report
            .target
            .architectures
            .expect("PE analyzer should detect at least one architecture");
        // test.exe is a 64-bit MSVC build. The canonical label is
        // `"x86_64"` — what expose emits and what every analyst-facing
        // tool (objdump, file(1), LIEF) reports. The ctx-fed path
        // returns this verbatim; the legacy fallback maps 0x8664 to
        // the same string.
        assert_eq!(
            archs,
            vec!["x86_64".to_string()],
            "test.exe arch label drifted from canonical x86_64",
        );
    }

    /// Verify `arch_name` returns expose's canonical lowercase label
    /// (`"x86_64"`, `"i386"`, `"arm64"`).
    #[test]
    fn arch_name_returns_expose_canonical_label() {
        let analyzer = PEAnalyzer::new();
        let test_file = test_pe_path();
        if !test_file.exists() {
            return;
        }
        let bytes = std::fs::read(&test_file).unwrap();
        let ctx = crate::analysis_context::AnalysisContext::open(&test_file, &bytes).unwrap();
        // test.exe is x86_64; expose surfaces it via `pe.machine`.
        assert_eq!(analyzer.arch_name(&ctx), "x86_64");
    }

    #[test]
    fn test_pe_sections_analyzed() {
        let analyzer = PEAnalyzer::new();
        let test_file = test_pe_path();

        if !test_file.exists() {
            return;
        }

        let report = analyzer.analyze(&test_file).unwrap();
        assert!(!report.sections.is_empty());
    }

    #[test]
    fn test_pe_has_imports() {
        let analyzer = PEAnalyzer::new();
        let test_file = test_pe_path();

        if !test_file.exists() {
            return;
        }

        let report = analyzer.analyze(&test_file).unwrap();
        assert!(!report.imports.is_empty());
    }

    /// `analyze_structural_with_ctx` produces non-empty
    /// imports / sections views for a standard MSVC fixture.
    /// Source tags should land as `"pe"` (from expose's typed view).
    #[test]
    fn analyze_structural_populates_pe_views() {
        let analyzer = PEAnalyzer::new();
        let test_file = test_pe_path();
        if !test_file.exists() {
            return;
        }
        let bytes = std::fs::read(&test_file).unwrap();
        let ctx = crate::analysis_context::AnalysisContext::open(&test_file, &bytes).unwrap();
        let report = analyzer.analyze_structural_with_ctx(&test_file, &bytes, None, &ctx);

        assert!(!report.imports.is_empty());
        // `test.exe` is an EXE rather than a DLL, so `exports` may
        // legitimately be empty — assert the imports/sections lanes
        // only.
        assert!(!report.sections.is_empty());

        // Imports come from expose's typed view; the source tag is "pe".
        let sources: std::collections::HashSet<&str> =
            report.imports.iter().map(|i| i.source.as_str()).collect();
        assert!(sources.contains("pe"));
    }

    #[test]
    fn test_pe_capabilities_detected() {
        let analyzer = PEAnalyzer::new();
        let test_file = test_pe_path();

        if !test_file.exists() {
            return;
        }

        let report = analyzer.analyze(&test_file).unwrap();
        // Capabilities may or may not be detected depending on the binary
        // Just verify the analysis completes successfully
        let _ = &report.traits;
    }

    #[test]
    fn test_pe_strings_extracted() {
        let analyzer = PEAnalyzer::new();
        let test_file = test_pe_path();

        if !test_file.exists() {
            return;
        }

        let report = analyzer.analyze(&test_file).unwrap();
        assert!(!report.strings.is_empty());
    }

    #[test]
    fn test_pe_tools_used() {
        let analyzer = PEAnalyzer::new();
        let test_file = test_pe_path();

        if !test_file.exists() {
            return;
        }

        let report = analyzer.analyze(&test_file).unwrap();
        assert!(report.metadata.tools_used.contains(&"expose".to_string()));
    }

    #[test]
    fn test_pe_analysis_duration() {
        let analyzer = PEAnalyzer::new();
        let test_file = test_pe_path();

        if !test_file.exists() {
            return;
        }

        let report = analyzer.analyze(&test_file).unwrap();
        // Duration may be 0 for very fast analysis (sub-millisecond).
        // The important thing is that analysis completes and the field is set.
        // Duration is a u64, so it's always >= 0.
        assert!(
            report.metadata.analysis_duration_ms < 60000,
            "Analysis should complete in under a minute"
        );
    }

    #[test]
    fn test_analyze_self_extracting_7z() {
        use std::fs;
        use std::io::Write;

        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("sfx.exe");

        let Ok(mut host) = fs::read("tests/fixtures/test.exe") else {
            eprintln!("skipping test_analyze_self_extracting_7z: missing tests/fixtures/test.exe");
            return;
        };

        // Append a tiny ZIP archive as overlay so the PE behaves like a
        // self-extracting archive without relying on developer-local samples.
        let cursor = std::io::Cursor::new(Vec::new());
        let mut zip = zip::ZipWriter::new(cursor);
        let options = zip::write::SimpleFileOptions::default();
        zip.start_file("hello.txt", options).unwrap();
        zip.write_all(b"hello from overlay").unwrap();
        let cursor = zip.finish().unwrap();
        host.extend_from_slice(&cursor.into_inner());
        fs::write(&path, &host).unwrap();

        let analyzer = PEAnalyzer::new();
        let report = analyzer.analyze(&path).unwrap();

        // Should detect the self-extracting archive
        assert!(
            report
                .findings
                .iter()
                .any(|f| f.id.contains("self-extracting")),
            "Should detect self-extracting archive"
        );

        // Should have analyzed the embedded archive contents
        assert!(
            !report.archive_contents.is_empty(),
            "Should have extracted archive contents"
        );

        // Should have findings from the embedded files
        eprintln!(
            "SFX analysis found {} files in archive",
            report.archive_contents.len()
        );
        eprintln!(
            "SFX analysis found {} total findings",
            report.findings.len()
        );

        // All archive content paths should use standard archive delimiter
        for entry in &report.archive_contents {
            assert!(
                entry
                    .path
                    .contains(crate::types::file_analysis::ARCHIVE_DELIMITER),
                "Archive path should use '!!': {}",
                entry.path
            );
            assert!(
                entry.path.starts_with("sfx.exe!!"),
                "Archive path should start with PE filename: {}",
                entry.path
            );
        }
    }

    // =========================================================================
    // UPX Integration Tests
    // =========================================================================

    #[test]
    fn test_pe_upx_detection_in_data() {
        use crate::upx::UPXDecompressor;

        // PE with UPX magic
        let mut upx_data = vec![0u8; 256];
        // MZ header
        upx_data[0..2].copy_from_slice(b"MZ");
        // UPX magic
        upx_data[100..104].copy_from_slice(b"UPX!");
        assert!(UPXDecompressor::is_upx_packed(&upx_data));

        // PE without UPX magic
        let mut normal_data = vec![0u8; 256];
        normal_data[0..2].copy_from_slice(b"MZ");
        assert!(!UPXDecompressor::is_upx_packed(&normal_data));
    }

    #[test]
    fn test_pe_upx_packed_creates_finding() {
        use crate::upx::UPXDecompressor;

        let analyzer = PEAnalyzer::new();

        // Create minimal UPX-packed PE-like data (won't actually decompress)
        let mut upx_data = vec![0u8; 512];
        // DOS header
        upx_data[0..2].copy_from_slice(b"MZ");
        // e_lfanew pointing to PE header
        upx_data[0x3c..0x40].copy_from_slice(&[0x80, 0x00, 0x00, 0x00]);
        // PE signature at offset 0x80
        upx_data[0x80..0x84].copy_from_slice(b"PE\x00\x00");
        // Machine type (x64)
        upx_data[0x84..0x86].copy_from_slice(&[0x64, 0x86]);
        // UPX magic
        upx_data[200..204].copy_from_slice(b"UPX!");

        assert!(UPXDecompressor::is_upx_packed(&upx_data));

        let temp_file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(temp_file.path(), &upx_data).unwrap();

        let report = analyzer.analyze_structural(temp_file.path(), &upx_data, None);

        // Should have UPX packer finding
        assert!(
            report
                .findings
                .iter()
                .any(|f| f.id == "anti-static/packer/upx"),
            "Should have UPX packer finding"
        );
    }

    #[test]
    fn test_pe_upx_tool_missing_creates_finding() {
        use crate::upx::{disable_upx, UPXDecompressor};

        // Temporarily disable UPX to simulate tool not available
        disable_upx();

        let analyzer = PEAnalyzer::new();

        // Create minimal UPX-packed PE-like data
        let mut upx_data = vec![0u8; 512];
        upx_data[0..2].copy_from_slice(b"MZ");
        upx_data[0x3c..0x40].copy_from_slice(&[0x80, 0x00, 0x00, 0x00]);
        upx_data[0x80..0x84].copy_from_slice(b"PE\x00\x00");
        upx_data[0x84..0x86].copy_from_slice(&[0x64, 0x86]);
        upx_data[200..204].copy_from_slice(b"UPX!");

        assert!(UPXDecompressor::is_upx_packed(&upx_data));

        let temp_file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(temp_file.path(), &upx_data).unwrap();

        let report = analyzer.analyze_structural(temp_file.path(), &upx_data, None);

        // Should have both UPX finding and tool-missing finding
        assert!(
            report
                .findings
                .iter()
                .any(|f| f.id == "anti-static/packer/upx"),
            "Should have UPX packer finding"
        );
        assert!(
            report
                .findings
                .iter()
                .any(|f| f.id == "anti-static/packer/upx/tool-missing"),
            "Should have tool-missing finding when UPX is disabled"
        );

        // Should NOT have unpacked file analysis
        assert!(
            report.files.is_empty(),
            "Should not have unpacked FileAnalysis when tool is missing"
        );
    }

    #[test]
    fn test_pe_non_upx_data_no_upx_finding() {
        let analyzer = PEAnalyzer::new();

        // Create minimal PE-like data without UPX magic
        let mut pe_data = vec![0u8; 512];
        pe_data[0..2].copy_from_slice(b"MZ");
        pe_data[0x3c..0x40].copy_from_slice(&[0x80, 0x00, 0x00, 0x00]);
        pe_data[0x80..0x84].copy_from_slice(b"PE\x00\x00");
        pe_data[0x84..0x86].copy_from_slice(&[0x64, 0x86]);

        let temp_file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(temp_file.path(), &pe_data).unwrap();

        let report = analyzer.analyze_structural(temp_file.path(), &pe_data, None);

        // Should NOT have UPX packer finding
        assert!(
            !report
                .findings
                .iter()
                .any(|f| f.id == "anti-static/packer/upx"),
            "Should not have UPX finding for non-UPX binary"
        );

        // Should NOT have unpacked file analysis
        assert!(
            report.files.is_empty(),
            "Should not have unpacked FileAnalysis for non-UPX binary"
        );
    }

    #[test]
    fn test_pe_upx_finding_criticality() {
        use crate::upx::UPXDecompressor;

        let analyzer = PEAnalyzer::new();

        let mut upx_data = vec![0u8; 512];
        upx_data[0..2].copy_from_slice(b"MZ");
        upx_data[0x3c..0x40].copy_from_slice(&[0x80, 0x00, 0x00, 0x00]);
        upx_data[0x80..0x84].copy_from_slice(b"PE\x00\x00");
        upx_data[0x84..0x86].copy_from_slice(&[0x64, 0x86]);
        upx_data[200..204].copy_from_slice(b"UPX!");

        assert!(UPXDecompressor::is_upx_packed(&upx_data));

        let temp_file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(temp_file.path(), &upx_data).unwrap();

        let report = analyzer.analyze_structural(temp_file.path(), &upx_data, None);

        // Find the UPX finding
        let upx_finding = report
            .findings
            .iter()
            .find(|f| f.id == "anti-static/packer/upx");

        assert!(upx_finding.is_some(), "Should have UPX finding");
        let finding = upx_finding.unwrap();

        // UPX materially changes static visibility even when otherwise legitimate.
        assert_eq!(finding.crit, Criticality::Suspicious);
        assert_eq!(finding.conf, 1.0);
        assert_eq!(finding.desc, "Binary contains a UPX packing marker");
    }

    #[test]
    fn pe_certificate_range_from_ctx_reads_security_directory() {
        let mut pe_data = vec![0u8; 0x420];
        pe_data[0..2].copy_from_slice(b"MZ");
        pe_data[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        pe_data[0x80..0x84].copy_from_slice(b"PE\0\0");
        pe_data[0x84..0x86].copy_from_slice(&0x014cu16.to_le_bytes());
        pe_data[0x86..0x88].copy_from_slice(&1u16.to_le_bytes());
        pe_data[0x94..0x96].copy_from_slice(&0xE0u16.to_le_bytes());
        pe_data[0x98..0x9a].copy_from_slice(&0x010bu16.to_le_bytes());
        pe_data[0x80 + 24 + 92..0x80 + 24 + 96].copy_from_slice(&16u32.to_le_bytes());

        let data_directories = 0x80 + 24 + 96;
        let security_dir = data_directories + (4 * 8);
        pe_data[security_dir..security_dir + 4].copy_from_slice(&0x300u32.to_le_bytes());
        pe_data[security_dir + 4..security_dir + 8].copy_from_slice(&0x120u32.to_le_bytes());

        let section_table = 0x80 + 24 + 0xE0;
        pe_data[section_table..section_table + 5].copy_from_slice(b".text");
        pe_data[section_table + 16..section_table + 20].copy_from_slice(&0x200u32.to_le_bytes());
        pe_data[section_table + 20..section_table + 24].copy_from_slice(&0x100u32.to_le_bytes());

        // WIN_CERTIFICATE header at the certificate table offset (0x300)
        pe_data[0x300..0x304].copy_from_slice(&0x120u32.to_le_bytes());
        pe_data[0x304..0x306].copy_from_slice(&0x0200u16.to_le_bytes());
        pe_data[0x306..0x308].copy_from_slice(&0x0002u16.to_le_bytes());

        let path = std::path::Path::new("synthetic.exe");
        let ctx = crate::analysis_context::AnalysisContext::open(path, &pe_data)
            .expect("expose opens synthetic PE");
        assert_eq!(
            super::pe_certificate_range_from_ctx(&ctx, &pe_data),
            Some((0x300, 0x420)),
        );
    }

    // ──── Pure-function helpers ────────────────────────────────────

    #[test]
    fn dn_extract_cn_handles_canonical_dn() {
        let dn = "CN=Microsoft Corporation,O=Microsoft Corporation,L=Redmond,ST=Washington,C=US";
        assert_eq!(
            super::dn_extract_cn(dn).as_deref(),
            Some("Microsoft Corporation"),
        );
        assert_eq!(
            super::dn_extract_o(dn).as_deref(),
            Some("Microsoft Corporation"),
        );
        // Empty input → None, not a panic.
        assert_eq!(super::dn_extract_cn(""), None);
        // DN with no CN attribute returns None.
        assert_eq!(super::dn_extract_cn("OU=Engineering"), None);
        // RFC 4514 attributes are case-insensitive.
        assert_eq!(
            super::dn_extract_cn("cn=acme corp").as_deref(),
            Some("acme corp"),
        );
    }
}
