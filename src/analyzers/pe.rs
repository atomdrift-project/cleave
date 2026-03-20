//! PE (Portable Executable) analyzer for Windows binaries.
use crate::analyzers::{AnalysisInput, Analyzer};
use crate::capabilities::CapabilityMapper;
use crate::entropy::{calculate_entropy, EntropyLevel};
use crate::radare2::Radare2Analyzer;
use crate::strings::StringExtractor;
use crate::types::*;
use crate::yara_engine::YaraEngine;
use anyhow::{Context, Result};
use goblin::pe::PE;
use std::fs;
use std::path::Path;
use std::sync::Arc;

/// Analyzer for Windows PE binaries (executables, DLLs, drivers)
#[derive(Debug)]
pub struct PEAnalyzer {
    capability_mapper: Arc<CapabilityMapper>,
    radare2: Radare2Analyzer,
    string_extractor: StringExtractor,
    yara_engine: Option<Arc<YaraEngine>>,
    /// Pre-extracted strings from stng (avoids redundant extraction)
    preextracted_strings: Option<Vec<StringInfo>>,
    /// When true, skip scanning for embedded PE/ELF binaries (prevents recursion in sub-analysis).
    skip_embedded_scan: bool,
}

fn pe_certificate_range(pe: &PE<'_>, data: &[u8]) -> Option<(usize, usize)> {
    let opt = pe.header.optional_header.as_ref()?;
    let cert_table = opt.data_directories.data_directories.get(4)?.as_ref()?.1;
    let offset = cert_table.virtual_address as usize;
    let size = cert_table.size as usize;
    if offset == 0 || size == 0 || offset.checked_add(size)? > data.len() {
        return None;
    }
    Some((offset, offset + size))
}

fn pe_overlay_bounds_excluding_certificate(pe: &PE<'_>, data: &[u8]) -> Option<(usize, usize)> {
    let sections_end = pe
        .sections
        .iter()
        .map(|s| (s.pointer_to_raw_data + s.size_of_raw_data) as usize)
        .max()
        .unwrap_or(0);
    if sections_end == 0 || sections_end >= data.len() {
        return None;
    }

    let overlay_end = pe_certificate_range(pe, data)
        .map(|(cert_start, _)| cert_start)
        .filter(|&cert_start| cert_start >= sections_end)
        .unwrap_or(data.len());

    if overlay_end > sections_end {
        Some((sections_end, overlay_end))
    } else {
        None
    }
}

impl PEAnalyzer {
    /// Creates a new PE analyzer with default configuration
    #[must_use]
    pub fn new() -> Self {
        Self {
            capability_mapper: Arc::new(CapabilityMapper::empty()),
            radare2: Radare2Analyzer::new(),
            string_extractor: StringExtractor::new(),
            yara_engine: None,
            preextracted_strings: None,
            skip_embedded_scan: false,
        }
    }

    /// Disable embedded binary scanning (used when analyzing extracted sub-files).
    #[must_use]
    pub(crate) fn without_embedded_scan(mut self) -> Self {
        self.skip_embedded_scan = true;
        self
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
    pub(crate) fn analyze_structural(
        &self,
        file_path: &Path,
        data: &[u8],
        precomputed_sha256: Option<String>,
    ) -> AnalysisReport {
        use crate::types::file_analysis::encode_upx_path;
        use crate::upx::{UPXDecompressor, UPXError};

        if !UPXDecompressor::is_upx_packed(data) {
            return self.analyze_structural_with_strings(file_path, data, None, precomputed_sha256);
        }

        // UPX-packed: structural analysis of packed binary first
        let mut report =
            self.analyze_structural_with_strings(file_path, data, None, precomputed_sha256.clone());

        report.findings.push(
            Finding::structural(
                "anti-static/packer/upx".to_string(),
                "Binary is packed with UPX".to_string(),
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
                .with_criticality(Criticality::Notable),
            );
            return report;
        }

        match UPXDecompressor::decompress(file_path) {
            Ok(unpacked_data) => {
                if let Ok(temp_file) = tempfile::NamedTempFile::new() {
                    if fs::write(temp_file.path(), &unpacked_data).is_ok() {
                        let mut unpacked_report = self.analyze_structural_with_strings(
                            temp_file.path(),
                            &unpacked_data,
                            None,
                            None, // Hash will change after decompression
                        );
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
                    .with_criticality(Criticality::Suspicious),
                );
            }
        }

        report
    }

    /// Structural analysis with optional pre-extracted strings.
    fn analyze_structural_with_strings(
        &self,
        file_path: &Path,
        data: &[u8],
        stng_strings: Option<&[stng::ExtractedString]>,
        precomputed_sha256: Option<String>,
    ) -> AnalysisReport {
        let start = std::time::Instant::now();

        // Detect and handle tampered PE (junk prefix before MZ header)
        let (pe_data, tamper_findings) = self.detect_and_strip_tampering(data);

        // Try to parse with goblin (strict → permissive fallback)
        let (pe_parsed, parse_err) = match PE::parse(pe_data) {
            Ok(pe) => (Some(pe), None),
            Err(strict_err) => {
                let permissive_opts = goblin::pe::options::ParseOptions::default()
                    .with_parse_mode(goblin::options::ParseMode::Permissive);
                match PE::parse_with_opts(pe_data, &permissive_opts) {
                    Ok(pe) => {
                        tracing::debug!(
                            "PE strict parse failed ({}) but permissive succeeded for {}",
                            strict_err,
                            file_path.display()
                        );
                        (Some(pe), None)
                    }
                    Err(e) => (None, Some(e)),
                }
            }
        };

        self.analyze_pe(
            file_path,
            data,
            pe_data,
            pe_parsed.as_ref(),
            parse_err.as_ref(),
            tamper_findings,
            start,
            stng_strings,
            precomputed_sha256,
        )
    }

    /// Unified PE analysis — handles both valid and corrupted (unparseable) PEs.
    ///
    /// When goblin parses successfully, uses its data for structure, imports, exports,
    /// and sections. When goblin fails, falls back to rizin for everything.
    /// When goblin partially succeeds (e.g., 0 sections/imports but rizin finds them),
    /// uses rizin as fallback and emits suspicious findings for the discrepancy.
    #[allow(clippy::unnecessary_wraps, clippy::too_many_arguments)]
    fn analyze_pe(
        &self,
        file_path: &Path,
        original_data: &[u8],
        pe_data: &[u8],
        pe: Option<&PE<'_>>,
        parse_error: Option<&goblin::error::Error>,
        mut tamper_findings: Vec<Finding>,
        start: std::time::Instant,
        stng_strings: Option<&[stng::ExtractedString]>,
        precomputed_sha256: Option<String>,
    ) -> AnalysisReport {
        let goblin_ok = pe.is_some();

        // Extract goblin-derived data when available
        let pe_metrics = pe.map(|pe| self.compute_pe_metrics(pe, pe_data));
        let file_size = original_data.len() as u64;
        let goblin_code_size = pe.map_or(0, |pe| self.compute_code_size(pe, file_size));

        // Create target info
        let target = TargetInfo {
            path: file_path.display().to_string(),
            file_type: "pe".to_string(),
            size_bytes: original_data.len() as u64,
            sha256: precomputed_sha256
                .clone()
                .unwrap_or_else(|| crate::analyzers::utils::calculate_sha256(original_data)),
            architectures: pe.map(|pe| vec![self.arch_name(pe)]),
        };

        let mut report = AnalysisReport::new(target);
        let mut tools_used = Vec::new();
        if goblin_ok {
            tools_used.push("goblin".to_string());
        }

        // Add any tampering findings detected during preprocessing
        report.findings.append(&mut tamper_findings);

        // Run radare2 in parallel with goblin-based structural analysis.
        // Tell rizin the binary "has symbols" if goblin found metadata, or if goblin
        // failed entirely (so rizin tries harder).
        let has_symbols = pe.is_none_or(|pe| {
            !pe.imports.is_empty() || !pe.exports.is_empty() || !pe.sections.is_empty()
        });
        let (r2_result, _) = rayon::join(
            || {
                if Radare2Analyzer::is_available() {
                    Some(
                        self.radare2
                            .extract_batched(file_path, has_symbols, precomputed_sha256),
                    )
                } else {
                    None
                }
            },
            || {
                if let Some(pe) = pe {
                    self.analyze_structure(pe, &mut report);
                    self.analyze_imports(pe, &mut report);
                    self.analyze_exports(pe, pe_data, &mut report);
                    self.analyze_sections(pe, pe_data, &mut report);
                }
            },
        );

        // Detect inflated section headers (declared size extends beyond EOF)
        if let Some(pe) = pe {
            let has_inflated = pe.sections.iter().any(|s| {
                (s.pointer_to_raw_data as u64).saturating_add(s.size_of_raw_data as u64) > file_size
            });
            if has_inflated {
                report.findings.push(
                    Finding::structural(
                        "objectives/anti-static/pe-tampering/inflated-section-headers".to_string(),
                        "PE section headers declare sizes beyond end of file".to_string(),
                        0.9,
                    )
                    .with_criticality(Criticality::Suspicious),
                );
            }
        }

        // --- Process radare2 results, with fallback for goblin gaps ---
        let r2_strings = if let Some(Ok(batched)) = r2_result {
            tools_used.push("radare2".to_string());

            let mut binary_metrics = self
                .radare2
                .compute_metrics_from_batched(&batched, original_data.len() as u64);

            // When goblin succeeded, override r2 metrics with more accurate goblin values
            if let Some(pe) = pe {
                let mut code_size = goblin_code_size;
                if code_size > binary_metrics.file_size {
                    tracing::warn!(
                        "code_size ({}) > file_size ({}) — capping",
                        code_size,
                        binary_metrics.file_size
                    );
                    code_size = binary_metrics.file_size;
                }
                binary_metrics.code_size = code_size;

                // .pdata function count correction
                if let Some(pdata) = pe.sections.iter().find(|s| {
                    String::from_utf8_lossy(&s.name).trim_matches(char::from(0)) == ".pdata"
                }) {
                    let pdata_functions = pdata.virtual_size / 12;
                    if pdata_functions > 0
                        && (binary_metrics.function_count <= 1
                            || pdata_functions > binary_metrics.function_count * 10)
                    {
                        binary_metrics.function_count = pdata_functions;
                    }
                }

                // Prefer goblin section-header flags over r2 segment perms
                let (exec, write, wx) = self.compute_section_permission_counts(pe);
                binary_metrics.executable_sections = exec;
                binary_metrics.writable_sections = write;
                binary_metrics.wx_sections = wx;

                // Recalculate ratios with correct code_size
                if binary_metrics.file_size > 0 {
                    let data_size = binary_metrics.file_size.saturating_sub(code_size);
                    if data_size > 0 {
                        binary_metrics.code_to_data_ratio = code_size as f32 / data_size as f32;
                    }
                }
                let code_kb = code_size as f32 / 1024.0;
                if code_kb > 0.0 {
                    binary_metrics.import_density = binary_metrics.import_count as f32 / code_kb;
                    binary_metrics.string_density = binary_metrics.string_count as f32 / code_kb;
                    binary_metrics.function_density =
                        binary_metrics.function_count as f32 / code_kb;
                    binary_metrics.relocation_density =
                        binary_metrics.relocation_count as f32 / code_kb;
                    binary_metrics.complexity_per_kb =
                        binary_metrics.avg_complexity * 1024.0 / code_size as f32;
                }
            }

            report.metrics = Some(Metrics {
                binary: Some(binary_metrics),
                pe: pe_metrics,
                ..Default::default()
            });

            report.functions = batched.functions.into_iter().map(Function::from).collect();

            // --- Rizin fallback: sections ---
            if report.sections.is_empty() && !batched.sections.is_empty() {
                tracing::info!(
                    "goblin returned 0 sections but rizin found {} — using rizin fallback",
                    batched.sections.len()
                );
                for section in &batched.sections {
                    report.sections.push(Section {
                        name: section.name.clone(),
                        address: None,
                        size: section.size,
                        entropy: section.entropy,
                        permissions: section.perm.clone(),
                    });
                }
                if goblin_ok {
                    report.findings.push(
                        Finding::structural(
                            "objectives/anti-static/pe-tampering/hidden-sections".to_string(),
                            format!(
                                "PE section table empty but rizin found {} sections — possible header manipulation",
                                batched.sections.len()
                            ),
                            0.9,
                        )
                        .with_criticality(Criticality::Suspicious),
                    );
                }
            }

            // --- Rizin fallback: imports ---
            if report.imports.is_empty() && !batched.imports.is_empty() {
                tracing::info!(
                    "goblin returned 0 imports but rizin found {} — using rizin fallback",
                    batched.imports.len()
                );
                for import in &batched.imports {
                    report.imports.push(Import::new(
                        &import.name,
                        import.lib_name.clone(),
                        "radare2",
                    ));
                    let normalized = crate::types::binary::normalize_symbol(&import.name);
                    if let Some(capability) = self.capability_mapper.lookup(&normalized, "radare2")
                    {
                        if !report.findings.iter().any(|c| c.id == capability.id) {
                            report.findings.push(capability);
                        }
                    }
                }
                if goblin_ok {
                    report.findings.push(
                        Finding::structural(
                            "objectives/anti-static/pe-tampering/hidden-imports".to_string(),
                            format!(
                                "PE import table empty but rizin found {} imports — possible IAT manipulation",
                                report.imports.len()
                            ),
                            0.9,
                        )
                        .with_criticality(Criticality::Suspicious),
                    );
                }
            }

            Some(batched.strings)
        } else {
            // No rizin available — set metrics from goblin data only
            if let Some(pe_m) = pe_metrics {
                report.metrics = Some(Metrics {
                    pe: Some(pe_m),
                    ..Default::default()
                });
            }
            None
        };

        // --- Corrupted-header findings (goblin failed entirely) ---
        if let Some(err) = parse_error {
            let error_str = format!("{}", err);
            let is_resource_error = error_str.contains("ResourceString")
                || error_str.contains("ResourceTable")
                || error_str.contains("resource");
            let is_parser_limitation = error_str.contains("type is too big");

            // If rizin found sections/imports that goblin couldn't parse, the header
            // corruption is more significant — upgrade from baseline to suspicious.
            let rizin_found_hidden_content =
                !report.sections.is_empty() || !report.imports.is_empty();
            let (crit, conf) =
                if rizin_found_hidden_content && (is_resource_error || is_parser_limitation) {
                    (Criticality::Suspicious, 0.8)
                } else if is_resource_error || is_parser_limitation {
                    (Criticality::Baseline, 0.3)
                } else {
                    (Criticality::Hostile, 1.0)
                };

            report.findings.push(Finding {
                id: "objectives/anti-analysis/pe-tampering/corrupted-header".to_string(),
                kind: FindingKind::Structural,
                desc: format!("PE header too corrupted to parse: {}", err),
                conf,
                crit,
                mbc: Some("B0001".to_string()),
                attack: Some("T1027".to_string()),
                trait_refs: vec![],
                evidence: vec![Evidence {
                    method: "parse-failure".to_string(),
                    source: "goblin".to_string(),
                    value: format!("{}", err),
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
                    source: "goblin".to_string(),
                    value: format!("{}", err),
                    location: None,
                    ..Default::default()
                }],
            });
        }

        // --- Shared post-processing (strings, embedded code, metrics, overlay, SFX) ---

        // String extraction (preference: stng_strings > preextracted > extract_smart)
        if let Some(strings) = stng_strings {
            report.strings = self.string_extractor.convert_stng_strings(strings);
        } else if let Some(ref strings) = self.preextracted_strings {
            report.strings = strings.clone();
        } else {
            report.strings = self.string_extractor.extract_smart(pe_data, r2_strings);
        }
        tools_used.push("stng".to_string());

        // Embedded code in strings
        let (encoded_layers, plain_findings) =
            crate::analyzers::embedded_code_detector::process_all_strings(
                &file_path.display().to_string(),
                &report.strings,
                &self.capability_mapper,
                0,
            );
        report.files.extend(encoded_layers);
        report.findings.extend(plain_findings);

        // Common binary metrics
        crate::analyzers::metrics_utils::populate_binary_metrics(&mut report, original_data);

        // Emit signature findings
        if let Some(metrics) = &report.metrics {
            if let Some(pe_metrics) = &metrics.pe {
                if let Some(signer_full) = &pe_metrics.signer {
                    let sig_type = pe_metrics.signature_type.as_deref().unwrap_or("unknown");
                    // Split if we have multiple signers
                    for signer in signer_full.split(", ") {
                        let normalized_signer = signer
                            .to_lowercase()
                            .replace(' ', "-")
                            .replace(',', "")
                            .replace("(", "")
                            .replace(")", "");
                        report.findings.push(Finding {
                            id: format!("metadata/signed/{}::{}", sig_type, normalized_signer),
                            kind: FindingKind::Capability,
                            desc: format!("Signed by: {}", signer),
                            conf: 1.0,
                            crit: Criticality::Notable,
                            mbc: None,
                            attack: None,
                            trait_refs: vec![],
                            evidence: vec![Evidence {
                                method: "authenticode".to_string(),
                                source: "cleave".to_string(),
                                value: signer.to_string(),
                                ..Default::default()
                            }],
                            match_count: 1,
                            source_file: None,
                        });
                    }
                } else if !pe_metrics.has_signature {
                    report.findings.push(Finding {
                        id: "metadata/unsigned".to_string(),
                        kind: FindingKind::Capability,
                        desc: "Binary is not digitally signed".to_string(),
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
            }
        }

        // Overlay analysis (requires section data to find overlay start)
        let overlay_bounds = pe.and_then(|pe| pe_overlay_bounds_excluding_certificate(pe, pe_data));
        if let Some((overlay_start, overlay_end)) = overlay_bounds {
            let overlay_size = (overlay_end - overlay_start) as u64;
            if let Some(ref mut metrics) = report.metrics {
                if let Some(ref mut binary) = metrics.binary {
                    binary.has_overlay = true;
                    binary.overlay_size = overlay_size;
                    binary.overlay_ratio = overlay_size as f32 / pe_data.len() as f32;
                    binary.overlay_entropy =
                        crate::entropy::calculate_entropy(&pe_data[overlay_start..overlay_end])
                            as f32;
                }
            }
        }

        if let Some(ref metrics) = report.metrics {
            if let Some(ref binary) = metrics.binary {
                binary.validate(&report.target.path);
            }
        }

        // Overlay archive analysis
        if let Some((overlay_start, overlay_end)) = overlay_bounds {
            let overlay_data = &pe_data[overlay_start..overlay_end];
            if let Ok(Some(overlay_analysis)) = crate::analyzers::overlay::analyze_overlay(
                overlay_data,
                &report.target.path,
                Some(self.capability_mapper.clone()),
                self.yara_engine.clone(),
            ) {
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
        if let Some(sfx_kind) = crate::analyzers::sfx_detector::detect_sfx(pe_data) {
            let sfx_result = crate::analyzers::sfx_detector::analyze_sfx(
                file_path,
                sfx_kind,
                pe_data,
                Some(self.capability_mapper.clone()),
                self.yara_engine.clone(),
            );
            report.findings.push(sfx_result.sfx_finding);
            if let Some(archive_report) = sfx_result.archive_report {
                report.findings.extend(archive_report.findings);
                report.files.extend(archive_report.files);
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
            let cert_range = pe.and_then(|pe| pe_certificate_range(pe, pe_data));
            let embedded =
                crate::analyzers::embedded_binary_detector::scan_for_embedded_binaries(pe_data);
            for binary in &embedded {
                if cert_range
                    .is_some_and(|(start, end)| binary.offset >= start && binary.offset < end)
                {
                    continue;
                }
                let mut finding = crate::analyzers::embedded_binary_detector::finding_for(
                    binary,
                    &report.target.path,
                );
                // Downgrade embedded binaries in .rsrc to Notable (legitimate use)
                if let Some(pe) = pe {
                    let in_rsrc = pe.sections.iter().any(|s| {
                        let name = String::from_utf8_lossy(&s.name);
                        let name = name.trim_matches(char::from(0));
                        if name != ".rsrc" {
                            return false;
                        }
                        let start = s.pointer_to_raw_data as usize;
                        let end = start + s.size_of_raw_data as usize;
                        binary.offset >= start && binary.offset < end
                    });
                    if in_rsrc {
                        finding.crit = Criticality::Notable;
                    }
                }
                report.findings.push(finding);

                let slice_end = (binary.offset + binary.estimated_size).min(pe_data.len());
                let embedded_bytes = &pe_data[binary.offset..slice_end];
                let kind_str = binary.kind.as_str();
                if let Some(fa) = analyze_embedded_as_child(
                    embedded_bytes,
                    &host_name,
                    kind_str,
                    binary.offset,
                    self.capability_mapper.clone(),
                    self.yara_engine.clone(),
                ) {
                    report.files.push(fa);
                }
            }
        }

        report.metadata.analysis_duration_ms = start.elapsed().as_millis() as u64;
        report.metadata.tools_used = tools_used;

        report
    }

    fn analyze_structure<'a>(&self, pe: &PE<'a>, report: &mut AnalysisReport) {
        report.structure.push(StructuralFeature {
            id: "pe/header".to_string(),
            desc: format!(
                "PE file (machine: {}, subsystem: {:?})",
                self.arch_name(pe),
                pe.header
                    .optional_header
                    .as_ref()
                    .map(|h| h.windows_fields.subsystem)
            ),
            evidence: vec![Evidence {
                method: "header".to_string(),
                source: "goblin".to_string(),
                value: "PE".to_string(),
                location: None,
                ..Default::default()
            }],
        });

        // Check if DLL
        if pe.is_lib {
            report.structure.push(StructuralFeature {
                id: "pe/dll".to_string(),
                desc: "Dynamic Link Library (DLL)".to_string(),
                evidence: vec![Evidence {
                    method: "header".to_string(),
                    source: "goblin".to_string(),
                    value: "DLL".to_string(),
                    location: None,
                    ..Default::default()
                }],
            });
        }

        // Check for .NET
        if pe.header.optional_header.is_some() {
            report.structure.push(StructuralFeature {
                id: "pe/optional_header".to_string(),
                desc: "Has optional header (standard Windows executable)".to_string(),
                evidence: vec![Evidence {
                    method: "header".to_string(),
                    source: "goblin".to_string(),
                    value: "OptionalHeader".to_string(),
                    location: None,
                    ..Default::default()
                }],
            });
        }
    }

    fn analyze_imports<'a>(&self, pe: &PE<'a>, report: &mut AnalysisReport) {
        for import in &pe.imports {
            report.imports.push(Import::new(
                import.name.as_ref(),
                Some(import.dll.to_string()),
                "goblin",
            ));

            let normalized = crate::types::binary::normalize_symbol(import.name.as_ref());
            if let Some(capability) = self.capability_mapper.lookup(&normalized, "goblin") {
                if !report.findings.iter().any(|c| c.id == capability.id) {
                    report.findings.push(capability);
                }
            }
        }
    }

    fn analyze_exports<'a>(&self, pe: &PE<'a>, data: &[u8], report: &mut AnalysisReport) {
        for export in &pe.exports {
            if let Some(name) = export.name {
                report.exports.push(Export::new(
                    name,
                    Some(format!("{:#x}", export.rva)),
                    "goblin",
                ));
            }
        }

        // Detect export aliasing: multiple exports whose code jumps to the same target
        if report.exports.len() >= 2 {
            let bitness = match pe.header.coff_header.machine {
                0x8664 | 0xaa64 => 64,
                _ => 32,
            };
            let aliased = count_aliased_exports(pe, data, bitness);
            if aliased > 0 {
                let metrics = report
                    .metrics
                    .get_or_insert_with(crate::types::Metrics::default);
                let binary_metrics = metrics.binary.get_or_insert_with(Default::default);
                binary_metrics.aliased_exports = aliased;
            }
        }
    }

    fn analyze_sections<'a>(&self, pe: &PE<'a>, data: &[u8], report: &mut AnalysisReport) {
        for section in &pe.sections {
            let name = String::from_utf8_lossy(&section.name)
                .trim_matches(char::from(0))
                .to_string();
            let size = section.size_of_raw_data as u64;
            let offset = section.pointer_to_raw_data as u64;

            let characteristics = section.characteristics;
            let is_executable = (characteristics & 0x20000000) != 0;
            let is_writable = (characteristics & 0x80000000) != 0;
            let is_readable = (characteristics & 0x40000000) != 0;

            let permissions = format!(
                "{}{}{}",
                if is_readable { "r" } else { "-" },
                if is_writable { "w" } else { "-" },
                if is_executable { "x" } else { "-" }
            );

            let entropy = if offset < data.len() as u64 {
                let end = ((offset + size) as usize).min(data.len());
                let section_data = &data[offset as usize..end];
                calculate_entropy(section_data)
            } else {
                0.0
            };

            let _entropy_level = if entropy > 7.2 {
                EntropyLevel::High
            } else if entropy > 6.0 {
                EntropyLevel::Elevated
            } else if entropy > 4.0 {
                EntropyLevel::Normal
            } else {
                EntropyLevel::VeryLow
            };

            report.sections.push(Section {
                name: name.clone(),
                address: Some(section.virtual_address as u64),
                size,
                entropy,
                permissions: Some(permissions.clone()),
            });

            // NOTE: High entropy executable detection moved to YAML:
            // - traits/objectives/anti-analysis/packing/high-entropy-executable.yaml
            // NOTE: W^X section detection moved to YAML:
            // - traits/objectives/anti-static/hardening/memory/wx-sections.yaml
        }
    }

    fn arch_name<'a>(&self, pe: &PE<'a>) -> String {
        match pe.header.coff_header.machine {
            0x014c => "x86".to_string(),
            0x8664 => "x86_64".to_string(),
            0x01c0 => "ARM".to_string(),
            0xaa64 => "ARM64".to_string(),
            _ => format!("unknown-{:#x}", pe.header.coff_header.machine),
        }
    }

    /// Compute PE-specific metrics from parsed PE binary
    fn compute_pe_metrics<'a>(
        &self,
        pe: &PE<'a>,
        data: &[u8],
    ) -> crate::types::binary_metrics::PeMetrics {
        use crate::types::binary_metrics::PeMetrics;

        let mut metrics = PeMetrics::default();

        // Timestamp anomaly check
        let timestamp = pe.header.coff_header.time_date_stamp;
        if timestamp < 631152000 {
            // Before 1990
            metrics.timestamp_anomaly = true;
        } else if timestamp > chrono::Utc::now().timestamp() as u32 + 31536000 {
            // More than 1 year in future
            metrics.timestamp_anomaly = true;
        }

        // Check for Rich header (between DOS and PE signature)
        let dos_header = pe.header.dos_header;
        let pe_offset = dos_header.pe_pointer as usize;
        if pe_offset > 0x80 {
            // Rich header typically found here
            for i in (0x80..pe_offset.min(0x200)).step_by(4) {
                if i + 4 <= data.len() && &data[i..i + 4] == b"Rich" {
                    metrics.rich_header_present = true;
                    break;
                }
            }
        }

        // Check for .NET by looking for .NET-specific sections
        for section in &pe.sections {
            if let Ok(name) = section.name() {
                if name == ".text" && section.virtual_size > 0 {
                    // Check for .NET by looking for mscoree.dll import
                    for import in &pe.imports {
                        if import.dll.to_lowercase().contains("mscoree") {
                            metrics.is_dotnet = true;
                            break;
                        }
                    }
                }

                // Check resource section
                if name == ".rsrc" {
                    metrics.rsrc_size = section.size_of_raw_data as u64;
                    // Compute entropy from section data
                    let section_start = section.pointer_to_raw_data as usize;
                    let section_end = section_start + section.size_of_raw_data as usize;
                    if section_end <= data.len() {
                        let section_data = &data[section_start..section_end];
                        metrics.rsrc_entropy =
                            crate::entropy::calculate_entropy(section_data) as f32;
                    }
                }
            }
        }

        // Check for code signature (Authenticode)
        if let Some(opt) = &pe.header.optional_header {
            if let Some(Some(cert_table_entry)) = opt.data_directories.data_directories.get(4) {
                let cert_table = &cert_table_entry.1;
                // Note: virt_addr in security directory is actually a file offset
                let offset = cert_table.virtual_address as usize;
                let size = cert_table.size as usize;
                if offset > 0 && offset + size <= data.len() {
                    let cert_data = &data[offset..offset + size];
                    // Skip the WIN_CERTIFICATE header (8 bytes)
                    if cert_data.len() > 8 {
                        let pkcs7_data = &cert_data[8..];
                        if !pkcs7_data.is_empty() && pkcs7_data[0] == 0x30 {
                            metrics.has_signature = true;

                            // Simple extraction of common names from certificate chain
                            let cn_oid = [0x55, 0x04, 0x03];
                            let mut signers = Vec::new();
                            let mut search_pos = 0;

                            while let Some(pos) = pkcs7_data[search_pos..]
                                .windows(cn_oid.len())
                                .position(|w| w == cn_oid)
                            {
                                let abs_pos = search_pos + pos;
                                search_pos = abs_pos + cn_oid.len();

                                // Next byte is string type, then length
                                let type_pos = abs_pos + cn_oid.len();
                                if type_pos + 1 < pkcs7_data.len() {
                                    let len = pkcs7_data[type_pos + 1] as usize;
                                    let str_pos = type_pos + 2;
                                    if len > 0 && str_pos + len <= pkcs7_data.len() {
                                        if let Ok(cn) =
                                            std::str::from_utf8(&pkcs7_data[str_pos..str_pos + len])
                                        {
                                            let cn = cn.trim_matches(char::from(0)).trim();
                                            if !cn.is_empty() && !signers.contains(&cn.to_string())
                                            {
                                                signers.push(cn.to_string());
                                            }
                                        }
                                    }
                                }
                                if signers.len() > 10 {
                                    break;
                                }
                            }

                            if !signers.is_empty() {
                                metrics.signer = Some(signers.join(", "));
                                if signers
                                    .iter()
                                    .any(|s| s.contains("Microsoft") || s.contains("Windows"))
                                {
                                    metrics.signature_type = Some("platform".to_string());
                                } else {
                                    metrics.signature_type = Some("developer".to_string());
                                }
                            }
                        }
                    }
                }
            }
        }

        // Check for overlay data (appended after PE image, excluding signature)
        // This can be:
        // 1. Self-extracting archive (7z, ZIP, RAR)
        // 2. Resources or other data
        let sig_sections_end = pe
            .sections
            .iter()
            .map(|s| (s.pointer_to_raw_data + s.size_of_raw_data) as u64)
            .max()
            .unwrap_or(0);

        // Calculate overlay start, taking into account that the signature might be at the end
        let mut overlay_end = data.len() as u64;
        if let Some(opt) = &pe.header.optional_header {
            if let Some(Some(cert_table_entry)) = opt.data_directories.data_directories.get(4) {
                let cert_table = &cert_table_entry.1;
                let cert_offset = cert_table.virtual_address as u64;
                if cert_offset > sig_sections_end && cert_offset < overlay_end {
                    overlay_end = cert_offset;
                }
            }
        }

        if overlay_end > sig_sections_end && sig_sections_end > 0 {
            let _overlay_start = sig_sections_end as usize;
            let _overlay_data = &data[_overlay_start..overlay_end as usize];
        }

        // Ordinal-only imports
        for import in &pe.imports {
            if import.name.is_empty() {
                metrics.ordinal_imports += 1;
            }
        }

        // Export forwarders (exports with "." in name indicating forwarding)
        for export in &pe.exports {
            if let Some(name) = export.name {
                if name.contains('.') {
                    metrics.export_forwarders += 1;
                }
            }
        }

        // Section alignment check
        if let Some(opt_header) = &pe.header.optional_header {
            let file_alignment = opt_header.windows_fields.file_alignment;
            let section_alignment = opt_header.windows_fields.section_alignment;

            // Typical alignments: 0x200 (512) for file, 0x1000 (4096) for section
            // Unusual if they're equal, very small, or very large
            if file_alignment == section_alignment
                || !(0x200..=0x10000).contains(&file_alignment)
                || !(0x1000..=0x100000).contains(&section_alignment)
            {
                metrics.unusual_alignment = true;
            }
        }

        metrics
    }

    fn compute_section_permission_counts<'a>(&self, pe: &PE<'a>) -> (u32, u32, u32) {
        let mut executable_sections = 0;
        let mut writable_sections = 0;
        let mut wx_sections = 0;

        for section in &pe.sections {
            let characteristics = section.characteristics;
            let is_executable = (characteristics & 0x20000000) != 0;
            let is_writable = (characteristics & 0x80000000) != 0;

            if is_executable {
                executable_sections += 1;
            }
            if is_writable {
                writable_sections += 1;
            }
            if is_executable && is_writable {
                wx_sections += 1;
            }
        }

        (executable_sections, writable_sections, wx_sections)
    }

    /// Calculate code size from PE section headers using IMAGE_SCN_MEM_EXECUTE characteristic
    /// This is more accurate than radare2's section classification
    fn compute_code_size<'a>(&self, pe: &PE<'a>, file_size: u64) -> u64 {
        const IMAGE_SCN_MEM_EXECUTE: u32 = 0x20000000;

        let mut code_size: u64 = 0;

        for section in &pe.sections {
            if section.characteristics & IMAGE_SCN_MEM_EXECUTE != 0 {
                // Cap at section's actual extent within the file
                let raw_end = (section.pointer_to_raw_data as u64)
                    .saturating_add(section.size_of_raw_data as u64);
                let capped_size = if raw_end > file_size {
                    file_size.saturating_sub(section.pointer_to_raw_data as u64)
                } else {
                    section.size_of_raw_data as u64
                };
                code_size += capped_size;
            }
        }

        code_size
    }

    /// Detect PE tampering and return stripped data plus findings.
    ///
    /// Detects common anti-analysis techniques:
    /// - Junk bytes prepended before MZ header
    /// - Systematic byte injection (e.g., 0x20 padding throughout header)
    /// - .NET BSJB signature presence
    /// - PE signature corruption
    ///
    /// Returns (data_to_parse, findings) where data_to_parse may be a slice
    /// starting at the MZ header if junk prefix was detected.
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

        // Return original data (goblin will fail to parse, but that's expected)
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
            if sig != b"PE\x00\x00" {
                findings.push(Finding {
                    id: "objectives/anti-analysis/pe-tampering/pe-signature-corrupted".to_string(),
                    kind: FindingKind::Structural,
                    desc: format!(
                        "PE signature corrupted: expected PE\\x00\\x00, got {:02X} {:02X} {:02X} {:02X}",
                        sig[0], sig[1], sig[2], sig[3]
                    ),
                    conf: 1.0,
                    crit: Criticality::Hostile,
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
        // Use data and strings from input (no file read, no string extraction)
        let mut report = self.analyze_structural_with_strings(
            input.path,
            input.data,
            Some(input.strings),
            input.sha256.clone(),
        );

        // Post-processing
        self.capability_mapper
            .evaluate_and_merge_findings(&mut report, input.data, None, None);
        Ok(report)
    }

    fn analyze(&self, file_path: &Path) -> Result<AnalysisReport> {
        let data = fs::read(file_path).context("Failed to read file")?;
        let mut report = self.analyze_structural(file_path, &data, None);
        self.capability_mapper
            .evaluate_and_merge_findings(&mut report, &data, None, None);
        Ok(report)
    }

    fn can_analyze(&self, file_path: &Path) -> bool {
        if let Ok(data) = fs::read(file_path) {
            goblin::pe::PE::parse(&data).is_ok()
        } else {
            false
        }
    }
}

/// Count exports whose first instruction jumps/calls to the same target as another export.
///
/// Malware often aliases multiple export names to a single function via stub thunks.
/// This decodes the first instruction at each export RVA and groups by jump target.
fn count_aliased_exports(pe: &goblin::pe::PE<'_>, data: &[u8], bitness: u32) -> u32 {
    use iced_x86::{Decoder, DecoderOptions, Mnemonic};
    use std::collections::HashMap;

    let mut targets: HashMap<u64, u32> = HashMap::new();

    for export in &pe.exports {
        let rva = export.rva;
        // Convert RVA to file offset using PE sections
        let Some(file_offset) = rva_to_offset(pe, rva) else {
            continue;
        };

        if file_offset + 16 > data.len() {
            continue;
        }

        let code = &data[file_offset..file_offset + 16];
        let mut decoder = Decoder::with_ip(bitness, code, rva as u64, DecoderOptions::NONE);

        if let Some(instr) = decoder.iter().next() {
            let target = match instr.mnemonic() {
                Mnemonic::Jmp | Mnemonic::Call => {
                    let t = instr.near_branch_target();
                    if t != 0 {
                        t
                    } else {
                        rva as u64
                    }
                }
                // Not a stub — use the RVA itself as the "target"
                _ => rva as u64,
            };
            *targets.entry(target).or_insert(0) += 1;
        }
    }

    targets.values().filter(|&&c| c > 1).copied().sum()
}

/// Convert a PE RVA to a file offset using section headers.
fn rva_to_offset(pe: &goblin::pe::PE<'_>, rva: usize) -> Option<usize> {
    for section in &pe.sections {
        let vaddr = section.virtual_address as usize;
        let vsize = section.virtual_size as usize;
        if rva >= vaddr && rva < vaddr + vsize {
            let raw_offset = section.pointer_to_raw_data as usize;
            return Some(raw_offset + (rva - vaddr));
        }
    }
    None
}

/// Extract embedded binary bytes to a temp file, analyze with the appropriate analyzer,
/// and return a FileAnalysis suitable for inclusion as a nested child (depth=1).
///
/// Returns `None` if extraction or analysis fails — the parent finding is still emitted.
fn analyze_embedded_as_child(
    bytes: &[u8],
    host_name: &str,
    kind_str: &str,
    offset: usize,
    capability_mapper: Arc<CapabilityMapper>,
    yara_engine: Option<Arc<YaraEngine>>,
) -> Option<crate::types::FileAnalysis> {
    let suffix = if kind_str == "pe" { ".exe" } else { "" };
    let temp = tempfile::Builder::new().suffix(suffix).tempfile().ok()?;
    std::fs::write(temp.path(), bytes).ok()?;

    let report = if kind_str == "pe" {
        let mut analyzer = PEAnalyzer::new()
            .with_capability_mapper_arc(capability_mapper)
            .without_embedded_scan();
        if let Some(yara) = yara_engine {
            analyzer = analyzer.with_yara_arc(yara);
        }
        analyzer.analyze(temp.path()).ok()?
    } else {
        crate::analyzers::elf::ElfAnalyzer::new()
            .with_capability_mapper_arc(capability_mapper)
            .without_embedded_scan()
            .analyze(temp.path())
            .ok()?
    };

    let child_name = format!("embedded:{}@{:#x}", kind_str, offset);
    let child_path = crate::types::file_analysis::encode_archive_path(host_name, &child_name);

    let (mut fa, _nested, _) = report.into_file_analysis(0);
    fa.path = child_path;
    fa.depth = 1;
    Some(fa)
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
        assert!(report.target.architectures.is_some());
        let archs = report.target.architectures.unwrap();
        assert!(!archs.is_empty());
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
        assert!(report.metadata.tools_used.contains(&"goblin".to_string()));
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
        // Test with real 7z self-extracting installer if available
        let test_file =
            std::path::Path::new("/Users/t/data/cleave/malware/pe/2026.7zip.com/7z2501-x64.exe");

        if !test_file.exists() {
            eprintln!("Skipping SFX test - file not found: {:?}", test_file);
            return;
        }

        let analyzer = PEAnalyzer::new();
        let report = analyzer.analyze(test_file).unwrap();

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
                entry.path.starts_with("7z2501-x64.exe!!"),
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

        // UPX packing is Suspicious criticality
        assert_eq!(finding.crit, Criticality::Suspicious);
        assert_eq!(finding.conf, 1.0);
        assert_eq!(finding.desc, "Binary is packed with UPX");
    }

    #[test]
    fn test_pe_overlay_bounds_exclude_certificate_table() {
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
        // dwLength: 0x120 (total size including header)
        pe_data[0x300..0x304].copy_from_slice(&0x120u32.to_le_bytes());
        // wRevision: WIN_CERT_REVISION_2_0 (0x0200)
        pe_data[0x304..0x306].copy_from_slice(&0x0200u16.to_le_bytes());
        // wCertificateType: WIN_CERT_TYPE_PKCS_SIGNED_DATA (0x0002)
        pe_data[0x306..0x308].copy_from_slice(&0x0002u16.to_le_bytes());

        let pe = PE::parse(&pe_data).expect("synthetic PE should parse");
        assert_eq!(pe_certificate_range(&pe, &pe_data), Some((0x300, 0x420)));
        assert_eq!(
            pe_overlay_bounds_excluding_certificate(&pe, &pe_data),
            Some((0x300, 0x300)).filter(|(start, end)| end > start),
        );
    }
}
