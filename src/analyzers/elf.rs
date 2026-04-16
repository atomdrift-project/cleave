//! ELF binary analyzer for Linux executables.
//!
//! Analyzes ELF binaries using goblin, stng, and selective rizin deep analysis.

use crate::analyzers::goblin_safe;
use crate::analyzers::{AnalysisInput, Analyzer};
use crate::capabilities::CapabilityMapper;
use crate::entropy::{calculate_entropy, EntropyLevel};
use crate::radare2::Radare2Analyzer;
use crate::strings::StringExtractor;
use crate::types::binary_metrics::ElfMetrics;
use crate::types::{
    AnalysisReport, Criticality, Evidence, Export, Finding, FindingKind, Function, Import, Metrics,
    Section, StringInfo, StructuralFeature, TargetInfo,
};
use anyhow::{Context, Result};
use goblin::elf::note::NT_GNU_BUILD_ID;
use goblin::elf::Elf;
use std::fs;
use std::path::Path;
use std::sync::Arc;

/// Analyzer for Linux ELF binaries (executables, shared objects, kernel modules)
#[derive(Debug)]
pub(crate) struct ElfAnalyzer {
    capability_mapper: Arc<CapabilityMapper>,
    radare2: Radare2Analyzer,
    string_extractor: StringExtractor,
    /// Pre-extracted strings from stng (avoids redundant extraction)
    preextracted_strings: Option<Vec<StringInfo>>,
    /// When true, skip scanning for embedded PE/ELF binaries (prevents recursion in sub-analysis).
    skip_embedded_scan: bool,
    /// Per-request cancellation flag.
    cancellation: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
}

impl ElfAnalyzer {
    fn push_metadata_finding(
        report: &mut AnalysisReport,
        id: &str,
        desc: &str,
        method: &str,
        value: String,
    ) {
        report.findings.push(
            Finding::structural(id.to_string(), desc.to_string(), 1.0)
                .with_criticality(Criticality::Baseline)
                .with_evidence(vec![Evidence {
                    method: method.to_string(),
                    source: "goblin".to_string(),
                    value,
                    location: None,
                    ..Default::default()
                }]),
        );
    }

    fn gnu_debuglink_name(section_data: &[u8]) -> Option<String> {
        let nul = section_data.iter().position(|&b| b == 0)?;
        if nul == 0 {
            return None;
        }
        std::str::from_utf8(&section_data[..nul])
            .ok()
            .map(ToString::to_string)
    }

    /// Creates a new ELF analyzer with default configuration
    #[must_use]
    pub(crate) fn new() -> Self {
        Self {
            capability_mapper: Arc::new(CapabilityMapper::empty()),
            radare2: Radare2Analyzer::new(),
            string_extractor: StringExtractor::new(),
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
    #[must_use]
    pub(crate) fn with_yara_arc(self, yara_engine: Arc<crate::yara_engine::YaraEngine>) -> Self {
        // ELF analyzer currently doesn't use YARA engine directly for structural analysis,
        // but we accept it for consistency with other analyzers and future use.
        let _ = yara_engine;
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

    /// Core ELF analysis logic.
    ///
    /// If `stng_strings` is provided, uses those directly (avoids redundant extraction).
    /// Otherwise falls back to `self.preextracted_strings` or extracts with stng.
    fn analyze_elf_core(
        &self,
        logical_path: &Path,
        analysis_path: &Path,
        data: &[u8],
        stng_strings: Option<&[stng::ExtractedString]>,
        allow_rizin: bool,
        precomputed_sha256: Option<String>,
    ) -> AnalysisReport {
        let start = std::time::Instant::now();
        let sha256 = precomputed_sha256
            .clone()
            .unwrap_or_else(|| crate::analyzers::utils::calculate_sha256(data));

        // Create target info with default/empty values for fields that require parsing
        let target = TargetInfo {
            path: logical_path.display().to_string(),
            file_type: "elf".to_string(),
            size_bytes: data.len() as u64,
            sha256,
            architectures: None,
        };

        let mut report = AnalysisReport::new(target);
        let mut tools_used = vec![];

        // Attempt to parse with goblin via the panic-safe wrapper. A
        // returned `Failed` *or* a caught `Panicked` both fall through to
        // the rizin fallback below; they're treated as equivalent failures
        // for downstream metrics, with the exact message preserved in
        // `report.metadata.errors`.
        // Clone the sha256 hint up front so both the goblin-success rayon
        // closure and the failure-path rizin fallback can use it for the
        // shared cache lookup.
        let fallback_sha256 = precomputed_sha256.clone();
        let parse_outcome = goblin_safe::parse_elf(data);
        let parse_failure = parse_outcome.failure_info();
        let elf_opt = parse_outcome.ok();
        let (
            _elf_metrics_opt,
            _goblin_code_size,
            _has_symbols,
            r2_strings,
            elf_content_end,
            is_core_dump,
        ) = match elf_opt {
            Some(elf) => {
                tools_used.push("goblin".to_string());
                let is_core_dump = elf.header.e_type == goblin::elf::header::ET_CORE;

                // Update architecture now that we have parsed the header
                report.target.architectures = Some(vec![self.arch_name(&elf)]);

                // Compute ELF-specific metrics
                let elf_metrics = self.compute_elf_metrics(&elf, data);
                let symbols_found = !elf.syms.is_empty();

                // Calculate code_size from goblin section flags (more accurate than radare2)
                let code_size = Some(self.compute_code_size(&elf));
                let needs_r2_strings =
                    stng_strings.is_none() && self.preextracted_strings.is_none();

                // Parallelize Radare2 deep analysis with the rest of Goblin structural analysis
                let (r2_inner, _) = rayon::join(
                    || {
                        if !allow_rizin || self.is_cancelled() || !Radare2Analyzer::is_available() {
                            return None;
                        }
                        Some(self.radare2.extract_batched(
                            analysis_path,
                            symbols_found,
                            true, // goblin_success
                            needs_r2_strings,
                            precomputed_sha256,
                            self.cancellation.as_ref(),
                            Some(data),
                        ))
                    },
                    || {
                        // Analyze header and structure
                        self.analyze_structure(&elf, data, &mut report);

                        // Extract dynamic symbols and map to capabilities
                        self.analyze_dynamic_symbols(&elf, data, &mut report);

                        // Analyze sections and entropy
                        self.analyze_sections(&elf, data, &mut report);
                    },
                );

                // Process Radare2 results if available
                let r2_strings_extracted = if let Some(Ok(batched)) = r2_inner {
                    tools_used.push("radare2".to_string());

                    // Compute metrics from batched data
                    let mut binary_metrics = self.radare2.compute_metrics_from_batched(
                        &batched,
                        data.len() as u64,
                        "elf",
                    );

                    // Override code_size with goblin-based calculation (more accurate)
                    // In ELF, only sections with SHF_EXECINSTR flag contain executable code
                    if let Some(mut cs) = code_size {
                        // Sanity check: code_size should never exceed file size
                        if cs > binary_metrics.file_size {
                            eprintln!("WARNING: code_size ({}) > file_size ({}) - this indicates a bug in section classification", cs, binary_metrics.file_size);
                            cs = binary_metrics.file_size; // Cap at file_size to prevent invalid ratio
                        }

                        binary_metrics.code_size = cs;

                        // Recalculate code_to_data_ratio with correct code_size
                        if binary_metrics.file_size > 0 {
                            let data_size = binary_metrics.file_size.saturating_sub(cs);
                            if data_size > 0 {
                                binary_metrics.code_to_data_ratio = cs as f32 / data_size as f32;

                                // Sanity check: extremely high ratio likely indicates classification bug
                                if binary_metrics.code_to_data_ratio > 1000.0 {
                                    eprintln!("WARNING: code_to_data_ratio ({:.2}) > 1000 - this may indicate a bug", binary_metrics.code_to_data_ratio);
                                }
                            }
                        }

                        // Recalculate density metrics that depend on code_size
                        let code_kb = cs as f32 / 1024.0;
                        if code_kb > 0.0 {
                            binary_metrics.import_density =
                                binary_metrics.import_count as f32 / code_kb;
                            binary_metrics.string_density =
                                binary_metrics.string_count as f32 / code_kb;
                            binary_metrics.function_density =
                                binary_metrics.function_count as f32 / code_kb;
                            binary_metrics.relocation_density =
                                binary_metrics.relocation_count as f32 / code_kb;
                            binary_metrics.complexity_per_kb =
                                binary_metrics.avg_complexity * 1024.0 / cs as f32;
                        }
                    }

                    report.metrics = Some(Metrics {
                        binary: Some(binary_metrics),
                        elf: Some(elf_metrics.clone()),
                        ..Default::default()
                    });

                    // Convert R2Functions to Functions for the report
                    report.functions = batched.functions.into_iter().map(Function::from).collect();

                    // Use strings from batched data (no extra r2 spawn)
                    // Return None if empty so extract_smart falls back to stng extraction
                    if batched.strings.is_empty() {
                        None
                    } else {
                        Some(batched.strings)
                    }
                } else {
                    // Use ELF metrics computed from goblin if r2 failed/skipped
                    report.metrics = Some(Metrics {
                        elf: Some(elf_metrics.clone()),
                        ..Default::default()
                    });
                    None
                };

                // ELF overlay detection: data after the last PT_LOAD segment
                {
                    use goblin::elf::program_header::PT_LOAD;
                    let image_end = elf
                        .program_headers
                        .iter()
                        .filter(|ph| ph.p_type == PT_LOAD)
                        .map(|ph| ph.p_offset.saturating_add(ph.p_filesz) as usize)
                        .max()
                        .unwrap_or(0);
                    if image_end > 0 && data.len() > image_end {
                        let overlay = &data[image_end..];
                        // Check for squashfs (AppImage)
                        const SQUASHFS_LE: &[u8] = &[0x73, 0x71, 0x73, 0x68];
                        const SQUASHFS_BE: &[u8] = &[0x68, 0x73, 0x71, 0x73];
                        if overlay.starts_with(SQUASHFS_LE) || overlay.starts_with(SQUASHFS_BE) {
                            report.findings.push(crate::types::Finding {
                                id: "file/sfx/appimage".to_string(),
                                kind: crate::types::FindingKind::Structural,
                                desc: "Squashfs filesystem appended after ELF image (AppImage)"
                                    .to_string(),
                                conf: 1.0,
                                crit: crate::types::Criticality::Notable,
                                mbc: None,
                                attack: None,
                                trait_refs: vec![],
                                evidence: vec![crate::types::Evidence {
                                    method: "magic".to_string(),
                                    source: "elf_overlay".to_string(),
                                    value: format!("squashfs at offset {:#x}", image_end),
                                    location: Some(format!("{:#x}", image_end)),
                                    ..Default::default()
                                }],
                                match_count: 1,
                                source_file: None,
                            });
                        } else {
                            // Regular overlay — analyze via overlay detector
                            if let Ok(Some(ov)) = crate::analyzers::overlay::analyze_overlay(
                                overlay,
                                &report.target.path,
                                Some(self.capability_mapper.clone()),
                                None,
                            ) {
                                report.findings.push(ov.sfx_finding);
                                report.findings.extend(ov.archive_report.findings);
                                report.files.extend(ov.archive_report.files);
                            }
                        }
                    }
                }

                // Compute content_end for overlay metrics (after populate_binary_metrics)
                let sections_end = elf
                    .section_headers
                    .iter()
                    .filter(|s| s.sh_type != goblin::elf::section_header::SHT_NOBITS)
                    .map(|s| s.sh_offset + s.sh_size)
                    .max()
                    .unwrap_or(0);
                let segments_end = elf
                    .program_headers
                    .iter()
                    .map(|p| p.p_offset + p.p_filesz)
                    .max()
                    .unwrap_or(0);
                let content_end = sections_end.max(segments_end);

                (
                    Some(elf_metrics),
                    code_size,
                    symbols_found,
                    r2_strings_extracted,
                    content_end,
                    is_core_dump,
                )
            }
            None => {
                // goblin parse failed (Err or panic) — emit the structural
                // finding, salvage the architecture from the raw header, and
                // fall back to rizin via the shared cached path.
                let (err_msg_owned, panicked) = parse_failure
                    .as_ref()
                    .map(|f| (f.message.clone(), f.panicked))
                    .unwrap_or_else(|| {
                        tracing::error!("elf_opt is None but no parse_failure recorded");
                        (String::new(), false)
                    });
                let err_msg = &err_msg_owned;

                let mut crit = Criticality::Suspicious;
                if report.target.path.contains("!!embedded") {
                    crit = Criticality::Notable;
                } else {
                    let malformed_sections = err_msg.contains("section headers")
                        || err_msg.contains("dynamic segment offset + size exceeds");
                    let has_go_cli_markers = data
                        .windows(b"-trimpath=true".len())
                        .any(|w| w == b"-trimpath=true")
                        && data.windows(b"go.mod".len()).any(|w| w == b"go.mod");
                    let has_linuxbrew_marker = data
                        .windows(b"/home/linuxbrew/.linuxbrew/Cellar/".len())
                        .any(|w| w == b"/home/linuxbrew/.linuxbrew/Cellar/");
                    if data.len() >= 50 * 1024 * 1024
                        && (has_go_cli_markers || has_linuxbrew_marker)
                    {
                        // Very large Linuxbrew/Go CLI builds can carry metadata layouts
                        // that goblin rejects even though the executable is otherwise
                        // legitimate and dynamically linked. Keep the structural anomaly
                        // visible, but below suspicious for these known-benign contexts.
                        let _ = malformed_sections;
                        crit = Criticality::Notable;
                    }
                }
                report.findings.push(Finding {
                    kind: FindingKind::Structural,
                    id: "anti-analysis/malformed/elf-header".to_string(),
                    desc: format!("Malformed ELF header or section headers: {err_msg}"),
                    conf: 1.0,
                    crit,
                    mbc: Some("B0001".to_string()), // Defense Evasion: Software Packing/Obfuscation
                    attack: Some("T1027".to_string()), // Obfuscated Files or Information
                    evidence: vec![],
                    match_count: 0,
                    trait_refs: vec![],
                    source_file: None,
                });

                // Extract architecture from raw header even when full parse fails.
                // e_machine is at offset 18 (2 bytes), endianness from EI_DATA at offset 5.
                if data.len() >= 20 {
                    let is_big_endian = data.get(5) == Some(&2);
                    let e_machine = if is_big_endian {
                        u16::from_be_bytes([data[18], data[19]])
                    } else {
                        u16::from_le_bytes([data[18], data[19]])
                    };
                    let arch = self.arch_name_from_machine(e_machine);
                    report.structure.push(StructuralFeature {
                        id: format!("binary/arch/{}", arch),
                        desc: format!("{} architecture", arch),
                        evidence: vec![Evidence {
                            method: "header".to_string(),
                            source: "raw_header".to_string(),
                            value: format!("e_machine={}", e_machine),
                            ..Default::default()
                        }],
                    });
                    report.target.architectures = Some(vec![arch]);
                }

                report.metadata.errors.push(format!(
                    "ELF parse {}: {}",
                    if panicked { "panicked" } else { "error" },
                    err_msg
                ));
                (None, None, false, None, 0, false)
            }
        };

        // --- Rizin fallback for goblin-failed ELF binaries ---
        //
        // When goblin couldn't parse the file, populate `binary` metrics
        // from rizin instead so the binary doesn't end up with empty
        // structural data. This uses the same sha256-keyed disk cache as
        // the goblin-success path: a re-analysis of the same file is free.
        // Either way, we set `has_malformed_structure` so downstream
        // consumers know the structure didn't come from the primary parser.
        if parse_failure.is_some() {
            let mut binary_metrics =
                if allow_rizin && !self.is_cancelled() && Radare2Analyzer::is_available() {
                    let needs_r2_strings =
                        stng_strings.is_none() && self.preextracted_strings.is_none();
                    match self.radare2.extract_batched(
                        analysis_path,
                        false, // has_symbols=false: nothing came back from goblin
                        false, // goblin_success=false
                        needs_r2_strings,
                        fallback_sha256,
                        self.cancellation.as_ref(),
                        Some(data),
                    ) {
                        Ok(batched) => {
                            tools_used.push("radare2".to_string());
                            let bm = self.radare2.compute_metrics_from_batched(
                                &batched,
                                data.len() as u64,
                                "elf",
                            );
                            report.functions =
                                batched.functions.into_iter().map(Function::from).collect();
                            bm
                        }
                        Err(e) => {
                            tracing::debug!(
                                "rizin fallback also failed for goblin-malformed ELF {}: {}",
                                report.target.path,
                                e
                            );
                            crate::types::BinaryMetrics {
                                file_size: data.len() as u64,
                                ..Default::default()
                            }
                        }
                    }
                } else {
                    crate::types::BinaryMetrics {
                        file_size: data.len() as u64,
                        ..Default::default()
                    }
                };
            binary_metrics.has_malformed_structure = true;
            report.metrics = Some(Metrics {
                binary: Some(binary_metrics),
                ..Default::default()
            });
        }

        // --- Shared post-processing (strings, embedded code, metrics, overlay) ---

        // String extraction (preference: stng_strings > preextracted > extract_smart)
        let (report_strings, raw_stng_strings) = if let Some(strings) = stng_strings {
            (
                self.string_extractor.convert_stng_strings(strings),
                Some(strings.to_vec()),
            )
        } else if let Some(ref strings) = self.preextracted_strings {
            (strings.clone(), None)
        } else {
            let raw = self.string_extractor.extract_raw_smart(data, r2_strings);
            (
                self.string_extractor.convert_stng_strings(&raw),
                Some(raw),
            )
        };
        report.strings = report_strings;

        // Embedded ELF / PE scanning (host-agnostic, scans raw bytes)
        if !self.skip_embedded_scan && !is_core_dump {
            let host_name = std::path::Path::new(&report.target.path)
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("binary.elf")
                .to_string();
            let embedded = crate::analyzers::embedded_binary_detector::scan_for_embedded_binaries(
                data,
                self.cancellation.as_deref(),
            );
            for binary in &embedded {
                if self.is_cancelled() {
                    break;
                }
                report
                    .findings
                    .push(crate::analyzers::embedded_binary_detector::finding_for(
                        binary,
                        &report.target.path,
                    ));
                if binary.offset >= data.len() {
                    continue;
                }
                let slice_end = (binary.offset + binary.estimated_size).min(data.len());
                let embedded_bytes = &data[binary.offset..slice_end];
                let kind_str = binary.kind.as_str();
                if let Some(fa) = crate::analyzers::utils::analyze_embedded_as_child(
                    embedded_bytes,
                    &host_name,
                    kind_str,
                    binary.offset,
                    self.capability_mapper.clone(),
                    None, // YARA handled by child
                    raw_stng_strings.as_deref().unwrap_or(&[]),
                ) {
                    report.files.push(fa);
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

        // Analyze embedded code in strings
        let (encoded_layers, plain_findings) =
            crate::analyzers::embedded_code_detector::process_all_strings(
                &logical_path.display().to_string(),
                &report.strings,
                &self.capability_mapper,
                0,
                self.cancellation.as_deref(),
            );
        report.files.extend(encoded_layers);
        report.findings.extend(plain_findings);

        // Populate common binary metrics (strings, entropy, etc.)
        crate::analyzers::metrics_utils::populate_binary_metrics(&mut report, data);

        // ELF binaries are usually unsigned (or use non-standard signing)
        if !is_core_dump {
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

        // Populate overlay metrics using content_end computed from ELF headers
        if (data.len() as u64) > elf_content_end && elf_content_end > 0 {
            if let Some(ref mut metrics) = report.metrics {
                if let Some(ref mut binary) = metrics.binary {
                    let overlay_size = data.len() as u64 - elf_content_end;
                    binary.has_overlay = true;
                    binary.overlay_size = overlay_size;
                    binary.overlay_ratio = overlay_size as f32 / data.len() as f32;
                    binary.overlay_entropy =
                        crate::entropy::calculate_entropy(&data[elf_content_end as usize..]) as f32;
                }
            }
        }

        // Validate metric ranges to catch calculation bugs
        if let Some(ref metrics) = report.metrics {
            if let Some(ref binary) = metrics.binary {
                binary.validate(&report.target.path);
            }
        }

        report.metadata.analysis_duration_ms = start.elapsed().as_millis() as u64;
        report.metadata.tools_used = tools_used;

        // Free excess vector capacity to reduce memory footprint
        report.shrink_to_fit();

        report
    }

    fn analyze_structure<'a>(&self, elf: &Elf<'a>, data: &[u8], report: &mut AnalysisReport) {
        // Binary format
        report.structure.push(StructuralFeature {
            id: "binary/format/elf".to_string(),
            desc: "ELF binary format".to_string(),
            evidence: vec![Evidence {
                method: "magic".to_string(),
                source: "goblin".to_string(),
                value: format!("0x{:x}", elf.header.e_ident[0]),
                location: None,
                ..Default::default()
            }],
        });

        // Architecture
        let arch = self.arch_name(elf);
        report.structure.push(StructuralFeature {
            id: format!("binary/arch/{}", arch),
            desc: format!("{} architecture", arch),
            evidence: vec![Evidence {
                method: "header".to_string(),
                source: "goblin".to_string(),
                value: format!("e_machine={}", elf.header.e_machine),
                location: None,
                ..Default::default()
            }],
        });

        // Check if stripped
        if elf.syms.is_empty() {
            report.structure.push(StructuralFeature {
                id: "binary/stripped".to_string(),
                desc: "Symbol table stripped".to_string(),
                evidence: vec![Evidence {
                    method: "symbols".to_string(),
                    source: "goblin".to_string(),
                    value: "no_symbols".to_string(),
                    location: None,
                    ..Default::default()
                }],
            });
        }

        // Check if PIE (Position Independent Executable)
        if elf.header.e_type == goblin::elf::header::ET_DYN {
            report.structure.push(StructuralFeature {
                id: "binary/pie".to_string(),
                desc: "Position Independent Executable".to_string(),
                evidence: vec![Evidence {
                    method: "header".to_string(),
                    source: "goblin".to_string(),
                    value: "ET_DYN".to_string(),
                    location: None,
                    ..Default::default()
                }],
            });
        }

        if let Some(interpreter) = elf.interpreter {
            Self::push_metadata_finding(
                report,
                "metadata/binary/linking::elf-interpreter",
                "ELF program interpreter present",
                "pt_interp",
                interpreter.to_string(),
            );
        }

        if let Some(soname) = elf.soname {
            Self::push_metadata_finding(
                report,
                "metadata/binary/linking::elf-soname",
                "ELF SONAME present",
                "dt_soname",
                soname.to_string(),
            );
        }

        for needed in &elf.libraries {
            Self::push_metadata_finding(
                report,
                "metadata/binary/linking::elf-needed-lib",
                "ELF needed library",
                "dt_needed",
                (*needed).to_string(),
            );
        }

        for rpath in &elf.rpaths {
            Self::push_metadata_finding(
                report,
                "metadata/binary/linking::elf-rpath",
                "ELF RPATH entry",
                "dt_rpath",
                (*rpath).to_string(),
            );
        }

        for runpath in &elf.runpaths {
            Self::push_metadata_finding(
                report,
                "metadata/binary/linking::elf-runpath",
                "ELF RUNPATH entry",
                "dt_runpath",
                (*runpath).to_string(),
            );
        }

        if let Some(note_iter) = elf.iter_note_sections(data, None) {
            for note in note_iter.flatten() {
                if note.name == "GNU" && note.n_type == NT_GNU_BUILD_ID {
                    report.findings.push(
                        Finding::structural(
                            "metadata/build/reproducible::elf-build-id".to_string(),
                            "ELF GNU build-id note present".to_string(),
                            1.0,
                        )
                        .with_criticality(Criticality::Baseline)
                        .with_evidence(vec![Evidence {
                            method: "note".to_string(),
                            source: "goblin".to_string(),
                            value: hex::encode(note.desc),
                            location: None,
                            ..Default::default()
                        }]),
                    );
                    break;
                }
            }
        }

        for section in &elf.section_headers {
            let Some(name) = elf.shdr_strtab.get_at(section.sh_name) else {
                continue;
            };
            if name != ".gnu_debuglink" {
                continue;
            }

            let offset = section.sh_offset as usize;
            let size = section.sh_size as usize;
            if offset.saturating_add(size) > data.len() || size == 0 {
                continue;
            }

            if let Some(debuglink) = Self::gnu_debuglink_name(&data[offset..offset + size]) {
                Self::push_metadata_finding(
                    report,
                    "metadata/build/debug::elf-debuglink",
                    ".gnu_debuglink reference present",
                    "section",
                    debuglink,
                );
            }
        }
    }

    fn analyze_dynamic_symbols<'a>(
        &self,
        elf: &Elf<'a>,
        _data: &[u8],
        report: &mut AnalysisReport,
    ) {
        for dynsym in &elf.dynsyms {
            let Some(name) = elf.dynstrtab.get_at(dynsym.st_name) else {
                continue;
            };
            if dynsym.st_shndx == goblin::elf::section_header::SHN_UNDEF as usize {
                // Undefined symbol — resolved from another library (import)
                report.imports.push(Import::new(name, None, "goblin"));
                if let Some(cap) = self.capability_mapper.lookup(name, "goblin") {
                    if !report.findings.iter().any(|c| c.id == cap.id) {
                        report.findings.push(cap);
                    }
                }
            } else if dynsym.st_bind() == goblin::elf::sym::STB_GLOBAL {
                // Defined GLOBAL symbol — exported from this binary
                report.exports.push(Export::new(
                    name,
                    Some(format!("{:#x}", dynsym.st_value)),
                    "goblin",
                ));
            }
            // IFUNC resolvers (STT_GNU_IFUNC) are notable regardless of import/export direction
            if dynsym.st_type() == 10 {
                let clean_name = crate::types::binary::normalize_symbol(name);
                if !report.findings.iter().any(|f| f.desc.contains(&clean_name)) {
                    report.findings.push(Finding {
                        kind: FindingKind::Capability,
                        id: "feat/binary/elf/ifunc".to_string(),
                        desc: format!("ELF IFUNC resolver: {}", clean_name),
                        crit: Criticality::Notable,
                        conf: 1.0,
                        mbc: None,
                        attack: None,
                        trait_refs: vec![],
                        evidence: vec![Evidence {
                            method: "symbol_type".to_string(),
                            source: "goblin".to_string(),
                            value: "STT_GNU_IFUNC (LOOS)".to_string(),
                            location: Some(format!("{:#x}", dynsym.st_value)),
                            ..Default::default()
                        }],
                        match_count: 0,
                        source_file: None,
                    });
                }
            }
        }

        // Analyze static symbol table (.symtab) for any additional exports not in .dynsym
        for sym in &elf.syms {
            let st_type = sym.st_type();
            if sym.st_bind() == goblin::elf::sym::STB_GLOBAL
                && (st_type == goblin::elf::sym::STT_FUNC || st_type == 10)
            {
                if let Some(name) = elf.strtab.get_at(sym.st_name) {
                    // Skip symbols already captured via dynsyms to avoid duplication
                    if report.exports.iter().any(|e| e.symbol == name) {
                        continue;
                    }
                    let clean_name = crate::types::binary::normalize_symbol(name);
                    report.exports.push(Export::new(
                        name,
                        Some(format!("{:#x}", sym.st_value)),
                        "goblin",
                    ));
                    if st_type == 10
                        && !report.findings.iter().any(|f| f.desc.contains(&clean_name))
                    {
                        report.findings.push(Finding {
                            kind: FindingKind::Capability,
                            id: "feat/binary/elf/ifunc".to_string(),
                            desc: format!("ELF IFUNC resolver: {}", clean_name),
                            crit: Criticality::Notable,
                            conf: 1.0,
                            mbc: None,
                            attack: None,
                            trait_refs: vec![],
                            evidence: vec![Evidence {
                                method: "symbol_type".to_string(),
                                source: "goblin".to_string(),
                                value: "STT_GNU_IFUNC (LOOS)".to_string(),
                                location: Some(format!("{:#x}", sym.st_value)),
                                ..Default::default()
                            }],
                            match_count: 0,
                            source_file: None,
                        });
                    }
                }
            }
        }
    }

    fn analyze_sections<'a>(&self, elf: &Elf<'a>, data: &[u8], report: &mut AnalysisReport) {
        for section in &elf.section_headers {
            if let Some(name) = elf.shdr_strtab.get_at(section.sh_name) {
                let section_offset = section.sh_offset as usize;
                let section_size = section.sh_size as usize;

                if section_offset + section_size <= data.len() && section_size > 0 {
                    let section_data = &data[section_offset..section_offset + section_size];
                    let entropy = calculate_entropy(section_data);

                    report.sections.push(Section {
                        name: name.to_string(),
                        address: Some(section.sh_addr),
                        offset: Some(section.sh_offset),
                        size: section.sh_size,
                        entropy,
                        permissions: Some(format!("{:x}", section.sh_flags)),
                    });

                    // Add entropy-based structural features
                    let level = EntropyLevel::from_value(entropy);
                    if level == EntropyLevel::High {
                        report.structure.push(StructuralFeature {
                            id: "entropy/high".to_string(),
                            desc: "High entropy section (possibly packed/encrypted)".to_string(),
                            evidence: vec![Evidence {
                                method: "entropy".to_string(),
                                source: "entropy_analyzer".to_string(),
                                value: format!("{:.2}", entropy),
                                location: Some(name.to_string()),
                                ..Default::default()
                            }],
                        });
                    }
                }
            }
        }
    }

    fn arch_name<'a>(&self, elf: &Elf<'a>) -> String {
        self.arch_name_from_machine(elf.header.e_machine)
    }

    fn arch_name_from_machine(&self, e_machine: u16) -> String {
        match e_machine {
            goblin::elf::header::EM_X86_64 => "x86_64".to_string(),
            goblin::elf::header::EM_386 => "i386".to_string(),
            goblin::elf::header::EM_AARCH64 => "aarch64".to_string(),
            goblin::elf::header::EM_ARM => "arm".to_string(),
            goblin::elf::header::EM_RISCV => "riscv".to_string(),
            goblin::elf::header::EM_MIPS => "mips".to_string(),
            goblin::elf::header::EM_PPC => "powerpc".to_string(),
            goblin::elf::header::EM_PPC64 => "powerpc64".to_string(),
            goblin::elf::header::EM_SPARC | 18 | 43 => "sparc".to_string(), // SPARC, SPARC32PLUS, SPARCV9
            goblin::elf::header::EM_68K => "m68k".to_string(),
            22 => "s390".to_string(),   // S390
            42 => "superh".to_string(), // SH
            _ => format!("unknown_{}", e_machine),
        }
    }
    /// Compute ELF-specific metrics from parsed ELF binary
    fn compute_elf_metrics<'a>(&self, elf: &Elf<'a>, data: &[u8]) -> ElfMetrics {
        use goblin::elf::dynamic::{
            DT_BIND_NOW, DT_FINI_ARRAYSZ, DT_GNU_HASH, DT_INIT_ARRAYSZ, DT_RPATH, DT_RUNPATH,
            DT_TEXTREL,
        };
        use goblin::elf::program_header::{PF_X, PT_GNU_RELRO, PT_GNU_STACK, PT_LOAD};
        use goblin::elf::sym::STB_LOCAL;

        let mut metrics = ElfMetrics {
            e_type: elf.header.e_type as u32,
            e_machine: elf.header.e_machine as u32,
            class_bits: if elf.is_64 { 64 } else { 32 },
            little_endian: elf.little_endian,
            entry_point: elf.entry,
            program_header_count: elf.program_headers.len() as u32,
            section_header_count: elf.section_headers.len() as u32,
            has_interpreter: elf.interpreter.is_some(),
            has_soname: elf.soname.is_some(),
            rpath_count: elf.rpaths.len() as u32,
            runpath_count: elf.runpaths.len() as u32,
            dynsym_count: elf.dynsyms.len() as u32,
            symtab_count: elf.syms.len() as u32,
            dynrela_count: elf.dynrelas.len() as u32,
            dynrel_count: elf.dynrels.len() as u32,
            pltreloc_count: elf.pltrelocs.len() as u32,
            section_relocation_group_count: elf.shdr_relocs.len() as u32,
            ..Default::default()
        };

        // Entry point analysis
        let entry = elf.entry;
        if entry > 0 {
            // Find section containing entry point
            let mut found_in_text = false;
            for sh in &elf.section_headers {
                if entry >= sh.sh_addr && entry < sh.sh_addr + sh.sh_size {
                    if let Some(name) = elf.shdr_strtab.get_at(sh.sh_name) {
                        metrics.entry_section = Some(name.to_string());
                        if name == ".text" {
                            found_in_text = true;
                        }
                    }
                    break;
                }
            }
            metrics.entry_not_in_text = !found_in_text && metrics.entry_section.is_some();
        }

        // Dynamic section analysis
        if let Some(dynamic) = &elf.dynamic {
            metrics.needed_libs = dynamic.info.needed_count as u32;

            // Count init/fini array sizes from dynamic entries
            let mut init_arraysz = 0u64;
            let mut fini_arraysz = 0u64;

            // Check for various dynamic tags
            for dyn_entry in &dynamic.dyns {
                match dyn_entry.d_tag {
                    DT_RPATH => metrics.rpath_set = true,
                    DT_RUNPATH => metrics.runpath_set = true,
                    DT_TEXTREL => metrics.textrel_present = true,
                    DT_GNU_HASH => metrics.gnu_hash_present = true,
                    DT_BIND_NOW => {
                        // DT_BIND_NOW + GNU_RELRO = Full RELRO
                        if metrics.relro.is_some() {
                            metrics.relro = Some("full".to_string());
                        }
                    }
                    DT_INIT_ARRAYSZ => init_arraysz = dyn_entry.d_val,
                    DT_FINI_ARRAYSZ => fini_arraysz = dyn_entry.d_val,
                    _ => {}
                }
            }

            // Compute array counts (each entry is pointer size: 8 bytes for 64-bit, 4 for 32-bit)
            let ptr_size = if elf.is_64 { 8 } else { 4 };
            if init_arraysz > 0 {
                metrics.init_array_count = (init_arraysz / ptr_size) as u32;
            }
            if fini_arraysz > 0 {
                metrics.fini_array_count = (fini_arraysz / ptr_size) as u32;
            }
        }

        // Program header analysis (security features)
        for ph in &elf.program_headers {
            if ph.p_type == PT_LOAD {
                metrics.load_segment_max_p_filesz =
                    metrics.load_segment_max_p_filesz.max(ph.p_filesz);
                metrics.load_segment_max_p_memsz = metrics.load_segment_max_p_memsz.max(ph.p_memsz);
            }

            match ph.p_type {
                PT_GNU_RELRO => {
                    // GNU_RELRO present (partial unless DT_BIND_NOW also set)
                    if metrics.relro.is_none() {
                        metrics.relro = Some("partial".to_string());
                    }
                }
                PT_GNU_STACK => {
                    // Check if stack is executable
                    metrics.nx_enabled = (ph.p_flags & PF_X) == 0;
                }
                _ => {}
            }
        }

        // Symbol analysis
        let mut hidden_count = 0;
        let mut has_stack_chk = false;

        for sym in elf.syms.iter() {
            // Count hidden visibility symbols
            if sym.st_bind() == STB_LOCAL && sym.st_visibility() == goblin::elf::sym::STV_HIDDEN {
                hidden_count += 1;
            }

            // Check for stack canary symbol
            if let Some(name) = elf.strtab.get_at(sym.st_name) {
                if name == "__stack_chk_fail" || name == "__stack_chk_guard" {
                    has_stack_chk = true;
                }
            }
        }

        // Also check dynamic symbols
        for sym in elf.dynsyms.iter() {
            if sym.st_bind() == STB_LOCAL && sym.st_visibility() == goblin::elf::sym::STV_HIDDEN {
                hidden_count += 1;
            }

            if let Some(name) = elf.dynstrtab.get_at(sym.st_name) {
                if name == "__stack_chk_fail" || name == "__stack_chk_guard" {
                    has_stack_chk = true;
                }
            }
        }

        metrics.hidden_symbols = hidden_count;
        metrics.stack_canary = has_stack_chk;

        // Section analysis
        for sh in &elf.section_headers {
            if let Some(name) = elf.shdr_strtab.get_at(sh.sh_name) {
                match name {
                    ".plt" => metrics.has_plt = true,
                    ".got" | ".got.plt" => metrics.has_got = true,
                    ".eh_frame" => metrics.has_eh_frame = true,
                    n if n.starts_with(".note") => metrics.has_note = true,
                    ".gnu_debuglink" => metrics.debuglink_present = true,
                    n if n.starts_with(".debug") || n == ".zdebug" || n.starts_with(".zdebug") => {
                        metrics.debug_section_count += 1;
                    }
                    _ => {}
                }
            }
        }

        if let Some(note_iter) = elf.iter_note_sections(data, None) {
            for note in note_iter.flatten() {
                metrics.note_count += 1;
                if note.name == "GNU" && note.n_type == NT_GNU_BUILD_ID {
                    metrics.build_id_present = true;
                    metrics.build_id_length = note.desc.len() as u32;
                }
            }
        }

        metrics
    }

    /// Calculate code size from ELF section headers using SHF_EXECINSTR flag
    /// This is more accurate than radare2's section classification
    fn compute_code_size<'a>(&self, elf: &Elf<'a>) -> u64 {
        const SHF_EXECINSTR: u64 = 0x4; // Section contains executable code

        let mut code_size: u64 = 0;

        for section in &elf.section_headers {
            // Check if section has SHF_EXECINSTR flag set
            if section.sh_flags & SHF_EXECINSTR != 0 {
                code_size += section.sh_size;
            }
        }

        code_size
    }
}

impl Default for ElfAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl ElfAnalyzer {
    /// Perform structural analysis of an ELF binary (no YARA scan, no trait evaluation).
    /// Handles UPX decompression internally - unpacked content becomes a separate FileAnalysis
    /// entry in `report.files` with `encoding: ["upx"]`.
    /// Callers are responsible for running YARA and calling `evaluate_and_merge_findings`.
    pub(crate) fn analyze_structural(
        &self,
        file_path: &Path,
        data: &[u8],
        precomputed_sha256: Option<String>,
    ) -> AnalysisReport {
        use crate::types::file_analysis::encode_upx_path;
        use crate::upx::{UPXDecompressor, UPXError};

        if !UPXDecompressor::is_upx_packed(data) {
            return self.analyze_elf_core(
                file_path,
                file_path,
                data,
                None,
                true,
                precomputed_sha256,
            );
        }

        // UPX-packed: structural analysis of packed binary first
        let mut report = self.analyze_elf_core(
            file_path,
            file_path,
            data,
            None,
            true,
            precomputed_sha256.clone(),
        );

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

        if self.is_cancelled() {
            return report;
        }

        match UPXDecompressor::decompress(file_path) {
            Ok(unpacked_data) => {
                if let Ok(temp_file) = tempfile::NamedTempFile::new() {
                    if std::fs::write(temp_file.path(), &unpacked_data).is_ok() {
                        let unpacked_report = self.analyze_elf_core(
                            temp_file.path(),
                            temp_file.path(),
                            &unpacked_data,
                            None,
                            true,
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
}

impl Analyzer for ElfAnalyzer {
    fn analyze_input(&self, input: &AnalysisInput<'_>) -> Result<AnalysisReport> {
        // Use data and strings from input (no file read, no string extraction)
        let mut report = self.analyze_elf_core(
            input.path,
            input.backing_path(),
            input.data,
            Some(input.strings),
            !input.skip_rizin,
            input.sha256.clone(),
        );

        // Post-processing
        self.capability_mapper
            .evaluate_and_merge_findings(&mut report, input.data, None, None);
        crate::path_mapper::analyze_and_link_paths(&mut report);
        crate::env_mapper::analyze_and_link_env_vars(&mut report);
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
            "ELF analyzer extracting strings locally before analyze_input"
        );
        let input = AnalysisInput::with_strings(
            file_path,
            &data,
            &strings,
            crate::analyzers::FileType::Elf,
        );
        self.analyze_input(&input)
    }

    fn can_analyze(&self, file_path: &Path) -> bool {
        if let Ok(data) = fs::read(file_path) {
            goblin_safe::parse_elf(&data).is_ok()
        } else {
            false
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn test_elf_path() -> PathBuf {
        PathBuf::from("tests/fixtures/test.elf")
    }

    #[test]
    fn test_can_analyze_elf() {
        let analyzer = ElfAnalyzer::new();
        let test_file = test_elf_path();

        if test_file.exists() {
            assert!(analyzer.can_analyze(&test_file));
        }
    }

    #[test]
    fn test_cannot_analyze_non_elf() {
        let analyzer = ElfAnalyzer::new();
        assert!(!analyzer.can_analyze(&PathBuf::from("/dev/null")));
        assert!(!analyzer.can_analyze(&PathBuf::from("tests/fixtures/test.exe")));
    }

    #[test]
    fn test_analyze_elf_file() {
        let analyzer = ElfAnalyzer::new();
        let test_file = test_elf_path();

        if !test_file.exists() {
            return; // Skip if fixture doesn't exist
        }

        let result = analyzer.analyze(&test_file);
        assert!(result.is_ok());

        let report = result.unwrap();
        assert_eq!(report.target.file_type, "elf");
        assert!(report.target.size_bytes > 0);
        assert!(!report.target.sha256.is_empty());
    }

    #[test]
    fn test_elf_has_structure() {
        let analyzer = ElfAnalyzer::new();
        let test_file = test_elf_path();

        if !test_file.exists() {
            return;
        }

        let report = analyzer.analyze(&test_file).unwrap();
        assert!(!report.structure.is_empty());
    }

    #[test]
    fn test_elf_architecture_detected() {
        let analyzer = ElfAnalyzer::new();
        let test_file = test_elf_path();

        if !test_file.exists() {
            return;
        }

        let report = analyzer.analyze(&test_file).unwrap();
        assert!(report.target.architectures.is_some());
        let archs = report.target.architectures.unwrap();
        assert!(!archs.is_empty());
    }

    #[test]
    fn test_elf_sections_analyzed() {
        let analyzer = ElfAnalyzer::new();
        let test_file = test_elf_path();

        if !test_file.exists() {
            return;
        }

        let report = analyzer.analyze(&test_file).unwrap();
        assert!(!report.sections.is_empty());
    }

    #[test]
    fn test_elf_has_imports() {
        let analyzer = ElfAnalyzer::new();
        let test_file = test_elf_path();

        if !test_file.exists() {
            return;
        }

        let report = analyzer.analyze(&test_file).unwrap();
        // Most ELF binaries have dynamic imports
        assert!(!report.imports.is_empty());
    }

    #[test]
    fn test_elf_capabilities_detected() {
        let analyzer = ElfAnalyzer::new();
        let test_file = test_elf_path();

        if !test_file.exists() {
            return;
        }

        let report = analyzer.analyze(&test_file).unwrap();
        // Capabilities may or may not be detected depending on the binary
        // Just verify the analysis completes successfully
        let _ = &report.traits;
    }

    #[test]
    fn test_elf_strings_extracted() {
        let analyzer = ElfAnalyzer::new();
        let test_file = test_elf_path();

        if !test_file.exists() {
            return;
        }

        let report = analyzer.analyze(&test_file).unwrap();
        assert!(!report.strings.is_empty());
    }

    #[test]
    fn test_elf_tools_used() {
        let analyzer = ElfAnalyzer::new();
        let test_file = test_elf_path();

        if !test_file.exists() {
            return;
        }

        let report = analyzer.analyze(&test_file).unwrap();
        assert!(report.metadata.tools_used.contains(&"goblin".to_string()));
    }

    #[test]
    fn test_elf_analysis_duration() {
        let analyzer = ElfAnalyzer::new();
        let test_file = test_elf_path();

        if !test_file.exists() {
            return;
        }

        let report = analyzer.analyze(&test_file).unwrap();
        // Duration can vary substantially on loaded CI hosts.
        // Keep this as a sanity bound, not a performance benchmark.
        assert!(report.metadata.analysis_duration_ms < 60000);
    }

    // =========================================================================
    // UPX Integration Tests
    // =========================================================================

    #[test]
    fn test_upx_detection_in_data() {
        use crate::upx::UPXDecompressor;

        // Data with UPX magic
        let upx_data = b"\x7fELF\x00\x00\x00\x00UPX!\x00\x00";
        assert!(UPXDecompressor::is_upx_packed(upx_data));

        // Data without UPX magic
        let normal_data = b"\x7fELF\x01\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00";
        assert!(!UPXDecompressor::is_upx_packed(normal_data));
    }

    #[test]
    fn test_upx_packed_creates_finding() {
        use crate::upx::UPXDecompressor;

        let analyzer = ElfAnalyzer::new();

        // Create minimal UPX-packed ELF-like data (won't actually decompress)
        let mut upx_data = vec![0u8; 256];
        // ELF magic
        upx_data[0..4].copy_from_slice(b"\x7fELF");
        // UPX magic
        upx_data[100..104].copy_from_slice(b"UPX!");

        assert!(UPXDecompressor::is_upx_packed(&upx_data));

        // Use a temp file for the analysis
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
    fn test_upx_tool_missing_creates_finding() {
        use crate::upx::{disable_upx, UPXDecompressor};

        // Temporarily disable UPX to simulate tool not available
        disable_upx();

        let analyzer = ElfAnalyzer::new();

        // Create minimal UPX-packed ELF-like data
        let mut upx_data = vec![0u8; 256];
        upx_data[0..4].copy_from_slice(b"\x7fELF");
        upx_data[100..104].copy_from_slice(b"UPX!");

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

        // Should NOT have unpacked file analysis (since tool is missing)
        assert!(
            report.files.is_empty(),
            "Should not have unpacked FileAnalysis when tool is missing"
        );
    }

    #[test]
    fn test_non_upx_data_no_upx_finding() {
        let analyzer = ElfAnalyzer::new();

        // Create minimal ELF-like data without UPX magic
        let mut elf_data = vec![0u8; 256];
        elf_data[0..4].copy_from_slice(b"\x7fELF");
        elf_data[4] = 2; // 64-bit
        elf_data[5] = 1; // little-endian

        let temp_file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(temp_file.path(), &elf_data).unwrap();

        let report = analyzer.analyze_structural(temp_file.path(), &elf_data, None);

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
    fn test_upx_path_encoding_format() {
        use crate::types::file_analysis::encode_upx_path;

        // Test basic path encoding
        assert_eq!(
            encode_upx_path("/path/to/file.elf"),
            "/path/to/file.elf!!upx@0"
        );

        // Test path with special characters
        assert_eq!(
            encode_upx_path("/tmp/test-file_v1.2.elf"),
            "/tmp/test-file_v1.2.elf!!upx@0"
        );

        // Test path that already has archive delimiter
        assert_eq!(
            encode_upx_path("archive.zip!!inner.elf"),
            "archive.zip!!inner.elf!!upx@0"
        );
    }

    #[test]
    fn test_upx_file_analysis_fields() {
        use crate::types::file_analysis::{encode_upx_path, FileAnalysis};

        // Create a FileAnalysis as if from UPX unpacking
        let parent_path = "/test/sample.elf";
        let virtual_path = encode_upx_path(parent_path);

        let mut file = FileAnalysis::new(
            1, // id (unpacked is typically id=1)
            virtual_path.clone(),
            "elf".to_string(),
            "abc123def456".to_string(),
            1000,
        );
        file.parent_id = Some(0);
        file.depth = 1;
        file.encoding = Some(vec!["upx".to_string()]);
        file.compute_summary();

        // Verify all UPX-specific fields
        assert_eq!(file.id, 1);
        assert_eq!(file.path, "/test/sample.elf!!upx@0");
        assert_eq!(file.parent_id, Some(0));
        assert_eq!(file.depth, 1);
        assert_eq!(file.encoding, Some(vec!["upx".to_string()]));
        assert_eq!(file.file_type, "elf");
    }

    #[test]
    fn test_upx_finding_criticality() {
        use crate::upx::UPXDecompressor;

        let analyzer = ElfAnalyzer::new();

        let mut upx_data = vec![0u8; 256];
        upx_data[0..4].copy_from_slice(b"\x7fELF");
        upx_data[100..104].copy_from_slice(b"UPX!");

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
    fn test_upx_tampered_magic_detection() {
        use crate::upx::UPXDecompressor;

        // Test tampered UPX magic variants (APX!, BPX!, etc.)
        let mut data_apx = vec![0u8; 256];
        data_apx[100..104].copy_from_slice(b"APX!");
        assert!(
            UPXDecompressor::is_upx_packed(&data_apx),
            "Should detect APX! (tampered UPX)"
        );

        let mut data_bpx = vec![0u8; 256];
        data_bpx[100..104].copy_from_slice(b"BPX!");
        assert!(
            UPXDecompressor::is_upx_packed(&data_bpx),
            "Should detect BPX! (tampered UPX)"
        );

        let mut data_zpx = vec![0u8; 256];
        data_zpx[100..104].copy_from_slice(b"ZPX!");
        assert!(
            UPXDecompressor::is_upx_packed(&data_zpx),
            "Should detect ZPX! (tampered UPX)"
        );

        // lowercase should NOT match
        let mut data_lowercase = vec![0u8; 256];
        data_lowercase[100..104].copy_from_slice(b"upx!");
        assert!(
            !UPXDecompressor::is_upx_packed(&data_lowercase),
            "Should not detect lowercase upx!"
        );
    }
}
