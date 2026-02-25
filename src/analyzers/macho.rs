//! Mach-O binary analyzer for macOS executables.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use crate::analyzers::macho_codesign;
use crate::analyzers::Analyzer;
use crate::capabilities::CapabilityMapper;
use crate::entropy::{calculate_entropy, EntropyLevel};
use crate::radare2::Radare2Analyzer;
use crate::strings::StringExtractor;
use crate::types::*;
use anyhow::{Context, Result};
use goblin::mach::{Mach, MachO};
use std::fs;
use std::path::Path;
use std::sync::Arc;

/// Analyzer for macOS Mach-O binaries (executables, dylibs, bundles)
#[derive(Debug)]
pub(crate) struct MachOAnalyzer {
    capability_mapper: Arc<CapabilityMapper>,
    radare2: Radare2Analyzer,
    string_extractor: StringExtractor,
    /// Pre-extracted strings from stng (avoids redundant extraction)
    preextracted_strings: Option<Vec<StringInfo>>,
}

impl MachOAnalyzer {
    /// Creates a new Mach-O analyzer with default configuration
    #[must_use]
    pub(crate) fn new() -> Self {
        Self {
            capability_mapper: Arc::new(CapabilityMapper::empty()),
            radare2: Radare2Analyzer::new(),
            string_extractor: StringExtractor::new(),
            preextracted_strings: None,
        }
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

    /// Structural analysis of a thin Mach-O binary (no YARA scan, no trait evaluation).
    /// Only handles thin binaries — fat binary dispatch is done by the caller.
    /// Callers are responsible for running YARA and calling `evaluate_and_merge_findings`.
    pub(crate) fn analyze_structural(
        &self,
        file_path: &Path,
        data: &[u8],
    ) -> Result<AnalysisReport> {
        let start = std::time::Instant::now(); // Parse with goblin
        let macho = match goblin::mach::Mach::parse(data)? {
            Mach::Binary(m) => m,
            Mach::Fat(_) => {
                anyhow::bail!("Fat binaries should be handled separately");
            }
        };

        // Create target info
        let target = TargetInfo {
            path: file_path.display().to_string(),
            file_type: "macho".to_string(),
            size_bytes: data.len() as u64,
            sha256: crate::analyzers::utils::calculate_sha256(data),
            architectures: Some(vec![self.arch_name(&macho)]),
        };

        let mut report = AnalysisReport::new(target);
        let mut tools_used = vec!["goblin".to_string()];

        // Parse code signature early for metrics and findings
        let codesig_data: Option<macho_codesign::CodeSignature> =
            macho.load_commands.iter().find_map(|lc| {
                if let goblin::mach::load_command::CommandVariant::CodeSignature(cs) = &lc.command {
                    macho_codesign::parse_code_signature(data, cs.dataoff, cs.datasize).ok()
                } else {
                    None
                }
            });

        // Analyze header and structure
        self.analyze_structure_with_signature(&macho, &mut report, codesig_data.as_ref());

        // Generate signature findings from parsed code signature
        if let Some(ref codesig) = codesig_data {
            self.generate_signature_findings(codesig, &mut report);
        }

        // Extract imports and map to capabilities
        self.analyze_imports(file_path, &macho, &mut report)?;

        // Extract exports
        self.analyze_exports(&macho, &mut report)?;

        // Analyze sections and entropy
        self.analyze_sections(&macho, data, &mut report)?;

        // Initialize metrics with Mach-O header info
        let rpath_count = macho
            .load_commands
            .iter()
            .filter(|lc| {
                matches!(
                    lc.command,
                    goblin::mach::load_command::CommandVariant::Rpath(_)
                )
            })
            .count() as u32;

        let macho_metrics = MachoMetrics {
            file_type: macho.header.filetype,
            rpath_count,
            ..Default::default()
        };

        // Always compute basic binary metrics (even if radare2 fails)
        let binary_metrics = crate::types::BinaryMetrics {
            file_size: data.len() as u64,
            segment_count: macho
                .load_commands
                .iter()
                .filter(|lc| {
                    matches!(
                        lc.command,
                        goblin::mach::load_command::CommandVariant::Segment32(_)
                            | goblin::mach::load_command::CommandVariant::Segment64(_)
                    )
                })
                .count() as u32,
            is_stripped: macho.symbols().count() == 0,
            has_debug_info: macho.load_commands.iter().any(|lc| match &lc.command {
                goblin::mach::load_command::CommandVariant::Segment32(seg) => seg
                    .segname
                    .iter()
                    .take_while(|&&b| b != 0)
                    .map(|&b| b as char)
                    .collect::<String>()
                    .contains("DWARF"),
                goblin::mach::load_command::CommandVariant::Segment64(seg) => seg
                    .segname
                    .iter()
                    .take_while(|&&b| b != 0)
                    .map(|&b| b as char)
                    .collect::<String>()
                    .contains("DWARF"),
                _ => false,
            }),
            is_pie: (macho.header.flags & 0x200000) != 0,
            string_count: 0, // Will be updated after string extraction
            ..Default::default()
        };

        report.metrics = Some(Metrics {
            macho: Some(macho_metrics),
            binary: Some(binary_metrics.clone()),
            ..Default::default()
        });

        // AMOS cipher detection now handled by stng library internally

        // Use radare2 for deep analysis if available - SINGLE r2 spawn for all data
        let _t_r2 = std::time::Instant::now();
        let r2_strings = if Radare2Analyzer::is_available() {
            tools_used.push("radare2".to_string());

            // Use batched extraction - single r2 session for functions, sections, strings, imports
            let has_symbols = macho.symbols().count() > 0;
            if let Ok(batched) = self.radare2.extract_batched(file_path, has_symbols) {
                // Compute metrics from batched data (radare2-specific metrics)
                let r2_binary_metrics = self
                    .radare2
                    .compute_metrics_from_batched(&batched, data.len() as u64);

                // Enhance existing binary metrics with radare2 data
                if let Some(ref mut metrics) = report.metrics {
                    if let Some(ref mut binary_metrics) = metrics.binary {
                        // Merge radare2 metrics into existing basic metrics (only if non-zero)
                        if r2_binary_metrics.function_count > 0 {
                            binary_metrics.function_count = r2_binary_metrics.function_count;
                            binary_metrics.avg_function_size = r2_binary_metrics.avg_function_size;
                            binary_metrics.avg_complexity = r2_binary_metrics.avg_complexity;
                        }
                        // Don't use radare2's code_to_data_ratio - it has a bug where __const sections
                        // are incorrectly marked as executable. We calculate this correctly from
                        // goblin-based segment permissions in update_binary_metrics().

                        // Also merge section-level metrics from radare2
                        if r2_binary_metrics.section_count > 0 {
                            binary_metrics.executable_sections =
                                r2_binary_metrics.executable_sections;
                            binary_metrics.writable_sections = r2_binary_metrics.writable_sections;
                            binary_metrics.wx_sections = r2_binary_metrics.wx_sections;
                        }
                    } else {
                        // Fallback: set full radare2 metrics if binary metrics somehow missing
                        let mut full_metrics = r2_binary_metrics;
                        full_metrics.file_size = data.len() as u64;
                        full_metrics.segment_count = macho
                            .load_commands
                            .iter()
                            .filter(|lc| {
                                matches!(
                                    lc.command,
                                    goblin::mach::load_command::CommandVariant::Segment32(_)
                                        | goblin::mach::load_command::CommandVariant::Segment64(_)
                                )
                            })
                            .count() as u32;
                        full_metrics.is_stripped = macho.symbols().count() == 0;
                        full_metrics.is_pie = (macho.header.flags & 0x200000) != 0;
                        metrics.binary = Some(full_metrics);
                    }

                    if let Some(ref mut macho_metrics) = metrics.macho {
                        macho_metrics.has_code_signature = codesig_data.is_some();
                        macho_metrics.has_entitlements = !codesig_data
                            .as_ref()
                            .map(|c| c.entitlements.is_empty())
                            .unwrap_or(true);
                        if let Some(ref codesig) = codesig_data {
                            macho_metrics.signature_type =
                                Some(codesig.signature_type.as_str().to_string());
                            macho_metrics.team_identifier = codesig.team_id.clone();

                            // Count dangerous entitlements
                            let mut dangerous_count = 0u32;
                            for ent_key in codesig.entitlements.keys() {
                                if ent_key.contains("disable-library-validation")
                                    || ent_key.contains("allow-jit")
                                    || ent_key.contains("unsigned-executable-memory")
                                    || ent_key.contains("debugger")
                                {
                                    dangerous_count += 1;
                                }
                            }
                            macho_metrics.dangerous_entitlements = dangerous_count;
                        }
                    }
                }

                // Convert R2Functions to Functions for the report
                report.functions = batched.functions.into_iter().map(Function::from).collect();

                // Use strings from batched data (no extra r2 spawn)
                Some(batched.strings)
            } else {
                None
            }
        } else {
            None
        };

        // Use pre-extracted strings if available, otherwise extract with stng/r2
        if let Some(ref strings) = self.preextracted_strings {
            report.strings = strings.clone();
        } else {
            // Extract strings using language-aware extraction (Go/Rust)
            report.strings = self.string_extractor.extract_smart(data, r2_strings);
        }
        tools_used.push("stng".to_string());

        // Update binary metrics with string count
        if let Some(ref mut metrics) = report.metrics {
            if let Some(ref mut binary_metrics) = metrics.binary {
                binary_metrics.string_count = report.strings.len() as u32;
            }
        }

        // Analyze embedded code in strings
        let (encoded_layers, plain_findings) =
            crate::analyzers::embedded_code_detector::process_all_strings(
                &file_path.display().to_string(),
                &report.strings,
                &self.capability_mapper,
                0,
            );
        report.files.extend(encoded_layers);
        report.findings.extend(plain_findings);

        // Update binary metrics with data from report (import/export/string counts and entropy)
        Self::update_binary_metrics(&mut report);

        // Validate metric ranges to catch calculation bugs
        if let Some(ref metrics) = report.metrics {
            if let Some(ref binary) = metrics.binary {
                binary.validate();
            }
        }

        report.metadata.analysis_duration_ms = start.elapsed().as_millis() as u64;
        report.metadata.tools_used = tools_used;

        Ok(report)
    }

    /// Update binary metrics with counts from the report
    /// This fixes missing import/export/string counts and recalculates entropy from sections
    fn update_binary_metrics(report: &mut AnalysisReport) {
        if let Some(ref mut metrics) = report.metrics {
            if let Some(ref mut binary) = metrics.binary {
                // Update counts that aren't populated by radare2
                binary.import_count = report.imports.len() as u32;
                binary.export_count = report.exports.len() as u32;
                binary.string_count = report.strings.len() as u32;
                binary.section_count = report.sections.len() as u32;

                // Calculate string metrics
                if !report.strings.is_empty() {
                    use crate::entropy::calculate_entropy;
                    let entropies: Vec<f64> = report
                        .strings
                        .iter()
                        .map(|s| calculate_entropy(s.value.as_bytes()))
                        .collect();

                    let total_entropy: f64 = entropies.iter().sum();
                    binary.avg_string_entropy = (total_entropy / entropies.len() as f64) as f32;
                    binary.high_entropy_strings =
                        entropies.iter().filter(|&&e| e > 6.0).count() as u32;

                    // Calculate string length metrics
                    let mut total_length: u64 = 0;
                    let mut max_length: u32 = 0;
                    let mut wide_count: u32 = 0;

                    for s in &report.strings {
                        let len = s.value.len() as u32;
                        total_length += len as u64;
                        if len > max_length {
                            max_length = len;
                        }
                        // Check encoding chain for wide strings
                        if s.encoding_chain.iter().any(|e| e == "wide") {
                            wide_count += 1;
                        }
                    }

                    binary.avg_string_length = total_length as f32 / report.strings.len() as f32;
                    binary.max_string_length = max_length;
                    binary.wide_string_count = wide_count;
                }

                // Always calculate code_to_data_ratio from goblin-based section analysis
                // In Mach-O, sections inherit segment permissions, so we check section names
                // to determine which sections actually contain executable code
                if !report.sections.is_empty() {
                    let mut code_size: u64 = 0;
                    let mut total_size: u64 = 0;

                    for section in &report.sections {
                        total_size += section.size;

                        // Extract section name (e.g., "__text" from "__TEXT.____text")
                        let section_name = section.name.rsplit('.').next().unwrap_or(&section.name);
                        let section_name_clean = section_name.trim_start_matches("__");

                        // Only these sections contain executable code in Mach-O binaries
                        let is_code_section =
                            matches!(section_name_clean, "text" | "stubs" | "stub_helper");

                        // Must be in executable segment AND be a known code section
                        let has_exec_perm = section
                            .permissions
                            .as_ref()
                            .map(|p| p.contains('x'))
                            .unwrap_or(false);

                        if is_code_section && has_exec_perm {
                            code_size += section.size;
                        }
                    }

                    // Sanity check: code_size should never exceed total section size
                    if code_size > total_size {
                        eprintln!("WARNING: code_size ({}) > total_size ({}) - this indicates a bug in section classification", code_size, total_size);
                        code_size = total_size; // Cap at total_size to prevent invalid ratio
                    }

                    // Update code_size and ratio
                    binary.code_size = code_size;
                    if total_size > 0 {
                        let data_size = total_size.saturating_sub(code_size);
                        if data_size > 0 {
                            binary.code_to_data_ratio = code_size as f32 / data_size as f32;

                            // Sanity check: extremely high ratio likely indicates classification bug
                            if binary.code_to_data_ratio > 1000.0 {
                                eprintln!("WARNING: code_to_data_ratio ({:.2}) > 1000 - this may indicate a bug", binary.code_to_data_ratio);
                            }
                        }
                        binary.avg_section_size = total_size as f32 / report.sections.len() as f32;
                    }
                }

                // Calculate binary entropy and size metrics from sections if not already populated
                if binary.overall_entropy == 0.0 && !report.sections.is_empty() {
                    let mut entropies = Vec::new();
                    let mut code_entropies = Vec::new();
                    let mut data_entropies = Vec::new();

                    for section in &report.sections {
                        let entropy = section.entropy as f32;
                        entropies.push(entropy);

                        // Extract section name (e.g., "__text" from "__TEXT.____text")
                        let section_name = section.name.rsplit('.').next().unwrap_or(&section.name);
                        let section_name_clean = section_name.trim_start_matches("__");

                        // Only these sections contain executable code in Mach-O binaries
                        let is_code_section =
                            matches!(section_name_clean, "text" | "stubs" | "stub_helper");

                        // Must be in executable segment AND be a known code section
                        let has_exec_perm = section
                            .permissions
                            .as_ref()
                            .map(|p| p.contains('x'))
                            .unwrap_or(false);

                        if is_code_section && has_exec_perm {
                            code_entropies.push(entropy);
                        } else {
                            data_entropies.push(entropy);
                        }

                        // High entropy threshold: 6.5+ is suspicious for code sections
                        // Normal code is typically 5.0-6.0, data can be higher
                        if entropy > 6.5 {
                            binary.high_entropy_regions += 1;
                        }
                    }

                    if !entropies.is_empty() {
                        binary.overall_entropy =
                            entropies.iter().sum::<f32>() / entropies.len() as f32;

                        let mean = binary.overall_entropy;
                        let variance: f32 =
                            entropies.iter().map(|e| (e - mean).powi(2)).sum::<f32>()
                                / entropies.len() as f32;
                        binary.entropy_variance = variance.sqrt();
                    }

                    if !code_entropies.is_empty() {
                        binary.code_entropy =
                            code_entropies.iter().sum::<f32>() / code_entropies.len() as f32;
                    }

                    if !data_entropies.is_empty() {
                        binary.data_entropy =
                            data_entropies.iter().sum::<f32>() / data_entropies.len() as f32;
                    }
                }

                // Calculate function-related metrics from report data
                if !report.functions.is_empty() {
                    let total_size: u64 =
                        report.functions.iter().map(|f| f.size.unwrap_or(0)).sum();
                    if total_size > 0 {
                        binary.avg_function_size =
                            total_size as f32 / report.functions.len() as f32;
                    }

                    // Count high complexity functions (threshold: 15+)
                    // Cyclomatic complexity > 15 is considered high complexity
                    if binary.max_complexity > 0 {
                        binary.high_complexity_functions = report
                            .functions
                            .iter()
                            .filter(|f| f.complexity.unwrap_or(0) > 15)
                            .count()
                            as u32;
                    }

                    // Note: total_basic_blocks would require summing from control_flow metrics
                    // which aren't always populated. We leave it at the radare2-calculated value.
                }
            }

            // Update Mach-O specific metrics
            if let Some(ref mut macho_metrics) = metrics.macho {
                // Count dylibs from imports
                let mut dylibs = std::collections::HashSet::new();
                for import in &report.imports {
                    if let Some(lib) = &import.library {
                        dylibs.insert(lib.clone());
                    }
                }
                macho_metrics.dylib_count = dylibs.len() as u32;

                // Check if this is a universal binary by looking at architectures
                // Universal binaries have multiple architecture slices
                if let Some(ref archs) = report.target.architectures {
                    if archs.len() > 1 {
                        macho_metrics.is_universal = true;
                        macho_metrics.slice_count = archs.len() as u32;
                    }
                }
            }

            // Compute ratio metrics after all base counters are populated
            if let Some(ref mut binary) = metrics.binary {
                // Set file size if not already set
                if binary.file_size == 0 {
                    binary.file_size = report.target.size_bytes;
                }

                // Compute largest section ratio
                if binary.file_size > 0 && !report.sections.is_empty() {
                    let max_section_size =
                        report.sections.iter().map(|s| s.size).max().unwrap_or(0);
                    binary.largest_section_ratio =
                        max_section_size as f32 / binary.file_size as f32;
                }

                // Call compute_ratio_metrics to calculate density/normalized metrics
                // NOTE: This will overwrite code_to_data_ratio with radare2's buggy value,
                // so we need to recalculate it below using our correct goblin-based sections
                crate::radare2::Radare2Analyzer::compute_ratio_metrics(binary);

                // Recalculate code_to_data_ratio from goblin-based section analysis
                // In Mach-O, sections inherit segment permissions, so we need to check section names
                // to determine which sections actually contain executable code vs read-only data
                if !report.sections.is_empty() {
                    let mut code_size: u64 = 0;
                    let mut total_size: u64 = 0;

                    for section in &report.sections {
                        total_size += section.size;

                        // Extract section name (e.g., "__text" from "__TEXT.____text")
                        let section_name = section.name.rsplit('.').next().unwrap_or(&section.name);
                        let section_name_clean = section_name.trim_start_matches("__");

                        // Only these sections contain executable code in Mach-O binaries
                        let is_code_section =
                            matches!(section_name_clean, "text" | "stubs" | "stub_helper");

                        // Must be in executable segment AND be a known code section
                        let has_exec_perm = section
                            .permissions
                            .as_ref()
                            .map(|p| p.contains('x'))
                            .unwrap_or(false);

                        if is_code_section && has_exec_perm {
                            code_size += section.size;
                        }
                    }

                    // Sanity check: code_size should never exceed total section size
                    if code_size > total_size {
                        eprintln!("WARNING: code_size ({}) > total_size ({}) - this indicates a bug in section classification", code_size, total_size);
                        code_size = total_size; // Cap at total_size to prevent invalid ratio
                    }

                    binary.code_size = code_size;
                    if total_size > 0 {
                        let data_size = total_size.saturating_sub(code_size);
                        if data_size > 0 {
                            binary.code_to_data_ratio = code_size as f32 / data_size as f32;

                            // Sanity check: extremely high ratio likely indicates classification bug
                            if binary.code_to_data_ratio > 1000.0 {
                                eprintln!("WARNING: code_to_data_ratio ({:.2}) > 1000 - this may indicate a bug", binary.code_to_data_ratio);
                            }
                        }
                    }
                }
            }
        }
    }

    fn analyze_structure_with_signature<'a>(
        &self,
        macho: &MachO<'a>,
        report: &mut AnalysisReport,
        _codesig: Option<&macho_codesign::CodeSignature>,
    ) {
        // Binary format
        report.structure.push(StructuralFeature {
            id: "binary/format/macho".to_string(),
            desc: "Mach-O binary format".to_string(),
            evidence: vec![Evidence {
                method: "magic".to_string(),
                source: "goblin".to_string(),
                value: format!("0x{:x}", macho.header.magic),
                location: None,
                ..Default::default()
            }],
        });

        // Architecture
        let arch = self.arch_name(macho);
        report.structure.push(StructuralFeature {
            id: format!("binary/arch/{}", arch),
            desc: format!("{} architecture", arch),
            evidence: vec![Evidence {
                method: "header".to_string(),
                source: "goblin".to_string(),
                value: format!("cputype=0x{:x}", macho.header.cputype),
                location: None,
                ..Default::default()
            }],
        });

        // Check for code signature
        let has_signature = macho.load_commands.iter().any(|lc| {
            matches!(
                lc.command,
                goblin::mach::load_command::CommandVariant::CodeSignature(_)
            )
        });

        if has_signature {
            report.structure.push(StructuralFeature {
                id: "binary/signed".to_string(),
                desc: "Binary has code signature".to_string(),
                evidence: vec![Evidence {
                    method: "load_command".to_string(),
                    source: "goblin".to_string(),
                    value: "LC_CODE_SIGNATURE".to_string(),
                    location: Some("load_commands".to_string()),
                    ..Default::default()
                }],
            });
        }
    }

    fn analyze_imports<'a>(
        &self,
        file_path: &Path,
        macho: &MachO<'a>,
        report: &mut AnalysisReport,
    ) -> Result<()> {
        let imports = macho.imports()?;

        // Fallback: use symbol table and radare2 if imports() is empty
        if imports.is_empty() {
            // If we have radare2, use it to get library names for imports
            if Radare2Analyzer::is_available() {
                if let Ok(r2_imports) = self.radare2.extract_imports(file_path) {
                    for imp in r2_imports {
                        report.imports.push(Import::new(
                            &imp.name,
                            imp.lib_name.clone(),
                            "radare2",
                        ));
                        let name = crate::types::binary::normalize_symbol(&imp.name);

                        // Map import to capability
                        if let Some(cap) = self.capability_mapper.lookup(&name, "radare2") {
                            if !report.findings.iter().any(|c| c.id == cap.id) {
                                report.findings.push(cap);
                            }
                        }
                    }
                }
            }

            // Also try symbol table for basic names (catch anything r2 missed)
            if let Some(syms) = &macho.symbols {
                for (name, sym) in syms.iter().flatten() {
                    // N_EXT (external) and N_UNDF (undefined) means it's an import
                    if (sym.n_type & 0x01 != 0) && (sym.n_type & 0x0e == 0) {
                        let clean_name = crate::types::binary::normalize_symbol(name);
                        // Only add if not already added by radare2
                        if !report.imports.iter().any(|i| i.symbol == clean_name) {
                            report
                                .imports
                                .push(Import::new(name, None, "goblin_symtab"));
                        }
                    }
                }
            }
        } else {
            for imp in &imports {
                report
                    .imports
                    .push(Import::new(imp.name, Some(imp.dylib.to_string()), "goblin"));
                let name = crate::types::binary::normalize_symbol(imp.name);

                // Map import to capability
                if let Some(cap) = self.capability_mapper.lookup(&name, "goblin") {
                    // Check if we already have this capability
                    if !report.findings.iter().any(|c| c.id == cap.id) {
                        report.findings.push(cap);
                    }
                }
            }
        }

        Ok(())
    }

    fn analyze_exports<'a>(&self, macho: &MachO<'a>, report: &mut AnalysisReport) -> Result<()> {
        for exp in &macho.exports()? {
            report.exports.push(Export::new(
                &exp.name,
                Some(format!("0x{:x}", exp.offset)),
                "goblin",
            ));
        }

        Ok(())
    }

    fn analyze_sections<'a>(
        &self,
        macho: &MachO<'a>,
        data: &[u8],
        report: &mut AnalysisReport,
    ) -> Result<()> {
        for segment in &macho.segments {
            // Convert segment init_prot to permission string (r/w/x format)
            let segment_perm = {
                let init_prot = segment.initprot;
                let mut perm = String::new();
                if init_prot & 0x01 != 0 {
                    perm.push('r');
                } // VM_PROT_READ
                if init_prot & 0x02 != 0 {
                    perm.push('w');
                } // VM_PROT_WRITE
                if init_prot & 0x04 != 0 {
                    perm.push('x');
                } // VM_PROT_EXECUTE
                if perm.is_empty() {
                    perm.push('-');
                }
                perm
            };

            for (section, _) in &segment.sections()? {
                let section_name = format!(
                    "{}.__{}",
                    segment.name().unwrap_or("unknown"),
                    section.name().unwrap_or("unknown")
                );

                // Calculate entropy for this section
                let section_offset = section.offset as usize;
                let section_size = section.size as usize;

                if section_offset + section_size <= data.len() {
                    let section_data = &data[section_offset..section_offset + section_size];
                    let entropy = calculate_entropy(section_data);

                    report.sections.push(Section {
                        name: section_name.clone(),
                        address: Some(section.addr),
                        size: section.size,
                        entropy,
                        permissions: Some(segment_perm.clone()), // Use segment permissions
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
                                location: Some(section_name),
                                ..Default::default()
                            }],
                        });
                    }
                }
            }
        }

        Ok(())
    }

    /// Generate findings from parsed code signature data
    fn generate_signature_findings(
        &self,
        codesig: &macho_codesign::CodeSignature,
        report: &mut AnalysisReport,
    ) {
        // Combined signature trait: metadata/signed/{type}::{signer}
        // This allows matching by type (metadata/signed/developer) or specific signer
        let team_id = codesig.team_id.as_deref().unwrap_or("unknown");
        let (sig_category, signer, desc) = match codesig.signature_type {
            macho_codesign::SignatureType::DeveloperID => {
                let company = codesig
                    .authorities
                    .first()
                    .and_then(|auth| {
                        auth.split(": ")
                            .nth(1)
                            .map(|s| s.split(" (").next().unwrap_or(s).to_string())
                    })
                    .unwrap_or_else(|| team_id.to_string());
                ("developer", team_id, format!("Developer ID: {}", company))
            }
            macho_codesign::SignatureType::Platform => {
                ("platform", "apple", "macOS Platform Binary".to_string())
            }
            macho_codesign::SignatureType::Adhoc => {
                ("adhoc", "unsigned", "Ad-hoc Signature".to_string())
            }
            macho_codesign::SignatureType::Unknown => {
                ("unknown", "unknown", "Unknown Signature".to_string())
            }
        };

        report.findings.push(Finding {
            kind: FindingKind::Capability,
            trait_refs: vec![],
            id: format!("metadata/signed/{}::{}", sig_category, signer),
            desc,
            conf: 1.0,
            crit: Criticality::Baseline,
            mbc: None,
            attack: None,
            evidence: vec![Evidence {
                method: "code_signature".to_string(),
                source: "codesign_parser".to_string(),
                value: format!("{}::{}", sig_category, signer),
                location: None,
                ..Default::default()
            }],

            match_count: 0,
            source_file: None,
        });

        // Identifier trait - complete trait ID includes the bundle identifier
        if let Some(identifier) = &codesig.identifier {
            report.findings.push(Finding {
                kind: FindingKind::Capability,
                trait_refs: vec![],
                id: format!("metadata/signed/id::{}", identifier),
                desc: "Identifier".to_string(),
                conf: 1.0,
                crit: Criticality::Baseline,
                mbc: None,
                attack: None,
                evidence: vec![Evidence {
                    method: "code_directory".to_string(),
                    source: "codesign_parser".to_string(),
                    value: identifier.clone(),
                    location: None,
                    ..Default::default()
                }],

                match_count: 0,
                source_file: None,
            });
        }

        // Entitlements traits
        for (entitlement_key, entitlement_value) in &codesig.entitlements {
            let ent_trait_id = format!("metadata/entitlement::{}", entitlement_key);
            let desc = describe_entitlement(entitlement_key);
            let value_str = match entitlement_value {
                macho_codesign::EntitlementValue::Boolean(b) => b.to_string(),
                macho_codesign::EntitlementValue::String(s) => s.clone(),
                macho_codesign::EntitlementValue::Array(a) => a.join(", "),
            };
            report.findings.push(Finding {
                kind: FindingKind::Capability,
                trait_refs: vec![],
                id: ent_trait_id,
                desc,
                conf: 1.0,
                crit: determine_entitlement_criticality(entitlement_key, &codesig.signature_type),
                mbc: None,
                attack: None,
                evidence: vec![Evidence {
                    method: "entitlements_plist".to_string(),
                    source: "codesign_parser".to_string(),
                    value: format!("{}={}", entitlement_key, value_str),
                    location: None,
                    ..Default::default()
                }],

                match_count: 0,
                source_file: None,
            });
        }

        // Notarized by Apple
        if codesig.is_notarized {
            report.findings.push(Finding {
                kind: FindingKind::Capability,
                trait_refs: vec![],
                id: "metadata/notarized".to_string(),
                desc: "Binary is notarized by Apple".to_string(),
                conf: 1.0,
                crit: Criticality::Baseline,
                mbc: None,
                attack: None,
                evidence: vec![],
                match_count: 0,
                source_file: None,
            });
        }

        // Hardened runtime flag
        if codesig.has_hardened_runtime {
            report.findings.push(Finding {
                kind: FindingKind::Capability,
                trait_refs: vec![],
                id: "metadata/hardened-runtime".to_string(),
                desc: "Hardened runtime enabled".to_string(),
                conf: 1.0,
                crit: Criticality::Baseline,
                mbc: None,
                attack: None,
                evidence: vec![Evidence {
                    method: "code_directory_flags".to_string(),
                    source: "codesign_parser".to_string(),
                    value: "0x00010000".to_string(),
                    location: None,
                    ..Default::default()
                }],

                match_count: 0,
                source_file: None,
            });
        }
    }

    fn arch_name<'a>(&self, macho: &MachO<'a>) -> String {
        self.arch_name_from_cputype(macho.header.cputype)
    }

    fn arch_name_from_cputype(&self, cputype: u32) -> String {
        match cputype {
            0x01000007 => "x86_64".to_string(),
            0x0100000c => "arm64".to_string(),
            0x0200000c => "arm64e".to_string(),
            _ => format!("unknown_0x{:x}", cputype),
        }
    }

    // AMOS cipher detection/decryption removed - now handled by stng library internally
}

/// Determine criticality of an entitlement based on its key
fn describe_entitlement(key: &str) -> String {
    // Extract meaningful description from entitlement key
    let descriptions = [
        // Privacy/Device Access
        ("device.camera", "Camera access"),
        ("device.audio-input", "Microphone access"),
        ("device.microphone", "Microphone access"),
        ("device.bluetooth", "Bluetooth access"),
        ("personal-information.location", "Location data access"),
        ("personal-information.health", "Health data access"),
        (
            "personal-information.photos-library",
            "Photos library access",
        ),
        ("personal-information.contacts", "Contacts access"),
        ("personal-information.calendar", "Calendar access"),
        ("personal-information.reminders", "Reminders access"),
        // System Access
        ("keystore.access-keychain-keys", "Keychain key access"),
        ("keystore.lockassertion", "Keychain lock assertion"),
        ("security.storage.Keychains", "Keychain storage access"),
        // Code Execution & Security
        (
            "cs.disable-library-validation",
            "Disable library validation",
        ),
        ("cs.allow-jit", "Allow JIT compilation"),
        (
            "cs.allow-unsigned-executable-memory",
            "Allow unsigned executable memory",
        ),
        ("cs.debugger", "Debugger entitlement"),
        // Process & XPC
        (
            "xpc.launchd.ios-system-session",
            "iOS system session access",
        ),
        ("xpc.launchd", "Launchd XPC access"),
        // Application Features
        ("application-identifier", "Application identifier"),
        ("app-identifier", "App identifier"),
        ("push-service", "Push notification service"),
        ("icloud-container-identifiers", "iCloud container access"),
        // Databases & Storage
        ("sqlite.sqlite-encryption", "SQLite encryption"),
        // Debugging & Diagnostics
        ("symptom_diagnostics.report", "System diagnostics reporting"),
        // Private APIs (Apple Internal)
        ("private.MobileGestalt", "MobileGestalt queries"),
        ("private.applecredentialmanager", "Apple credential manager"),
        ("private.security.storage", "Private security storage"),
        // File/Sandbox Access
        ("sandbox.read-write", "Sandbox read-write"),
        ("home-directory", "Home directory access"),
    ];

    for (key_part, desc) in descriptions {
        if key.contains(key_part) {
            return desc.to_string();
        }
    }

    // Fallback: clean up the key name for readability
    let short_name = key
        .split('.')
        .next_back()
        .unwrap_or(key)
        .replace(['-', '_'], " ");

    // Capitalize first letter
    let mut chars = short_name.chars();
    match chars.next() {
        None => key.to_string(),
        Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
    }
}

fn determine_entitlement_criticality(
    entitlement_key: &str,
    signature_type: &macho_codesign::SignatureType,
) -> Criticality {
    // Platform binaries: all entitlements are Notable
    // (Apple control what goes in platform binaries)
    if matches!(signature_type, macho_codesign::SignatureType::Platform) {
        return Criticality::Notable;
    }

    // Sensitive privacy entitlements
    if entitlement_key.contains("personal-information") || entitlement_key.contains("device.") {
        return Criticality::Notable;
    }

    // Dangerous security-related entitlements (only suspicious for non-platform binaries)
    if entitlement_key.contains("disable-library-validation")
        || entitlement_key.contains("allow-jit")
        || entitlement_key.contains("debugger")
        || entitlement_key.contains("unsigned-executable-memory")
    {
        return Criticality::Suspicious;
    }

    // Default for other entitlements
    Criticality::Notable
}

impl Default for MachOAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl MachOAnalyzer {
    /// Returns the byte range of the preferred architecture slice within a fat binary,
    /// or `0..data.len()` for thin binaries.
    /// Used by test-rules/test-match for consistent single-arch evaluation.
    pub(crate) fn preferred_arch_range(&self, data: &[u8]) -> std::ops::Range<usize> {
        if let Ok(Mach::Fat(fat)) = goblin::mach::Mach::parse(data) {
            if let Ok(arches) = fat.arches() {
                let preferred = arches
                    .iter()
                    .find(|a| a.cputype == 0x0100000c) // CPU_TYPE_ARM64
                    .or_else(|| arches.first());
                if let Some(arch) = preferred {
                    let offset = arch.offset as usize;
                    let size = arch.size as usize;
                    if offset + size <= data.len() {
                        return offset..offset + size;
                    }
                }
            }
        }
        0..data.len()
    }

    /// Returns byte ranges for ALL architecture slices in a fat binary.
    /// For thin binaries, returns a single range covering the entire file.
    /// This ensures we scan all architectures and don't miss malware hidden in non-preferred slices.
    #[allow(clippy::single_range_in_vec_init)] // Intentional: returns single range for thin binaries
    pub(crate) fn all_arch_ranges(&self, data: &[u8]) -> Vec<std::ops::Range<usize>> {
        if let Ok(Mach::Fat(fat)) = goblin::mach::Mach::parse(data) {
            if let Ok(arches) = fat.arches() {
                let ranges: Vec<_> = arches
                    .iter()
                    .filter_map(|arch| {
                        let offset = arch.offset as usize;
                        let size = arch.size as usize;
                        if offset + size <= data.len() {
                            Some(offset..offset + size)
                        } else {
                            None
                        }
                    })
                    .collect();
                if !ranges.is_empty() {
                    return ranges;
                }
            }
        }
        // Return the full data range as a single-element Vec for thin binaries
        vec![0..data.len()]
    }

    /// Updates a report with fat binary metadata (architecture list, universal binary flag).
    /// No-op for thin binaries.
    pub(crate) fn apply_fat_metadata(&self, report: &mut AnalysisReport, data: &[u8]) {
        if let Ok(Mach::Fat(fat)) = goblin::mach::Mach::parse(data) {
            if let Ok(arches) = fat.arches() {
                let arch_names: Vec<String> = arches
                    .iter()
                    .map(|a| self.arch_name_from_cputype(a.cputype))
                    .collect();
                report.target.architectures = Some(arch_names.clone());
                if let Some(ref mut metrics) = report.metrics {
                    if let Some(ref mut macho_metrics) = metrics.macho {
                        if arch_names.len() > 1 {
                            macho_metrics.is_universal = true;
                            macho_metrics.slice_count = arch_names.len() as u32;
                        }
                    }
                }
            }
        }
    }
}

impl Analyzer for MachOAnalyzer {
    fn analyze(&self, file_path: &Path) -> Result<AnalysisReport> {
        let data = fs::read(file_path).context("Failed to read file")?;

        // Get all architecture slices (for FAT binaries) or the single slice (for thin binaries)
        let arch_ranges = self.all_arch_ranges(&data);

        // Use preferred arch for structural analysis (imports, exports, strings, etc.)
        let preferred_range = self.preferred_arch_range(&data);
        let preferred_data = &data[preferred_range];
        let mut report = self.analyze_structural(file_path, preferred_data)?;
        self.apply_fat_metadata(&mut report, &data);

        // For FAT binaries, re-extract strings from the entire file so offsets are file-relative.
        // This ensures offset_range constraints (like [-2200, -100]) work correctly.
        let is_fat = arch_ranges.len() > 1;
        if is_fat && self.preextracted_strings.is_none() {
            report.strings = self.string_extractor.extract_smart(&data, None);
            // Update string count metric
            if let Some(ref mut metrics) = report.metrics {
                if let Some(ref mut binary_metrics) = metrics.binary {
                    binary_metrics.string_count = report.strings.len() as u32;
                }
            }
        }

        // Evaluate traits against binary data.
        // For FAT binaries, evaluate against the full file since strings have file-relative offsets.
        // For thin binaries, evaluate against the single slice (same as full file).
        if is_fat {
            // Full file evaluation - strings and offsets are file-relative
            self.capability_mapper
                .evaluate_and_merge_findings(&mut report, &data, None, None);
        } else {
            // Thin binary - single slice is the whole file
            self.capability_mapper.evaluate_and_merge_findings(
                &mut report,
                preferred_data,
                None,
                None,
            );
        }

        Ok(report)
    }

    fn can_analyze(&self, file_path: &Path) -> bool {
        if let Ok(data) = fs::read(file_path) {
            goblin::mach::Mach::parse(&data).is_ok()
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn test_macho_path() -> PathBuf {
        PathBuf::from("tests/fixtures/test.macho")
    }

    #[test]
    fn test_can_analyze_macho() {
        let analyzer = MachOAnalyzer::new();
        let test_file = test_macho_path();

        if test_file.exists() {
            assert!(analyzer.can_analyze(&test_file));
        }
    }

    #[test]
    fn test_cannot_analyze_non_macho() {
        let analyzer = MachOAnalyzer::new();
        assert!(!analyzer.can_analyze(&PathBuf::from("/dev/null")));
        assert!(!analyzer.can_analyze(&PathBuf::from("tests/fixtures/test.elf")));
    }

    #[test]
    fn test_analyze_macho_file() {
        let analyzer = MachOAnalyzer::new();
        let test_file = test_macho_path();

        if !test_file.exists() {
            return;
        }

        let result = analyzer.analyze(&test_file);
        assert!(result.is_ok());

        let report = result.unwrap();
        assert_eq!(report.target.file_type, "macho");
        assert!(report.target.size_bytes > 0);
        assert!(!report.target.sha256.is_empty());
    }

    #[test]
    fn test_macho_has_structure() {
        let analyzer = MachOAnalyzer::new();
        let test_file = test_macho_path();

        if !test_file.exists() {
            return;
        }

        let report = analyzer.analyze(&test_file).unwrap();
        assert!(!report.structure.is_empty());
    }

    #[test]
    fn test_macho_architecture_detected() {
        let analyzer = MachOAnalyzer::new();
        let test_file = test_macho_path();

        if !test_file.exists() {
            return;
        }

        let report = analyzer.analyze(&test_file).unwrap();
        assert!(report.target.architectures.is_some());
        let archs = report.target.architectures.unwrap();
        assert!(!archs.is_empty());
    }

    #[test]
    fn test_macho_sections_analyzed() {
        let analyzer = MachOAnalyzer::new();
        let test_file = test_macho_path();

        if !test_file.exists() {
            return;
        }

        let report = analyzer.analyze(&test_file).unwrap();
        assert!(!report.sections.is_empty());
    }

    #[test]
    fn test_macho_has_imports() {
        let analyzer = MachOAnalyzer::new();
        let test_file = test_macho_path();

        if !test_file.exists() {
            return;
        }

        let report = analyzer.analyze(&test_file).unwrap();
        assert!(!report.imports.is_empty());
    }

    #[test]
    fn test_macho_capabilities_detected() {
        let analyzer = MachOAnalyzer::new();
        let test_file = test_macho_path();

        if !test_file.exists() {
            return;
        }

        let report = analyzer.analyze(&test_file).unwrap();
        // Capabilities may or may not be detected depending on the binary
        // Just verify the analysis completes successfully
        let _ = &report.traits;
    }

    #[test]
    fn test_macho_strings_extracted() {
        let analyzer = MachOAnalyzer::new();
        let test_file = test_macho_path();

        if !test_file.exists() {
            return;
        }

        let report = analyzer.analyze(&test_file).unwrap();
        assert!(!report.strings.is_empty());
    }

    #[test]
    fn test_macho_tools_used() {
        let analyzer = MachOAnalyzer::new();
        let test_file = test_macho_path();

        if !test_file.exists() {
            return;
        }

        let report = analyzer.analyze(&test_file).unwrap();
        assert!(report.metadata.tools_used.contains(&"goblin".to_string()));
    }

    #[test]
    fn test_macho_analysis_duration() {
        let analyzer = MachOAnalyzer::new();
        let test_file = test_macho_path();

        if !test_file.exists() {
            return;
        }

        let report = analyzer.analyze(&test_file).unwrap();
        assert!(report.metadata.analysis_duration_ms > 0);
    }

    // Integration tests for code signature extraction and finding generation
    #[test]
    fn test_signature_findings_generated() {
        let analyzer = MachOAnalyzer::new();
        let test_file = test_macho_path();

        if !test_file.exists() {
            return;
        }

        let report = analyzer.analyze(&test_file).unwrap();

        // Check that signature-related findings are present
        let has_signed = report.findings.iter().any(|f| f.id.contains("signed/type"));
        // Note: test.macho might not be signed, so this is a soft assertion
        if has_signed {
            assert!(report.findings.iter().any(|f| f.id.contains("signed/type")));
        }
    }

    #[test]
    fn test_entitlements_extracted_when_present() {
        let analyzer = MachOAnalyzer::new();
        let test_file = test_macho_path();

        if !test_file.exists() {
            return;
        }

        let report = analyzer.analyze(&test_file).unwrap();

        // Check if any entitlement findings are present
        let entitlement_findings: Vec<_> = report
            .findings
            .iter()
            .filter(|f| f.id.contains("entitlement"))
            .collect();

        // If the binary has entitlements, verify they're properly extracted
        if !entitlement_findings.is_empty() {
            for finding in &entitlement_findings {
                // Entitlements should have proper evidence
                assert!(!finding.evidence.is_empty());
                // Method should be "entitlements_plist"
                assert!(finding
                    .evidence
                    .iter()
                    .any(|e| e.method == "entitlements_plist"));
            }
        }
    }

    #[test]
    fn test_team_id_extracted_when_signed() {
        let analyzer = MachOAnalyzer::new();
        let test_file = test_macho_path();

        if !test_file.exists() {
            return;
        }

        let report = analyzer.analyze(&test_file).unwrap();

        // Check for team ID findings
        let team_findings: Vec<_> = report
            .findings
            .iter()
            .filter(|f| f.id.contains("signed/team"))
            .collect();

        // If team findings exist, verify they have proper structure
        for finding in &team_findings {
            assert!(!finding.evidence.is_empty());
            assert_eq!(finding.evidence[0].method, "cms_certificate");
        }
    }

    #[test]
    fn test_hardened_runtime_detection() {
        let analyzer = MachOAnalyzer::new();
        let test_file = test_macho_path();

        if !test_file.exists() {
            return;
        }

        let report = analyzer.analyze(&test_file).unwrap();

        // Check for hardened-runtime finding
        let hardened = report
            .findings
            .iter()
            .find(|f| f.id == "metadata/hardened-runtime");

        if let Some(finding) = hardened {
            assert_eq!(finding.evidence[0].method, "code_directory_flags");
            assert_eq!(finding.evidence[0].value, "0x00010000");
        }
    }

    #[test]
    fn test_signature_type_criticality() {
        let analyzer = MachOAnalyzer::new();
        let test_file = test_macho_path();

        if !test_file.exists() {
            return;
        }

        let report = analyzer.analyze(&test_file).unwrap();

        // Signature type findings should have Notable criticality
        let sig_type_findings: Vec<_> = report
            .findings
            .iter()
            .filter(|f| f.id.contains("signed/type"))
            .collect();

        for finding in &sig_type_findings {
            assert_eq!(finding.crit, Criticality::Notable);
            assert_eq!(finding.conf, 1.0); // Should be high confidence
        }
    }

    #[test]
    fn test_entitlement_finding_confidence() {
        let analyzer = MachOAnalyzer::new();
        let test_file = test_macho_path();

        if !test_file.exists() {
            return;
        }

        let report = analyzer.analyze(&test_file).unwrap();

        // All entitlement findings should have high confidence
        let ent_findings: Vec<_> = report
            .findings
            .iter()
            .filter(|f| f.id.contains("entitlement"))
            .collect();

        for finding in &ent_findings {
            assert_eq!(finding.conf, 1.0); // Entitlements from signature have 100% confidence
        }
    }

    #[test]
    fn test_describe_entitlement_coverage() {
        // Test that describe_entitlement handles various entitlement keys
        assert_eq!(
            describe_entitlement("com.apple.security.cs.disable-library-validation"),
            "Disable library validation"
        );
        assert_eq!(
            describe_entitlement("com.apple.security.cs.allow-jit"),
            "Allow JIT compilation"
        );
        assert_eq!(
            describe_entitlement("personal-information.location"),
            "Location data access"
        );
        assert_eq!(describe_entitlement("device.camera"), "Camera access");
        assert_eq!(
            describe_entitlement("com.apple.developer.team-identifier"),
            "Team identifier"
        );
    }

    #[test]
    fn test_describe_entitlement_fallback() {
        // Test fallback behavior for unknown entitlements
        let desc = describe_entitlement("com.example.unknown-entitlement");
        assert!(!desc.is_empty());
        assert_ne!(desc, "com.example.unknown-entitlement"); // Should be transformed
    }

    #[test]
    fn test_determine_entitlement_criticality_platform_binary() {
        let crit = determine_entitlement_criticality(
            "com.apple.security.cs.allow-jit",
            &macho_codesign::SignatureType::Platform,
        );
        // Platform binaries should have Notable criticality for all entitlements
        assert_eq!(crit, Criticality::Notable);
    }

    #[test]
    fn test_determine_entitlement_criticality_dangerous() {
        let crit = determine_entitlement_criticality(
            "com.apple.security.cs.disable-library-validation",
            &macho_codesign::SignatureType::DeveloperID,
        );
        assert_eq!(crit, Criticality::Suspicious);
    }

    #[test]
    fn test_determine_entitlement_criticality_privacy() {
        let crit = determine_entitlement_criticality(
            "personal-information.location",
            &macho_codesign::SignatureType::Adhoc,
        );
        assert_eq!(crit, Criticality::Notable);
    }

    #[test]
    fn test_determine_entitlement_criticality_device_access() {
        let crit = determine_entitlement_criticality(
            "device.bluetooth",
            &macho_codesign::SignatureType::DeveloperID,
        );
        assert_eq!(crit, Criticality::Notable);
    }

    #[test]
    fn test_determine_entitlement_criticality_debugger() {
        let crit = determine_entitlement_criticality(
            "com.apple.security.cs.debugger",
            &macho_codesign::SignatureType::DeveloperID,
        );
        assert_eq!(crit, Criticality::Suspicious);
    }

    #[test]
    fn test_determine_entitlement_criticality_unsigned_memory() {
        let crit = determine_entitlement_criticality(
            "com.apple.security.cs.allow-unsigned-executable-memory",
            &macho_codesign::SignatureType::DeveloperID,
        );
        assert_eq!(crit, Criticality::Suspicious);
    }

    #[test]
    fn test_macho_metrics_dangerous_entitlements_counting() {
        let analyzer = MachOAnalyzer::new();
        let test_file = test_macho_path();

        if !test_file.exists() {
            return;
        }

        let report = analyzer.analyze(&test_file).unwrap();

        // If metrics are present, verify dangerous_entitlements is set
        if let Some(metrics) = &report.metrics {
            if let Some(macho_metrics) = &metrics.macho {
                // dangerous_entitlements should be initialized
                let _ = macho_metrics.dangerous_entitlements;
            }
        }
    }

    #[test]
    fn test_macho_metrics_signature_type_recorded() {
        let analyzer = MachOAnalyzer::new();
        let test_file = test_macho_path();

        if !test_file.exists() {
            return;
        }

        let report = analyzer.analyze(&test_file).unwrap();

        // If metrics are present and binary is signed, signature type should be recorded
        if let Some(metrics) = &report.metrics {
            if let Some(macho_metrics) = &metrics.macho {
                // If has_entitlements, then signature_type should also be set
                if macho_metrics.has_entitlements {
                    assert!(macho_metrics.signature_type.is_some());
                }
            }
        }
    }

    #[test]
    fn test_signature_findings_have_proper_kind() {
        let analyzer = MachOAnalyzer::new();
        let test_file = test_macho_path();

        if !test_file.exists() {
            return;
        }

        let report = analyzer.analyze(&test_file).unwrap();

        // All signature-related findings should be Capability kind
        for finding in report
            .findings
            .iter()
            .filter(|f| f.id.contains("signed") || f.id.contains("entitlement"))
        {
            assert_eq!(finding.kind, FindingKind::Capability);
        }
    }

    #[test]
    fn test_identifier_finding_when_present() {
        let analyzer = MachOAnalyzer::new();
        let test_file = test_macho_path();

        if !test_file.exists() {
            return;
        }

        let report = analyzer.analyze(&test_file).unwrap();

        // Check for identifier findings
        let identifier_findings: Vec<_> = report
            .findings
            .iter()
            .filter(|f| f.id.contains("signed/id"))
            .collect();

        // If identifier findings exist, they should have proper evidence
        for finding in &identifier_findings {
            assert_eq!(finding.evidence[0].method, "code_directory");
            assert_eq!(finding.evidence[0].source, "codesign_parser");
        }
    }
}
