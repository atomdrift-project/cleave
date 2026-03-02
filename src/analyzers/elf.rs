//! ELF binary analyzer for Linux executables.
#![allow(clippy::unwrap_used, clippy::expect_used)]
//!
//! Analyzes ELF binaries using radare2/rizin and string extraction.

use crate::analyzers::{AnalysisInput, Analyzer};
use crate::capabilities::CapabilityMapper;
use crate::entropy::{calculate_entropy, EntropyLevel};
use crate::radare2::Radare2Analyzer;
use crate::strings::StringExtractor;
use crate::types::binary_metrics::ElfMetrics;
use crate::types::*;
use anyhow::{Context, Result};
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
}

impl ElfAnalyzer {
    /// Creates a new ELF analyzer with default configuration
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

    /// Core ELF analysis logic.
    ///
    /// If `stng_strings` is provided, uses those directly (avoids redundant extraction).
    /// Otherwise falls back to `self.preextracted_strings` or extracts with stng.
    fn analyze_elf_core(
        &self,
        file_path: &Path,
        data: &[u8],
        stng_strings: Option<&[stng::ExtractedString]>,
    ) -> AnalysisReport {
        let start = std::time::Instant::now();
        let _t_sha = std::time::Instant::now();
        let sha256 = crate::analyzers::utils::calculate_sha256(data);

        // Create target info with default/empty values for fields that require parsing
        let target = TargetInfo {
            path: file_path.display().to_string(),
            file_type: "elf".to_string(),
            size_bytes: data.len() as u64,
            sha256,
            architectures: None,
        };

        let mut report = AnalysisReport::new(target);
        let mut tools_used = vec![];

        // Attempt to parse with goblin
        let mut elf_metrics_opt = None;
        let mut goblin_code_size: Option<u64> = None;
        let mut has_symbols = false; // set below from goblin parse
        match Elf::parse(data) {
            Ok(elf) => {
                tools_used.push("goblin".to_string());

                // Update architecture now that we have parsed the header
                report.target.architectures = Some(vec![self.arch_name(&elf)]);

                // Compute ELF-specific metrics
                elf_metrics_opt = Some(self.compute_elf_metrics(&elf));
                has_symbols = !elf.syms.is_empty();

                // Calculate code_size from goblin section flags (more accurate than radare2)
                goblin_code_size = Some(self.compute_code_size(&elf));

                // Analyze header and structure
                self.analyze_structure(&elf, &mut report);

                // Extract dynamic symbols and map to capabilities
                self.analyze_dynamic_symbols(&elf, data, &mut report);

                // Analyze sections and entropy
                self.analyze_sections(&elf, data, &mut report);
            }
            Err(e) => {
                // Parsing failed - this is a strong indicator of malformed/hostile binary
                report.findings.push(Finding {
                    kind: FindingKind::Structural,
                    id: "anti-analysis/malformed/elf-header".to_string(),
                    desc: format!("Malformed ELF header or section headers: {}", e),
                    conf: 1.0,
                    crit: Criticality::Hostile,
                    mbc: Some("B0001".to_string()), // Defense Evasion: Software Packing/Obfuscation
                    attack: Some("T1027".to_string()), // Obfuscated Files or Information
                    evidence: vec![],
                    match_count: 0,
                    trait_refs: vec![],

                    source_file: None,
                });

                report
                    .metadata
                    .errors
                    .push(format!("ELF parse error: {}", e));
            }
        }

        // Use radare2 for deep analysis if available - SINGLE r2 spawn for all data
        let r2_strings = if Radare2Analyzer::is_available() {
            tools_used.push("radare2".to_string());

            // Use batched extraction - single r2 session for functions, sections, strings, imports
            if let Ok(batched) = self.radare2.extract_batched(file_path, has_symbols) {
                // Check if rizin timed out - add anti-analysis finding
                if batched.timed_out {
                    report.findings.push(Finding {
                        kind: FindingKind::Capability,
                        id: "anti-analysis/evasion/analysis-resistant".to_string(),
                        desc: "Binary resistant to automated analysis (rizin timeout)".to_string(),
                        conf: 0.8,
                        crit: Criticality::Suspicious,
                        mbc: Some("B0003".to_string()), // Defense Evasion: Anti-Analysis
                        attack: Some("T1027".to_string()), // Obfuscated Files or Information
                        evidence: vec![Evidence {
                            method: "timeout".to_string(),
                            source: "rizin".to_string(),
                            value: "Analysis timed out after 60 seconds".to_string(),
                            ..Default::default()
                        }],
                        match_count: 0,
                        trait_refs: vec![],
                        source_file: None,
                    });
                }

                // Compute metrics from batched data
                let mut binary_metrics = self
                    .radare2
                    .compute_metrics_from_batched(&batched, data.len() as u64);

                // Override code_size with goblin-based calculation (more accurate)
                // In ELF, only sections with SHF_EXECINSTR flag contain executable code
                if let Some(mut code_size) = goblin_code_size {
                    // Sanity check: code_size should never exceed file size
                    if code_size > binary_metrics.file_size {
                        eprintln!("WARNING: code_size ({}) > file_size ({}) - this indicates a bug in section classification", code_size, binary_metrics.file_size);
                        code_size = binary_metrics.file_size; // Cap at file_size to prevent invalid ratio
                    }

                    binary_metrics.code_size = code_size;

                    // Recalculate code_to_data_ratio with correct code_size
                    if binary_metrics.file_size > 0 {
                        let data_size = binary_metrics.file_size.saturating_sub(code_size);
                        if data_size > 0 {
                            binary_metrics.code_to_data_ratio = code_size as f32 / data_size as f32;

                            // Sanity check: extremely high ratio likely indicates classification bug
                            if binary_metrics.code_to_data_ratio > 1000.0 {
                                eprintln!("WARNING: code_to_data_ratio ({:.2}) > 1000 - this may indicate a bug", binary_metrics.code_to_data_ratio);
                            }
                        }
                    }

                    // Recalculate density metrics that depend on code_size
                    let code_kb = code_size as f32 / 1024.0;
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
                            binary_metrics.avg_complexity * 1024.0 / code_size as f32;
                    }
                }

                // Use ELF metrics computed from goblin (or default if parsing failed)
                let elf_metrics = elf_metrics_opt.unwrap_or_default();

                report.metrics = Some(Metrics {
                    binary: Some(binary_metrics),
                    elf: Some(elf_metrics),
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
                None
            }
        } else {
            None
        };

        // Use strings in order of preference:
        // 1. stng_strings parameter (from AnalysisInput - avoids redundant extraction)
        // 2. self.preextracted_strings (legacy builder pattern)
        // 3. Extract fresh with stng/r2
        let _t_stng = std::time::Instant::now();
        if let Some(strings) = stng_strings {
            report.strings = self.string_extractor.convert_stng_strings(strings);
        } else if let Some(ref strings) = self.preextracted_strings {
            report.strings = strings.clone();
        } else {
            // Extract strings using language-aware extraction (Go/Rust)
            report.strings = self.string_extractor.extract_smart(data, r2_strings);
        }
        tools_used.push("stng".to_string());

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

        // Validate metric ranges to catch calculation bugs
        if let Some(ref metrics) = report.metrics {
            if let Some(ref binary) = metrics.binary {
                binary.validate();
            }
        }

        report.metadata.analysis_duration_ms = start.elapsed().as_millis() as u64;
        report.metadata.tools_used = tools_used;

        // Free excess vector capacity to reduce memory footprint
        report.shrink_to_fit();

        report
    }

    fn analyze_structure<'a>(&self, elf: &Elf<'a>, report: &mut AnalysisReport) {
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
    }

    fn analyze_dynamic_symbols<'a>(
        &self,
        elf: &Elf<'a>,
        _data: &[u8],
        report: &mut AnalysisReport,
    ) {
        // Analyze dynamic symbols (imports)
        for dynsym in &elf.dynsyms {
            if let Some(name) = elf.dynstrtab.get_at(dynsym.st_name) {
                // Add to imports
                report.imports.push(Import::new(name, None, "goblin"));

                // Check for IFUNC (LOOS type 10) - highly relevant for supply chain hijacks
                if dynsym.st_type() == 10 {
                    report.findings.push(Finding {
                        kind: FindingKind::Capability,
                        id: "feat/binary/elf/ifunc".to_string(),
                        desc: format!("ELF IFUNC resolver: {}", name),
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

                // Map to capability
                if let Some(cap) = self.capability_mapper.lookup(name, "goblin") {
                    if !report.findings.iter().any(|c| c.id == cap.id) {
                        report.findings.push(cap);
                    }
                }
            }
        }

        // Analyze regular symbols for exports
        for sym in &elf.syms {
            let st_type = sym.st_type();
            if sym.st_bind() == goblin::elf::sym::STB_GLOBAL
                && (st_type == goblin::elf::sym::STT_FUNC || st_type == 10)
            {
                if let Some(name) = elf.strtab.get_at(sym.st_name) {
                    let clean_name = crate::types::binary::normalize_symbol(name);
                    report.exports.push(Export::new(
                        name,
                        Some(format!("{:#x}", sym.st_value)),
                        "goblin",
                    ));

                    // Also flag IFUNC in regular symbols
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
        match elf.header.e_machine {
            goblin::elf::header::EM_X86_64 => "x86_64".to_string(),
            goblin::elf::header::EM_386 => "i386".to_string(),
            goblin::elf::header::EM_AARCH64 => "aarch64".to_string(),
            goblin::elf::header::EM_ARM => "arm".to_string(),
            goblin::elf::header::EM_RISCV => "riscv".to_string(),
            _ => format!("unknown_{}", elf.header.e_machine),
        }
    }
    /// Compute ELF-specific metrics from parsed ELF binary
    fn compute_elf_metrics<'a>(&self, elf: &Elf<'a>) -> ElfMetrics {
        use goblin::elf::dynamic::*;
        use goblin::elf::program_header::*;
        use goblin::elf::sym::STB_LOCAL;

        let mut metrics = ElfMetrics {
            e_type: elf.header.e_type as u32,
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
                    _ => {}
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
    pub(crate) fn analyze_structural(&self, file_path: &Path, data: &[u8]) -> AnalysisReport {
        use crate::types::file_analysis::encode_upx_path;
        use crate::upx::{UPXDecompressor, UPXError};

        if !UPXDecompressor::is_upx_packed(data) {
            return self.analyze_elf_core(file_path, data, None);
        }

        // UPX-packed: structural analysis of packed binary first
        let mut report = self.analyze_elf_core(file_path, data, None);

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
                        let unpacked_report =
                            self.analyze_elf_core(temp_file.path(), &unpacked_data, None);

                        // Create separate FileAnalysis for unpacked layer
                        let unpacked_sha256 =
                            crate::analyzers::utils::calculate_sha256(&unpacked_data);
                        let virtual_path = encode_upx_path(&file_path.display().to_string());

                        let mut unpacked_file = unpacked_report.to_file_analysis(0, true);
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
        let mut report = self.analyze_elf_core(input.path, input.data, Some(input.strings));

        // Post-processing
        self.capability_mapper
            .evaluate_and_merge_findings(&mut report, input.data, None, None);
        crate::path_mapper::analyze_and_link_paths(&mut report);
        crate::env_mapper::analyze_and_link_env_vars(&mut report);
        Ok(report)
    }

    fn analyze(&self, file_path: &Path) -> Result<AnalysisReport> {
        let data = fs::read(file_path).context("Failed to read file")?;
        let mut report = self.analyze_structural(file_path, &data);
        self.capability_mapper
            .evaluate_and_merge_findings(&mut report, &data, None, None);
        crate::path_mapper::analyze_and_link_paths(&mut report);
        crate::env_mapper::analyze_and_link_env_vars(&mut report);
        Ok(report)
    }

    fn can_analyze(&self, file_path: &Path) -> bool {
        if let Ok(data) = fs::read(file_path) {
            goblin::elf::Elf::parse(&data).is_ok()
        } else {
            false
        }
    }
}

#[cfg(test)]
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
        // Duration can be 0 on fast systems where analysis completes in < 1ms
        // Just verify the field exists and was set (not the default u64::MAX or similar)
        assert!(report.metadata.analysis_duration_ms < 10000);
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

        let report = analyzer.analyze_structural(temp_file.path(), &upx_data);

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

        let report = analyzer.analyze_structural(temp_file.path(), &upx_data);

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

        let report = analyzer.analyze_structural(temp_file.path(), &elf_data);

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
            "/path/to/file.elf##upx@0"
        );

        // Test path with special characters
        assert_eq!(
            encode_upx_path("/tmp/test-file_v1.2.elf"),
            "/tmp/test-file_v1.2.elf##upx@0"
        );

        // Test path that already has archive delimiter
        assert_eq!(
            encode_upx_path("archive.zip!!inner.elf"),
            "archive.zip!!inner.elf##upx@0"
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
        assert_eq!(file.path, "/test/sample.elf##upx@0");
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

        let report = analyzer.analyze_structural(temp_file.path(), &upx_data);

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
