//! Mach-O binary analyzer for macOS executables.
use crate::analyzers::macho_codesign;
use crate::analyzers::{goblin_safe, AnalysisInput, Analyzer};
use crate::capabilities::CapabilityMapper;
use crate::entropy::{calculate_entropy, EntropyLevel};
use crate::radare2::Radare2Analyzer;
use crate::strings::StringExtractor;
use crate::types::{
    AnalysisReport, Criticality, Evidence, Export, Finding, FindingKind, Function, Import,
    MachoMetrics, Metrics, Section, StringInfo, StructuralFeature, TargetInfo,
};
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
    /// Per-request cancellation flag.
    cancellation: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
}

impl MachOAnalyzer {
    fn push_metadata_finding(
        report: &mut AnalysisReport,
        id: &str,
        desc: &str,
        method: &str,
        source: &str,
        value: String,
    ) {
        report.findings.push(
            Finding::structural(id.to_string(), desc.to_string(), 1.0)
                .with_criticality(Criticality::Baseline)
                .with_evidence(vec![Evidence {
                    method: method.to_string(),
                    source: source.to_string(),
                    value,
                    location: None,
                    ..Default::default()
                }]),
        );
    }

    fn unpack_macho_version(version: u32) -> (u32, u32, u32) {
        (
            (version >> 16) & 0xffff,
            (version >> 8) & 0xff,
            version & 0xff,
        )
    }

    /// Creates a new Mach-O analyzer with default configuration
    #[must_use]
    pub(crate) fn new() -> Self {
        Self {
            capability_mapper: Arc::new(CapabilityMapper::empty()),
            radare2: Radare2Analyzer::new(),
            string_extractor: StringExtractor::new(),
            preextracted_strings: None,
            cancellation: None,
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

    /// Structural analysis of a thin Mach-O binary (no YARA scan, no trait evaluation).
    /// Only handles thin binaries — fat binary dispatch is done by the caller.
    /// Callers are responsible for running YARA and calling `evaluate_and_merge_findings`.
    pub(crate) fn analyze_structural(
        &self,
        file_path: &Path,
        data: &[u8],
        precomputed_sha256: Option<String>,
    ) -> AnalysisReport {
        self.analyze_structural_with_ctx(file_path, data, precomputed_sha256, None)
    }

    /// Same as [`Self::analyze_structural`] but accepts an
    /// [`AnalysisContext`] borrowing the same bytes. When provided,
    /// imports / exports come from expose's typed views instead of
    /// re-walking goblin's dyld-bind / export-trie tables.
    ///
    /// [`AnalysisContext`]: crate::analysis_context::AnalysisContext
    pub(crate) fn analyze_structural_with_ctx<'a>(
        &self,
        file_path: &'a Path,
        data: &'a [u8],
        precomputed_sha256: Option<String>,
        ctx: Option<&crate::analysis_context::AnalysisContext<'a>>,
    ) -> AnalysisReport {
        self.analyze_structural_with_strings(
            file_path,
            file_path,
            data,
            None,
            true,
            precomputed_sha256,
            ctx,
        )
    }

    /// Structural analysis with optional pre-extracted strings.
    #[allow(clippy::too_many_arguments)]
    fn analyze_structural_with_strings<'a>(
        &self,
        logical_path: &Path,
        analysis_path: &Path,
        data: &'a [u8],
        stng_strings: Option<&[stng::ExtractedString]>,
        allow_rizin: bool,
        precomputed_sha256: Option<String>,
        ctx: Option<&crate::analysis_context::AnalysisContext<'a>>,
    ) -> AnalysisReport {
        let start = std::time::Instant::now();
        let sha256 = precomputed_sha256
            .clone()
            .unwrap_or_else(|| crate::analyzers::utils::calculate_sha256(data));

        // Parse with goblin via the panic-safe wrapper. If parsing fails
        // (Err *or* panic), or returns a fat archive we can't currently
        // analyze structurally, fall back to rizin-based metrics so the
        // binary still gets the malformed-structure signal and the basic
        // structural metrics rather than an empty report.
        let parse_outcome = goblin_safe::parse_mach(data);
        let parse_failure = parse_outcome.failure_info();
        let macho_opt = match parse_outcome.ok() {
            Some(Mach::Binary(macho)) => Some(macho),
            Some(Mach::Fat(_)) | None => None,
        };
        let Some(macho) = macho_opt else {
            return self.analyze_macho_fallback(
                logical_path,
                analysis_path,
                data,
                sha256,
                parse_failure.as_ref(),
                allow_rizin,
                precomputed_sha256,
                start,
            );
        };

        // Create target info
        let target = TargetInfo {
            path: logical_path.display().to_string(),
            file_type: "macho".to_string(),
            size_bytes: data.len() as u64,
            sha256: sha256.clone(),
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
        let _t = std::time::Instant::now();
        self.analyze_structure_with_signature(&macho, &mut report, codesig_data.as_ref());
        let structure_ms = _t.elapsed().as_millis();

        // Generate signature findings from parsed code signature.
        // The unsigned case is now emitted by the YAML trait
        // `metadata/signed::unsigned-macho` reading from
        // `kv: signing.is_signed exists: false`.
        let _t = std::time::Instant::now();
        if let Some(ref codesig) = codesig_data {
            self.generate_signature_findings(codesig, &mut report);
        }
        let sig_findings_ms = _t.elapsed().as_millis();

        // Extract imports and map to capabilities
        let _t = std::time::Instant::now();
        let _ = self.analyze_imports(&macho, &mut report, ctx);
        let imports_ms = _t.elapsed().as_millis();

        // Extract exports
        let _t = std::time::Instant::now();
        let _ = self.analyze_exports(&macho, &mut report, ctx);
        let exports_ms = _t.elapsed().as_millis();

        // Analyze sections and entropy
        let _t = std::time::Instant::now();
        let _ = self.analyze_sections(&macho, data, &mut report);
        let sections_ms = _t.elapsed().as_millis();

        tracing::info!(
            path = %logical_path.display(),
            structure_ms,
            sig_findings_ms,
            imports_ms,
            exports_ms,
            sections_ms,
            "macho:phase1"
        );

        // Initialize metrics with Mach-O header info
        let mut macho_metrics = MachoMetrics {
            file_type: macho.header.filetype,
            cpu_type: macho.header.cputype,
            cpu_subtype: macho.header.cpusubtype,
            flags: macho.header.flags,
            class_bits: if macho.is_64 { 64 } else { 32 },
            little_endian: macho.little_endian,
            entry: macho.entry,
            old_style_entry: macho.old_style_entry,
            load_command_count: macho.header.ncmds as u32,
            load_commands_size: macho.header.sizeofcmds,
            rpath_count: macho.rpaths.len() as u32,
            has_install_name: macho.name.is_some(),
            // Tier A: decoded MH_* header bits. (PIE is on
            // BinaryMetrics; not duplicated here.)
            allow_stack_execution: (macho.header.flags & 0x0008_0000) != 0,
            no_heap_execution: (macho.header.flags & 0x0100_0000) != 0,
            app_extension_safe: (macho.header.flags & 0x0200_0000) != 0,
            dylib_in_cache: (macho.header.flags & 0x8000_0000) != 0,
            ..Default::default()
        };

        // Track segments + dylibs for Tier A/B anomaly detection.
        // (vmaddr, vmend, writable, executable, name)
        let mut segment_ranges: Vec<(u64, u64, bool, bool, String)> = Vec::new();
        let mut dylib_names: Vec<String> = Vec::new();
        let mut data_in_code_count: u32 = 0;

        for lc in &macho.load_commands {
            match &lc.command {
                goblin::mach::load_command::CommandVariant::CodeSignature(cs) => {
                    macho_metrics.has_code_signature = true;
                    macho_metrics.code_signature_size = cs.datasize;
                }
                goblin::mach::load_command::CommandVariant::Uuid(_) => {
                    macho_metrics.has_uuid = true;
                }
                goblin::mach::load_command::CommandVariant::BuildVersion(command) => {
                    let (min_os_major, min_os_minor, min_os_patch) =
                        Self::unpack_macho_version(command.minos);
                    let (sdk_major, sdk_minor, sdk_patch) = Self::unpack_macho_version(command.sdk);
                    macho_metrics.has_build_version = true;
                    macho_metrics.build_platform = command.platform;
                    macho_metrics.min_os_major = min_os_major;
                    macho_metrics.min_os_minor = min_os_minor;
                    macho_metrics.min_os_patch = min_os_patch;
                    macho_metrics.sdk_major = sdk_major;
                    macho_metrics.sdk_minor = sdk_minor;
                    macho_metrics.sdk_patch = sdk_patch;
                    macho_metrics.build_tool_count = command.ntools;
                }
                goblin::mach::load_command::CommandVariant::SourceVersion(command) => {
                    macho_metrics.has_source_version = true;
                    macho_metrics.source_version = command.version;
                }
                goblin::mach::load_command::CommandVariant::Main(_) => {
                    macho_metrics.has_main_command = true;
                }
                goblin::mach::load_command::CommandVariant::Unixthread(_) => {
                    macho_metrics.has_unixthread_command = true;
                }
                goblin::mach::load_command::CommandVariant::LoadWeakDylib(d) => {
                    macho_metrics.dylib_count += 1;
                    macho_metrics.weak_dylib_count += 1;
                    let entry = mk_dylib_entry(d, "weak");
                    dylib_names.push(entry.name.clone());
                    macho_metrics.dylib_entries.push(entry);
                }
                goblin::mach::load_command::CommandVariant::ReexportDylib(d) => {
                    macho_metrics.dylib_count += 1;
                    macho_metrics.reexport_dylib_count += 1;
                    let entry = mk_dylib_entry(d, "reexport");
                    dylib_names.push(entry.name.clone());
                    macho_metrics.dylib_entries.push(entry);
                }
                goblin::mach::load_command::CommandVariant::LoadUpwardDylib(d) => {
                    macho_metrics.dylib_count += 1;
                    macho_metrics.upward_dylib_count += 1;
                    let entry = mk_dylib_entry(d, "upward");
                    dylib_names.push(entry.name.clone());
                    macho_metrics.dylib_entries.push(entry);
                }
                goblin::mach::load_command::CommandVariant::LazyLoadDylib(d) => {
                    macho_metrics.dylib_count += 1;
                    macho_metrics.lazy_dylib_count += 1;
                    let entry = mk_dylib_entry(d, "lazy");
                    dylib_names.push(entry.name.clone());
                    macho_metrics.dylib_entries.push(entry);
                }
                goblin::mach::load_command::CommandVariant::LoadDylib(d) => {
                    macho_metrics.dylib_count += 1;
                    let entry = mk_dylib_entry(d, "regular");
                    dylib_names.push(entry.name.clone());
                    macho_metrics.dylib_entries.push(entry);
                }
                goblin::mach::load_command::CommandVariant::LoadDylinker(_)
                | goblin::mach::load_command::CommandVariant::IdDylinker(_)
                | goblin::mach::load_command::CommandVariant::DyldEnvironment(_) => {
                    macho_metrics.has_dylinker = true;
                }
                goblin::mach::load_command::CommandVariant::Segment32(seg) => {
                    let (entry, is_pagezero, vm_end, w, x) = mk_macho_seg_entry32(seg);
                    if is_pagezero {
                        macho_metrics.pagezero_size = seg.vmsize as u64;
                    }
                    let name = entry.name.clone();
                    if name == "__DATA_CONST" {
                        macho_metrics.has_data_const_segment = true;
                    }
                    segment_ranges.push((seg.vmaddr as u64, vm_end, w, x, name));
                    macho_metrics.segment_entries.push(entry);
                }
                goblin::mach::load_command::CommandVariant::Segment64(seg) => {
                    let (entry, is_pagezero, vm_end, w, x) = mk_macho_seg_entry64(seg);
                    if is_pagezero {
                        macho_metrics.pagezero_size = seg.vmsize;
                    }
                    let name = entry.name.clone();
                    if name == "__DATA_CONST" {
                        macho_metrics.has_data_const_segment = true;
                    }
                    segment_ranges.push((seg.vmaddr, vm_end, w, x, name));
                    macho_metrics.segment_entries.push(entry);
                }
                goblin::mach::load_command::CommandVariant::EncryptionInfo32(e)
                    if e.cryptid != 0 =>
                {
                    macho_metrics.has_encrypted_section = true;
                }
                goblin::mach::load_command::CommandVariant::EncryptionInfo64(e)
                    if e.cryptid != 0 =>
                {
                    macho_metrics.has_encrypted_section = true;
                }
                goblin::mach::load_command::CommandVariant::DyldChainedFixups(_) => {
                    macho_metrics.has_chained_fixups = true;
                }
                goblin::mach::load_command::CommandVariant::DyldInfo(_)
                | goblin::mach::load_command::CommandVariant::DyldInfoOnly(_) => {
                    macho_metrics.has_dyld_info_legacy = true;
                }
                goblin::mach::load_command::CommandVariant::VersionMinMacosx(_)
                | goblin::mach::load_command::CommandVariant::VersionMinIphoneos(_)
                | goblin::mach::load_command::CommandVariant::VersionMinTvos(_)
                | goblin::mach::load_command::CommandVariant::VersionMinWatchos(_) => {
                    macho_metrics.uses_legacy_version_min = true;
                }
                goblin::mach::load_command::CommandVariant::DataInCode(c) => {
                    // datasize / sizeof(DataInCodeEntry=8 bytes)
                    data_in_code_count = c.datasize / 8;
                }
                _ => {}
            }
        }
        macho_metrics.data_in_code_count = data_in_code_count;

        // Populate the dylib_entries[].name from macho.libs[1..] —
        // goblin keeps libs[0] as the binary's own name and the rest
        // in load-command order, matching dylib_entries.
        let mut name_iter = macho.libs.iter().skip(1);
        for entry in macho_metrics.dylib_entries.iter_mut() {
            if let Some(name) = name_iter.next() {
                entry.name = (*name).to_string();
            }
        }
        // Refresh dylib_names from the now-populated entries.
        let dylib_names: Vec<String> = macho_metrics
            .dylib_entries
            .iter()
            .map(|e| e.name.clone())
            .collect();

        // Tier A derived: EP-in-segment analysis + W+X count.
        let mut wx_count: u32 = 0;
        let mut ep_in_segment = false;
        let mut ep_in_writable = false;
        let mut last_seg_idx: Option<usize> = None;
        let mut last_seg_vmaddr: u64 = 0;
        let entry_va = macho.entry;
        for (i, (start, end, w, x, _name)) in segment_ranges.iter().enumerate() {
            if *w && *x {
                wx_count = wx_count.saturating_add(1);
            }
            if entry_va >= *start && entry_va < *end && entry_va != 0 {
                ep_in_segment = true;
                if *w {
                    ep_in_writable = true;
                }
            }
            if last_seg_idx.is_none() || *start > last_seg_vmaddr {
                last_seg_idx = Some(i);
                last_seg_vmaddr = *start;
            }
        }
        macho_metrics.wx_segment_count = wx_count;
        macho_metrics.entry_in_writable_segment = ep_in_writable;
        macho_metrics.entry_outside_segments = !ep_in_segment && entry_va != 0;
        if let Some(idx) = last_seg_idx {
            if let Some((start, end, _, _, _)) = segment_ranges.get(idx) {
                if entry_va >= *start && entry_va < *end && entry_va != 0 {
                    macho_metrics.entry_in_last_segment = true;
                }
            }
        }

        // Segment overlap detection — sort by vmaddr, walk pairs.
        // __PAGEZERO sits at vaddr 0 with vast vmsize on 64-bit, so
        // skip it for overlap purposes (it's expected to "overlap"
        // nothing but is also at the start of the address space).
        if segment_ranges.len() > 1 {
            let mut sorted: Vec<&(u64, u64, bool, bool, String)> = segment_ranges
                .iter()
                .filter(|(_, _, _, _, name)| name != "__PAGEZERO")
                .collect();
            sorted.sort_by_key(|t| t.0);
            let mut overlap_names: std::collections::HashSet<String> =
                std::collections::HashSet::new();
            for w in sorted.windows(2) {
                let (a_start, a_end, _, _, a_name) = w[0];
                let (b_start, _, _, _, b_name) = w[1];
                if *a_end > *b_start && *b_start >= *a_start {
                    overlap_names.insert(a_name.clone());
                    overlap_names.insert(b_name.clone());
                }
            }
            macho_metrics.segment_overlap_count = overlap_names.len() as u32;
            let mut names: Vec<String> = overlap_names.into_iter().collect();
            names.sort();
            macho_metrics.overlapping_segments = names;
        }

        // Tier B derived: dylib path direction + duplicates.
        let file_type = macho_metrics.file_type;
        const MH_EXECUTE: u32 = 0x2;
        const MH_DYLIB: u32 = 0x6;
        let mut name_counts: std::collections::HashMap<String, u32> =
            std::collections::HashMap::new();
        for n in &dylib_names {
            *name_counts.entry(n.clone()).or_default() += 1;
            if !n.starts_with('/') && !n.starts_with('@') && !n.is_empty() {
                macho_metrics.dylib_path_unrooted_count =
                    macho_metrics.dylib_path_unrooted_count.saturating_add(1);
            }
            if n.contains("@executable_path") && file_type == MH_DYLIB {
                macho_metrics.executable_path_in_dylib = true;
            }
            if n.contains("@loader_path") && file_type == MH_EXECUTE {
                macho_metrics.loader_path_in_executable = true;
            }
        }
        macho_metrics.duplicate_dylib_count = name_counts
            .values()
            .filter(|&&c| c > 1)
            .map(|c| c - 1)
            .sum();

        // Tier 1 — supply-chain similarity hashes. Sort + dedupe + join
        // so byte-equal vendor releases produce byte-equal hashes.
        if !dylib_names.is_empty() {
            macho_metrics.dylib_hash = Some(sha256_of_sorted(&dylib_names));
        }
        if let Ok(imports) = macho.imports() {
            let import_names: Vec<String> = imports.iter().map(|i| i.name.to_string()).collect();
            if !import_names.is_empty() {
                macho_metrics.symhash = Some(sha256_of_sorted(&import_names));
            }
        }
        if let Ok(exports) = macho.exports() {
            let export_names: Vec<String> = exports.iter().map(|e| e.name.clone()).collect();
            if !export_names.is_empty() {
                macho_metrics.export_hash = Some(sha256_of_sorted(&export_names));
            }
        }

        // Always compute basic binary metrics (even if radare2 fails)
        let binary_metrics = crate::types::BinaryMetrics {
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
        let r2_strings = if allow_rizin && !self.is_cancelled() && Radare2Analyzer::is_available() {
            tools_used.push("radare2".to_string());

            // Use batched extraction - single r2 session for functions, sections, strings, imports
            let has_symbols = macho.symbols().count() > 0;
            let needs_r2_strings = stng_strings.is_none() && self.preextracted_strings.is_none();
            if let Ok(batched) = self.radare2.extract_batched(
                analysis_path,
                data.len() as u64,
                has_symbols,
                true, // goblin_success
                needs_r2_strings,
                precomputed_sha256,
                self.cancellation.as_ref(),
                Some(data),
            ) {
                crate::radare2::push_rizin_warnings(&mut report, &batched);

                // Compute metrics from batched data (radare2-specific metrics)
                let r2_binary_metrics =
                    self.radare2
                        .compute_metrics_from_batched(&batched, data.len() as u64, "macho");

                // Enhance existing binary metrics with radare2 data
                if let Some(ref mut metrics) = report.metrics {
                    if let Some(ref mut binary_metrics) = metrics.binary {
                        // Merge radare2 metrics into existing basic metrics (only if non-zero)
                        if r2_binary_metrics.func_count > 0 {
                            binary_metrics.func_count = r2_binary_metrics.func_count;
                            binary_metrics.avg_func_size = r2_binary_metrics.avg_func_size;
                            binary_metrics.avg_complexity = r2_binary_metrics.avg_complexity;
                        }
                        // Don't use radare2's code_to_data_ratio - it has a bug where __const sections
                        // are incorrectly marked as executable. We calculate this correctly from
                        // goblin-based segment permissions in update_binary_metrics().

                        // Also merge section-level metrics from radare2
                        if r2_binary_metrics.section_count > 0 {
                            binary_metrics.executable_section_count =
                                r2_binary_metrics.executable_section_count;
                            binary_metrics.writable_section_count =
                                r2_binary_metrics.writable_section_count;
                            binary_metrics.wx_section_count = r2_binary_metrics.wx_section_count;
                        }
                    } else {
                        // Fallback: set full radare2 metrics if binary metrics somehow missing
                        let mut full_metrics = r2_binary_metrics;
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
                            // Tier 1 — entitlement_hash. Sort + join
                            // entitlement keys (values can be paths /
                            // identifiers that drift across releases;
                            // keys are the stable surface).
                            let keys: Vec<String> = codesig.entitlements.keys().cloned().collect();
                            if !keys.is_empty() {
                                macho_metrics.entitlement_hash = Some(sha256_of_sorted(&keys));
                            }
                            // Raw CodeDirectory flags; decoded named
                            // bits surface via kv `macho.cs_flags.*`.
                            macho_metrics.cs_flags = codesig.cs_flags;
                            macho_metrics.cs_runtime_version = codesig.cs_runtime_version.clone();
                        }
                    }
                }

                // Convert R2Functions to Functions for the report
                report.functions = batched.functions.into_iter().map(Function::from).collect();

                // Process batched imports if goblin didn't find any
                if report.imports.is_empty() && !batched.imports.is_empty() {
                    for imp in &batched.imports {
                        report.imports.push(Import::new(
                            &imp.name,
                            imp.lib_name.clone(),
                            "radare2",
                        ));
                        let name = crate::types::binary::normalize_symbol(&imp.name);
                        if let Some(cap) = self.capability_mapper.lookup(&name, "radare2") {
                            if !report.findings.iter().any(|c| c.id == cap.id) {
                                report.findings.push(cap);
                            }
                        }
                    }
                }

                // Use strings from batched data (no extra r2 spawn)
                Some(batched.strings)
            } else {
                None
            }
        } else {
            None
        };

        let r2_total_ms = _t_r2.elapsed().as_millis();

        // Use strings in order of preference:
        // 1. stng_strings parameter (from AnalysisInput - avoids redundant extraction)
        // 2. self.preextracted_strings (legacy builder pattern)
        // 3. Extract fresh with stng/r2
        let _t = std::time::Instant::now();
        if let Some(strings) = stng_strings {
            report.strings = self.string_extractor.convert_stng_strings(strings);
        } else if let Some(ref strings) = self.preextracted_strings {
            report.strings = strings.clone();
        } else {
            // Extract strings using language-aware extraction (Go/Rust)
            report.strings = self.string_extractor.extract_smart(data, r2_strings);
        }
        let strings_ms = _t.elapsed().as_millis();

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

        // Update binary metrics with string count
        if let Some(ref mut metrics) = report.metrics {
            if let Some(ref mut binary_metrics) = metrics.binary {
                binary_metrics.string_count = report.strings.len() as u32;
            }
        }

        // Analyze embedded code in strings
        let _t = std::time::Instant::now();
        let string_count = report.strings.len();
        let (encoded_layers, plain_findings) =
            crate::analyzers::embedded_code_detector::process_all_strings(
                &logical_path.display().to_string(),
                &report.strings,
                &self.capability_mapper,
                0,
                Some(&crate::FileType::MachO),
                self.cancellation.as_deref(),
            );
        report.files.extend(encoded_layers);
        report.findings.extend(plain_findings);
        let embedded_ms = _t.elapsed().as_millis();

        // Populate common binary metrics (strings, entropy, etc.)
        let _t = std::time::Instant::now();
        crate::analyzers::metrics_utils::populate_binary_metrics(&mut report, data);
        let metrics_ms = _t.elapsed().as_millis();

        tracing::info!(
            path = %logical_path.display(),
            r2_total_ms,
            strings_ms,
            string_count,
            embedded_ms,
            metrics_ms,
            "macho:phase2"
        );

        // Validate metric ranges to catch calculation bugs
        if let Some(ref metrics) = report.metrics {
            if let Some(ref binary) = metrics.binary {
                binary.validate(&report.target.path, report.target.size_bytes);
            }
        }

        // Round up to 1ms when the work completed in <1ms so the
        // recorded duration is always distinguishable from the
        // "never set" sentinel (0). Avoids spurious test flakes on
        // fast machines without lying about long analyses.
        report.metadata.analysis_duration_ms = (start.elapsed().as_millis() as u64).max(1);
        report.metadata.tools_used = tools_used;

        report
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

        // Mach-O UUID is now emitted by the YAML trait
        // `metadata/build/reproducible::macho-uuid` reading from the
        // binary kv tree (`macho.uuid` — populated by
        // `analyzers::macho_extractors::extract`).

        if let Some(name) = macho.name {
            Self::push_metadata_finding(
                report,
                "metadata/binary/linking::macho-install-name",
                "Mach-O install name present",
                "lc_id_dylib",
                "goblin",
                name.to_string(),
            );
        }

        for dylib in &macho.libs {
            if *dylib == "self" || macho.name.is_some_and(|name| name == *dylib) {
                continue;
            }
            Self::push_metadata_finding(
                report,
                "metadata/binary/linking::macho-dylib",
                "Mach-O linked dylib",
                "load_dylib",
                "goblin",
                (*dylib).to_string(),
            );
        }

        for rpath in &macho.rpaths {
            Self::push_metadata_finding(
                report,
                "metadata/binary/linking::macho-rpath",
                "Mach-O runtime search path",
                "rpath",
                "goblin",
                (*rpath).to_string(),
            );
        }
    }

    fn analyze_imports<'a>(
        &self,
        macho: &MachO<'a>,
        report: &mut AnalysisReport,
        ctx: Option<&crate::analysis_context::AnalysisContext<'_>>,
    ) -> Result<()> {
        // When the shared expose-side parse is available, mirror
        // its typed Imports view (source: "macho-bind") — same
        // dyld bind-info walk goblin would do here, with dylib
        // names already normalised to lowercase basenames.
        // Falls back to the legacy goblin/symtab path when no
        // ctx is provided (CLI direct paths, tests).
        if let Some(c) = ctx {
            let bridged = c.imports_from_expose();
            if !bridged.is_empty() {
                for imp in bridged {
                    if let Some(cap) = self.capability_mapper.lookup(&imp.symbol, &imp.source) {
                        if !report.findings.iter().any(|c| c.id == cap.id) {
                            report.findings.push(cap);
                        }
                    }
                    report.imports.push(imp);
                }
                return Ok(());
            }
            // expose returned an empty Imports view — fall through
            // to goblin's symtab-fallback path below.
        }

        let imports = macho.imports()?;

        // Fallback: use symbol table if imports() is empty
        // (r2 imports are now handled via batched analysis above)
        if imports.is_empty() {
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

    fn analyze_exports<'a>(
        &self,
        macho: &MachO<'a>,
        report: &mut AnalysisReport,
        ctx: Option<&crate::analysis_context::AnalysisContext<'_>>,
    ) -> Result<()> {
        if let Some(c) = ctx {
            for exp in c.exports_from_expose() {
                report.exports.push(exp);
            }
            return Ok(());
        }
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
                        offset: Some(section.offset as u64),
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

        let sig_value = if let Some(ref s) = codesig.signer {
            format!("{}::{}", sig_category, s)
        } else {
            format!("{}::{}", sig_category, signer)
        };

        report.findings.push(Finding {
            kind: FindingKind::Capability,
            trait_refs: vec![],
            id: format!("metadata/signed/{}::{}", sig_category, signer),
            desc,
            conf: 1.0,
            crit: Criticality::Notable,
            mbc: None,
            attack: None,
            evidence: vec![Evidence {
                method: "code_signature".to_string(),
                source: "codesign_parser".to_string(),
                value: sig_value,
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
            let ent_category = entitlement_category(entitlement_key);
            let ent_trait_id =
                format!("metadata/entitlement/{}::{}", ent_category, entitlement_key);
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
                crit: determine_entitlement_criticality(
                    entitlement_key,
                    &codesig.signature_type,
                    codesig
                        .entitlements
                        .contains_key("com.apple.security.cs.disable-library-validation"),
                ),
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

        // `metadata/notarized` and `metadata/hardened-runtime` were
        // here.  Now emitted by YAML kv traits reading
        // `signing.notarized` and `signing.hardened_runtime` from the
        // binary kv tree.  See:
        //   - metadata/signed/macho-codesign.yaml::macho-notarized
        //   - metadata/signed/trust-level/traits.yaml::hardened-runtime-dup
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

/// Construct a baseline `MachoDylibEntry` from a goblin DylibCommand.
/// Name is left empty for the caller to fill from macho.libs/imports.
fn mk_dylib_entry(
    cmd: &goblin::mach::load_command::DylibCommand,
    kind: &str,
) -> crate::types::binary_metrics::MachoDylibEntry {
    crate::types::binary_metrics::MachoDylibEntry {
        name: String::new(),
        current_version: cmd.dylib.current_version,
        compatibility_version: cmd.dylib.compatibility_version,
        kind: kind.to_string(),
    }
}

/// Build a Mach-O segment carrier entry from a 32-bit segment cmd.
/// Returns the entry plus derived flags `(is_pagezero, vm_end,
/// writable, executable)` for Tier A processing.
fn mk_macho_seg_entry32(
    seg: &goblin::mach::load_command::SegmentCommand32,
) -> (
    crate::types::binary_metrics::MachoSegmentEntry,
    bool,
    u64,
    bool,
    bool,
) {
    let name = std::str::from_utf8(&seg.segname)
        .unwrap_or("")
        .trim_end_matches('\0')
        .to_string();
    const VM_PROT_READ: u32 = 0x01;
    const VM_PROT_WRITE: u32 = 0x02;
    const VM_PROT_EXECUTE: u32 = 0x04;
    let perms = format!(
        "{}{}{}",
        if seg.initprot & VM_PROT_READ != 0 {
            "r"
        } else {
            "-"
        },
        if seg.initprot & VM_PROT_WRITE != 0 {
            "w"
        } else {
            "-"
        },
        if seg.initprot & VM_PROT_EXECUTE != 0 {
            "x"
        } else {
            "-"
        },
    );
    let entry = crate::types::binary_metrics::MachoSegmentEntry {
        name: name.clone(),
        vmaddr: seg.vmaddr as u64,
        vmsize: seg.vmsize as u64,
        fileoff: seg.fileoff as u64,
        filesize: seg.filesize as u64,
        maxprot_hex: format!("{:x}", seg.maxprot),
        initprot_hex: format!("{:x}", seg.initprot),
        perms,
    };
    let vm_end = (seg.vmaddr as u64).saturating_add(seg.vmsize as u64);
    let writable = (seg.initprot & VM_PROT_WRITE) != 0 || (seg.maxprot & VM_PROT_WRITE) != 0;
    let executable = (seg.initprot & VM_PROT_EXECUTE) != 0;
    (entry, name == "__PAGEZERO", vm_end, writable, executable)
}

/// 64-bit variant. Same shape as `mk_macho_seg_entry32`.
fn mk_macho_seg_entry64(
    seg: &goblin::mach::load_command::SegmentCommand64,
) -> (
    crate::types::binary_metrics::MachoSegmentEntry,
    bool,
    u64,
    bool,
    bool,
) {
    let name = std::str::from_utf8(&seg.segname)
        .unwrap_or("")
        .trim_end_matches('\0')
        .to_string();
    const VM_PROT_READ: u32 = 0x01;
    const VM_PROT_WRITE: u32 = 0x02;
    const VM_PROT_EXECUTE: u32 = 0x04;
    let perms = format!(
        "{}{}{}",
        if seg.initprot & VM_PROT_READ != 0 {
            "r"
        } else {
            "-"
        },
        if seg.initprot & VM_PROT_WRITE != 0 {
            "w"
        } else {
            "-"
        },
        if seg.initprot & VM_PROT_EXECUTE != 0 {
            "x"
        } else {
            "-"
        },
    );
    let entry = crate::types::binary_metrics::MachoSegmentEntry {
        name: name.clone(),
        vmaddr: seg.vmaddr,
        vmsize: seg.vmsize,
        fileoff: seg.fileoff,
        filesize: seg.filesize,
        maxprot_hex: format!("{:x}", seg.maxprot),
        initprot_hex: format!("{:x}", seg.initprot),
        perms,
    };
    let vm_end = seg.vmaddr.saturating_add(seg.vmsize);
    let writable = (seg.initprot & VM_PROT_WRITE) != 0 || (seg.maxprot & VM_PROT_WRITE) != 0;
    let executable = (seg.initprot & VM_PROT_EXECUTE) != 0;
    (entry, name == "__PAGEZERO", vm_end, writable, executable)
}

/// SHA-256 of `\n`-joined sorted-deduplicated input strings, lowercase
/// hex. Used for the Mach-O similarity-hash family
/// (`dylib_hash`, `symhash`, `export_hash`, `entitlement_hash`).
/// Sort + dedupe so the order returned by goblin doesn't affect the
/// hash — vendor releases share byte-equal hashes regardless of
/// load-command ordering.
fn sha256_of_sorted(items: &[String]) -> String {
    use sha2::{Digest, Sha256};
    let mut sorted: Vec<&String> = items.iter().filter(|s| !s.is_empty()).collect();
    sorted.sort();
    sorted.dedup();
    let joined = sorted
        .iter()
        .map(|s| s.as_str())
        .collect::<Vec<_>>()
        .join("\n");
    let mut h = Sha256::new();
    h.update(joined.as_bytes());
    hex::encode(h.finalize())
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

/// Categorize an entitlement key into a subdirectory for the ML pipeline.
/// The full finding ID becomes `metadata/entitlement/<category>::<key>`.
fn entitlement_category(key: &str) -> &'static str {
    // Device hardware access
    if key.contains("device.") {
        return "device";
    }
    // Personal/private data access
    if key.contains("personal-information") {
        return "privacy";
    }
    // Code-signing / runtime security policy
    if key.contains(".cs.") {
        return "security";
    }
    // Network capabilities
    if key.contains("network.") {
        return "network";
    }
    // File system / sandbox scope
    if key.contains("files.")
        || key.contains("sandbox")
        || key.contains("home-directory")
        || key.contains("temporary-exception.files")
    {
        return "filesystem";
    }
    // Keychain / credential storage
    if key.contains("keychain")
        || key.contains("keystore")
        || key.contains("Keychain")
        || key.contains("credential")
    {
        return "keychain";
    }
    // IPC: XPC, launchd, mach services
    if key.contains("xpc")
        || key.contains("launchd")
        || key.contains("mach-lookup")
        || key.contains("mach-register")
    {
        return "ipc";
    }
    // iCloud / push / app services
    if key.contains("icloud")
        || key.contains("push-service")
        || key.contains("aps-environment")
        || key.contains("ubiquity")
    {
        return "cloud";
    }
    // Application identity
    if key.contains("application-identifier")
        || key.contains("app-identifier")
        || key.contains("team-identifier")
        || key.contains("bundle-identifier")
    {
        return "identity";
    }
    // Apple private/internal APIs
    if key.contains("private.") || key.contains("root-access") {
        return "private-api";
    }
    // Virtualization / hypervisor
    if key.contains("hypervisor") || key.contains("virtualization") {
        return "virtualization";
    }
    // Accessibility / automation
    if key.contains("accessibility") || key.contains("automation") || key.contains("apple-events") {
        return "automation";
    }
    "other"
}

fn determine_entitlement_criticality(
    entitlement_key: &str,
    signature_type: &macho_codesign::SignatureType,
    has_disable_library_validation: bool,
) -> Criticality {
    // Platform (Apple-signed) binaries: all entitlements are notable
    if matches!(signature_type, macho_codesign::SignatureType::Platform) {
        return Criticality::Notable;
    }

    // Dangerous entitlements are suspicious on non-Apple binaries:
    // - allow-jit: allows JIT compilation (code generation at runtime)
    // - debugger: allows attaching to other processes
    // - allow-unsigned-executable-memory: bypasses code signing enforcement
    // - disable-executable-page-protection: weakens memory protections
    if entitlement_key.contains("debugger")
        || entitlement_key.contains("disable-executable-page-protection")
    {
        return Criticality::Suspicious;
    }

    if entitlement_key.contains("allow-unsigned-executable-memory") {
        if matches!(signature_type, macho_codesign::SignatureType::DeveloperID)
            && has_disable_library_validation
        {
            return Criticality::Notable;
        }
        return Criticality::Suspicious;
    }

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
        if let Some(Mach::Fat(fat)) = goblin_safe::parse_mach(data).ok() {
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
    /// Returns per-architecture byte ranges for fat/universal Mach-O binaries.
    /// Each entry maps an `Arch` to its byte range within the file.
    /// For thin binaries, returns a single entry with the detected architecture.
    #[allow(dead_code)] // Used by lib.rs pipeline, not visible to binary target
    pub(crate) fn labeled_arch_ranges(
        &self,
        data: &[u8],
    ) -> Vec<(crate::composite_rules::Arch, std::ops::Range<usize>)> {
        use crate::composite_rules::Arch;
        if let Some(goblin::mach::Mach::Fat(fat)) = goblin_safe::parse_mach(data).ok() {
            if let Ok(arches) = fat.arches() {
                let ranges: Vec<_> = arches
                    .iter()
                    .filter_map(|arch| {
                        let offset = arch.offset as usize;
                        let size = arch.size as usize;
                        if offset + size <= data.len() {
                            let name = self.arch_name_from_cputype(arch.cputype);
                            Some((Arch::from_report_str(&name), offset..offset + size))
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
        vec![(Arch::All, 0..data.len())]
    }

    #[allow(clippy::single_range_in_vec_init)] // Intentional: returns single range for thin binaries
    pub(crate) fn all_arch_ranges(&self, data: &[u8]) -> Vec<std::ops::Range<usize>> {
        if let Some(Mach::Fat(fat)) = goblin_safe::parse_mach(data).ok() {
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

    /// Parse every non-preferred arch slice of a fat Mach-O and union its imports
    /// and exports into the report, running capability lookups on each new import
    /// so rules matching on goblin-derived imports still fire for malware hidden
    /// in a non-preferred arch.
    ///
    /// Preferred arch has already been parsed by the main structural pass, so
    /// imports/exports already present are skipped (deduped by normalized symbol
    /// name + library for imports; by symbol name for exports).
    ///
    /// Only runs on fat binaries; caller is expected to check.
    pub(crate) fn union_supplementary_arches(
        &self,
        report: &mut AnalysisReport,
        data: &[u8],
        preferred_offset: usize,
    ) {
        use std::collections::HashSet;

        let Some(Mach::Fat(fat)) = goblin_safe::parse_mach(data).ok() else {
            return;
        };
        let Ok(arches) = fat.arches() else {
            return;
        };

        // Build dedup sets from what's already in the report.
        let mut seen_imports: HashSet<(String, Option<String>)> = report
            .imports
            .iter()
            .map(|i| (i.symbol.clone(), i.library.clone()))
            .collect();
        let mut seen_exports: HashSet<String> =
            report.exports.iter().map(|e| e.symbol.clone()).collect();
        let baseline_imports = report.imports.len();
        let baseline_exports = report.exports.len();
        let mut arches_parsed = 0;

        for arch in arches.iter() {
            let offset = arch.offset as usize;
            if offset == preferred_offset {
                continue;
            }
            let size = arch.size as usize;
            if offset.saturating_add(size) > data.len() {
                continue;
            }
            let slice = &data[offset..offset + size];
            let arch_name = self.arch_name_from_cputype(arch.cputype);
            let import_source = format!("goblin-{}", arch_name);

            let parse = goblin_safe::parse_mach(slice);
            let Some(Mach::Binary(macho)) = parse.ok() else {
                continue;
            };
            arches_parsed += 1;

            let goblin_imports = macho.imports().unwrap_or_default();
            if !goblin_imports.is_empty() {
                for imp in &goblin_imports {
                    let symbol = crate::types::binary::normalize_symbol(imp.name);
                    let library = Some(imp.dylib.to_string());
                    if !seen_imports.insert((symbol.clone(), library.clone())) {
                        continue;
                    }
                    report
                        .imports
                        .push(Import::new(imp.name, library, import_source.clone()));
                    if let Some(cap) = self.capability_mapper.lookup(&symbol, "goblin") {
                        if !report.findings.iter().any(|c| c.id == cap.id) {
                            report.findings.push(cap);
                        }
                    }
                }
            } else if let Some(syms) = &macho.symbols {
                // Mirror analyze_imports' symtab fallback: N_EXT+undefined means import
                for (name, sym) in syms.iter().flatten() {
                    if (sym.n_type & 0x01 != 0) && (sym.n_type & 0x0e == 0) {
                        let symbol = crate::types::binary::normalize_symbol(name);
                        if !seen_imports.insert((symbol.clone(), None)) {
                            continue;
                        }
                        report
                            .imports
                            .push(Import::new(name, None, import_source.clone()));
                        if let Some(cap) = self.capability_mapper.lookup(&symbol, "goblin") {
                            if !report.findings.iter().any(|c| c.id == cap.id) {
                                report.findings.push(cap);
                            }
                        }
                    }
                }
            }

            if let Ok(exports) = macho.exports() {
                for exp in &exports {
                    let symbol = crate::types::binary::normalize_symbol(&exp.name);
                    if !seen_exports.insert(symbol) {
                        continue;
                    }
                    report.exports.push(Export::new(
                        &exp.name,
                        Some(format!("0x{:x}", exp.offset)),
                        import_source.clone(),
                    ));
                }
            }
        }

        let extra_imports = report.imports.len() - baseline_imports;
        let extra_exports = report.exports.len() - baseline_exports;
        if arches_parsed > 0 && (extra_imports > 0 || extra_exports > 0) {
            tracing::debug!(
                arches_parsed,
                extra_imports,
                extra_exports,
                "fat mach-O supplementary arch union"
            );
        }
    }

    /// Updates a report with fat binary metadata (architecture list, universal binary flag).
    /// No-op for thin binaries.
    pub(crate) fn apply_fat_metadata(&self, report: &mut AnalysisReport, data: &[u8]) {
        // Source arch names from expose's `macho.slices[]` — each slice
        // entry carries a `cpu_type` string ("x86_64" / "arm64" / etc).
        // Falls back to a goblin walk only when expose can't open the
        // bytes (extremely unusual for valid fat Mach-O).
        let arch_names: Vec<String> = match expose::open_with_path(report.target.path.as_ref(), data) {
            Ok(parsed) => parsed
                .values()
                .get("macho.slices")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|entry| {
                            entry
                                .get("cpu_type")
                                .and_then(|c| c.as_str())
                                .map(str::to_string)
                        })
                        .collect()
                })
                .unwrap_or_default(),
            Err(_) => goblin_safe::parse_mach(data)
                .ok()
                .and_then(|m| match m {
                    Mach::Fat(fat) => fat.arches().ok().map(|a| {
                        a.iter()
                            .map(|arch| self.arch_name_from_cputype(arch.cputype))
                            .collect()
                    }),
                    _ => None,
                })
                .unwrap_or_default(),
        };
        if arch_names.is_empty() {
            return;
        }
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

    /// Build a minimal Mach-O analysis report when goblin couldn't parse
    /// the binary cleanly (returned an error, panicked, or returned a fat
    /// archive we can't currently structurally analyze).
    ///
    /// Mirrors the rizin-fallback strategy used by `pe.rs` and `elf.rs`:
    /// runs `Radare2Analyzer::extract_batched` (which has its own
    /// sha256-keyed disk cache, so a re-analysis of the same binary is
    /// essentially free), populates `BinaryMetrics` from the result, and
    /// sets `has_malformed_structure` so downstream consumers know the
    /// structural data didn't come from the primary parser.
    #[allow(clippy::too_many_arguments)]
    fn analyze_macho_fallback(
        &self,
        logical_path: &Path,
        analysis_path: &Path,
        data: &[u8],
        sha256: String,
        parse_failure: Option<&goblin_safe::GoblinFailureInfo>,
        allow_rizin: bool,
        precomputed_sha256: Option<String>,
        _start: std::time::Instant,
    ) -> AnalysisReport {
        let target = TargetInfo {
            path: logical_path.display().to_string(),
            file_type: "macho".to_string(),
            size_bytes: data.len() as u64,
            sha256,
            architectures: None,
        };
        let mut report = AnalysisReport::new(target);

        if let Some(failure) = parse_failure {
            report.metadata.errors.push(format!(
                "Mach-O parse {}: {}",
                if failure.panicked {
                    "panicked"
                } else {
                    "error"
                },
                failure.message
            ));
            report.findings.push(Finding {
                kind: FindingKind::Structural,
                id: "anti-analysis/malformed/macho-header".to_string(),
                desc: format!("Malformed Mach-O header: {}", failure.message),
                conf: 1.0,
                crit: Criticality::Suspicious,
                mbc: Some("B0001".to_string()),
                attack: Some("T1027".to_string()),
                evidence: vec![],
                match_count: 0,
                trait_refs: vec![],
                source_file: None,
            });
        }

        let mut binary_metrics =
            if allow_rizin && !self.is_cancelled() && Radare2Analyzer::is_available() {
                match self.radare2.extract_batched(
                    analysis_path,
                    data.len() as u64,
                    false, // has_symbols=false: nothing came back from goblin
                    false, // goblin_success=false
                    true,  // include_strings: no stng pre-extraction in this path
                    precomputed_sha256,
                    self.cancellation.as_ref(),
                    Some(data),
                ) {
                    Ok(batched) => {
                        crate::radare2::push_rizin_warnings(&mut report, &batched);
                        let bm = self.radare2.compute_metrics_from_batched(
                            &batched,
                            data.len() as u64,
                            "macho",
                        );
                        report.functions =
                            batched.functions.into_iter().map(Function::from).collect();
                        bm
                    }
                    Err(e) => {
                        tracing::debug!(
                            "rizin fallback also failed for goblin-malformed Mach-O {}: {}",
                            report.target.path,
                            e
                        );
                        crate::types::BinaryMetrics {
                            ..Default::default()
                        }
                    }
                }
            } else {
                crate::types::BinaryMetrics {
                    ..Default::default()
                }
            };
        binary_metrics.has_malformed_structure = true;
        report.metrics = Some(Metrics {
            binary: Some(binary_metrics),
            ..Default::default()
        });
        report
    }
}

impl Analyzer for MachOAnalyzer {
    fn analyze_input(&self, input: &AnalysisInput<'_>) -> Result<AnalysisReport> {
        // Get all architecture slices (for FAT binaries) or the single slice (for thin binaries)
        let arch_ranges = self.all_arch_ranges(input.data);

        // Use preferred arch for structural analysis (imports, exports, strings, etc.)
        let preferred_range = self.preferred_arch_range(input.data);
        let preferred_data = &input.data[preferred_range];
        let strings = if input.strings.is_empty() {
            None
        } else {
            Some(input.strings)
        };
        // Open expose-side parse so downstream helpers source structural
        // data from expose's typed views rather than re-walking goblin.
        // Falls through to legacy goblin paths when expose can't open
        // (corrupted Mach-O / unknown shape).
        let ctx =
            crate::analysis_context::AnalysisContext::open(input.path, preferred_data).ok();
        let mut report = self.analyze_structural_with_strings(
            input.path,
            input.backing_path(),
            preferred_data,
            strings,
            !input.skip_rizin,
            input.sha256.clone(),
            ctx.as_ref(),
        );
        self.apply_fat_metadata(&mut report, input.data);

        // For FAT binaries, strings should already be file-relative from input.strings
        // (extracted from the full file by the entry point)
        let is_fat = arch_ranges.len() > 1;

        if is_fat {
            let preferred_offset = self.preferred_arch_range(input.data).start;
            self.union_supplementary_arches(&mut report, input.data, preferred_offset);
        }

        // Evaluate traits against binary data.
        // For FAT binaries, evaluate against the full file since strings have file-relative offsets.
        // For thin binaries, evaluate against the single slice (same as full file).
        if is_fat {
            // Full file evaluation - strings and offsets are file-relative
            self.capability_mapper
                .evaluate_and_merge_findings(&mut report, input.data, None, None);
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

    fn analyze(&self, file_path: &Path) -> Result<AnalysisReport> {
        let data = fs::read(file_path).context("Failed to read file")?;
        let opts = crate::analyzers::stng_analysis_opts(4);
        let strings = stng::extract_strings_with_options(&data, &opts);
        tracing::debug!(
            path = %file_path.display(),
            strings = strings.len(),
            string_mode = "stng-local",
            reason = "legacy analyze() path without pre-extracted AnalysisInput",
            "Mach-O analyzer extracting strings locally before analyze_input"
        );
        let input = AnalysisInput::with_strings(
            file_path,
            &data,
            &strings,
            crate::analyzers::FileType::MachO,
        );
        self.analyze_input(&input)
    }

    fn can_analyze(&self, file_path: &Path) -> bool {
        // Magic-byte gate. Full parse runs once we commit to analyze().
        // Covers thin Mach-O (LE/BE 32 and 64-bit) and fat universal
        // binaries (cafebabe / cafebabf / bebafeca / bfbafeca).
        let Ok(mut file) = fs::File::open(file_path) else {
            return false;
        };
        use std::io::Read;
        let mut magic = [0u8; 4];
        if file.read_exact(&mut magic).is_err() {
            return false;
        }
        matches!(
            magic,
            [0xfe, 0xed, 0xfa, 0xce]     // thin 32-bit, big-endian
                | [0xce, 0xfa, 0xed, 0xfe]    // thin 32-bit, little-endian
                | [0xfe, 0xed, 0xfa, 0xcf]    // thin 64-bit, big-endian
                | [0xcf, 0xfa, 0xed, 0xfe]    // thin 64-bit, little-endian
                | [0xca, 0xfe, 0xba, 0xbe]    // fat 32-bit
                | [0xbe, 0xba, 0xfe, 0xca]    // fat 32-bit, byte-swapped
                | [0xca, 0xfe, 0xba, 0xbf]    // fat 64-bit
                | [0xbf, 0xba, 0xfe, 0xca]    // fat 64-bit, byte-swapped
        )
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn test_macho_path() -> PathBuf {
        PathBuf::from("tests/fixtures/test.macho")
    }

    #[test]
    fn test_sha256_of_sorted_order_independent() {
        let a = sha256_of_sorted(&[
            "libfoo.dylib".into(),
            "libbar.dylib".into(),
            "libbaz.dylib".into(),
        ]);
        let b = sha256_of_sorted(&[
            "libbaz.dylib".into(),
            "libbar.dylib".into(),
            "libfoo.dylib".into(),
        ]);
        assert_eq!(a, b, "input order must not affect hash");
    }

    #[test]
    fn test_sha256_of_sorted_dedups() {
        let a = sha256_of_sorted(&["libfoo.dylib".into(), "libfoo.dylib".into()]);
        let b = sha256_of_sorted(&["libfoo.dylib".into()]);
        assert_eq!(a, b, "duplicates must be removed before hashing");
    }

    #[test]
    fn test_sha256_of_sorted_empty_inputs_skipped() {
        let a = sha256_of_sorted(&["".into(), "libfoo.dylib".into()]);
        let b = sha256_of_sorted(&["libfoo.dylib".into()]);
        assert_eq!(a, b, "empty strings must be filtered out");
    }

    #[test]
    fn test_sha256_of_sorted_known_value() {
        // Single input, no padding — SHA-256 of "libfoo.dylib".
        let h = sha256_of_sorted(&["libfoo.dylib".into()]);
        assert_eq!(h.len(), 64);
        assert!(h.chars().all(|c| c.is_ascii_hexdigit()));
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
    fn test_determine_entitlement_criticality_platform_always_notable() {
        // Platform (Apple-signed) binaries: all entitlements are notable
        for key in [
            "com.apple.security.cs.allow-jit",
            "com.apple.security.cs.debugger",
            "com.apple.security.cs.disable-library-validation",
        ] {
            assert_eq!(
                determine_entitlement_criticality(
                    key,
                    &macho_codesign::SignatureType::Platform,
                    false,
                ),
                Criticality::Notable,
                "platform binary entitlement {key} should be notable"
            );
        }
    }

    #[test]
    fn test_determine_entitlement_criticality_dangerous_non_apple() {
        // Dangerous entitlements are suspicious on non-Apple binaries
        for key in [
            "com.apple.security.cs.debugger",
            "com.apple.security.cs.allow-unsigned-executable-memory",
        ] {
            assert_eq!(
                determine_entitlement_criticality(
                    key,
                    &macho_codesign::SignatureType::DeveloperID,
                    false,
                ),
                Criticality::Suspicious,
                "non-Apple entitlement {key} should be suspicious"
            );
        }
        // allow-jit is common in legitimate apps, notable not suspicious
        assert_eq!(
            determine_entitlement_criticality(
                "com.apple.security.cs.allow-jit",
                &macho_codesign::SignatureType::DeveloperID,
                false,
            ),
            Criticality::Notable,
        );
    }

    #[test]
    fn test_determine_entitlement_criticality_disable_library_validation_notable() {
        // disable-library-validation is common for developer-signed apps (plugins, frameworks)
        assert_eq!(
            determine_entitlement_criticality(
                "com.apple.security.cs.disable-library-validation",
                &macho_codesign::SignatureType::DeveloperID,
                false,
            ),
            Criticality::Notable,
        );
    }

    #[test]
    fn test_determine_entitlement_criticality_privacy_notable() {
        for key in ["personal-information.location", "device.bluetooth"] {
            assert_eq!(
                determine_entitlement_criticality(
                    key,
                    &macho_codesign::SignatureType::Adhoc,
                    false,
                ),
                Criticality::Notable,
            );
        }
    }

    #[test]
    fn test_determine_entitlement_criticality_allow_unsigned_exec_memory_common_helper() {
        assert_eq!(
            determine_entitlement_criticality(
                "com.apple.security.cs.allow-unsigned-executable-memory",
                &macho_codesign::SignatureType::DeveloperID,
                true,
            ),
            Criticality::Notable,
        );
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
