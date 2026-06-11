//! ELF binary analyzer for Linux executables.
//!
//! Every ELF-internal helper takes a non-optional
//! [`crate::analysis_context::AnalysisContext`]: structural data
//! (sections, segments, dynamic-section facts, notes) is read from
//! `filefacts`'s typed views rather than re-walked with goblin. The
//! analyzer no longer carries its own goblin parse path.

use crate::analyzers::{AnalysisInput, Analyzer};
use crate::capabilities::CapabilityMapper;
use crate::entropy::EntropyLevel;
use crate::strings::StringExtractor;
use crate::types::{
    AnalysisReport, Criticality, Evidence, Finding, FindingKind, Section, StringInfo,
    StructuralFeature, TargetInfo,
};
use crate::yara_engine::YaraEngine;
use anyhow::{Context, Result};
use std::fs;
use std::path::Path;
use std::sync::Arc;

type Ctx<'a> = crate::analysis_context::AnalysisContext<'a>;

/// Analyzer for Linux ELF binaries (executables, shared objects, kernel modules).
///
/// Wave B routed deep-binary signal through `filefacts::open`: function
/// CFG fields and recovered symbols for stripped binaries arrive on
/// `ctx.parsed.symbols()` (filtered by kind) /
/// `sections()`. The analyzer no longer spawns rizin itself.
#[derive(Debug)]
pub(crate) struct ElfAnalyzer {
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

/// Map an ELF `e_machine` value to its canonical short name. Used
/// only when filefacts's parse fails entirely and we salvage the
/// architecture from raw header bytes (see `analyze_elf_core`'s
/// failure branch).
fn arch_name_from_machine(e_machine: u16) -> String {
    match e_machine {
        62 => "x86_64".to_string(),
        3 => "i386".to_string(),
        183 => "aarch64".to_string(),
        40 => "arm".to_string(),
        243 => "riscv".to_string(),
        8 => "mips".to_string(),
        20 => "powerpc".to_string(),
        21 => "powerpc64".to_string(),
        2 | 18 | 43 => "sparc".to_string(),
        4 => "m68k".to_string(),
        22 => "s390".to_string(),
        42 => "superh".to_string(),
        _ => format!("unknown_{}", e_machine),
    }
}

impl ElfAnalyzer {
    /// Push a baseline structural metadata finding with its evidence anchored
    /// at `location` (a hex offset such as the originating section's file
    /// offset, e.g. for a `.gnu_debuglink` reference).
    fn push_metadata_finding_at(
        report: &mut AnalysisReport,
        id: &str,
        desc: &str,
        method: &str,
        value: String,
        location: String,
    ) {
        report.findings.push(
            Finding::structural(id.to_string(), desc.to_string(), 1.0)
                .with_criticality(Criticality::Baseline)
                .with_evidence(vec![Evidence {
                    method: method.to_string(),
                    source: "filefacts".to_string(),
                    value,
                    location: Some(location),
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
    #[must_use]
    pub(crate) fn with_yara_arc(
        mut self,
        yara_engine: &Arc<crate::yara_engine::YaraEngine>,
    ) -> Self {
        self.yara_engine = Some(yara_engine.clone());
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
    #[allow(clippy::too_many_arguments)]
    fn analyze_elf_core<'a>(
        &self,
        logical_path: &Path,
        analysis_path: &Path,
        data: &'a [u8],
        stng_strings: Option<&[stng::ExtractedString]>,
        allow_rizin: bool,
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

        let mut report = AnalysisReport::new(target);
        let mut tools_used = vec![];
        let mut embedded_binary_count: u32 = 0;
        let mut embedded_archive_count: u32 = 0;

        // Filefacts's ELF parse status drives the analyzer. A successful
        // parse populates `elf.machine`; a failed/panicked parse leaves
        // it absent and instead sets `elf.parse_failed` /
        // `elf.parse_panicked`. We branch on that single signal.
        let parsed_values = ctx.parsed.values();
        let parsed_metrics = ctx.parsed.metrics();
        let filefacts_ok = parsed_values.get("elf.machine").is_some();
        let parse_failed = parsed_metrics.get("elf.parse_failed").is_some();
        let parse_panicked = parsed_metrics.get("elf.parse_panicked").is_some();

        let is_core_dump = filefacts_ok
            && parsed_values
                .get("elf.type")
                .and_then(|v| v.as_str())
                .is_some_and(|s| s == "core");

        let (r2_strings, elf_content_end) = if filefacts_ok {
            tools_used.push("filefacts".to_string());
            report.target.architectures = Some(vec![
                parsed_values
                    .get("elf.machine")
                    .and_then(|v| v.as_str())
                    .map(str::to_string)
                    .unwrap_or_else(|| "unknown".to_string()),
            ]);

            let struct_start = std::time::Instant::now();
            self.fill_structure_from_ctx(ctx, data, &mut report);
            self.fill_dynamic_symbols_from_ctx(ctx, &mut report);
            self.fill_sections_from_ctx(ctx, &mut report);
            let struct_ms = struct_start.elapsed().as_millis();
            tracing::info!(
                path = %analysis_path.display(),
                rayon_thread = ?rayon::current_thread_index(),
                allow_rizin,
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
            let r2_strings_extracted: Option<Vec<stng::ExtractedString>> = None;

            // ELF overlay detection: data after the last PT_LOAD segment.
            let image_end = ctx
                .parsed
                .values()
                .get("elf.segments")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter(|seg| seg.get("type").and_then(|t| t.as_str()) == Some("load"))
                        .filter_map(|seg| {
                            let off = seg.get("file_offset")?.as_u64()?;
                            let sz = seg.get("file_size")?.as_u64()?;
                            Some(off.saturating_add(sz) as usize)
                        })
                        .max()
                        .unwrap_or(0)
                })
                .unwrap_or(0);
            if image_end > 0 && data.len() > image_end {
                let overlay = &data[image_end..];
                const SQUASHFS_LE: &[u8] = &[0x73, 0x71, 0x73, 0x68];
                const SQUASHFS_BE: &[u8] = &[0x68, 0x73, 0x71, 0x73];
                if overlay.starts_with(SQUASHFS_LE) || overlay.starts_with(SQUASHFS_BE) {
                    report.findings.push(crate::types::Finding {
                        id: "file/sfx/appimage".to_string(),
                        kind: crate::types::FindingKind::Structural,
                        desc: "Squashfs filesystem appended after ELF image (AppImage)".to_string(),
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
                    embedded_archive_count = embedded_archive_count.saturating_add(1);
                } else if let Ok(Some(ov)) = crate::analyzers::overlay::analyze_overlay(
                    overlay,
                    &report.target.path,
                    Some(self.capability_mapper.clone()),
                    None,
                ) {
                    report.findings.push(ov.sfx_finding);
                    report.findings.extend(ov.archive_report.findings);
                    report.files.extend(ov.archive_report.files);
                    embedded_archive_count = embedded_archive_count.saturating_add(1);
                }
            }

            // content_end = max of (sections file end, segments file end).
            // Sources both from filefacts's typed view + the kv segments
            // array so SHT_NOBITS sections are naturally skipped (their
            // file_size on the typed view is 0).
            let sections_end: u64 = ctx
                .parsed
                .sections()
                .iter()
                .map(|s| s.file_offset.saturating_add(s.file_size))
                .max()
                .unwrap_or(0);
            let segments_end: u64 = ctx
                .parsed
                .values()
                .get("elf.segments")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|seg| {
                            let off = seg.get("file_offset")?.as_u64()?;
                            let sz = seg.get("file_size")?.as_u64()?;
                            Some(off.saturating_add(sz))
                        })
                        .max()
                        .unwrap_or(0)
                })
                .unwrap_or(0);
            let content_end = sections_end.max(segments_end);

            (r2_strings_extracted, content_end)
        } else {
            // Filefacts's ELF parse failed (or it didn't identify the bytes
            // as ELF at all). Emit the structural finding, salvage
            // architecture from the raw header, and fall back to rizin
            // via the shared cached path.
            let err_msg = report
                .metadata
                .errors
                .iter()
                .find(|e| e.contains("elf-parse"))
                .cloned()
                .unwrap_or_default();
            let mut crit = Criticality::Suspicious;
            if report.target.path.contains("!!embedded") {
                crit = Criticality::Notable;
            } else {
                let has_go_cli_markers = data
                    .windows(b"-trimpath=true".len())
                    .any(|w| w == b"-trimpath=true")
                    && data.windows(b"go.mod".len()).any(|w| w == b"go.mod");
                let has_linuxbrew_marker = data
                    .windows(b"/home/linuxbrew/.linuxbrew/Cellar/".len())
                    .any(|w| w == b"/home/linuxbrew/.linuxbrew/Cellar/");
                let has_android_gif_drawable_marker =
                    report.target.path.contains("libpl_droidsonroids_gif.so")
                        || data
                            .windows(b"android-gif-drawable".len())
                            .any(|w| w == b"android-gif-drawable");
                if (data.len() >= 50 * 1024 * 1024 && (has_go_cli_markers || has_linuxbrew_marker))
                    || has_android_gif_drawable_marker
                {
                    // Very large Linuxbrew/Go CLI builds and some legacy
                    // Android native libraries can carry metadata layouts
                    // filefacts's parser rejects even though the executable is
                    // otherwise legitimate. Keep the structural anomaly
                    // visible, but below suspicious for these known-benign
                    // contexts.
                    crit = Criticality::Notable;
                }
            }
            report.findings.push(Finding {
                kind: FindingKind::Structural,
                id: "anti-analysis/malformed/elf-header".to_string(),
                desc: format!("Malformed ELF header or section headers: {err_msg}"),
                conf: 1.0,
                crit,
                mbc: Some("B0001".to_string()),
                attack: Some("T1027".to_string()),
                evidence: vec![],
                match_count: 0,
                trait_refs: vec![],
                source_file: None,
            });

            // Architecture salvage from raw header bytes — `e_machine` at
            // offset 18 (2 bytes); endianness via EI_DATA at offset 5.
            if data.len() >= 20 {
                let is_big_endian = data.get(5) == Some(&2);
                let e_machine = if is_big_endian {
                    u16::from_be_bytes([data[18], data[19]])
                } else {
                    u16::from_le_bytes([data[18], data[19]])
                };
                let arch = arch_name_from_machine(e_machine);
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
                if parse_panicked { "panicked" } else { "error" },
                if err_msg.is_empty() {
                    "filefacts could not parse ELF"
                } else {
                    err_msg.as_str()
                },
            ));

            // Rizin recovery is owned by `filefacts::open` now: when
            // goblin's ELF parse comes back empty, filefacts's internal
            // fallback re-runs through rizin and fills the unified
            // `Symbols` view with Function records (plus Imports /
            // Exports) before we ever look at them. Projecting from
            // `ctx.parsed.symbols()` here mirrors the happy path
            // and avoids duplicating the cache-key plumbing.
            report.functions = ctx
                .parsed
                .symbols()
                .iter_kind(filefacts::SymbolKind::Function)
                .filter_map(crate::analysis_context::project_filefacts_function)
                .collect();
            let _ = (parse_failed, allow_rizin, precomputed_sha256);
            (None, 0u64)
        };

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
            let _ = r2_strings;
            let raw = self.string_extractor.extract_raw_smart(data);
            (self.string_extractor.convert_stng_strings(&raw), Some(raw))
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
                embedded_binary_count = embedded_binary_count.saturating_add(1);
                if binary.offset >= data.len() {
                    continue;
                }
                // For base64-encoded payloads we must decode before
                // recursing — otherwise the child analyzer reads
                // base64 text and reports the embedded binary as
                // malformed (Kong-ingress-controller 2024).
                let decoded_storage: Vec<u8>;
                let embedded_bytes: &[u8] = if binary.encoding == Some("base64") {
                    let run_end = binary.offset
                        + data[binary.offset..]
                            .iter()
                            .take_while(|&&b| {
                                b.is_ascii_alphanumeric() || b == b'+' || b == b'/' || b == b'='
                            })
                            .count();
                    let trimmed_end = run_end - (run_end - binary.offset) % 4;
                    match base64::Engine::decode(
                        &base64::engine::general_purpose::STANDARD,
                        &data[binary.offset..trimmed_end],
                    ) {
                        Ok(b) => {
                            decoded_storage = b;
                            &decoded_storage[..]
                        }
                        Err(_) => continue,
                    }
                } else {
                    let slice_end = (binary.offset + binary.estimated_size).min(data.len());
                    &data[binary.offset..slice_end]
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
                    None, // YARA handled by child
                    raw_stng_strings.as_deref().unwrap_or(&[]),
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
                Some(&crate::FileType::Elf),
                self.cancellation.as_deref(),
            );
        report.files.extend(encoded_layers);
        report.findings.extend(plain_findings);

        // ELF binaries are usually unsigned (or use non-standard signing) —
        // this is the norm on Linux/BSD, so it's baseline metadata rather
        // than a notable deviation (unlike PE / Mach-O where signing is expected).
        if !is_core_dump {
            report.findings.push(Finding {
                id: "metadata/unsigned".to_string(),
                kind: FindingKind::Capability,
                desc: "Binary is not digitally signed".to_string(),
                conf: 1.0,
                crit: Criticality::Baseline,
                mbc: None,
                attack: None,
                trait_refs: vec![],
                evidence: vec![],
                match_count: 0,
                source_file: None,
            });
        }

        let _ = elf_content_end;

        // Emit recursive-scan counters. Mirrors pe.rs — embedded
        // payload discovery is cleave-side recursive work, not
        // filefacts's parse-time view.
        if embedded_binary_count > 0 || embedded_archive_count > 0 {
            use crate::types::core::MetricsExt;
            let flat = report
                .filefacts_metrics
                .get_or_insert_with(Default::default);
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

        // Free excess vector capacity to reduce memory footprint
        report.shrink_to_fit();

        report
    }

    /// `analyze_structure`'s filefacts-backed counterpart. Synthesises the
    /// same `binary/format/elf`, `binary/arch/*`, `binary/stripped`,
    /// `binary/pie`, and `metadata/build/debug::elf-debuglink` features
    /// but pulls every input from filefacts's view of the file.
    /// Synthesize `binary/format/elf`, `binary/arch/*`,
    /// `binary/stripped`, `binary/pie`, and `metadata/build/debug::elf-debuglink`
    /// structural features from filefacts's typed view.
    fn fill_structure_from_ctx(&self, ctx: &Ctx<'_>, data: &[u8], report: &mut AnalysisReport) {
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

        // `binary.is_stripped` = 1.0 when `.symtab` is absent (the
        // canonical "stripped" definition; filefacts computes this in
        // `binary_flags`).
        if metrics.get("binary.is_stripped").unwrap_or(0.0) > 0.0 {
            report.structure.push(StructuralFeature {
                id: "binary/stripped".to_string(),
                desc: "Symbol table stripped".to_string(),
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

        // `.gnu_debuglink` section — present when a build was stripped
        // with split-debug. Walk filefacts's typed section list, then
        // slice into `data` for the section contents.
        for section in parsed.sections().iter() {
            if section.name != ".gnu_debuglink" || section.file_size == 0 {
                continue;
            }
            let offset = section.file_offset as usize;
            let end = offset.saturating_add(section.file_size as usize);
            if end > data.len() {
                continue;
            }
            if let Some(debuglink) = Self::gnu_debuglink_name(&data[offset..end]) {
                Self::push_metadata_finding_at(
                    report,
                    "metadata/build/debug::elf-debuglink",
                    ".gnu_debuglink reference present",
                    "section",
                    debuglink,
                    format!("0x{:x}", section.file_offset),
                );
            }
        }
    }

    /// Project filefacts's typed Imports / Exports into the report.
    /// Capability lookup runs against each import's symbol so capability
    /// findings still attach. Exports come from `.dynsym` only —
    /// filefacts's typed view doesn't filefacts `.symtab` exports today.
    fn fill_dynamic_symbols_from_ctx(&self, ctx: &Ctx<'_>, report: &mut AnalysisReport) {
        for imp in ctx.imports_from_filefacts() {
            // Capability lookup runs against the symbol name; the
            // source argument is used only for evidence attribution.
            if let Some(cap) = self
                .capability_mapper
                .lookup(&imp.symbol, imp.offset.as_deref())
                && !report.findings.iter().any(|c| c.id == cap.id)
            {
                report.findings.push(cap);
            }
            report.imports.push(imp);
        }
        for exp in ctx.exports_from_filefacts() {
            if report.exports.iter().any(|e| e.symbol == exp.symbol) {
                continue;
            }
            report.exports.push(exp);
        }
        // STT_GNU_IFUNC names are surfaced via the value path
        // `elf.ifunc_symbols[]` (populated by binary_extractors) and
        // matched by the YAML trait `metadata/binary/linking::ifunc`.
    }

    /// Walk the section table from filefacts's typed `Sections` view +
    /// per-section entropies from its metric map.
    fn fill_sections_from_ctx(&self, ctx: &Ctx<'_>, report: &mut AnalysisReport) {
        let parsed = &ctx.parsed;
        let metrics_view = parsed.metrics();
        for (idx, section) in parsed.sections().iter().enumerate() {
            if section.file_size == 0 {
                continue;
            }
            let entropy = metrics_view
                .iter()
                .find(|(k, _)| *k == format!("sections[{idx}].entropy"))
                .map(|(_, v)| v)
                .unwrap_or(0.0);
            report.sections.push(Section {
                name: section.name.clone(),
                address: Some(section.vaddr),
                offset: Some(section.file_offset),
                size: section.file_size,
                entropy,
                permissions: Some(section.flags.join(",")),
                flags: section.flags.clone(),
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
        precomputed_sha256: Option<String>,
    ) -> AnalysisReport {
        match crate::analysis_context::AnalysisContext::open(file_path, data) {
            Ok(ctx) => self.analyze_structural_with_ctx(
                file_path,
                data,
                precomputed_sha256.as_deref(),
                &ctx,
            ),
            Err(e) => {
                let mut report = AnalysisReport::new(TargetInfo {
                    path: file_path.display().to_string(),
                    file_type: "elf".to_string(),
                    size_bytes: data.len() as u64,
                    sha256: precomputed_sha256
                        .unwrap_or_else(|| crate::analyzers::utils::calculate_sha256(data)),
                    architectures: None,
                });
                report
                    .metadata
                    .errors
                    .push(format!("filefacts open failed: {e}"));
                report
            }
        }
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
                ctx,
            );
        }

        // UPX-packed: structural analysis of packed binary first
        let mut report = self.analyze_elf_core(
            file_path,
            file_path,
            data,
            None,
            true,
            precomputed_sha256,
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
                if let Ok(temp_file) = tempfile::NamedTempFile::new()
                    && std::fs::write(temp_file.path(), &unpacked_data).is_ok()
                {
                    let opts = crate::analyzers::stng_analysis_opts(4);
                    let unpacked_strings =
                        stng::extract_strings_with_options(&unpacked_data, &opts);
                    // UPX-unpacked bytes differ from the caller's
                    // bytes; open a fresh context on the
                    // decompressed payload so the downstream
                    // helpers see a self-consistent view.
                    let Ok(unpacked_ctx) = crate::analysis_context::AnalysisContext::open(
                        temp_file.path(),
                        &unpacked_data,
                    ) else {
                        return report;
                    };
                    let unpacked_report = self.analyze_elf_core(
                        temp_file.path(),
                        temp_file.path(),
                        &unpacked_data,
                        Some(&unpacked_strings),
                        true,
                        None,
                        &unpacked_ctx,
                    );
                    let mut unpacked_report = unpacked_report;
                    crate::analyzers::binary_extractors::augment_report(
                        &mut unpacked_report,
                        &unpacked_data,
                    );
                    if let Some(yara) = &self.yara_engine {
                        match yara
                            .scan_bytes_to_findings(&unpacked_data, Some(&["elf", "so", "ko"]))
                        {
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
                    self.capability_mapper
                        .evaluate_and_merge_findings_with_precomputed(
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
}

impl Analyzer for ElfAnalyzer {
    fn analyze_input(&self, input: &AnalysisInput<'_>) -> Result<AnalysisReport> {
        // Use caller-provided strings when present; an empty slice means the
        // caller only supplied bytes, so the core analyzer should extract.
        let strings = if input.strings.is_empty() {
            None
        } else {
            Some(input.strings)
        };
        // Open filefacts-side parse once so analyze_elf_core's helpers
        // read structural data straight from filefacts. When filefacts can't
        // open the bytes, we still produce a report so tamper findings
        // and rizin disassembly surface for triage.
        let ctx = crate::analysis_context::AnalysisContext::open(input.path, input.data)
            .map_err(|e| anyhow::anyhow!("filefacts open failed for ELF: {e}"))?;
        let mut report = self.analyze_elf_core(
            input.path,
            input.backing_path(),
            input.data,
            strings,
            !input.skip_rizin,
            input.sha256.as_deref(),
            &ctx,
        );

        // Post-processing
        self.capability_mapper
            .evaluate_and_merge_findings_with_precomputed(
                &mut report,
                input.data,
                crate::capabilities::AnalysisBorrow::with_filefacts(None, Some(&ctx)),
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
        // ELF magic: `\x7fELF` (`7f 45 4c 46`). Read 4 bytes — the
        // full filefacts-backed parse runs once we commit to analyze().
        let Ok(mut file) = fs::File::open(file_path) else {
            return false;
        };
        use std::io::Read;
        let mut magic = [0u8; 4];
        file.read_exact(&mut magic).is_ok() && magic == [0x7f, b'E', b'L', b'F']
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_arch_name_from_machine_known() {
        assert_eq!(arch_name_from_machine(62), "x86_64");
        assert_eq!(arch_name_from_machine(183), "aarch64");
        assert_eq!(arch_name_from_machine(3), "i386");
        assert!(arch_name_from_machine(0xfff0).starts_with("unknown_"));
    }

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
    #[cfg(any())]
    fn _deleted_bounded_note_scanner_tests() {}

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
        assert!(
            report
                .metadata
                .tools_used
                .contains(&"filefacts".to_string())
        );
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
        use crate::upx::{UPXDecompressor, disable_upx};

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
        use crate::types::file_analysis::{FileAnalysis, encode_upx_path};

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

        // UPX materially changes static visibility even when otherwise legitimate.
        assert_eq!(finding.crit, Criticality::Suspicious);
        assert_eq!(finding.conf, 1.0);
        assert_eq!(finding.desc, "Binary contains a UPX packing marker");
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
