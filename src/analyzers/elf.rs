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
use crate::yara_engine::YaraEngine;
use anyhow::{Context, Result};
use goblin::elf::note::NT_GNU_BUILD_ID;
use goblin::elf::Elf;
use std::fs;
use std::path::Path;
use std::sync::Arc;

const MAX_ELF_NOTE_SECTIONS: usize = 64;
const MAX_ELF_NOTE_BYTES: usize = 1024 * 1024;
const MAX_ELF_NOTES: u32 = 4096;
const MAX_ELF_NOTE_NAME_BYTES: usize = 256;
const MAX_ELF_BUILD_ID_BYTES: usize = 1024;

#[derive(Debug, Clone, Default)]
struct ElfNoteSummary {
    note_count: u32,
    build_id: Option<Vec<u8>>,
    truncated: bool,
    /// `GNU_PROPERTY_X86_FEATURE_1_AND` IBT bit observed.
    has_cet_ibt: bool,
    /// `GNU_PROPERTY_X86_FEATURE_1_AND` SHSTK bit observed.
    has_cet_shstk: bool,
    /// `GNU_PROPERTY_AARCH64_FEATURE_1_AND` BTI bit observed.
    has_aarch64_bti: bool,
    /// `GNU_PROPERTY_AARCH64_FEATURE_1_AND` PAC bit observed.
    has_aarch64_pac: bool,
    /// Minimum kernel version from `NT_GNU_ABI_TAG` (e.g. `"3.2.0"`).
    gnu_abi_min_kernel: Option<String>,
    /// `GNU_PROPERTY_X86_ISA_1_NEEDED` decoded into a microarch
    /// level string (`"x86-64"`, `"x86-64-v2"`, …).
    x86_isa_level: Option<String>,
    /// `GNU_PROPERTY_AARCH64_FEATURE_PAUTH` platform/version string.
    pauth_scheme: Option<String>,
}

/// Analyzer for Linux ELF binaries (executables, shared objects, kernel modules)
#[derive(Debug)]
pub(crate) struct ElfAnalyzer {
    capability_mapper: Arc<CapabilityMapper>,
    radare2: Radare2Analyzer,
    string_extractor: StringExtractor,
    yara_engine: Option<Arc<YaraEngine>>,
    /// Pre-extracted strings from stng (avoids redundant extraction)
    preextracted_strings: Option<Vec<StringInfo>>,
    /// When true, skip scanning for embedded PE/ELF binaries (prevents recursion in sub-analysis).
    skip_embedded_scan: bool,
    /// Per-request cancellation flag.
    cancellation: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
}

/// Parse the descriptor of an `NT_GNU_PROPERTY_TYPE_0` note and
/// extract the modern hardening bits we care about into the summary.
///
/// Layout: a stream of `[type:u32, datasz:u32, data:datasz, pad to 8]`
/// records. We only inspect the X86_FEATURE_1_AND and
/// AARCH64_FEATURE_1_AND types; everything else is skipped.
fn parse_gnu_property_note(desc: &[u8], summary: &mut ElfNoteSummary) {
    const GNU_PROPERTY_X86_FEATURE_1_AND: u32 = 0xc0000002;
    const GNU_PROPERTY_X86_ISA_1_NEEDED: u32 = 0xc0008002;
    const GNU_PROPERTY_AARCH64_FEATURE_1_AND: u32 = 0xc0000000;
    const GNU_PROPERTY_AARCH64_FEATURE_PAUTH: u32 = 0xc0000001;
    const X86_FEATURE_1_IBT: u32 = 0x1;
    const X86_FEATURE_1_SHSTK: u32 = 0x2;
    const AARCH64_FEATURE_1_BTI: u32 = 0x1;
    const AARCH64_FEATURE_1_PAC: u32 = 0x2;

    let mut p = 0usize;
    while p + 8 <= desc.len() {
        let t = u32::from_le_bytes([desc[p], desc[p + 1], desc[p + 2], desc[p + 3]]);
        let dsz = u32::from_le_bytes([desc[p + 4], desc[p + 5], desc[p + 6], desc[p + 7]]) as usize;
        let data_start = p + 8;
        let Some(data_end) = data_start.checked_add(dsz) else {
            break;
        };
        if data_end > desc.len() {
            break;
        }
        if dsz >= 4 {
            let bits = u32::from_le_bytes([
                desc[data_start],
                desc[data_start + 1],
                desc[data_start + 2],
                desc[data_start + 3],
            ]);
            match t {
                GNU_PROPERTY_X86_FEATURE_1_AND => {
                    if bits & X86_FEATURE_1_IBT != 0 {
                        summary.has_cet_ibt = true;
                    }
                    if bits & X86_FEATURE_1_SHSTK != 0 {
                        summary.has_cet_shstk = true;
                    }
                }
                GNU_PROPERTY_AARCH64_FEATURE_1_AND => {
                    if bits & AARCH64_FEATURE_1_BTI != 0 {
                        summary.has_aarch64_bti = true;
                    }
                    if bits & AARCH64_FEATURE_1_PAC != 0 {
                        summary.has_aarch64_pac = true;
                    }
                }
                GNU_PROPERTY_X86_ISA_1_NEEDED => {
                    // Highest bit set determines the required level:
                    // 0x1 = baseline (x86-64), 0x2 = v2, 0x4 = v3, 0x8 = v4.
                    let level = if bits & 0x8 != 0 {
                        Some("x86-64-v4")
                    } else if bits & 0x4 != 0 {
                        Some("x86-64-v3")
                    } else if bits & 0x2 != 0 {
                        Some("x86-64-v2")
                    } else if bits & 0x1 != 0 {
                        Some("x86-64")
                    } else {
                        None
                    };
                    if let Some(s) = level {
                        summary.x86_isa_level = Some(s.to_string());
                    }
                }
                GNU_PROPERTY_AARCH64_FEATURE_PAUTH if dsz >= 8 => {
                    // Encoded as platform:u32 + version:u32.
                    {
                        let platform = bits;
                        let version = u32::from_le_bytes([
                            desc[data_start + 4],
                            desc[data_start + 5],
                            desc[data_start + 6],
                            desc[data_start + 7],
                        ]);
                        let scheme = match platform {
                            0x1 => format!("llvm.{version}"),
                            0x2 => format!("darwin.{version}"),
                            _ => format!("platform_{platform:#x}.{version}"),
                        };
                        summary.pauth_scheme = Some(scheme);
                    }
                }
                _ => {}
            }
        }
        // Each record is 8-byte padded.
        let next = (data_end + 7) & !7usize;
        if next <= p {
            break;
        }
        p = next;
    }
}

/// Resolve an ELF program-header `p_type` to its symbolic name.
/// Covers the standard PT_* values; falls back to `"PT_<hex>"` for
/// processor- or OS-specific types.
/// True when `name` resolves to one of the well-known dynamic loader
/// SO-names (`ld-linux-*`, `ld-musl-*`, `ld.so`, `ld64.so`).
/// Decompose `sh_flags` bits into the conventional name vocabulary
/// (`alloc`, `write`, `executable`, `merge`, `strings`, `info_link`,
/// `tls`). Matches expose's ELF flag vocabulary so trait rules that
/// key on `sections[*].flags` see the same values whether the data
/// came from cleave's legacy ELF parse or expose's typed view.
fn elf_sh_flag_names(flags: u64) -> Vec<String> {
    let mut out = Vec::new();
    if flags & 0x1 != 0 {
        out.push("write".into());
    }
    if flags & 0x2 != 0 {
        out.push("alloc".into());
    }
    if flags & 0x4 != 0 {
        out.push("executable".into());
    }
    if flags & 0x10 != 0 {
        out.push("merge".into());
    }
    if flags & 0x20 != 0 {
        out.push("strings".into());
    }
    if flags & 0x40 != 0 {
        out.push("info_link".into());
    }
    if flags & 0x100 != 0 {
        out.push("tls".into());
    }
    out
}

fn is_dynamic_loader_soname(name: &str) -> bool {
    let base = name.rsplit('/').next().unwrap_or(name);
    base.starts_with("ld-linux")
        || base.starts_with("ld-musl")
        || base.starts_with("ld.so")
        || base.starts_with("ld64.so")
        || base == "ld.so"
}

fn phdr_type_name(p_type: u32) -> String {
    let name = match p_type {
        0 => "PT_NULL",
        1 => "PT_LOAD",
        2 => "PT_DYNAMIC",
        3 => "PT_INTERP",
        4 => "PT_NOTE",
        5 => "PT_SHLIB",
        6 => "PT_PHDR",
        7 => "PT_TLS",
        0x6474_e550 => "PT_GNU_EH_FRAME",
        0x6474_e551 => "PT_GNU_STACK",
        0x6474_e552 => "PT_GNU_RELRO",
        0x6474_e553 => "PT_GNU_PROPERTY",
        _ => return format!("PT_{p_type:#x}"),
    };
    name.to_string()
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

    fn read_u32(bytes: &[u8], little_endian: bool) -> Option<u32> {
        let raw: [u8; 4] = bytes.get(..4)?.try_into().ok()?;
        Some(if little_endian {
            u32::from_le_bytes(raw)
        } else {
            u32::from_be_bytes(raw)
        })
    }

    fn align_note_offset(offset: usize, align: usize) -> Option<usize> {
        let align = if align == 0 { 4 } else { align };
        if !align.is_power_of_two() {
            return offset.checked_add(align - 1).map(|n| n / align * align);
        }
        offset.checked_add(align - 1).map(|n| n & !(align - 1))
    }

    fn is_gnu_note_name(name: &[u8]) -> bool {
        name.strip_suffix(&[0]).unwrap_or(name) == b"GNU"
    }

    // Work around goblin note parsing getting stuck on hostile or unusual SHT_NOTE
    // ranges: goblin's Note::try_from_ctx decodes note names as UTF-8 and can spend
    // unbounded CPU validating attacker-controlled namesz/section data. Cleave only
    // needs note count and GNU build-id, so scan raw bytes with explicit budgets.
    fn summarize_elf_notes<'a>(&self, elf: &Elf<'a>, data: &[u8]) -> ElfNoteSummary {
        use goblin::elf::section_header::SHT_NOTE;

        let mut summary = ElfNoteSummary::default();
        let mut sections_seen = 0usize;
        let mut bytes_scanned = 0usize;

        for section in &elf.section_headers {
            if section.sh_type != SHT_NOTE {
                continue;
            }

            sections_seen += 1;
            if sections_seen > MAX_ELF_NOTE_SECTIONS {
                summary.truncated = true;
                break;
            }

            let Ok(section_offset) = usize::try_from(section.sh_offset) else {
                summary.truncated = true;
                continue;
            };
            let Ok(section_size) = usize::try_from(section.sh_size) else {
                summary.truncated = true;
                continue;
            };
            if section_size == 0 {
                continue;
            }
            let Some(section_end) = section_offset.checked_add(section_size) else {
                summary.truncated = true;
                continue;
            };
            if section_offset >= data.len() || section_end > data.len() {
                summary.truncated = true;
                continue;
            }

            let remaining_budget = MAX_ELF_NOTE_BYTES.saturating_sub(bytes_scanned);
            if remaining_budget == 0 {
                summary.truncated = true;
                break;
            }
            let scan_len = section_size.min(remaining_budget);
            if scan_len < section_size {
                summary.truncated = true;
            }
            bytes_scanned = bytes_scanned.saturating_add(scan_len);

            let scan_end = section_offset + scan_len;
            let section_data = &data[section_offset..scan_end];
            let mut offset = 0usize;
            let align = usize::try_from(section.sh_addralign).unwrap_or(4).max(1);

            while offset
                .checked_add(12)
                .is_some_and(|end| end <= section_data.len())
            {
                if summary.note_count >= MAX_ELF_NOTES {
                    summary.truncated = true;
                    return summary;
                }

                let namesz =
                    match Self::read_u32(&section_data[offset..offset + 4], elf.little_endian) {
                        Some(value) => value as usize,
                        None => {
                            summary.truncated = true;
                            break;
                        }
                    };
                let descsz = match Self::read_u32(
                    &section_data[offset + 4..offset + 8],
                    elf.little_endian,
                ) {
                    Some(value) => value as usize,
                    None => {
                        summary.truncated = true;
                        break;
                    }
                };
                let Some(n_type) =
                    Self::read_u32(&section_data[offset + 8..offset + 12], elf.little_endian)
                else {
                    summary.truncated = true;
                    break;
                };

                let Some(name_start) = offset.checked_add(12) else {
                    summary.truncated = true;
                    break;
                };
                let Some(name_end) = name_start.checked_add(namesz) else {
                    summary.truncated = true;
                    break;
                };
                if name_end > section_data.len() {
                    summary.truncated = true;
                    break;
                }
                let Some(desc_start) = Self::align_note_offset(name_end, align) else {
                    summary.truncated = true;
                    break;
                };
                let Some(desc_end) = desc_start.checked_add(descsz) else {
                    summary.truncated = true;
                    break;
                };
                if desc_end > section_data.len() {
                    summary.truncated = true;
                    break;
                }
                let Some(next_offset) = Self::align_note_offset(desc_end, align) else {
                    summary.truncated = true;
                    break;
                };
                if next_offset <= offset {
                    summary.truncated = true;
                    break;
                }

                summary.note_count = summary.note_count.saturating_add(1);
                let name_bytes = &section_data[name_start..name_end];
                let desc_bytes = &section_data[desc_start..desc_end];
                let is_gnu = Self::is_gnu_note_name(name_bytes);
                if summary.build_id.is_none()
                    && n_type == NT_GNU_BUILD_ID
                    && namesz <= MAX_ELF_NOTE_NAME_BYTES
                    && descsz <= MAX_ELF_BUILD_ID_BYTES
                    && is_gnu
                {
                    summary.build_id = Some(desc_bytes.to_vec());
                } else if namesz > MAX_ELF_NOTE_NAME_BYTES || descsz > MAX_ELF_BUILD_ID_BYTES {
                    summary.truncated = true;
                }
                // NT_GNU_ABI_TAG (1) — minimum kernel version when
                // os == GNU/Linux (0).
                if n_type == 1 && is_gnu && desc_bytes.len() >= 16 {
                    let os = u32::from_le_bytes([
                        desc_bytes[0],
                        desc_bytes[1],
                        desc_bytes[2],
                        desc_bytes[3],
                    ]);
                    if os == 0 && summary.gnu_abi_min_kernel.is_none() {
                        let major = u32::from_le_bytes([
                            desc_bytes[4],
                            desc_bytes[5],
                            desc_bytes[6],
                            desc_bytes[7],
                        ]);
                        let minor = u32::from_le_bytes([
                            desc_bytes[8],
                            desc_bytes[9],
                            desc_bytes[10],
                            desc_bytes[11],
                        ]);
                        let sub = u32::from_le_bytes([
                            desc_bytes[12],
                            desc_bytes[13],
                            desc_bytes[14],
                            desc_bytes[15],
                        ]);
                        summary.gnu_abi_min_kernel = Some(format!("{major}.{minor}.{sub}"));
                    }
                }
                // NT_GNU_PROPERTY_TYPE_0 (5) — walk type-tagged
                // properties for CET / BTI / PAC bits.
                if n_type == 5 && is_gnu {
                    parse_gnu_property_note(desc_bytes, &mut summary);
                }

                if next_offset > section_data.len() {
                    summary.truncated = true;
                    break;
                }
                offset = next_offset;
            }
        }

        summary
    }

    /// Creates a new ELF analyzer with default configuration
    #[must_use]
    pub(crate) fn new() -> Self {
        Self {
            capability_mapper: Arc::new(CapabilityMapper::empty()),
            radare2: Radare2Analyzer::new(),
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
        precomputed_sha256: Option<String>,
        ctx: Option<&crate::analysis_context::AnalysisContext<'a>>,
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
        let mut embedded_binary_count: u32 = 0;
        let mut embedded_archive_count: u32 = 0;

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
                // Source structural facts from ctx when available — the
                // ELF type ("core" string), arch name, and symbol-table
                // presence all live in expose's emitted view.
                let is_core_dump = ctx
                    .and_then(|c| {
                        c.parsed
                            .values()
                            .get("elf.type")
                            .and_then(|v| v.as_str())
                            .map(|s| s == "core")
                    })
                    .unwrap_or_else(|| elf.header.e_type == goblin::elf::header::ET_CORE);

                report.target.architectures = Some(vec![ctx
                    .and_then(|c| {
                        c.parsed
                            .values()
                            .get("elf.machine")
                            .and_then(|v| v.as_str())
                            .map(str::to_string)
                    })
                    .unwrap_or_else(|| self.arch_name(&elf))]);

                let note_summary = if let Some(c) = ctx {
                    self.summarize_elf_notes_from_ctx(c)
                } else {
                    self.summarize_elf_notes(&elf, data)
                };

                // Compute ELF-specific metrics
                let elf_metrics = if let Some(c) = ctx {
                    self.compute_elf_metrics_from_ctx(c, &note_summary)
                } else {
                    self.compute_elf_metrics(&elf, &note_summary, data)
                };
                let symbols_found = ctx
                    .map(|c| c.parsed.metrics().get("elf.symtab_count").unwrap_or(0.0) > 0.0)
                    .unwrap_or_else(|| !elf.syms.is_empty());

                // Calculate code_size from executable section sizes
                // (more accurate than radare2's function discovery).
                let code_size = Some(if let Some(c) = ctx {
                    self.compute_code_size_from_ctx(c)
                } else {
                    self.compute_code_size(&elf)
                });
                let needs_r2_strings =
                    stng_strings.is_none() && self.preextracted_strings.is_none();

                // Overlap rizin (subprocess-bound) with goblin structural work
                // (CPU-bound) only for off-pool callers. Inside archive-member
                // `par_iter`, a nested `rayon::join` can starve the pool if each
                // worker blocks in the rizin arm while its goblin sibling task is
                // still queued.
                let on_rayon_worker = rayon::current_thread_index().is_some();
                let mut goblin_ms = 0u128;
                let mut rizin_ms = 0u128;
                if on_rayon_worker && allow_rizin {
                    tracing::debug!(
                        path = %analysis_path.display(),
                        size_bytes = data.len(),
                        symbols_found,
                        needs_r2_strings,
                        rayon_thread = ?rayon::current_thread_index(),
                        "ELF analysis on rayon worker; running goblin and rizin sequentially to avoid nested join starvation",
                    );
                }
                let r2_inner = if on_rayon_worker {
                    let goblin_start = std::time::Instant::now();
                    if let Some(c) = ctx {
                        self.analyze_structure_from_ctx(c, data, &mut report);
                    } else {
                        self.analyze_structure(&elf, data, &mut report);
                    }
                    self.analyze_dynamic_symbols(&elf, data, &mut report, ctx);
                    if let Some(c) = ctx {
                        self.analyze_sections_from_ctx(c, &mut report);
                    } else {
                        self.analyze_sections(&elf, data, &mut report);
                    }
                    goblin_ms = goblin_start.elapsed().as_millis();
                    if !allow_rizin || self.is_cancelled() || !Radare2Analyzer::is_available() {
                        None
                    } else {
                        let rizin_start = std::time::Instant::now();
                        let out = Some(self.radare2.extract_batched(
                            analysis_path,
                            data.len() as u64,
                            symbols_found,
                            true, // goblin_success
                            needs_r2_strings,
                            precomputed_sha256,
                            self.cancellation.as_ref(),
                            Some(data),
                        ));
                        rizin_ms = rizin_start.elapsed().as_millis();
                        out
                    }
                } else {
                    let (r2_inner, _) = rayon::join(
                        || {
                            if !allow_rizin
                                || self.is_cancelled()
                                || !Radare2Analyzer::is_available()
                            {
                                return None;
                            }
                            let rizin_start = std::time::Instant::now();
                            let out = Some(self.radare2.extract_batched(
                                analysis_path,
                                data.len() as u64,
                                symbols_found,
                                true, // goblin_success
                                needs_r2_strings,
                                precomputed_sha256,
                                self.cancellation.as_ref(),
                                Some(data),
                            ));
                            rizin_ms = rizin_start.elapsed().as_millis();
                            out
                        },
                        || {
                            let goblin_start = std::time::Instant::now();
                            if let Some(c) = ctx {
                        self.analyze_structure_from_ctx(c, data, &mut report);
                    } else {
                        self.analyze_structure(&elf, data, &mut report);
                    }
                            self.analyze_dynamic_symbols(&elf, data, &mut report, ctx);
                            if let Some(c) = ctx {
                        self.analyze_sections_from_ctx(c, &mut report);
                    } else {
                        self.analyze_sections(&elf, data, &mut report);
                    }
                            goblin_ms = goblin_start.elapsed().as_millis();
                        },
                    );
                    r2_inner
                };
                tracing::info!(
                    path = %analysis_path.display(),
                    on_rayon_worker,
                    rayon_thread = ?rayon::current_thread_index(),
                    allow_rizin,
                    symbols_found,
                    scope_goblin_ms = goblin_ms as u64,
                    scope_rizin_ms = rizin_ms as u64,
                    "ELF structural phase timings",
                );

                // Process Radare2 results if available
                let r2_strings_extracted = if let Some(Ok(batched)) = r2_inner {
                    tools_used.push("radare2".to_string());
                    crate::radare2::push_rizin_warnings(&mut report, &batched);

                    // Compute metrics from batched data
                    let mut binary_metrics = self.radare2.compute_metrics_from_batched(
                        &batched,
                        data.len() as u64,
                        "elf",
                    );

                    // Override code_size with goblin-based calculation (more accurate)
                    // In ELF, only sections with SHF_EXECINSTR flag contain executable code
                    if let Some(mut cs) = code_size {
                        let file_size = data.len() as u64;
                        // Sanity check: code_size should never exceed file size
                        if cs > file_size {
                            eprintln!("WARNING: code_size ({}) > file_size ({}) - this indicates a bug in section classification", cs, file_size);
                            cs = file_size; // Cap at file_size to prevent invalid ratio
                        }

                        binary_metrics.code_size = cs;

                        // Recalculate code_to_data_ratio with correct code_size
                        if file_size > 0 {
                            let data_size = file_size.saturating_sub(cs);
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
                            binary_metrics.func_density =
                                binary_metrics.func_count as f32 / code_kb;
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
                            embedded_archive_count = embedded_archive_count.saturating_add(1);
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
                                embedded_archive_count = embedded_archive_count.saturating_add(1);
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
                        data.len() as u64,
                        false, // has_symbols=false: nothing came back from goblin
                        false, // goblin_success=false
                        needs_r2_strings,
                        fallback_sha256,
                        self.cancellation.as_ref(),
                        Some(data),
                    ) {
                        Ok(batched) => {
                            tools_used.push("radare2".to_string());
                            crate::radare2::push_rizin_warnings(&mut report, &batched);
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

        // Populate common binary metrics (strings, entropy, etc.)
        crate::analyzers::metrics_utils::populate_binary_metrics(&mut report, data);

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

        // Flush embedded content counters into binary metrics.
        if let Some(ref mut metrics) = report.metrics {
            if let Some(ref mut binary) = metrics.binary {
                binary.embedded_binary_count = embedded_binary_count;
                binary.embedded_archive_count = embedded_archive_count;
                binary.embedded_file_count =
                    embedded_binary_count.saturating_add(embedded_archive_count);
            }
        }

        // Validate metric ranges to catch calculation bugs
        if let Some(ref metrics) = report.metrics {
            if let Some(ref binary) = metrics.binary {
                binary.validate(&report.target.path, report.target.size_bytes);
            }
        }

        report.metadata.analysis_duration_ms = start.elapsed().as_millis() as u64;
        report.metadata.tools_used = tools_used;

        // Free excess vector capacity to reduce memory footprint
        report.shrink_to_fit();

        report
    }

    /// `analyze_structure`'s expose-backed counterpart. Synthesises the
    /// same `binary/format/elf`, `binary/arch/*`, `binary/stripped`,
    /// `binary/pie`, and `metadata/build/debug::elf-debuglink` features
    /// but pulls every input from expose's view of the file.
    fn analyze_structure_from_ctx(
        &self,
        ctx: &crate::analysis_context::AnalysisContext<'_>,
        data: &[u8],
        report: &mut AnalysisReport,
    ) {
        let parsed = &ctx.parsed;
        let metrics = parsed.metrics();
        let values = parsed.values();

        report.structure.push(StructuralFeature {
            id: "binary/format/elf".to_string(),
            desc: "ELF binary format".to_string(),
            evidence: vec![Evidence {
                method: "magic".to_string(),
                source: "expose".to_string(),
                value: "0x7f".to_string(), // ELF magic byte 0
                location: None,
                ..Default::default()
            }],
        });

        // Architecture comes from expose's `elf.machine` string (e.g.
        // "x86_64"). Fall back to "unknown" when expose couldn't
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
                source: "expose".to_string(),
                value: format!("elf.machine={}", arch),
                location: None,
                ..Default::default()
            }],
        });

        // `binary.is_stripped` = 1.0 when `.symtab` is absent (the
        // canonical "stripped" definition; expose computes this in
        // `binary_flags`).
        if metrics.get("binary.is_stripped").unwrap_or(0.0) > 0.0 {
            report.structure.push(StructuralFeature {
                id: "binary/stripped".to_string(),
                desc: "Symbol table stripped".to_string(),
                evidence: vec![Evidence {
                    method: "symbols".to_string(),
                    source: "expose".to_string(),
                    value: "no_symtab".to_string(),
                    location: None,
                    ..Default::default()
                }],
            });
        }

        // PIE detection: expose flags `binary.is_pie = 1.0` for
        // dynamically-linked ET_DYN executables (shared libraries that
        // are also ET_DYN don't count).
        if metrics.get("binary.is_pie").unwrap_or(0.0) > 0.0 {
            report.structure.push(StructuralFeature {
                id: "binary/pie".to_string(),
                desc: "Position Independent Executable".to_string(),
                evidence: vec![Evidence {
                    method: "header".to_string(),
                    source: "expose".to_string(),
                    value: "ET_DYN".to_string(),
                    location: None,
                    ..Default::default()
                }],
            });
        }

        // `.gnu_debuglink` section — present when a build was stripped
        // with split-debug. Walk expose's typed section list, then
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

        // ELF dynamic-linking metadata (interpreter, soname, needed
        // libs, rpath, runpath) is now emitted by YAML traits in
        // `metadata/binary/linking/runtime/elf.yaml` reading from the
        // binary kv tree (`elf.{interpreter,soname,needed,rpath,runpath}`).
        // The kv tree is populated by `compute_elf_metrics` →
        // `analyzers::binary_kv::elf_section`.

        // ELF GNU build-id is now emitted by the YAML trait
        // `metadata/build/reproducible::elf-build-id` reading from the
        // binary kv tree (`debug.build_id` — populated by
        // `compute_elf_metrics`).

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
        ctx: Option<&crate::analysis_context::AnalysisContext<'_>>,
    ) {
        // When the shared expose-side parse is available, mirror its
        // typed Imports/Exports views — expose's `elf-dynsym` source
        // emits exactly the same SHN_UNDEF / STB_GLOBAL distinction
        // this loop was doing, and st_value flows through as the
        // export offset already. The legacy goblin path stays as the
        // fallback when ctx is None.
        if let Some(c) = ctx {
            for imp in c.imports_from_expose() {
                // Capability lookup still runs over whichever source
                // produced the imports; lookup uses source only for
                // evidence attribution.
                if let Some(cap) = self.capability_mapper.lookup(&imp.symbol, &imp.source) {
                    if !report.findings.iter().any(|c| c.id == cap.id) {
                        report.findings.push(cap);
                    }
                }
                report.imports.push(imp);
            }
            // Exports flow through directly. Note: expose's typed
            // view only carries dynsym-derived exports today; the
            // legacy path also raked .symtab for additional STT_FUNC
            // GLOBALs — that second pass is a follow-up (#65-ish).
            // For stripped binaries (the common case) .symtab is
            // empty and the two paths produce identical exports.
            for exp in c.exports_from_expose() {
                if report.exports.iter().any(|e| e.symbol == exp.symbol) {
                    continue;
                }
                report.exports.push(exp);
            }
            return;
        }

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
            // STT_GNU_IFUNC names are surfaced via the kv path
            // `elf.ifunc_symbols[]` (populated by binary_extractors)
            // and matched by the YAML trait
            // `metadata/binary/linking::ifunc`.
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
                    report.exports.push(Export::new(
                        name,
                        Some(format!("{:#x}", sym.st_value)),
                        "goblin",
                    ));
                    // STT_GNU_IFUNC names from .symtab flow into the
                    // `elf.ifunc_symbols[]` kv path via the
                    // binary_extractors scan. The YAML trait
                    // `metadata/binary/linking::ifunc` reads from kv.
                }
            }
        }
    }

    /// Walk the section table from expose's typed `Sections` view +
    /// per-section entropies from its metric map. No second goblin
    /// parse — the data is already in `ctx.parsed`.
    fn analyze_sections_from_ctx(
        &self,
        ctx: &crate::analysis_context::AnalysisContext<'_>,
        report: &mut AnalysisReport,
    ) {
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
                        flags: elf_sh_flag_names(section.sh_flags),
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

    /// Map an ELF `e_machine` value to its canonical short name. The
    /// constants come straight from the System V ABI / `elf.h` and
    /// are stable across vendors, so a literal match avoids depending
    /// on goblin's re-export.
    fn arch_name_from_machine(&self, e_machine: u16) -> String {
        match e_machine {
            62 => "x86_64".to_string(),     // EM_X86_64
            3 => "i386".to_string(),        // EM_386
            183 => "aarch64".to_string(),   // EM_AARCH64
            40 => "arm".to_string(),        // EM_ARM
            243 => "riscv".to_string(),     // EM_RISCV
            8 => "mips".to_string(),        // EM_MIPS
            20 => "powerpc".to_string(),    // EM_PPC
            21 => "powerpc64".to_string(),  // EM_PPC64
            2 | 18 | 43 => "sparc".to_string(), // EM_SPARC + SPARC32PLUS + SPARCV9
            4 => "m68k".to_string(),        // EM_68K
            22 => "s390".to_string(),       // EM_S390
            42 => "superh".to_string(),     // EM_SH
            _ => format!("unknown_{}", e_machine),
        }
    }
    /// Compute ELF-specific metrics from parsed ELF binary
    fn compute_elf_metrics<'a>(
        &self,
        elf: &Elf<'a>,
        note_summary: &ElfNoteSummary,
        data: &[u8],
    ) -> ElfMetrics {
        use goblin::elf::dynamic::{
            DT_BIND_NOW, DT_FINI_ARRAYSZ, DT_GNU_HASH, DT_INIT_ARRAYSZ, DT_RPATH, DT_RUNPATH,
            DT_TEXTREL,
        };
        use goblin::elf::program_header::{PF_X, PT_GNU_RELRO, PT_GNU_STACK, PT_LOAD};
        use goblin::elf::sym::STB_LOCAL;

        // RPATH/RUNPATH entries from goblin arrive as one Vec entry per
        // DT_*PATH dynamic tag, but each entry is itself a `:`-separated
        // list of paths.  Split so each path is its own string — that's
        // the form trait authors and downstream tooling expect.
        let split_paths = |entries: &[&str]| -> Vec<String> {
            entries
                .iter()
                .flat_map(|e| e.split(':'))
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_string)
                .collect()
        };

        let mut metrics = ElfMetrics {
            e_type: elf.header.e_type as u32,
            e_machine: elf.header.e_machine as u32,
            class_bits: if elf.is_64 { 64 } else { 32 },
            little_endian: elf.little_endian,
            entry: elf.entry,
            program_header_count: elf.program_headers.len() as u32,
            section_count: elf.section_headers.len() as u32,
            has_interpreter: elf.interpreter.is_some(),
            has_soname: elf.soname.is_some(),
            soname: elf.soname.map(str::to_string),
            needed: elf.libraries.iter().map(|s| (*s).to_string()).collect(),
            rpaths: split_paths(&elf.rpaths),
            runpaths: split_paths(&elf.runpaths),
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
            use goblin::elf::dynamic::{
                DT_AUDIT, DT_DEBUG, DT_DEPAUDIT, DT_FLAGS_1, DT_PREINIT_ARRAYSZ, DT_RELACOUNT,
                DT_VERSYM,
            };
            // DT_RELR family — modern compressed relocations.
            // glibc 2.36+ / lld 13+. Not exposed by goblin as named
            // constants; use literal values from the ELF spec.
            const DT_RELR: u64 = 36;
            let mut preinit_arraysz: u64 = 0;
            for dyn_entry in &dynamic.dyns {
                match dyn_entry.d_tag {
                    DT_RPATH => metrics.has_rpath = true,
                    DT_RUNPATH => metrics.has_runpath = true,
                    DT_TEXTREL => metrics.has_textrel = true,
                    DT_GNU_HASH => metrics.has_gnu_hash = true,
                    // DT_BIND_NOW + GNU_RELRO = Full RELRO
                    DT_BIND_NOW if metrics.relro.is_some() => {
                        metrics.relro = Some("full".to_string());
                    }
                    DT_INIT_ARRAYSZ => init_arraysz = dyn_entry.d_val,
                    DT_FINI_ARRAYSZ => fini_arraysz = dyn_entry.d_val,
                    DT_AUDIT => metrics.has_dt_audit = true,
                    DT_DEPAUDIT => metrics.has_dt_depaudit = true,
                    DT_FLAGS_1 => metrics.dt_flags_1 = dyn_entry.d_val as u32,
                    // Tier A — modern toolchain / hardening signals.
                    DT_RELR => metrics.has_dt_relr = true,
                    DT_PREINIT_ARRAYSZ => preinit_arraysz = dyn_entry.d_val,
                    DT_DEBUG if dyn_entry.d_val != 0 => {
                        metrics.has_dt_debug = true;
                    }
                    DT_VERSYM if metrics.dt_versym_count == 0 => {
                        // DT_VERSYM stores the address of the
                        // versym table; presence implies versioned
                        // symbols are used. Set to 1 as a marker;
                        // the actual count is filled in below from
                        // the section if available.
                        metrics.dt_versym_count = 1;
                    }
                    DT_RELACOUNT => metrics.relacount = dyn_entry.d_val as u32,
                    _ => {}
                }
            }
            let ptr_size_for_preinit = if elf.is_64 { 8u64 } else { 4u64 };
            if preinit_arraysz > 0 {
                metrics.dt_preinit_array_count = (preinit_arraysz / ptr_size_for_preinit) as u32;
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

        // DT_NEEDED path-shape anomalies + DT_RUNPATH $ORIGIN check
        // + direct dynamic-loader dependency.
        for needed in &metrics.needed {
            if needed.starts_with('/') {
                metrics.dt_needed_abs_path_count =
                    metrics.dt_needed_abs_path_count.saturating_add(1);
            }
            if needed.split('/').any(|seg| seg == "..") {
                metrics.dt_needed_traversal_count =
                    metrics.dt_needed_traversal_count.saturating_add(1);
            }
            if is_dynamic_loader_soname(needed.as_str()) {
                metrics.has_direct_loader_dep = true;
            }
        }
        if metrics.runpaths.iter().any(|p| p.contains("$ORIGIN")) {
            metrics.dt_runpath_uses_origin = true;
        }

        // Program header analysis (security features + Tier A anomalies)
        use goblin::elf::program_header::{PF_R, PF_W, PT_INTERP};
        let mut interp_count = 0u32;
        let mut wx_count = 0u32;
        let mut load_ranges: Vec<(u64, u64, usize)> = Vec::new();
        let mut bss_segments_present = false;
        let mut entry_in_writable = false;
        let mut entry_in_section = false;
        let mut last_load_idx: Option<usize> = None;
        let mut last_load_vaddr: u64 = 0;
        let mut min_load_offset: Option<u64> = None;

        for (idx, ph) in elf.program_headers.iter().enumerate() {
            if ph.p_type == PT_LOAD {
                metrics.load_segment_max_p_filesz =
                    metrics.load_segment_max_p_filesz.max(ph.p_filesz);
                metrics.load_segment_max_p_memsz = metrics.load_segment_max_p_memsz.max(ph.p_memsz);
                let span = ph.p_memsz.max(ph.p_filesz);
                let end = ph.p_vaddr.saturating_add(span);
                load_ranges.push((ph.p_vaddr, end, idx));
                if ph.p_filesz < ph.p_memsz {
                    bss_segments_present = true;
                }
                if (ph.p_flags & PF_W) != 0 && (ph.p_flags & PF_X) != 0 {
                    wx_count = wx_count.saturating_add(1);
                }
                if elf.entry >= ph.p_vaddr && elf.entry < end && elf.entry != 0 {
                    entry_in_section = true;
                    if (ph.p_flags & PF_W) != 0 {
                        entry_in_writable = true;
                    }
                }
                if last_load_idx.is_none() || ph.p_vaddr > last_load_vaddr {
                    last_load_idx = Some(idx);
                    last_load_vaddr = ph.p_vaddr;
                }
                min_load_offset = Some(
                    min_load_offset
                        .map(|m| m.min(ph.p_offset))
                        .unwrap_or(ph.p_offset),
                );
            }
            // Carrier population — every program header surfaces via kv.
            let perms = format!(
                "{}{}{}",
                if ph.p_flags & PF_R != 0 { "r" } else { "-" },
                if ph.p_flags & PF_W != 0 { "w" } else { "-" },
                if ph.p_flags & PF_X != 0 { "x" } else { "-" },
            );
            metrics
                .segment_entries
                .push(crate::types::binary_metrics::ElfSegmentEntry {
                    p_type: phdr_type_name(ph.p_type),
                    p_vaddr: ph.p_vaddr,
                    p_offset: ph.p_offset,
                    p_filesz: ph.p_filesz,
                    p_memsz: ph.p_memsz,
                    flags_hex: format!("{:x}", ph.p_flags),
                    perms,
                });

            match ph.p_type {
                // GNU_RELRO present (partial unless DT_BIND_NOW also set)
                PT_GNU_RELRO if metrics.relro.is_none() => {
                    metrics.relro = Some("partial".to_string());
                }
                PT_GNU_STACK => {
                    // Check if stack is executable
                    metrics.nx_enabled = (ph.p_flags & PF_X) == 0;
                    if (ph.p_flags & PF_X) != 0 {
                        metrics.executable_stack = true;
                    }
                }
                PT_INTERP => {
                    interp_count = interp_count.saturating_add(1);
                }
                _ => {}
            }
        }

        // Tier A derived signals.
        metrics.wx_segment_count = wx_count;
        metrics.entry_in_writable_segment = entry_in_writable;
        metrics.entry_outside_segments = !entry_in_section && elf.entry != 0;
        metrics.multiple_pt_interp = interp_count > 1;
        if let Some(idx) = last_load_idx {
            // EP in last segment when found section is the last by vaddr.
            for ph in &elf.program_headers {
                if ph.p_type == PT_LOAD {
                    let span = ph.p_memsz.max(ph.p_filesz);
                    let end = ph.p_vaddr.saturating_add(span);
                    if elf.entry >= ph.p_vaddr && elf.entry < end && elf.entry != 0 {
                        if elf.program_headers.iter().position(|p| std::ptr::eq(p, ph)) == Some(idx)
                        {
                            metrics.entry_in_last_segment = true;
                        }
                        break;
                    }
                }
            }
        }
        // Section overlap (count pairs of overlapping vaddr ranges).
        if load_ranges.len() > 1 {
            let mut sorted = load_ranges.clone();
            sorted.sort_by_key(|t| t.0);
            let mut overlap_idxs: std::collections::HashSet<usize> =
                std::collections::HashSet::new();
            for w in sorted.windows(2) {
                let (a_start, a_end, a_idx) = w[0];
                let (b_start, _, b_idx) = w[1];
                if a_end > b_start && b_start >= a_start {
                    overlap_idxs.insert(a_idx);
                    overlap_idxs.insert(b_idx);
                }
            }
            metrics.segment_overlap_count = overlap_idxs.len() as u32;
            let mut names: Vec<String> = overlap_idxs
                .into_iter()
                .map(|i| format!("PT_LOAD#{i}"))
                .collect();
            names.sort();
            metrics.overlapping_segments = names;
        }
        // First-segment gap: bytes between (e_phoff + e_phnum * e_phentsize)
        // and the first PT_LOAD's p_offset.
        let header_end = elf
            .header
            .e_phoff
            .saturating_add(elf.header.e_phnum as u64 * elf.header.e_phentsize as u64);
        if let Some(first_off) = min_load_offset {
            if first_off > header_end {
                metrics.first_segment_gap = (first_off - header_end) as u32;
            }
        }
        // Section header count mismatch.
        metrics.section_header_count_mismatch =
            elf.header.e_shnum as usize != elf.section_headers.len();
        let _ = bss_segments_present;

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

        metrics.hidden_symbol_count = hidden_count;
        metrics.stack_canary = has_stack_chk;

        // Section analysis
        let mut has_gnu_stack_section = false;
        let mut has_dot_hash = false;
        let mut has_dot_gnu_hash = false;
        let mut has_dot_text_writable = false;
        let mut has_dot_rodata_writable = false;
        let mut has_symtab = false;
        let mut compressed_count: u32 = 0;
        let mut name_seen_count: std::collections::HashMap<String, u32> =
            std::collections::HashMap::new();
        const SHF_WRITE: u64 = 0x1;
        const SHF_COMPRESSED: u64 = 0x800;
        for sh in &elf.section_headers {
            if sh.sh_flags & SHF_COMPRESSED != 0 {
                compressed_count = compressed_count.saturating_add(1);
            }
            if let Some(name) = elf.shdr_strtab.get_at(sh.sh_name) {
                if !name.is_empty() {
                    *name_seen_count.entry(name.to_string()).or_default() += 1;
                }
                match name {
                    ".plt" => metrics.has_plt = true,
                    ".got" | ".got.plt" => metrics.has_got = true,
                    ".eh_frame" => metrics.has_eh_frame = true,
                    n if n.starts_with(".note") => metrics.has_note = true,
                    ".gnu_debuglink" => metrics.has_debuglink = true,
                    n if n.starts_with(".debug") || n == ".zdebug" || n.starts_with(".zdebug") => {
                        metrics.debug_section_count += 1;
                    }
                    ".note.GNU-stack" => has_gnu_stack_section = true,
                    ".hash" => has_dot_hash = true,
                    ".gnu.hash" => has_dot_gnu_hash = true,
                    ".gnu.version" => {
                        // 16-bit half per dynamic symbol — accurate
                        // count overrides the marker set during the
                        // dynamic-tag walk.
                        let count = (sh.sh_size / 2) as u32;
                        if count > 0 {
                            metrics.dt_versym_count = count;
                        }
                    }
                    ".text" if sh.sh_flags & SHF_WRITE != 0 => has_dot_text_writable = true,
                    ".rodata" if sh.sh_flags & SHF_WRITE != 0 => has_dot_rodata_writable = true,
                    ".symtab" => has_symtab = true,
                    _ => {}
                }
            }
        }
        // Tier B section-anomaly metrics.
        // `.note.GNU-stack` absence is only meaningful for non-relocatable
        // objects (executables / shared libraries). Object files (.o)
        // legitimately omit it.
        if !has_gnu_stack_section && elf.header.e_type != 1 {
            metrics.gnu_stack_section_absent = true;
        }
        metrics.has_both_hash_tables = has_dot_hash && has_dot_gnu_hash;
        metrics.duplicate_section_name_count =
            name_seen_count.values().filter(|&&c| c > 1).count() as u32;
        // Direct writes — the consistency layer used to bridge these
        // through internal carriers; we now own the public fields.
        metrics.text_section_writable = has_dot_text_writable;
        metrics.rodata_writable = has_dot_rodata_writable;
        // `stripped_but_symtab_present` is a derived bool: `.symtab`
        // present AND no debug sections (set later when
        // debug_section_count is finalised).
        metrics.stripped_but_symtab_present = has_symtab && metrics.debug_section_count == 0;
        metrics.compressed_sections_count = compressed_count;

        // FORTIFY_SOURCE — count `__*_chk` imports in dynsym.
        let mut fortify_count: u32 = 0;
        for sym in elf.dynsyms.iter() {
            if let Some(name) = elf.dynstrtab.get_at(sym.st_name) {
                if name.starts_with("__") && name.ends_with("_chk") {
                    fortify_count = fortify_count.saturating_add(1);
                }
            }
        }
        metrics.fortify_source_used = fortify_count;

        // Linker family — derive from .comment section content if
        // present. Common signatures: "GNU ld", "gold", "LLD", "mold".
        for sh in &elf.section_headers {
            if let Some(name) = elf.shdr_strtab.get_at(sh.sh_name) {
                if name == ".comment" {
                    let start = sh.sh_offset as usize;
                    let end = start.saturating_add(sh.sh_size as usize);
                    if end <= data.len() && start < end {
                        let comment = String::from_utf8_lossy(&data[start..end]);
                        let family = if comment.contains("LLD ") || comment.contains("ld.lld") {
                            Some("lld")
                        } else if comment.contains("mold") {
                            Some("mold")
                        } else if comment.contains("gold") {
                            Some("gold")
                        } else if comment.contains("GNU ld") || comment.contains("GNU ld.bfd") {
                            Some("gnu_ld")
                        } else {
                            None
                        };
                        if let Some(f) = family {
                            metrics.linker_family = Some(f.to_string());
                            break;
                        }
                    }
                }
            }
        }

        metrics.note_count = note_summary.note_count;
        if let Some(build_id) = &note_summary.build_id {
            metrics.has_build_id = true;
            metrics.build_id_length = build_id.len() as u32;
            metrics.build_id = Some(hex::encode(build_id));
        }
        // Tier 2 — modern hardening markers from NT_GNU_PROPERTY_TYPE_0
        // and the minimum-kernel string from NT_GNU_ABI_TAG.
        metrics.has_cet_ibt = note_summary.has_cet_ibt;
        metrics.has_cet_shstk = note_summary.has_cet_shstk;
        metrics.has_aarch64_bti = note_summary.has_aarch64_bti;
        metrics.has_aarch64_pac = note_summary.has_aarch64_pac;
        metrics.gnu_abi_min_kernel = note_summary.gnu_abi_min_kernel.clone();
        metrics.x86_isa_level = note_summary.x86_isa_level.clone();
        metrics.pauth_scheme = note_summary.pauth_scheme.clone();

        metrics
    }

    /// `compute_elf_metrics`'s expose-backed counterpart. Reads every
    /// field from `ctx.parsed`'s emitted metrics + values + section
    /// list — no goblin walks needed. The structural data expose
    /// surfaces during its own parse covers everything cleave used to
    /// re-derive locally.
    fn compute_elf_metrics_from_ctx(
        &self,
        ctx: &crate::analysis_context::AnalysisContext<'_>,
        note_summary: &ElfNoteSummary,
    ) -> crate::types::binary_metrics::ElfMetrics {
        let parsed = &ctx.parsed;
        let m = parsed.metrics();
        let v = parsed.values();

        // `:` lists from DT_RPATH / DT_RUNPATH that expose surfaces as
        // arrays-of-strings under values; each entry can still be a
        // colon-joined list when goblin returned one DT_*PATH entry
        // carrying multiple paths.
        let split_paths = |json: Option<&serde_json::Value>| -> Vec<String> {
            json.and_then(|j| j.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|e| e.as_str())
                        .flat_map(|s| s.split(':'))
                        .map(str::trim)
                        .filter(|s| !s.is_empty())
                        .map(str::to_string)
                        .collect()
                })
                .unwrap_or_default()
        };
        let string_array = |path: &str| -> Vec<String> {
            v.get(path)
                .and_then(|j| j.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|e| e.as_str().map(str::to_string))
                        .collect()
                })
                .unwrap_or_default()
        };
        let get_u32 = |key: &str| m.get(key).unwrap_or(0.0) as u32;
        let get_u64 = |key: &str| m.get(key).unwrap_or(0.0) as u64;
        let get_bool = |key: &str| m.get(key).unwrap_or(0.0) > 0.0;

        let needed: Vec<String> = string_array("elf.needed");
        let rpaths = split_paths(v.get("elf.rpath"));
        let runpaths = split_paths(v.get("elf.runpath"));

        let mut metrics = crate::types::binary_metrics::ElfMetrics {
            // Header fields. e_type/e_machine numeric IDs are dropped
            // — the canonical names live in values as elf.type/machine
            // strings, and trait engines threshold on those.
            class_bits: get_u32("elf.bits"),
            little_endian: get_bool("elf.little_endian"),
            entry: get_u64("elf.entry"),
            program_header_count: get_u32("elf.program_header_count"),
            section_count: get_u32("elf.section_count"),
            section_relocation_group_count: get_u32("elf.section_relocation_group_count"),

            // Dynamic-section structural facts.
            has_interpreter: v.get("elf.interpreter").is_some(),
            has_soname: v.get("elf.soname").is_some(),
            soname: v
                .get("elf.soname")
                .and_then(|j| j.as_str())
                .map(str::to_string),
            rpath_count: rpaths.len() as u32,
            runpath_count: runpaths.len() as u32,
            needed,
            rpaths,
            runpaths,

            // Symbol + relocation table counts.
            dynsym_count: get_u32("elf.dynsym_count"),
            symtab_count: get_u32("elf.symtab_count"),
            dynrela_count: get_u32("elf.dynrela_count"),
            dynrel_count: get_u32("elf.dynrel_count"),
            pltreloc_count: get_u32("elf.pltreloc_count"),

            // Section + dynamic flags.
            has_plt: get_bool("elf.has_plt"),
            has_got: get_bool("elf.has_got"),
            has_eh_frame: get_bool("elf.has_eh_frame"),
            has_note: get_bool("elf.has_note"),
            has_rpath: !v.get("elf.rpath").is_none(),
            has_runpath: !v.get("elf.runpath").is_none(),
            has_gnu_hash: get_bool("elf.has_gnu_hash"),
            has_textrel: get_bool("elf.has_dt_textrel"),
            has_dt_audit: get_bool("elf.has_dt_audit"),
            has_dt_depaudit: get_bool("elf.has_dt_depaudit"),
            has_dt_debug: get_bool("elf.has_dt_debug"),
            has_dt_relr: get_bool("elf.has_dt_relr"),

            // Constructor counts.
            init_array_count: get_u32("elf.init_array_count"),
            fini_array_count: get_u32("elf.fini_array_count"),
            dt_preinit_array_count: get_u32("elf.preinit_array_count"),

            // Program-header analysis.
            load_segment_max_p_filesz: get_u64("elf.load_segment_max_file_size"),
            load_segment_max_p_memsz: get_u64("elf.load_segment_max_memory_size"),
            nx_enabled: get_bool("elf.nx_enabled"),
            executable_stack: get_bool("elf.executable_stack"),
            gnu_stack_section_absent: get_bool("elf.gnu_stack_section_absent"),
            entry_in_writable_segment: get_bool("elf.entry_in_writable_segment"),

            // DT_NEEDED anomalies.
            dt_needed_abs_path_count: get_u32("elf.dt_needed_abs_path_count"),
            dt_needed_traversal_count: get_u32("elf.dt_needed_traversal_count"),
            dt_runpath_uses_origin: get_bool("elf.dt_runpath_uses_origin"),
            has_direct_loader_dep: get_bool("elf.has_direct_loader_dep"),

            // RELRO from expose's values tree (`elf.relro` is
            // "partial" / "full"; absent when no PT_GNU_RELRO).
            relro: v
                .get("elf.relro")
                .and_then(|j| j.as_str())
                .map(str::to_string),

            // Entry-point section name from expose's values tree.
            entry_section: v
                .get("elf.entry_section")
                .and_then(|j| j.as_str())
                .map(str::to_string),

            // FORTIFY_SOURCE — count of __*_chk imports.
            fortify_source_used: get_u32("elf.fortify_source_count"),

            // .comment-section toolchain attribution.
            comment_entry_count: get_u32("elf.comment_entry_count"),
            comment_distinct_count: get_u32("elf.comment_distinct_count"),

            ..Default::default()
        };

        // Entry-not-in-text derives from entry_section.
        metrics.entry_not_in_text = metrics.entry != 0
            && metrics.entry_section.is_some()
            && metrics.entry_section.as_deref() != Some(".text");

        // Note-summary fields populated from the ElfNoteSummary the
        // caller already built (from expose data via
        // summarize_elf_notes_from_ctx).
        metrics.note_count = note_summary.note_count;
        if let Some(build_id) = &note_summary.build_id {
            metrics.has_build_id = true;
            metrics.build_id_length = build_id.len() as u32;
            metrics.build_id = Some(hex::encode(build_id));
        }
        metrics.has_cet_ibt = note_summary.has_cet_ibt;
        metrics.has_cet_shstk = note_summary.has_cet_shstk;
        metrics.has_aarch64_bti = note_summary.has_aarch64_bti;
        metrics.has_aarch64_pac = note_summary.has_aarch64_pac;
        metrics.gnu_abi_min_kernel = note_summary.gnu_abi_min_kernel.clone();
        metrics.x86_isa_level = note_summary.x86_isa_level.clone();
        metrics.pauth_scheme = note_summary.pauth_scheme.clone();

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

    /// Sum of executable section sizes, sourced from expose's typed
    /// section view. Equivalent to `compute_code_size` but reads
    /// `flags` containing `"execinstr"` instead of decoding the raw
    /// `SHF_EXECINSTR` bit.
    fn compute_code_size_from_ctx(
        &self,
        ctx: &crate::analysis_context::AnalysisContext<'_>,
    ) -> u64 {
        ctx.parsed
            .sections()
            .iter()
            .filter(|s| s.flags.iter().any(|f| f == "execinstr"))
            .map(|s| s.vsize)
            .sum()
    }

    /// `summarize_elf_notes`'s expose-backed counterpart. All the
    /// hardening features expose decodes during its own parse —
    /// `elf.has_cet_ibt`, `elf.has_aarch64_pac`, `elf.build_id`,
    /// `elf.abi.min_kernel`, `elf.x86_isa_level`, `elf.pauth_scheme`,
    /// `elf.note_count` — are already on the report's flat metric
    /// map / kv tree, so this just gathers them. No bytes-level notes
    /// walking.
    fn summarize_elf_notes_from_ctx(
        &self,
        ctx: &crate::analysis_context::AnalysisContext<'_>,
    ) -> ElfNoteSummary {
        let parsed = &ctx.parsed;
        let metrics = parsed.metrics();
        let values = parsed.values();

        let note_count = metrics.get("elf.note_count").unwrap_or(0.0) as u32;
        let build_id = values
            .get("elf.build_id")
            .and_then(|v| v.as_str())
            .and_then(decode_hex_string);
        let gnu_abi_min_kernel = values
            .get("elf.abi.min_kernel")
            .and_then(|v| v.as_str())
            .map(str::to_string);
        let x86_isa_level = values
            .get("elf.x86_isa_level")
            .and_then(|v| v.as_str())
            .map(str::to_string);
        let pauth_scheme = values
            .get("elf.pauth_scheme")
            .and_then(|v| v.as_str())
            .map(str::to_string);

        ElfNoteSummary {
            note_count,
            build_id,
            truncated: false,
            has_cet_ibt: metrics.get("elf.has_cet_ibt").unwrap_or(0.0) > 0.0,
            has_cet_shstk: metrics.get("elf.has_cet_shstk").unwrap_or(0.0) > 0.0,
            has_aarch64_bti: metrics.get("elf.has_aarch64_bti").unwrap_or(0.0) > 0.0,
            has_aarch64_pac: metrics.get("elf.has_aarch64_pac").unwrap_or(0.0) > 0.0,
            gnu_abi_min_kernel,
            x86_isa_level,
            pauth_scheme,
        }
    }
}

/// Decode a contiguous hex string into bytes. Returns `None` on odd
/// length or non-hex characters. Used to recover the raw GNU build-id
/// bytes from `elf.build_id` (which expose stores hex-encoded).
fn decode_hex_string(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    for pair in bytes.chunks_exact(2) {
        let hi = hex_nibble(pair[0])?;
        let lo = hex_nibble(pair[1])?;
        out.push((hi << 4) | lo);
    }
    Some(out)
}

fn hex_nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
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
        self.analyze_structural_with_ctx(file_path, data, precomputed_sha256, None)
    }

    /// Same as [`Self::analyze_structural`] but accepts an
    /// [`AnalysisContext`] borrowing the same bytes — mirrors the
    /// PE analyzer's ctx-aware entry point. When provided, the
    /// imports / exports loop reads from expose's typed views
    /// rather than re-walking `.dynsym` with goblin. Pass `None`
    /// to keep the legacy goblin-everywhere behaviour.
    ///
    /// [`AnalysisContext`]: crate::analysis_context::AnalysisContext
    pub(crate) fn analyze_structural_with_ctx<'a>(
        &self,
        file_path: &'a Path,
        data: &'a [u8],
        precomputed_sha256: Option<String>,
        ctx: Option<&crate::analysis_context::AnalysisContext<'a>>,
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
            precomputed_sha256.clone(),
            ctx,
        );

        report.findings.push(
            Finding::structural(
                "anti-static/packer/upx".to_string(),
                "Binary is packed with UPX".to_string(),
                1.0,
            )
            .with_criticality(Criticality::Notable),
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
                        let opts = crate::analyzers::stng_analysis_opts(4);
                        let unpacked_strings =
                            stng::extract_strings_with_options(&unpacked_data, &opts);
                        // UPX-unpacked bytes are not what the outer
                        // `ctx` borrows; pass `None` so the inner
                        // analysis runs goblin afresh on the unpacked
                        // payload.
                        let unpacked_report = self.analyze_elf_core(
                            temp_file.path(),
                            temp_file.path(),
                            &unpacked_data,
                            Some(&unpacked_strings),
                            true,
                            None,
                            None,
                        );
                        let mut unpacked_report = unpacked_report;
                        crate::analyzers::binary_kv::attach_to_report(&mut unpacked_report);
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
                        self.capability_mapper.evaluate_and_merge_findings(
                            &mut unpacked_report,
                            &unpacked_data,
                            None,
                            None,
                        );
                        crate::path_mapper::analyze_and_link_paths(&mut unpacked_report);
                        crate::env_mapper::analyze_and_link_env_vars(&mut unpacked_report);

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
                    .with_criticality(Criticality::Notable),
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
        // Open expose-side parse once so analyze_elf_core's helpers
        // (analyze_sections, summarize_elf_notes, compute_elf_metrics)
        // can read structural data straight from expose instead of
        // walking goblin a second time. Falls back gracefully when
        // expose can't open the bytes (corrupted ELF / unknown shape).
        let ctx = crate::analysis_context::AnalysisContext::open(input.path, input.data).ok();
        let mut report = self.analyze_elf_core(
            input.path,
            input.backing_path(),
            input.data,
            strings,
            !input.skip_rizin,
            input.sha256.clone(),
            ctx.as_ref(),
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
        // ELF magic: `\x7fELF` (`7f 45 4c 46`). Read 4 bytes — full
        // goblin parse runs once we commit to analyze().
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
    fn test_parse_gnu_property_x86_ibt_shstk() {
        // One record: type=X86_FEATURE_1_AND (0xc0000002), datasz=4,
        // data=u32(IBT|SHSTK = 0x3), padding to 8-byte alignment.
        let mut desc = vec![];
        desc.extend_from_slice(&0xc0000002u32.to_le_bytes());
        desc.extend_from_slice(&4u32.to_le_bytes());
        desc.extend_from_slice(&3u32.to_le_bytes()); // IBT | SHSTK
        desc.extend_from_slice(&[0u8; 4]); // pad to 16 bytes
        let mut s = ElfNoteSummary::default();
        parse_gnu_property_note(&desc, &mut s);
        assert!(s.has_cet_ibt);
        assert!(s.has_cet_shstk);
        assert!(!s.has_aarch64_bti);
        assert!(!s.has_aarch64_pac);
    }

    #[test]
    fn test_parse_gnu_property_aarch64_bti_pac() {
        let mut desc = vec![];
        desc.extend_from_slice(&0xc0000000u32.to_le_bytes());
        desc.extend_from_slice(&4u32.to_le_bytes());
        desc.extend_from_slice(&3u32.to_le_bytes()); // BTI | PAC
        desc.extend_from_slice(&[0u8; 4]);
        let mut s = ElfNoteSummary::default();
        parse_gnu_property_note(&desc, &mut s);
        assert!(s.has_aarch64_bti);
        assert!(s.has_aarch64_pac);
        assert!(!s.has_cet_ibt);
    }

    #[test]
    fn test_parse_gnu_property_empty_desc_safe() {
        let mut s = ElfNoteSummary::default();
        parse_gnu_property_note(&[], &mut s);
        assert!(!s.has_cet_ibt);
    }

    #[test]
    fn test_parse_gnu_property_unknown_type_skipped() {
        let mut desc = vec![];
        desc.extend_from_slice(&0xdeadbeefu32.to_le_bytes());
        desc.extend_from_slice(&4u32.to_le_bytes());
        desc.extend_from_slice(&0xffffffffu32.to_le_bytes());
        desc.extend_from_slice(&[0u8; 4]);
        let mut s = ElfNoteSummary::default();
        parse_gnu_property_note(&desc, &mut s);
        assert!(!s.has_cet_ibt);
        assert!(!s.has_aarch64_bti);
    }

    #[test]
    fn test_phdr_type_name_known() {
        assert_eq!(phdr_type_name(1), "PT_LOAD");
        assert_eq!(phdr_type_name(3), "PT_INTERP");
        assert_eq!(phdr_type_name(0x6474_e551), "PT_GNU_STACK");
        assert_eq!(phdr_type_name(0x6474_e552), "PT_GNU_RELRO");
    }

    #[test]
    fn test_phdr_type_name_unknown_falls_back_to_hex() {
        let s = phdr_type_name(0xdeadbeef);
        assert!(s.starts_with("PT_"));
        assert!(s.contains("0xdeadbeef"));
    }

    fn push_u16(out: &mut Vec<u8>, value: u16) {
        out.extend_from_slice(&value.to_le_bytes());
    }

    fn push_u32(out: &mut Vec<u8>, value: u32) {
        out.extend_from_slice(&value.to_le_bytes());
    }

    fn push_u64(out: &mut Vec<u8>, value: u64) {
        out.extend_from_slice(&value.to_le_bytes());
    }

    fn pad_to(out: &mut Vec<u8>, len: usize) {
        out.resize(len, 0);
    }

    fn note_record(name: &[u8], desc: &[u8], n_type: u32) -> Vec<u8> {
        let mut out = Vec::new();
        push_u32(&mut out, name.len() as u32);
        push_u32(&mut out, desc.len() as u32);
        push_u32(&mut out, n_type);
        out.extend_from_slice(name);
        while out.len() % 4 != 0 {
            out.push(0);
        }
        out.extend_from_slice(desc);
        while out.len() % 4 != 0 {
            out.push(0);
        }
        out
    }

    fn elf64_with_note_section(note_data: &[u8], sh_addralign: u64) -> Vec<u8> {
        let note_offset = 0x100usize;
        let shstrtab = b"\0.note.gnu.build-id\0.shstrtab\0";
        let shstr_offset = note_offset + note_data.len();
        let shoff = (shstr_offset + shstrtab.len() + 7) & !7;
        let mut out = Vec::new();

        out.extend_from_slice(b"\x7fELF");
        out.extend_from_slice(&[2, 1, 1, 0, 0]);
        out.extend_from_slice(&[0; 7]);
        push_u16(&mut out, goblin::elf::header::ET_EXEC);
        push_u16(&mut out, goblin::elf::header::EM_X86_64);
        push_u32(&mut out, 1);
        push_u64(&mut out, 0);
        push_u64(&mut out, 0);
        push_u64(&mut out, shoff as u64);
        push_u32(&mut out, 0);
        push_u16(&mut out, 64);
        push_u16(&mut out, 56);
        push_u16(&mut out, 0);
        push_u16(&mut out, 64);
        push_u16(&mut out, 3);
        push_u16(&mut out, 2);

        pad_to(&mut out, note_offset);
        out.extend_from_slice(note_data);
        out.extend_from_slice(shstrtab);
        pad_to(&mut out, shoff);

        out.extend_from_slice(&[0; 64]);

        push_u32(&mut out, 1);
        push_u32(&mut out, goblin::elf::section_header::SHT_NOTE);
        push_u64(&mut out, 0);
        push_u64(&mut out, 0);
        push_u64(&mut out, note_offset as u64);
        push_u64(&mut out, note_data.len() as u64);
        push_u32(&mut out, 0);
        push_u32(&mut out, 0);
        push_u64(&mut out, sh_addralign);
        push_u64(&mut out, 0);

        push_u32(&mut out, 20);
        push_u32(&mut out, goblin::elf::section_header::SHT_STRTAB);
        push_u64(&mut out, 0);
        push_u64(&mut out, 0);
        push_u64(&mut out, shstr_offset as u64);
        push_u64(&mut out, shstrtab.len() as u64);
        push_u32(&mut out, 0);
        push_u32(&mut out, 0);
        push_u64(&mut out, 1);
        push_u64(&mut out, 0);

        out
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
    fn test_bounded_note_scanner_finds_gnu_build_id_without_goblin_iterator() {
        let build_id: Vec<u8> = (0u8..20).collect();
        let data = elf64_with_note_section(&note_record(b"GNU\0", &build_id, NT_GNU_BUILD_ID), 4);
        let elf = Elf::parse(&data).unwrap();
        let analyzer = ElfAnalyzer::new();

        let summary = analyzer.summarize_elf_notes(&elf, &data);

        assert_eq!(summary.note_count, 1);
        assert_eq!(summary.build_id.as_deref(), Some(build_id.as_slice()));
        assert!(!summary.truncated);
    }

    #[test]
    fn test_bounded_note_scanner_caps_note_count() {
        let one_note = note_record(b"\0", &[], 0);
        let mut notes = Vec::new();
        for _ in 0..(MAX_ELF_NOTES + 32) {
            notes.extend_from_slice(&one_note);
        }
        let data = elf64_with_note_section(&notes, 4);
        let elf = Elf::parse(&data).unwrap();
        let analyzer = ElfAnalyzer::new();

        let summary = analyzer.summarize_elf_notes(&elf, &data);

        assert_eq!(summary.note_count, MAX_ELF_NOTES);
        assert!(summary.truncated);
    }

    #[test]
    fn test_bounded_note_scanner_stops_on_malformed_large_name() {
        let mut note = Vec::new();
        push_u32(&mut note, u32::MAX);
        push_u32(&mut note, 0);
        push_u32(&mut note, NT_GNU_BUILD_ID);
        let data = elf64_with_note_section(&note, 4);
        let elf = Elf::parse(&data).unwrap();
        let analyzer = ElfAnalyzer::new();

        let summary = analyzer.summarize_elf_notes(&elf, &data);

        assert_eq!(summary.note_count, 0);
        assert!(summary.build_id.is_none());
        assert!(summary.truncated);
    }

    #[test]
    fn test_bounded_note_scanner_enforces_byte_budget() {
        let mut notes = Vec::new();
        let note = note_record(b"\0", &[], 0);
        while notes.len() <= MAX_ELF_NOTE_BYTES + note.len() {
            notes.extend_from_slice(&note);
        }
        let data = elf64_with_note_section(&notes, 4);
        let elf = Elf::parse(&data).unwrap();
        let analyzer = ElfAnalyzer::new();

        let summary = analyzer.summarize_elf_notes(&elf, &data);

        assert!(summary.note_count <= MAX_ELF_NOTES);
        assert!(summary.truncated);
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

        // UPX packing alone is packaging evidence, not a hostile conclusion.
        assert_eq!(finding.crit, Criticality::Notable);
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
