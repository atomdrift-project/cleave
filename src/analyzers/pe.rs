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
    AnalysisReport, Criticality, Evidence, Export, Finding, FindingKind, Import, Section,
    StructuralFeature, TargetInfo,
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

/// The data directory a standard PE section name is *reserved for*. Only
/// names with a rigid, single-purpose convention are listed: `.text`,
/// `.rdata` and `.data` are deliberately absent because real toolchains
/// legitimately park imports, TLS, debug and load-config data in all three,
/// and a packer's invented name (`UPX1`, `.vmp0`) is absent because an
/// unfamiliar name claims nothing.
///
/// This is what makes `pe.directory_section_mismatch_count` a lie detector
/// rather than a novelty detector: it fires only when a section's name is
/// reserved for one directory while it actually holds a *different* one.
fn section_name_reserved_for(name: &str) -> Option<&'static str> {
    match name {
        ".rsrc" => Some("resource"),
        ".reloc" => Some("base_relocation"),
        ".edata" => Some("export"),
        ".idata" => Some("import"),
        ".pdata" => Some("exception"),
        ".tls" => Some("tls"),
        ".didat" => Some("delay_import"),
        _ => None,
    }
}

/// Classify one section's bytes as natural-language prose rather than code
/// or structured data.
///
/// Trailing zero padding to `FileAlignment` is trimmed first — it is an
/// artifact of the layout, not content — and sections too short to judge
/// return false. The three ratios separate the two populations by a wide
/// margin on real binaries: prose runs ~0.99 printable, ~0.15 spaces,
/// ~0.80 letters, while compiled code and structured tables sit below 0.67,
/// 0.02 and 0.46 respectively. Thresholds are set in the empty middle.
fn section_is_prose(bytes: &[u8]) -> bool {
    let trimmed: &[u8] = bytes
        .iter()
        .rposition(|&b| b != 0)
        .and_then(|last| bytes.get(..=last))
        .unwrap_or_default();
    // Below this a run of ASCII is as likely to be a string table fragment
    // as a document, and the ratios get noisy.
    if trimmed.len() < 256 {
        return false;
    }
    let len = trimmed.len() as f64;
    let mut printable = 0u64;
    let mut spaces = 0u64;
    let mut letters = 0u64;
    for &b in trimmed {
        if (0x20..0x7f).contains(&b) || b == b'\t' || b == b'\n' || b == b'\r' {
            printable = printable.saturating_add(1);
        }
        if b == b' ' {
            spaces = spaces.saturating_add(1);
        }
        if b.is_ascii_alphabetic() {
            letters = letters.saturating_add(1);
        }
    }
    printable as f64 / len >= 0.95 && spaces as f64 / len >= 0.08 && letters as f64 / len >= 0.60
}

/// Derived PE layout metrics: the shape of the *container*, independent of
/// what the code inside it does.
///
/// These exist because a PE can be restructured — padded, renamed,
/// stuffed — without a single instruction changing, and every behavioural
/// signal cleave has will keep describing the original, benign program.
/// For example, a genuine signed utility can be given a 10 MB
/// `SizeOfHeaders` (a zero hole the loader maps), section names shuffled off
/// their contents, sections stuffed with licence prose, its Authenticode
/// stripped and its checksum zeroed: every behavioural signal still reads
/// benign, and only the container's shape gives it away.
///
/// Emitted onto the flat metric map alongside filefacts's own `pe.*` keys,
/// same as the recursive-scan counters below.
fn layout_metrics(ctx: &Ctx<'_>, pe_data: &[u8], report: &mut AnalysisReport) {
    use crate::types::core::MetricsExt;

    let values = ctx.parsed.values();
    let file_size = pe_data.len() as u64;

    // SizeOfHeaders against the file. The PE spec only requires it to cover
    // the headers and be a FileAlignment multiple; nothing bounds it above,
    // so inflating it and inserting the matching filler moves every section
    // deep into the file while leaving a loadable image. Even a PE with the
    // conventional 96-section maximum needs under 8 KB of headers, so any
    // large value here is a deliberate choice, and the ratio says whether
    // the file is mostly program or mostly filler.
    let headers_size = values
        .get("pe.headers_size")
        .and_then(serde_json::Value::as_u64);

    // Data directories parked in a section reserved for a different one.
    let mismatches = values
        .get("pe.declared_data_directories")
        .and_then(serde_json::Value::as_array)
        .map_or(0u64, |dirs| {
            dirs.iter()
                .filter(|d| {
                    let Some(name) = d.get("name").and_then(serde_json::Value::as_str) else {
                        return false;
                    };
                    let Some(section) = d.get("section").and_then(serde_json::Value::as_str) else {
                        return false;
                    };
                    section_name_reserved_for(section).is_some_and(|owner| owner != name)
                })
                .count() as u64
        });

    // Sections whose bytes are prose. Counted twice: once overall, and once
    // for the sections the loader will map executable — text in a page
    // marked CODE|EXECUTE is not a resource that happens to be misfiled, it
    // is a section whose declared purpose its contents cannot serve.
    let mut prose = 0u64;
    let mut prose_exec = 0u64;
    for section in ctx.parsed.sections() {
        let start = usize::try_from(section.file_offset).unwrap_or(usize::MAX);
        let len = usize::try_from(section.file_size).unwrap_or(0);
        let Some(section_bytes) = start
            .checked_add(len)
            .and_then(|end| pe_data.get(start..end))
        else {
            continue;
        };
        if !section_is_prose(section_bytes) {
            continue;
        }
        prose = prose.saturating_add(1);
        if section.has_flag(filefacts::SectionFlag::Executable) {
            prose_exec = prose_exec.saturating_add(1);
        }
    }

    let flat = report
        .filefacts_metrics
        .get_or_insert_with(Default::default);
    if let Some(headers_size) = headers_size {
        flat.set_u("pe.headers_size", headers_size);
        if file_size > 0 {
            flat.set_f(
                "pe.headers_size_ratio",
                headers_size as f64 / file_size as f64,
            );
        }
    }
    flat.set_u("pe.directory_section_mismatch_count", mismatches);
    flat.set_u("pe.prose_section_count", prose);
    flat.set_u("pe.executable_prose_section_count", prose_exec);
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
    report.findings.push(overlay.sfx_finding);
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

/// Report a PE that filefacts could not identify, or parsed only down to its
/// headers. The exact failure is not surfaced by filefacts's metrics; the
/// absence of `pe.machine` or presence of `pe.partial_parse` is the signal.
///
/// A header-only parse means the COFF header was readable but a downstream
/// walker failed (resource-only DLLs and resource-table errors land there),
/// so it is informational. An unidentifiable PE that is not a plain DOS
/// executable is suspicious, more surely when nothing was recovered from it.
fn report_corrupted_header(report: &mut AnalysisReport, pe_data: &[u8], filefacts_ok: bool) {
    let (crit, conf) = if !filefacts_ok && !looks_like_dos_executable(pe_data) {
        let recovered_hidden_content = !report.sections.is_empty() || !report.imports.is_empty();
        (
            Criticality::Suspicious,
            if recovered_hidden_content { 0.8 } else { 0.85 },
        )
    } else {
        (Criticality::Baseline, 0.3)
    };
    let msg = if filefacts_ok {
        "PE parsed with header-only fallback (downstream walker failed)"
    } else {
        "PE could not be identified by filefacts"
    };
    let evidence = || Evidence {
        method: "parse-failure".to_string(),
        source: "filefacts".to_string(),
        value: msg.to_string(),
        location: Some("0x0".to_string()),
        ..Default::default()
    };
    report.findings.push(Finding {
        precomputed_spans: None,
        src: None,
        id: "objectives/anti-analysis/pe-tampering/corrupted-header"
            .to_string()
            .into(),
        kind: FindingKind::Structural,
        desc: msg.to_string().into(),
        conf,
        crit,
        mbc: Some("B0001".into()),
        attack: Some("T1027".into()),
        trait_refs: vec![],
        evidence: vec![evidence()],
        match_count: 1,
        source_file: None,
        downgraded: false,
    });
    report.structure.push(StructuralFeature {
        id: "pe/corrupted".to_string(),
        desc: "Corrupted/tampered PE binary (header parsing failed)".to_string(),
        evidence: vec![evidence()],
    });
    report.metadata.errors.push(msg.to_string());
}

/// The bytes of an embedded image: its estimated extent, or for a base64
/// image the decoded run starting at its offset (trimmed to whole quads), so
/// the child analyzer reads the binary rather than its encoding. `None` when
/// the offset is past the data or the base64 does not decode.
fn embedded_image<'d>(
    pe_data: &'d [u8],
    binary: &crate::analyzers::embedded_binary_detector::EmbeddedBinary,
) -> Option<std::borrow::Cow<'d, [u8]>> {
    let rest = pe_data
        .get(binary.offset..)
        .filter(|rest| !rest.is_empty())?;
    if binary.encoding == Some("base64") {
        let run = rest
            .iter()
            .take_while(|&&b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'='))
            .count();
        let encoded = rest.get(..run & !3).unwrap_or_default();
        base64::Engine::decode(&base64::engine::general_purpose::STANDARD, encoded)
            .ok()
            .map(std::borrow::Cow::Owned)
    } else {
        Some(std::borrow::Cow::Borrowed(
            rest.get(..binary.estimated_size.min(rest.len()))
                .unwrap_or_default(),
        ))
    }
}

/// Read the certificate-table range `(offset, end)` from filefacts's
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
        let end = offset.checked_add(size)?;
        if offset == 0 || size == 0 || end > data.len() {
            return None;
        }
        return Some((offset, end));
    }
    None
}

fn le_u16(data: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes(
        data.get(at..at.checked_add(2)?)?.try_into().ok()?,
    ))
}

fn le_u32(data: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        data.get(at..at.checked_add(4)?)?.try_into().ok()?,
    ))
}

/// The 4 bytes at `e_lfanew`, where a PE signature belongs.
fn pe_signature_at_lfanew(data: &[u8]) -> Option<(usize, &[u8])> {
    let offset = le_u32(data, 0x3c)? as usize;
    Some((offset, data.get(offset..offset.checked_add(4)?)?))
}

fn looks_like_dos_executable(data: &[u8]) -> bool {
    if data.len() < 0x40 || !data.starts_with(b"MZ") {
        return false;
    }

    if pe_signature_at_lfanew(data).is_some_and(|(_, sig)| sig == b"PE\x00\x00") {
        return false;
    }

    let (Some(last_page_bytes), Some(page_count), Some(header_paragraphs)) =
        (le_u16(data, 2), le_u16(data, 4), le_u16(data, 8))
    else {
        return false;
    };
    let (last_page_bytes, page_count, header_paragraphs) = (
        usize::from(last_page_bytes),
        usize::from(page_count),
        usize::from(header_paragraphs),
    );
    if page_count == 0 || header_paragraphs == 0 {
        return false;
    }

    let declared_size = page_count
        .saturating_sub(1)
        .saturating_mul(512)
        .saturating_add(if last_page_bytes == 0 {
            512
        } else {
            last_page_bytes
        });
    let header_size = header_paragraphs.saturating_mul(16);
    declared_size >= header_size
        && declared_size <= data.len().saturating_add(512)
        && header_size < data.len()
}

impl PEAnalyzer {
    /// Emit the small list of structural-feature entries cleave's
    /// downstream consumers expect: `pe/header`, `pe/dll` (when the
    /// IMAGE_FILE_DLL characteristic is set), and `pe/optional_header`
    /// (when the optional header is present). All facts come from
    /// filefacts's emitted values — no goblin re-walk.
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
                source: "filefacts".to_string(),
                value: "PE".to_string(),
                location: Some("0x0".to_string()),
                ..Default::default()
            }],
        });

        // filefacts always emits the raw COFF Characteristics u16 here;
        // IMAGE_FILE_DLL is bit 0x2000.
        let is_dll = ctx
            .parsed
            .values()
            .get("pe.characteristics_raw")
            .and_then(serde_json::Value::as_u64)
            .is_some_and(|characteristics| characteristics & 0x2000 != 0);
        if is_dll {
            features.push(StructuralFeature {
                id: "pe/dll".to_string(),
                desc: "Dynamic Link Library (DLL)".to_string(),
                evidence: vec![Evidence {
                    method: "header".to_string(),
                    source: "filefacts".to_string(),
                    value: "DLL".to_string(),
                    location: Some("0x0".to_string()),
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
                    source: "filefacts".to_string(),
                    value: "OptionalHeader".to_string(),
                    location: Some("0x0".to_string()),
                    ..Default::default()
                }],
            });
        }
        features
    }

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
        embedded: &[crate::analyzers::embedded_binary_detector::EmbeddedBinary],
        cert_range: Option<(usize, usize)>,
    ) -> u32 {
        let host_name = std::path::Path::new(&report.target.path)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("binary.exe")
            .to_string();
        let mut count: u32 = 0;
        for binary in embedded {
            if self.is_cancelled() {
                break;
            }
            if cert_range.is_some_and(|(start, end)| binary.offset >= start && binary.offset < end)
            {
                continue;
            }
            count = count.saturating_add(1);
            let finding = crate::analyzers::embedded_binary_detector::finding_for(
                binary,
                &report.target.path,
            );
            let Some(embedded_bytes) = embedded_image(pe_data, binary) else {
                report.findings.push(finding);
                continue;
            };
            if let Some(files) = crate::analyzers::utils::analyze_embedded_as_child(
                &embedded_bytes,
                &host_name,
                binary.kind.as_str(),
                &binary.display_kind(),
                binary.offset,
                self.engine.clone(),
                self.yara_engine.clone(),
            ) {
                report.files.extend(files);
            }
            report.findings.push(finding);
        }
        count
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

        if !UPXDecompressor::is_upx_packed(data) {
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

        let initial = UPXDecompressor::decompress(data);
        if let Err(error) = &initial
            && let Some(finding) = crate::upx::standard_unpack_refusal(error)
        {
            report.findings.push(finding);
        }
        let recovered = if initial
            .as_ref()
            .err()
            .is_some_and(|e| crate::upx::classify_failure(e).checksum_mismatch)
        {
            UPXDecompressor::repair_nrv2b_checksums(data)
                .and_then(|copy| UPXDecompressor::decompress(&copy).ok())
        } else {
            None
        };
        let unpacked = if let Some(bytes) = recovered {
            report.findings.push(
                Finding::structural(
                    "metadata/binary/layout/compression::upx-checksum-mismatch".to_string(),
                    "UPX-packed image fails checksum validation".to_string(),
                    1.0,
                )
                .with_criticality(Criticality::Suspicious),
            );
            report.findings.push(
                Finding::structural(
                    "metadata/binary/layout/compression::upx-checksum-repaired-analysis-copy"
                        .to_string(),
                    "Recovered UPX payload after repairing checksums on an analysis copy"
                        .to_string(),
                    1.0,
                )
                .with_criticality(Criticality::Notable),
            );
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
                    // Merge filefacts facts (incl. `pe.go.*`) into the
                    // unpacked report so `augment_report` can reshape the Go
                    // build-info; idempotent with the merge during the
                    // composite evaluation below.
                    crate::capabilities::merge_filefacts_context(
                        &mut unpacked_report,
                        &unpacked_ctx,
                    );
                    crate::analyzers::binary_extractors::augment_report(
                        &mut unpacked_report,
                        &unpacked_data,
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
                let failure = crate::upx::classify_failure(&e);
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
    /// `pe_data` is the post-tamper-strip slice; `original_data` is
    /// the caller's bytes verbatim. The two diverge only when
    /// `detect_and_strip_tampering` peeled a junk prefix off the
    /// front — overlay extraction and embedded-binary scanning
    /// operate on `pe_data`, while file-size metrics use
    /// `original_data`.
    #[allow(clippy::too_many_arguments)]
    fn analyze_pe<'a>(
        &self,
        logical_path: &Path,
        analysis_path: &Path,
        original_data: &[u8],
        pe_data: &'a [u8],
        mut tamper_findings: Vec<Finding>,
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
        let mut embedded_binary_count: u32 = 0;
        let mut embedded_archive_count: u32 = 0;
        if filefacts_ok {
            tools_used.push("filefacts".to_string());
        }

        // Add any tampering findings detected during preprocessing
        report.findings.append(&mut tamper_findings);

        // Project structural views from filefacts's typed accessors.
        // Recovery (for stripped / packed PEs) already ran inside
        // `filefacts::open` — `ctx.parsed.symbols()` / `imports()` /
        // `sections()` already carry what binform recovered.
        let scope_start = std::time::Instant::now();
        let mut struct_ms = 0u128;
        if filefacts_ok {
            let s_start = std::time::Instant::now();
            let structural_features = self.structural_features(ctx);
            let pe_imports = self.pe_imports(ctx);
            let (pe_exports, _aliased_count) = self.pe_exports(ctx);
            let pe_sections = self.pe_sections(ctx);
            struct_ms = s_start.elapsed().as_millis();

            report.structure.extend(structural_features);
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

        // --- Corrupted-header findings (filefacts's PE parse fell back
        // to header-only, or failed entirely). The exact failure
        // detail isn't surfaced by filefacts's metrics; the absence of
        // `pe.machine` or presence of `pe.partial_parse` IS the
        // signal.
        if !filefacts_ok || partial_parse {
            report_corrupted_header(&mut report, pe_data, filefacts_ok);
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
        report.strings = self
            .string_extractor
            .convert_stng_strings(&raw_stng_strings);
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

        self.analyze_recovered_payloads(&mut report, pe_data, ctx, logical_path);

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
            && let Ok(Some(overlay_analysis)) = crate::analyzers::overlay::analyze_overlay(
                overlay_data,
                &report.target.path,
                &self.engine,
                self.yara_engine.clone(),
                Some(&self.archive_config),
            )
        {
            embedded_archive_count = embedded_archive_count.saturating_add(1);
            adopt_overlay(&mut report, &mut tools_used, overlay_analysis);
        }

        // NSIS / Inno Setup detection
        // Discover embedded images once and use their validated spans when
        // identifying SFX markers. A nested Inno installer must be analyzed
        // as the embedded child; its marker must not make the host itself look
        // like an Inno setup or trigger extraction of the wrong byte range.
        let embedded = if self.skip_embedded_scan {
            Vec::new()
        } else {
            crate::analyzers::embedded_binary_detector::scan_for_embedded_binaries(
                pe_data,
                self.cancellation.as_deref(),
            )
        };
        let detected_sfx_kind = crate::analyzers::sfx_detector::detect_sfx(pe_data, &embedded);
        if let Some(sfx_kind) = detected_sfx_kind {
            let sfx_result = crate::analyzers::sfx_detector::analyze_sfx(
                analysis_path,
                sfx_kind,
                pe_data,
                &self.engine,
                self.yara_engine.clone(),
                Some(&self.archive_config),
                &embedded,
            );
            report.findings.push(sfx_result.sfx_finding);
            report.findings.extend(sfx_result.extraction_findings);
            if let Some(archive_report) = sfx_result.archive_report {
                embedded_archive_count = embedded_archive_count.saturating_add(1);
                report.findings.extend(archive_report.findings);
                report.files.extend(archive_report.files);
                // Preserve the complete extracted-member inventory, including
                // data files that are not promoted to separate analyses unless
                // --all-files is enabled. Prefixing here records the installer
                // as the immediate provenance parent.
                adopt_member_inventory(&mut report, archive_report.archive_contents);
                // Merge per-format kv subtrees from the inner archive report
                // (e.g. `pyinstaller.*`) into the host PE's values_tree so they
                // surface in the host's `k` field at finalize time.
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
            if bundle_analyzer.analyze_dotnet_bundle(pe_data, &mut report) {
                embedded_archive_count = embedded_archive_count.saturating_add(1);
            }
        }

        if !self.skip_embedded_scan {
            embedded_binary_count = self.analyze_embedded_binaries(
                &mut report,
                pe_data,
                &embedded,
                pe_certificate_range_from_ctx(ctx, pe_data),
            );
        }

        // Container-shape metrics, on the same flat map for the same reason:
        // filefacts reports the header fields verbatim, deriving what they mean
        // against each other is cleave's job. Gated on a successful parse —
        // the values these read are absent on the fallback path.
        if filefacts_ok {
            layout_metrics(ctx, pe_data, &mut report);
        }

        // Emit recursive-scan counters. Embedded-binary detection is
        // cleave's job (it spawns child analyses on each find), so
        // these counts live on cleave's flat metric map alongside the
        // filefacts-emitted `binary.*` keys.
        if embedded_binary_count > 0 || embedded_archive_count > 0 {
            use crate::types::core::MetricsExt;
            let flat = report
                .filefacts_metrics
                .get_or_insert_with(Default::default);
            if embedded_binary_count > 0 {
                flat.set_f("binary.embedded_binaries", f64::from(embedded_binary_count));
                flat.set_f(
                    "binary.embedded_files",
                    f64::from(embedded_binary_count.saturating_add(embedded_archive_count)),
                );
            }
            if embedded_archive_count > 0 {
                flat.set_f(
                    "binary.embedded_archives",
                    f64::from(embedded_archive_count),
                );
            }
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

    fn detect_and_strip_tampering<'a>(&self, data: &'a [u8]) -> (&'a [u8], Vec<Finding>) {
        let mut findings = Vec::new();

        // Check if MZ is at offset 0
        if data.starts_with(b"MZ") {
            // Normal PE, but still check for other tampering
            self.detect_header_tampering(data, 0, &mut findings);
            return (data, findings);
        }

        // Search for an MZ header within the first 64 bytes.
        let mz_offset = data
            .get(..64)
            .unwrap_or(data)
            .windows(2)
            .position(|pair| pair == b"MZ");

        if let Some(offset) = mz_offset {
            // Found MZ at a non-zero offset inside `data`: junk prefix.
            let prefix = data.get(..offset).unwrap_or_default();
            let prefix_display = if prefix.len() <= 32 {
                String::from_utf8_lossy(prefix).to_string()
            } else {
                format!(
                    "{}... ({} bytes)",
                    String::from_utf8_lossy(prefix.get(..32).unwrap_or(prefix)),
                    prefix.len()
                )
            };

            findings.push(Finding {
                precomputed_spans: None,
                src: None,
                id: "objectives/anti-analysis/pe-tampering/junk-prefix"
                    .to_string()
                    .into(),
                kind: FindingKind::Structural,
                desc: format!(
                    "PE has {} bytes prepended before MZ header (anti-analysis)",
                    offset
                )
                .into(),
                conf: 1.0,
                crit: Criticality::Hostile,
                mbc: Some("B0001".into()),    // Executable Code Obfuscation
                attack: Some("T1027".into()), // Obfuscated Files or Information
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
                downgraded: false,
            });

            // Check for additional tampering in the actual PE data
            let pe_data = data.get(offset..).unwrap_or(data);
            self.detect_header_tampering(pe_data, offset, &mut findings);

            return (pe_data, findings);
        }

        // No MZ found - check for BSJB (.NET) signature without valid PE
        if let Some(bsjb_offset) = data.windows(4).position(|window| window == b"BSJB") {
            findings.push(Finding {
                precomputed_spans: None,
                src: None,
                id: "objectives/anti-analysis/pe-tampering/dotnet-invalid-pe"
                    .to_string()
                    .into(),
                kind: FindingKind::Structural,
                desc: ".NET assembly (BSJB signature) with corrupted/missing PE header"
                    .to_string()
                    .into(),
                conf: 0.95,
                crit: Criticality::Hostile,
                mbc: Some("B0001".into()),
                attack: Some("T1027".into()),
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
                downgraded: false,
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
        let header_area = data.get(..512).unwrap_or(data);
        let mut byte_counts = [0u32; 256];
        for &b in header_area {
            if let Some(count) = byte_counts.get_mut(usize::from(b)) {
                *count = count.saturating_add(1);
            }
        }

        let header_len = header_area.len() as u32;
        for (byte_val, &count) in byte_counts.iter().enumerate() {
            // Skip 0x00 (common in headers) and check if any byte is >40% of
            // header (`5·count > 2·len` is `count > 2·len/5` without truncation).
            if byte_val != 0 && count.saturating_mul(5) > header_len.saturating_mul(2) {
                findings.push(Finding {
                    precomputed_spans: None,
                    src: None,
                    id: "objectives/anti-analysis/pe-tampering/byte-injection"
                        .to_string()
                        .into(),
                    kind: FindingKind::Structural,
                    desc: format!(
                        "PE header has excessive 0x{:02X} bytes ({} of {} = {:.1}%)",
                        byte_val,
                        count,
                        header_len,
                        count as f32 / header_len as f32 * 100.0
                    )
                    .into(),
                    conf: 0.9,
                    crit: Criticality::Suspicious,
                    mbc: Some("B0001".into()),
                    attack: Some("T1027".into()),
                    trait_refs: vec![],
                    evidence: vec![Evidence {
                        method: "frequency-analysis".to_string(),
                        source: "cleave".to_string(),
                        value: format!("byte 0x{:02X} appears {} times in header", byte_val, count),
                        location: Some(format!(
                            "{:#x}-{:#x}",
                            base_offset,
                            base_offset.saturating_add(512)
                        )),
                        ..Default::default()
                    }],
                    match_count: 1,
                    source_file: None,
                    downgraded: false,
                });
                break; // Only report the most prominent injection
            }
        }

        // Check the actual PE signature location from the DOS header, not the first
        // incidental `PE` byte sequence anywhere in the file.
        if let Some((pe_sig_offset, sig)) = pe_signature_at_lfanew(data)
            && sig != b"PE\x00\x00"
            && !looks_like_dos_executable(data)
        {
            findings.push(Finding {
                src: None,
                precomputed_spans: None,
                id: "objectives/anti-analysis/pe-tampering/pe-signature-corrupted"
                    .to_string()
                    .into(),
                kind: FindingKind::Structural,
                desc: format!(
                    "PE signature corrupted: expected PE\\x00\\x00, got {}",
                    sig.iter()
                        .map(|b| format!("{b:02X}"))
                        .collect::<Vec<_>>()
                        .join(" ")
                )
                .into(),
                conf: 0.85,
                crit: Criticality::Suspicious,
                mbc: Some("B0001".into()),
                attack: Some("T1027".into()),
                trait_refs: vec![],
                evidence: vec![Evidence {
                    method: "signature".to_string(),
                    source: "cleave".to_string(),
                    value: format!("PE signature at {:#x}: {:?}", pe_sig_offset, sig),
                    location: Some(format!("{:#x}", base_offset.saturating_add(pe_sig_offset))),
                    ..Default::default()
                }],
                match_count: 1,
                source_file: None,
                downgraded: false,
            });
        }

        // .NET BSJB CLR metadata signature is detected by the YAML trait
        // metadata/binary/framework::dotnet-metadata (raw "BSJB" scan).
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
        let ctx = match &input.parsed_ctx {
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

    fn can_analyze(&self, file_path: &Path) -> bool {
        // PE magic-byte check: `MZ` + valid `e_lfanew` pointing at `PE\0\0`.
        // A full filefacts parse just to gate analyzability is wasted
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
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]
mod tests;
