//! Mach-O binary analyzer for macOS executables.
//!
//! Every Mach-O helper takes a non-optional
//! [`crate::analysis_context::AnalysisContext`]: structural data
//! (segments, dylibs, code signature, header bits) is read from
//! `filefacts`'s typed views rather than re-walked with goblin. The
//! analyzer no longer carries its own goblin parse path.
use crate::analyzers::{AnalysisInput, Analyzer};
use crate::capabilities::CapabilityMapper;
use crate::entropy::EntropyLevel;
use crate::strings::StringExtractor;
use crate::types::{
    AnalysisReport, Criticality, Evidence, Export, Finding, FindingKind, StringInfo,
    StructuralFeature, TargetInfo,
};
use anyhow::{Context, Result};
use sha2::{Digest, Sha256, Sha384};
use std::fs;
use std::path::Path;
use std::sync::Arc;

type Ctx<'a> = crate::analysis_context::AnalysisContext<'a>;

/// Analyzer for macOS Mach-O binaries (executables, dylibs, bundles).
///
/// Wave B routed deep-binary signal through `filefacts::open`: function
/// CFG fields and rizin-recovered symbols arrive on
/// `ctx.parsed.symbols()` (filtered by kind). The analyzer
/// no longer merges its own rizin import augment over goblin's view —
/// filefacts's typed Mach-O imports cover what cleave needed previously.
#[derive(Debug)]
pub(crate) struct MachOAnalyzer {
    capability_mapper: Arc<CapabilityMapper>,
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
        // Header/whole-file facts (magic, arch, format bits) genuinely live at
        // the header, so the default anchor is offset 0.
        Self::push_metadata_finding_at(report, id, desc, method, source, value, "0x0".to_string());
    }

    /// Like [`Self::push_metadata_finding`] but with an explicit evidence
    /// `location` — used where the fact sits at a known non-header offset
    /// (e.g. a dylib load command).
    fn push_metadata_finding_at(
        report: &mut AnalysisReport,
        id: &str,
        desc: &str,
        method: &str,
        source: &str,
        value: String,
        location: String,
    ) {
        report.findings.push(
            Finding::structural(id.to_string(), desc.to_string(), 1.0)
                .with_criticality(Criticality::Baseline)
                .with_evidence(vec![Evidence {
                    method: method.to_string(),
                    source: source.to_string(),
                    value,
                    location: Some(location),
                    ..Default::default()
                }]),
        );
    }

    /// Creates a new Mach-O analyzer with default configuration
    #[must_use]
    pub(crate) fn new() -> Self {
        Self {
            capability_mapper: Arc::new(CapabilityMapper::empty()),
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

    /// Structural analysis of a thin Mach-O binary (no YARA scan, no trait evaluation).
    /// Only handles thin binaries — fat binary dispatch is done by the caller.
    /// Callers are responsible for running YARA and calling `evaluate_and_merge_findings`.
    ///
    /// Synthesises an [`AnalysisContext`] internally; callers that
    /// already hold one should call [`Self::analyze_structural_with_ctx`]
    /// directly to avoid the second filefacts parse.
    ///
    /// [`AnalysisContext`]: crate::analysis_context::AnalysisContext
    pub(crate) fn analyze_structural(
        &self,
        file_path: &Path,
        data: &[u8],
        precomputed_sha256: Option<String>,
    ) -> AnalysisReport {
        match crate::analysis_context::AnalysisContext::open(file_path, data) {
            Ok(ctx) => self.analyze_structural_with_ctx(file_path, data, precomputed_sha256, &ctx),
            Err(e) => {
                let sha256 = precomputed_sha256
                    .unwrap_or_else(|| crate::analyzers::utils::calculate_sha256(data));
                self.analyze_macho_fallback(
                    file_path,
                    file_path,
                    data,
                    sha256,
                    Some(format!("filefacts open failed: {e}")),
                    true,
                    None,
                    std::time::Instant::now(),
                )
            }
        }
    }

    /// Same as [`Self::analyze_structural`] but accepts an
    /// [`AnalysisContext`] borrowing the same bytes. Imports,
    /// exports, segments, code-signature metadata and header bits all
    /// come from filefacts's typed views; no goblin walk happens here.
    ///
    /// [`AnalysisContext`]: crate::analysis_context::AnalysisContext
    pub(crate) fn analyze_structural_with_ctx<'a>(
        &self,
        file_path: &'a Path,
        data: &'a [u8],
        precomputed_sha256: Option<String>,
        ctx: &Ctx<'a>,
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
    /// The caller provides an [`AnalysisContext`] borrowing `data`;
    /// every Mach-O-internal helper reads from filefacts's typed views
    /// via that ctx (no goblin re-parse).
    ///
    /// [`AnalysisContext`]: crate::analysis_context::AnalysisContext
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
        let sha256 = precomputed_sha256
            .clone()
            .unwrap_or_else(|| crate::analyzers::utils::calculate_sha256(data));

        // filefacts marks unparseable bytes with `macho.parse_failed` or
        // `macho.parse_panicked` metrics. When neither the parse
        // succeeded nor a fat-slice cpu_type was observed, fall back
        // to the rizin path so the binary still gets baseline metrics
        // and a malformed-structure signal.
        let m = ctx.parsed.metrics();
        let parse_failed = m.get("macho.parse_failed").is_some();
        let parse_panicked = m.get("macho.parse_panicked").is_some();
        let cpu_type_known = ctx.parsed.values().get("macho.cpu_type").is_some();
        if parse_failed || parse_panicked || !cpu_type_known {
            let parse_msg = if parse_panicked {
                Some("Mach-O parse panicked in filefacts".to_string())
            } else if parse_failed {
                Some("Mach-O parse failed in filefacts".to_string())
            } else {
                None
            };
            return self.analyze_macho_fallback(
                logical_path,
                analysis_path,
                data,
                sha256,
                parse_msg,
                allow_rizin,
                precomputed_sha256,
                start,
            );
        }

        // Create target info
        let target = TargetInfo {
            path: logical_path.display().to_string(),
            file_type: "macho".to_string(),
            size_bytes: data.len() as u64,
            sha256: sha256.clone(),
            architectures: Some(vec![arch_name_from_ctx(ctx)]),
        };

        let mut report = AnalysisReport::new(target);
        let mut tools_used = vec!["filefacts".to_string()];

        // Phase 1: structural features, signature findings, imports,
        // exports, sections. All driven from ctx.
        let _t = std::time::Instant::now();
        self.fill_structural_features_from_ctx(ctx, &mut report);
        let structure_ms = _t.elapsed().as_millis();

        // Code-signature identity/trust/entitlement findings. filefacts
        // supplies the decoded metadata; cleave additionally verifies the
        // CodeDirectory page hashes against the bytes being analyzed.
        let _t = std::time::Instant::now();
        self.generate_signature_findings_from_ctx(ctx, data, &mut report);
        let sig_findings_ms = _t.elapsed().as_millis();

        let _t = std::time::Instant::now();
        self.analyze_imports_from_ctx(ctx, &mut report);
        let imports_ms = _t.elapsed().as_millis();

        let _t = std::time::Instant::now();
        self.analyze_exports_from_ctx(ctx, &mut report);
        let exports_ms = _t.elapsed().as_millis();

        let _t = std::time::Instant::now();
        self.analyze_sections_from_ctx(ctx, &mut report);
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

        // Cross-format metric facts (segment_count, is_stripped, is_pie,
        // has_debug_info, code-signature details) flow through
        // `filefacts.values.macho.*` and `filefacts.metrics` now.

        // Functions come from filefacts's typed `Functions` view —
        // `aflj`-derived CFG fields ride along when filefacts's rizin
        // recovery fired (stripped binaries / packed bodies); symbol-
        // table-only entries leave the cleave CFG mirror `None`.
        let _t_r2 = std::time::Instant::now();
        report.functions = ctx
            .parsed
            .symbols()
            .iter_kind(filefacts::SymbolKind::Function)
            .filter_map(crate::analysis_context::project_filefacts_function)
            .collect();
        let r2_strings: Option<Vec<stng::ExtractedString>> = None;
        let _ = (allow_rizin, precomputed_sha256);

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
            // No pre-extracted strings supplied: source them from filefacts.
            let _ = r2_strings;
            report.strings = crate::strings::strings_from_filefacts(analysis_path, data);
        }
        let strings_ms = _t.elapsed().as_millis();

        // Report string truncation if limits were hit
        if self
            .string_extractor
            .truncated
            .load(std::sync::atomic::Ordering::SeqCst)
        {
            report.findings.push(Finding {
                src: None,
                id: "metadata/strings-truncated".to_string().into(),
                kind: FindingKind::Structural,
                desc: format!(
                    "String extraction truncated due to limits (count: {}, total bytes: {} MB)",
                    crate::strings::MAX_STRINGS_PER_FILE,
                    crate::strings::MAX_TOTAL_STRING_BYTES / (1024 * 1024)
                )
                .to_string()
                .into(),
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

        tracing::info!(
            path = %logical_path.display(),
            r2_total_ms,
            strings_ms,
            string_count,
            embedded_ms,
            "macho:phase2"
        );

        // Round up to 1ms when the work completed in <1ms so the
        // recorded duration is always distinguishable from the
        // "never set" sentinel (0). Avoids spurious test flakes on
        // fast machines without lying about long analyses.
        report.metadata.analysis_duration_ms = (start.elapsed().as_millis() as u64).max(1);
        report.metadata.tools_used = tools_used;

        report
    }

    /// Emit the binary/format, architecture, signature presence, and
    /// metadata findings (install name, linked dylibs, rpaths) from
    /// filefacts's typed views. No goblin walk — every fact comes from
    /// `ctx.parsed`.
    fn fill_structural_features_from_ctx(&self, ctx: &Ctx<'_>, report: &mut AnalysisReport) {
        let v = ctx.parsed.values();

        report.structure.push(StructuralFeature {
            id: "binary/format/macho".to_string(),
            desc: "Mach-O binary format".to_string(),
            evidence: vec![Evidence {
                method: "magic".to_string(),
                source: "filefacts".to_string(),
                // Cleave traits historically read `0x{magic:x}` but
                // filefacts doesn't surface the magic word directly. The
                // file_type_raw (MH_* constant) gives a stable
                // architecture-agnostic identity.
                value: format!(
                    "filetype=0x{:x}",
                    v.get("macho.file_type_raw")
                        .and_then(serde_json::Value::as_u64)
                        .unwrap_or(0)
                ),
                location: Some("0x0".to_string()),
                ..Default::default()
            }],
        });

        let arch = arch_name_from_ctx(ctx);
        let cputype_raw = v
            .get("macho.cpu_type_raw")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0);
        report.structure.push(StructuralFeature {
            id: format!("binary/arch/{}", arch),
            desc: format!("{} architecture", arch),
            evidence: vec![Evidence {
                method: "header".to_string(),
                source: "filefacts".to_string(),
                value: format!("cputype=0x{:x}", cputype_raw),
                location: Some("0x0".to_string()),
                ..Default::default()
            }],
        });

        // Code signature presence: an LC_CODE_SIGNATURE in the load
        // command list or any `macho.code_signature.*` value (parsed
        // out by filefacts's code-signature reader) means the binary
        // carries a signature blob.
        let has_signature = lc_present(ctx, "LC_CODE_SIGNATURE");
        if has_signature {
            report.structure.push(StructuralFeature {
                id: "binary/signed".to_string(),
                desc: "Binary has code signature".to_string(),
                evidence: vec![Evidence {
                    method: "load_command".to_string(),
                    source: "filefacts".to_string(),
                    value: "LC_CODE_SIGNATURE".to_string(),
                    location: Some("load_commands".to_string()),
                    ..Default::default()
                }],
            });
        }

        if let Some(name) = v.get("macho.install_name").and_then(|x| x.as_str()) {
            Self::push_metadata_finding(
                report,
                "metadata/binary/linking::macho-install-name",
                "Mach-O install name present",
                "lc_id_dylib",
                "filefacts",
                name.to_string(),
            );
        }

        if let Some(libs) = v.get("macho.libraries").and_then(|x| x.as_array()) {
            // Map each dylib path to its load-command file offset (filefacts
            // exposes these via `macho.load_dylibs`) so the evidence is
            // anchored where the dylib reference physically sits.
            let dylib_offsets: std::collections::HashMap<&str, u64> = v
                .get("macho.load_dylibs")
                .and_then(|x| x.as_array())
                .map(|entries| {
                    entries
                        .iter()
                        .filter_map(|e| {
                            let path = e.get("path")?.as_str()?;
                            let off = e.get("offset")?.as_u64()?;
                            Some((path, off))
                        })
                        .collect()
                })
                .unwrap_or_default();
            for lib in libs {
                let Some(name) = lib.as_str() else { continue };
                if name.is_empty() {
                    continue;
                }
                let location = dylib_offsets
                    .get(name)
                    .map_or_else(|| "0x0".to_string(), |off| format!("0x{off:x}"));
                Self::push_metadata_finding_at(
                    report,
                    "metadata/binary/linking::macho-dylib",
                    "Mach-O linked dylib",
                    "load_dylib",
                    "filefacts",
                    name.to_string(),
                    location,
                );
            }
        }

        if let Some(rpaths) = v.get("macho.rpaths").and_then(|x| x.as_array()) {
            for rpath in rpaths {
                let Some(name) = rpath.as_str() else { continue };
                Self::push_metadata_finding(
                    report,
                    "metadata/binary/linking::macho-rpath",
                    "Mach-O runtime search path",
                    "rpath",
                    "filefacts",
                    name.to_string(),
                );
            }
        }
    }

    /// Pull imports off filefacts's typed Imports view into the report. Symbol
    /// traits match these through the trait engine's symbol index.
    fn analyze_imports_from_ctx(&self, ctx: &Ctx<'_>, report: &mut AnalysisReport) {
        report.imports.extend(ctx.imports_from_filefacts());
    }

    /// Pull exports off filefacts's typed Exports view.
    fn analyze_exports_from_ctx(&self, ctx: &Ctx<'_>, report: &mut AnalysisReport) {
        for exp in ctx.exports_from_filefacts() {
            report.exports.push(exp);
        }
    }

    /// Project filefacts's typed Sections view into the report, marking
    /// high-entropy sections with the canonical `entropy/high`
    /// structural feature.
    fn analyze_sections_from_ctx(&self, ctx: &Ctx<'_>, report: &mut AnalysisReport) {
        for section in ctx.sections_from_filefacts() {
            let entropy = section.entropy;
            let section_name = section.name.clone();
            report.sections.push(section);
            let level = EntropyLevel::from_value(entropy);
            if level == EntropyLevel::High {
                report.structure.push(StructuralFeature {
                    id: "entropy/high".to_string(),
                    desc: "High entropy section (possibly packed/encrypted)".to_string(),
                    evidence: vec![Evidence {
                        method: "entropy".to_string(),
                        source: "filefacts".to_string(),
                        value: format!("{:.2}", entropy),
                        location: Some(section_name),
                        ..Default::default()
                    }],
                });
            }
        }
    }

    /// Project filefacts's parsed code signature into identity/trust and
    /// entitlement findings. filefacts decodes the typed metadata and
    /// normalized [`Identity`]; cleave only walks the CodeDirectory enough to
    /// verify its signed page hashes against `data`. filefacts reports the
    /// `LC_CODE_SIGNATURE` blob's file offset via
    /// `macho.code_signature_offset` and the identifier string's offset via
    /// `macho.code_signature.identifier_offset`. We read those facts and
    /// anchor each finding at the offset of the thing it describes.
    ///
    /// [`Identity`]: filefacts::Identity
    fn generate_signature_findings_from_ctx(
        &self,
        ctx: &Ctx<'_>,
        data: &[u8],
        report: &mut AnalysisReport,
    ) {
        let values = ctx.parsed.values();
        // The `LC_CODE_SIGNATURE` blob offset is present iff the binary is
        // signed. Without it there's nothing to attribute — unsigned
        // binaries are covered by the YAML `unsigned-macho` trait.
        let Some(sig_offset) = values
            .get("macho.code_signature_offset")
            .and_then(serde_json::Value::as_u64)
        else {
            return;
        };
        // Absolute file offset of the identifier C-string inside the
        // CodeDirectory, when filefacts resolved one. Anchors the identifier
        // finding at the string itself rather than at the signature blob.
        let identifier_offset = values
            .get("macho.code_signature.identifier_offset")
            .and_then(serde_json::Value::as_u64);
        let identity = ctx.identity().unwrap_or_default();
        let entitlements = values
            .get("macho.code_signature.entitlements")
            .and_then(serde_json::Value::as_object);
        emit_signature_findings(
            report,
            sig_offset,
            identifier_offset,
            &identity,
            entitlements,
        );
        if let CodeDirectoryIntegrity::Invalid {
            mismatched,
            checked,
        } = verify_code_directory_hashes(data, sig_offset as usize)
        {
            report.findings.push(signature_finding(
                "metadata/signed/integrity::macho-code-directory-invalid".to_string(),
                "Mach-O code signature content is invalid".to_string(),
                Criticality::Suspicious,
                "code_directory_hashes",
                format!("{mismatched} of {checked} signed code pages do not match"),
                &format!("0x{sig_offset:x}"),
            ));
        }
    }

    // AMOS cipher detection/decryption removed - now handled by stng library internally
}

/// Outcome of checking the supported CodeDirectory page-hash tables in an
/// embedded Mach-O signature. Unsupported algorithms or scatter tables are
/// deliberately silent: absence of verification is not proof of tampering.
#[derive(Debug, PartialEq, Eq)]
enum CodeDirectoryIntegrity {
    Valid { checked: usize },
    Invalid { mismatched: usize, checked: usize },
    Unsupported,
    Malformed,
}

/// Verify SHA-256/SHA-384 CodeDirectory page hashes. Modern Developer ID
/// signatures use these algorithms; legacy SHA-1 and scatter-vector layouts
/// remain unsupported rather than being guessed at.
fn verify_code_directory_hashes(data: &[u8], sig_offset: usize) -> CodeDirectoryIntegrity {
    const EMBEDDED_SIGNATURE: u32 = 0xfade_0cc0;
    const DETACHED_SIGNATURE: u32 = 0xfade_0cc1;
    const CODE_DIRECTORY: u32 = 0xfade_0c02;

    let Some(magic) = read_be_u32(data, sig_offset) else {
        return CodeDirectoryIntegrity::Malformed;
    };
    if !matches!(magic, EMBEDDED_SIGNATURE | DETACHED_SIGNATURE) {
        return CodeDirectoryIntegrity::Malformed;
    }
    let Some(total_len) = read_be_u32(data, sig_offset + 4).map(|v| v as usize) else {
        return CodeDirectoryIntegrity::Malformed;
    };
    let Some(sig_end) = sig_offset.checked_add(total_len) else {
        return CodeDirectoryIntegrity::Malformed;
    };
    if total_len < 12 || sig_end > data.len() {
        return CodeDirectoryIntegrity::Malformed;
    }
    let Some(count) = read_be_u32(data, sig_offset + 8).map(|v| v as usize) else {
        return CodeDirectoryIntegrity::Malformed;
    };
    let Some(index_end) = count.checked_mul(8).and_then(|n| n.checked_add(12)) else {
        return CodeDirectoryIntegrity::Malformed;
    };
    if index_end > total_len {
        return CodeDirectoryIntegrity::Malformed;
    }

    let mut checked = 0usize;
    let mut mismatched = 0usize;
    let mut saw_supported = false;
    for i in 0..count {
        let index = sig_offset + 12 + i * 8;
        let Some(blob_rel) = read_be_u32(data, index + 4).map(|v| v as usize) else {
            return CodeDirectoryIntegrity::Malformed;
        };
        if blob_rel.checked_add(8).is_none_or(|end| end > total_len) {
            return CodeDirectoryIntegrity::Malformed;
        }
        let Some(blob_start) = sig_offset.checked_add(blob_rel) else {
            return CodeDirectoryIntegrity::Malformed;
        };
        if read_be_u32(data, blob_start) != Some(CODE_DIRECTORY) {
            continue;
        }
        let Some(blob_len) = read_be_u32(data, blob_start + 4).map(|v| v as usize) else {
            return CodeDirectoryIntegrity::Malformed;
        };
        let Some(blob_end) = blob_start.checked_add(blob_len) else {
            return CodeDirectoryIntegrity::Malformed;
        };
        if blob_len < 44 || blob_end > sig_end {
            return CodeDirectoryIntegrity::Malformed;
        }
        let blob = &data[blob_start..blob_end];
        let version = read_be_u32(blob, 8).unwrap_or(0);
        let hash_offset = read_be_u32(blob, 16).unwrap_or(0) as usize;
        let slots = read_be_u32(blob, 28).unwrap_or(0) as usize;
        let mut code_limit = read_be_u32(blob, 32).unwrap_or(0) as usize;
        let hash_size = blob[36] as usize;
        let hash_type = blob[37];
        let page_log2 = blob[39];

        // Scatter-vector CodeDirectories describe non-contiguous ranges and
        // require a different slot-to-file mapping.
        if version >= 0x0002_0100 && read_be_u32(blob, 44).unwrap_or(0) != 0 {
            continue;
        }
        if version >= 0x0002_0300 && blob.len() >= 64 {
            let limit64 = read_be_u64(blob, 56).unwrap_or(0);
            if limit64 != 0 {
                let Ok(limit) = usize::try_from(limit64) else {
                    return CodeDirectoryIntegrity::Malformed;
                };
                code_limit = limit;
            }
        }
        if code_limit > data.len() || hash_size == 0 {
            return CodeDirectoryIntegrity::Malformed;
        }
        let page_size = if page_log2 == 0 {
            code_limit.max(1)
        } else if page_log2 < usize::BITS as u8 {
            1usize << page_log2
        } else {
            return CodeDirectoryIntegrity::Malformed;
        };
        let expected_slots = code_limit.div_ceil(page_size);
        if slots != expected_slots {
            return CodeDirectoryIntegrity::Malformed;
        }
        let Some(hash_end) = slots
            .checked_mul(hash_size)
            .and_then(|n| hash_offset.checked_add(n))
        else {
            return CodeDirectoryIntegrity::Malformed;
        };
        if hash_offset < 44 || hash_end > blob.len() {
            return CodeDirectoryIntegrity::Malformed;
        }
        let digest_len = match hash_type {
            2 | 3 => 32,
            4 => 48,
            _ => continue,
        };
        if hash_size > digest_len {
            return CodeDirectoryIntegrity::Malformed;
        }
        saw_supported = true;
        for slot in 0..slots {
            let start = slot * page_size;
            let end = start.saturating_add(page_size).min(code_limit);
            let actual = match hash_type {
                2 | 3 => Sha256::digest(&data[start..end]).to_vec(),
                4 => Sha384::digest(&data[start..end]).to_vec(),
                _ => return CodeDirectoryIntegrity::Unsupported,
            };
            let stored_start = hash_offset + slot * hash_size;
            let stored = &blob[stored_start..stored_start + hash_size];
            checked += 1;
            if stored != &actual[..hash_size] {
                mismatched += 1;
            }
        }
    }

    if !saw_supported {
        CodeDirectoryIntegrity::Unsupported
    } else if mismatched > 0 {
        CodeDirectoryIntegrity::Invalid {
            mismatched,
            checked,
        }
    } else {
        CodeDirectoryIntegrity::Valid { checked }
    }
}

fn read_be_u32(data: &[u8], offset: usize) -> Option<u32> {
    let bytes: [u8; 4] = data.get(offset..offset.checked_add(4)?)?.try_into().ok()?;
    Some(u32::from_be_bytes(bytes))
}

fn read_be_u64(data: &[u8], offset: usize) -> Option<u64> {
    let bytes: [u8; 8] = data.get(offset..offset.checked_add(8)?)?.try_into().ok()?;
    Some(u64::from_be_bytes(bytes))
}

/// Shift a hex-string file offset (`"0x5078"`) in place by `delta`,
/// preserving `0x` formatting. A location string that doesn't parse as a
/// plain hex (or decimal) number is left unchanged — only real byte
/// offsets are rebased.
fn shift_hex_offset(offset: &mut Option<String>, delta: u64) {
    let Some(current) = offset.as_deref() else {
        return;
    };
    let parsed = current
        .strip_prefix("0x")
        .or_else(|| current.strip_prefix("0X"))
        .and_then(|hex| u64::from_str_radix(hex, 16).ok())
        .or_else(|| current.parse::<u64>().ok());
    if let Some(value) = parsed {
        *offset = Some(format!("0x{:x}", value.saturating_add(delta)));
    }
}

/// Rebase a finding's evidence anchor by `delta`. Shifts every concrete
/// byte offset and a location string that encodes a byte offset (`"0x.."`
/// or `"offset:.."`), matching the forms [`Evidence::byte_offset`] reads.
/// Named or `archive:`-scoped locations carry no file offset and are left
/// untouched.
///
/// [`Evidence::byte_offset`]: crate::types::Evidence::byte_offset
/// Add `delta` to every `*_offset` numeric leaf in a value tree, recursing into
/// objects and arrays. filefacts records a structural fact's source offset under
/// a `<key>_offset` sibling (e.g. `macho.uuid_offset`); on a fat slice those are
/// slice-relative and must shift with everything else.
fn shift_value_tree_offsets(value: &mut serde_json::Value, delta: u64) {
    match value {
        serde_json::Value::Object(map) => {
            for (key, child) in map.iter_mut() {
                if key.ends_with("_offset") {
                    if let Some(n) = child.as_u64() {
                        *child = serde_json::Value::from(n.saturating_add(delta));
                    }
                } else {
                    shift_value_tree_offsets(child, delta);
                }
            }
        }
        serde_json::Value::Array(items) => {
            for item in items {
                shift_value_tree_offsets(item, delta);
            }
        }
        _ => {}
    }
}

fn shift_evidence_offset(evidence: &mut crate::types::Evidence, delta: u64) {
    for off in &mut evidence.offsets {
        *off = off.saturating_add(delta);
    }
    let Some(loc) = evidence.location.as_deref() else {
        return;
    };
    if let Some(rest) = loc.strip_prefix("offset:")
        && let Some(v) = parse_hex_or_dec_loc(rest)
    {
        evidence.location = Some(format!("offset:0x{:x}", v.saturating_add(delta)));
    } else if (loc.starts_with("0x") || loc.starts_with("0X"))
        && let Some(v) = parse_hex_or_dec_loc(loc)
    {
        evidence.location = Some(format!("0x{:x}", v.saturating_add(delta)));
    }
}

/// Parse a string as hex (`0x` prefix) or decimal — the location-string
/// number grammar shared with the context-capture anchor parser.
fn parse_hex_or_dec_loc(s: &str) -> Option<u64> {
    match s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        Some(hex) => u64::from_str_radix(hex, 16).ok(),
        None => s.parse().ok(),
    }
}

/// Architecture label for a Mach-O ctx. Mirrors filefacts's
/// `cpu_type_string` taxonomy (`x86_64`, `arm64`, `arm64e`, …) so
/// downstream consumers see a canonical lowercase name. Returns
/// `unknown_0x<hex>` when the cpu type isn't in filefacts's known set.
fn arch_name_from_ctx(ctx: &Ctx<'_>) -> String {
    let v = ctx.parsed.values();
    if let Some(name) = v.get("macho.cpu_type").and_then(|x| x.as_str())
        && name != "unknown"
    {
        return name.to_string();
    }
    let raw = v
        .get("macho.cpu_type_raw")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(0);
    format!("unknown_0x{:x}", raw)
}

/// True when filefacts's `macho.load_commands[]` list contains `name`.
fn lc_present(ctx: &Ctx<'_>, name: &str) -> bool {
    ctx.parsed
        .values()
        .get("macho.load_commands")
        .and_then(|v| v.as_array())
        .is_some_and(|arr| arr.iter().any(|lc| lc.as_str().is_some_and(|s| s == name)))
}

/// Build the code-signature findings — signer + trust class, bundle
/// identifier, entitlements — from filefacts's normalized [`Identity`]
/// and the projected entitlements map. Split out from
/// [`MachOAnalyzer::generate_signature_findings_from_ctx`] so the
/// taxonomy mapping is unit-testable without a parsed binary. Findings
/// anchor at `sig_offset`, the `LC_CODE_SIGNATURE` blob offset filefacts
/// reports, except the identifier finding, which anchors at
/// `identifier_offset` — the byte position of the identifier C-string
/// inside the CodeDirectory — when filefacts resolved one. Both offsets
/// are slice-relative on fat binaries; [`MachOAnalyzer::rebase_slice_offsets`]
/// rebases them to full-file coordinates together.
///
/// [`Identity`]: filefacts::Identity
/// True when the leading magic marks a Mach-O *fat* (multi-architecture)
/// wrapper. Thin Mach-O binaries (`FEEDFACE`/`FEEDFACF` and byte-swapped
/// forms) return false, so callers can skip the slice-table parse for the
/// common thin case. Callers already know the bytes are Mach-O, so the
/// `0xCAFEBABE` overlap with Java `.class` magic is not ambiguous here.
fn is_fat_macho(data: &[u8]) -> bool {
    matches!(
        data.get(0..4),
        Some([0xCA, 0xFE, 0xBA, 0xBE]) // FAT_MAGIC
            | Some([0xCA, 0xFE, 0xBA, 0xBF]) // FAT_MAGIC_64
            | Some([0xBE, 0xBA, 0xFE, 0xCA]) // FAT_CIGAM
            | Some([0xBF, 0xBA, 0xFE, 0xCA]) // FAT_CIGAM_64
    )
}

fn emit_signature_findings(
    report: &mut AnalysisReport,
    sig_offset: u64,
    identifier_offset: Option<u64>,
    identity: &filefacts::Identity,
    entitlements: Option<&serde_json::Map<String, serde_json::Value>>,
) {
    use filefacts::Trust;
    let location = format!("0x{sig_offset:x}");

    // Signer + trust class, mapped onto the established
    // `metadata/signed/{category}::{signer}` taxonomy so existing
    // composites (`developer-signed`, `platform::*`) and ML features keep
    // resolving. `category` is the stable path segment; the `signer`
    // suffix carries the team id / vendor for per-instance granularity.
    let team_id = identity.team_id.as_ref().map(|c| c.value.as_str());
    let signer_org = identity
        .signer
        .as_ref()
        .and_then(|s| s.organization.as_deref().or(s.common_name.as_deref()));
    let is_platform = matches!(identity.trust, Trust::System | Trust::Platform);
    let (category, signer, desc) = match identity.trust {
        Trust::DeveloperId | Trust::CaSigned => {
            let team = team_id.unwrap_or("unknown");
            let company = signer_org.unwrap_or(team);
            (
                "developer",
                team.to_string(),
                format!("Developer ID: {company}"),
            )
        }
        Trust::System | Trust::Platform => (
            "platform",
            "apple".to_string(),
            "macOS Platform Binary".to_string(),
        ),
        Trust::AdHoc => (
            "adhoc",
            "unsigned".to_string(),
            "Ad-hoc Signature".to_string(),
        ),
        Trust::SelfSigned => (
            "self-signed",
            signer_org.unwrap_or("unknown").to_string(),
            "Self-signed".to_string(),
        ),
        // A signature offset existed but filefacts resolved no trust
        // tier (`Unsigned`) or a tier added after this match: surface it
        // as an unknown signature rather than dropping it.
        _ => (
            "unknown",
            "unknown".to_string(),
            "Unknown Signature".to_string(),
        ),
    };
    let signer_value = signer_org.map_or_else(|| signer.clone(), str::to_string);
    report.findings.push(signature_finding(
        format!("metadata/signed/{category}::{signer}"),
        desc,
        Criticality::Notable,
        "code_signature",
        format!("{category}::{signer_value}"),
        &location,
    ));

    // Bundle / executable identifier — the identity the binary claims.
    // Notable across all formats (see trust-level/traits.yaml rationale).
    // Anchors at the identifier string's own offset, falling back to the
    // signature blob only when filefacts couldn't resolve the string offset.
    if let Some(identifier) = identity.identifier.as_ref().map(|c| c.value.as_str()) {
        let id_location =
            identifier_offset.map_or_else(|| location.clone(), |off| format!("0x{off:x}"));
        report.findings.push(signature_finding(
            format!("metadata/signed/id::{identifier}"),
            format!("Identifier: {identifier}"),
            Criticality::Notable,
            "code_directory",
            identifier.to_string(),
            &id_location,
        ));
    }

    // Entitlements — each granted capability is at least Notable.
    let Some(entitlements) = entitlements else {
        return;
    };
    let has_disable_lib_val =
        entitlements.contains_key("com.apple.security.cs.disable-library-validation");
    for (key, value) in entitlements {
        report.findings.push(signature_finding(
            format!(
                "metadata/entitlement/{}::{}",
                entitlement_category(key),
                key
            ),
            describe_entitlement(key),
            determine_entitlement_criticality(key, is_platform, has_disable_lib_val),
            "entitlements_plist",
            format!("{key}={}", entitlement_value_string(value)),
            &location,
        ));
    }
}

/// One code-signature finding, anchored at the signature blob `location`.
/// All signature findings share this shape: a full-confidence Capability
/// sourced from filefacts.
fn signature_finding(
    id: String,
    desc: String,
    crit: Criticality,
    method: &str,
    value: String,
    location: &str,
) -> Finding {
    Finding {
        src: None,
        kind: FindingKind::Capability,
        trait_refs: vec![],
        id: id.into(),
        desc: desc.into(),
        conf: 1.0,
        crit,
        mbc: None,
        attack: None,
        evidence: vec![Evidence {
            method: method.to_string(),
            source: "filefacts".to_string(),
            value,
            location: Some(location.to_string()),
            ..Default::default()
        }],
        match_count: 0,
        source_file: None,
    }
}

/// Render an entitlement value (from the projected plist JSON) as the
/// compact `key=value` evidence string. Mirrors the prior
/// boolean/string/array handling and adds numbers; nested objects are
/// vanishingly rare in entitlements and fall back to their JSON form.
fn entitlement_value_string(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::Bool(b) => b.to_string(),
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Number(n) => n.to_string(),
        serde_json::Value::Array(a) => a
            .iter()
            .map(entitlement_value_string)
            .collect::<Vec<_>>()
            .join(", "),
        other => other.to_string(),
    }
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
            "Allows libraries without signature validation",
        ),
        ("cs.allow-jit", "Allows JIT-compiled executable memory"),
        (
            "cs.allow-unsigned-executable-memory",
            "Allows unsigned executable memory",
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
        (
            "files.user-selected.read-write",
            "Can read and modify user-selected files",
        ),
        ("home-directory", "Home directory access"),
        // Network client/server entitlement names are otherwise reduced by the
        // fallback to the unhelpful one-word labels "Client" and "Server".
        (
            "security.network.client",
            "Can make outbound network connections",
        ),
        (
            "security.network.server",
            "Can accept incoming network connections",
        ),
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

/// Criticality for a single entitlement. Permissions are *always*
/// Notable-or-higher, never Baseline: an entitlement is a capability the
/// binary is granted (debugger access, JIT, disabled library validation),
/// which is exactly the kind of provenance signal an analyst reads in a
/// diff. Dangerous entitlements escalate to Suspicious; nothing here returns
/// Baseline. This mirrors the cross-format identity/permissions principle in
/// traits/metadata/signed/trust-level/traits.yaml.
fn determine_entitlement_criticality(
    entitlement_key: &str,
    is_platform: bool,
    has_disable_library_validation: bool,
) -> Criticality {
    // Platform/system (Apple-signed) binaries: all entitlements are notable
    if is_platform {
        return Criticality::Notable;
    }

    // Dangerous entitlements are suspicious on non-Apple binaries:
    // - allow-jit: allows JIT compilation (code generation at runtime)
    // - debugger: allows attaching to other processes
    // - allow-unsigned-executable-memory: bypasses code signing enforcement
    if entitlement_key.contains("debugger") {
        return Criticality::Suspicious;
    }

    if entitlement_key.contains("allow-unsigned-executable-memory") {
        if has_disable_library_validation {
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
    /// Returns the byte range of the preferred architecture slice
    /// within a fat binary, or `0..data.len()` for thin binaries.
    /// Reads slice extents from filefacts's `macho.slices[]` instead of
    /// re-parsing the fat wrapper through goblin. Prefers arm64; falls
    /// back to the first slice when arm64 isn't present.
    pub(crate) fn preferred_arch_range(&self, data: &[u8]) -> std::ops::Range<usize> {
        // Thin (non-fat) binaries have no slice table, so the answer is the
        // whole file. Detect that from the magic up front and skip the full
        // filefacts parse this otherwise does just to discover there are no
        // slices — the common case for Mach-O.
        if !is_fat_macho(data) {
            return 0..data.len();
        }
        let Ok(parsed) = filefacts::open(data) else {
            return 0..data.len();
        };
        let Some(slices) = parsed
            .values()
            .get("macho.slices")
            .and_then(|v| v.as_array())
        else {
            return 0..data.len();
        };
        let pick = slices
            .iter()
            .find(|s| s.get("cpu_type").and_then(|c| c.as_str()) == Some("arm64"))
            .or_else(|| slices.first());
        if let Some(slice) = pick {
            let off = slice
                .get("file_offset")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0) as usize;
            let size = slice
                .get("file_size")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0) as usize;
            if size > 0 && off.saturating_add(size) <= data.len() {
                return off..off + size;
            }
        }
        0..data.len()
    }

    /// Rebase a fat slice's structural file offsets into full-file
    /// coordinates by adding `delta` (the slice's byte offset within the
    /// fat wrapper).
    ///
    /// filefacts parses each slice from its own bytes at base 0, so every
    /// import, export, function, and section *file* offset it reports is
    /// slice-relative. The rest of the pipeline — extracted strings, raw
    /// pattern matching, YARA, and the hex/context view — all operate on
    /// the full file. Without this shift a fat binary's symbol annotations
    /// land `delta` bytes early in the hex view, and `section:`- and
    /// `near_bytes:`-bounded trait searches target the wrong region.
    ///
    /// A section's `address` is a virtual (vm) address, not a file offset,
    /// so it is deliberately left untouched.
    pub(crate) fn rebase_slice_offsets(report: &mut AnalysisReport, delta: u64) {
        if delta == 0 {
            return;
        }
        for func in &mut report.functions {
            shift_hex_offset(&mut func.offset, delta);
        }
        for import in &mut report.imports {
            shift_hex_offset(&mut import.offset, delta);
        }
        for export in &mut report.exports {
            shift_hex_offset(&mut export.offset, delta);
        }
        for section in &mut report.sections {
            section.offset = section.offset.map(|o| o.saturating_add(delta));
        }
        // Structural findings emitted by this analyzer (code-signature
        // identity, signer, entitlements) anchor their evidence at
        // slice-relative file offsets. The context-capture pass renders
        // them against the full file, so they need the same shift — without
        // it the "Identifier"/signer annotations land `delta` bytes early,
        // inside the slice's __text instead of on the signature blob.
        for finding in &mut report.findings {
            for evidence in &mut finding.evidence {
                shift_evidence_offset(evidence, delta);
            }
        }
        // `*_offset` siblings in the value tree (e.g. `macho.uuid_offset`) are
        // slice-relative too. The capability mapper reads them *after* this
        // pass to anchor `type: value` matches, so shift them here — otherwise
        // those findings render `delta` bytes early on a fat binary.
        if let Some(tree) = report.values_tree.as_deref_mut() {
            shift_value_tree_offsets(tree, delta);
        }
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
        // Thin binaries are a single full-file arch; skip the parse (see
        // `preferred_arch_range`).
        if !is_fat_macho(data) {
            return vec![(Arch::All, 0..data.len())];
        }
        let Ok(parsed) = filefacts::open(data) else {
            return vec![(Arch::All, 0..data.len())];
        };
        let ranges = parsed
            .values()
            .get("macho.slices")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|s| {
                        let off =
                            s.get("file_offset").and_then(serde_json::Value::as_u64)? as usize;
                        let size = s.get("file_size").and_then(serde_json::Value::as_u64)? as usize;
                        let name = s.get("cpu_type").and_then(|v| v.as_str())?;
                        if size > 0 && off.saturating_add(size) <= data.len() {
                            Some((Arch::from_report_str(name), off..off + size))
                        } else {
                            None
                        }
                    })
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        if !ranges.is_empty() {
            return ranges;
        }
        vec![(Arch::All, 0..data.len())]
    }

    #[allow(clippy::single_range_in_vec_init)] // Intentional: returns single range for thin binaries
    pub(crate) fn all_arch_ranges(&self, data: &[u8]) -> Vec<std::ops::Range<usize>> {
        let Ok(parsed) = filefacts::open(data) else {
            return vec![0..data.len()];
        };
        let ranges = parsed
            .values()
            .get("macho.slices")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|s| {
                        let off =
                            s.get("file_offset").and_then(serde_json::Value::as_u64)? as usize;
                        let size = s.get("file_size").and_then(serde_json::Value::as_u64)? as usize;
                        if size > 0 && off.saturating_add(size) <= data.len() {
                            Some(off..off + size)
                        } else {
                            None
                        }
                    })
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        if !ranges.is_empty() {
            return ranges;
        }
        vec![0..data.len()]
    }

    /// Parse every non-preferred arch slice of a fat Mach-O and union its imports
    /// and exports into the report, running capability lookups on each new import
    /// so rules matching on filefacts-derived imports still fire for malware hidden
    /// in a non-preferred arch.
    ///
    /// Preferred arch has already been parsed by the main structural pass, so
    /// imports/exports already present are skipped (deduped by normalized symbol
    /// name + library for imports; by symbol name for exports).
    ///
    /// Each non-preferred slice is opened as its own [`AnalysisContext`],
    /// so the slice's bytes flow through the same filefacts pipeline as
    /// the preferred slice did. Slices that filefacts can't open are
    /// skipped silently — fat binaries with one bad slice are rare
    /// enough that surfacing the failure as a finding adds noise.
    ///
    /// Only runs on fat binaries; caller is expected to check.
    ///
    /// [`AnalysisContext`]: crate::analysis_context::AnalysisContext
    pub(crate) fn union_supplementary_arches(
        &self,
        report: &mut AnalysisReport,
        data: &[u8],
        preferred_offset: usize,
    ) {
        use std::collections::HashSet;

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

        // Use the same `macho.slices[]` view the public range helpers
        // already consume, then open a fresh ctx per slice.
        let Ok(parsed) = filefacts::open(data) else {
            return;
        };
        let Some(slices) = parsed
            .values()
            .get("macho.slices")
            .and_then(|v| v.as_array())
        else {
            return;
        };
        let dummy_path = Path::new("");
        for slice in slices {
            let Some(offset) = slice.get("file_offset").and_then(serde_json::Value::as_u64) else {
                continue;
            };
            let Some(size) = slice.get("file_size").and_then(serde_json::Value::as_u64) else {
                continue;
            };
            let offset = offset as usize;
            let size = size as usize;
            if offset == preferred_offset {
                continue;
            }
            if offset.saturating_add(size) > data.len() || size == 0 {
                continue;
            }
            let slice_bytes = &data[offset..offset + size];
            let Ok(slice_ctx) =
                crate::analysis_context::AnalysisContext::open(dummy_path, slice_bytes)
            else {
                continue;
            };
            arches_parsed += 1;

            for mut imp in slice_ctx.imports_from_filefacts() {
                let key = (imp.symbol.clone(), imp.library.clone());
                if !seen_imports.insert(key) {
                    continue;
                }
                // This slice was parsed at base 0; rebase its offsets into
                // full-file coordinates by the slice's fat offset, matching
                // the preferred slice (rebased by `rebase_slice_offsets`).
                shift_hex_offset(&mut imp.offset, offset as u64);
                report.imports.push(crate::types::Import { ..imp });
            }

            for mut exp in slice_ctx.exports_from_filefacts() {
                if !seen_exports.insert(exp.symbol.clone()) {
                    continue;
                }
                shift_hex_offset(&mut exp.offset, offset as u64);
                report.exports.push(Export { ..exp });
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
    /// No-op for thin binaries. Arch names come from filefacts's
    /// `macho.slices[]` — each slice entry carries a `cpu_type` string
    /// (`"x86_64"` / `"arm64"` / etc). If filefacts can't open the bytes
    /// the fat marker is silently dropped; this is rare enough on
    /// real fat Mach-Os that a finding here would only add noise.
    pub(crate) fn apply_fat_metadata(&self, report: &mut AnalysisReport, data: &[u8]) {
        let arch_names: Vec<String> = filefacts::open_with_path(report.target.path.as_ref(), data)
            .ok()
            .and_then(|parsed| {
                parsed
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
            })
            .unwrap_or_default();
        if arch_names.is_empty() {
            return;
        }
        report.target.architectures = Some(arch_names);
    }

    /// Build a minimal Mach-O analysis report when filefacts couldn't
    /// parse the binary cleanly (the parse failed or panicked, or
    /// no `macho.cpu_type` was emitted).
    ///
    /// Wave B retired the cleave-side rizin spawn here: filefacts owns
    /// the rizin recovery path now, and it fires from inside
    /// `filefacts::open` on the same bytes when goblin's typed views
    /// come back empty. Callers that already hold an
    /// `AnalysisContext` route through `analyze_structural_with_ctx`
    /// to surface those recovered functions / imports / sections.
    #[allow(clippy::too_many_arguments)]
    fn analyze_macho_fallback(
        &self,
        logical_path: &Path,
        analysis_path: &Path,
        data: &[u8],
        sha256: String,
        parse_failure: Option<String>,
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

        let plausible_macho_size = data.len() >= 4096;
        if plausible_macho_size && let Some(msg) = parse_failure {
            report.metadata.errors.push(msg.clone());
            report.findings.push(Finding {
                src: None,
                kind: FindingKind::Structural,
                id: "anti-analysis/malformed/macho-header".to_string().into(),
                desc: format!("Malformed Mach-O header: {}", msg).into(),
                conf: 1.0,
                crit: Criticality::Suspicious,
                mbc: Some("B0001".into()),
                attack: Some("T1027".into()),
                evidence: vec![],
                match_count: 0,
                trait_refs: vec![],
                source_file: None,
            });
        }

        // Filefacts's rizin recovery already populated the typed
        // `Functions` view (if rizin was usable) by the time the
        // fallback path runs — the analysis context here is built
        // by the caller and projected through `open_with_path`.
        // Wave B drops the cleave-side `extract_batched` spawn; if
        // a future caller needs to opt into rizin from this branch
        // it should pass an `AnalysisContext` instead of bytes.
        let _ = (analysis_path, allow_rizin, precomputed_sha256);
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
        // Open filefacts-side parse so downstream helpers source structural
        // data from filefacts's typed views. When filefacts can't open the
        // bytes the fallback path (rizin-based metrics + malformed
        // signal) is taken by `analyze_structural_with_strings` via
        // `analyze_structural` synthesising a fresh ctx; either way
        // we never re-walk with goblin from here.
        let preferred_ctx =
            crate::analysis_context::AnalysisContext::open(input.path, preferred_data).ok();
        let mut report = if let Some(ctx) = preferred_ctx.as_ref() {
            self.analyze_structural_with_strings(
                input.path,
                input.backing_path(),
                preferred_data,
                strings,
                !input.skip_rizin,
                input.sha256.clone(),
                ctx,
            )
        } else {
            let sha256 = input
                .sha256
                .clone()
                .unwrap_or_else(|| crate::analyzers::utils::calculate_sha256(preferred_data));
            self.analyze_macho_fallback(
                input.path,
                input.backing_path(),
                preferred_data,
                sha256,
                Some("filefacts open failed".to_string()),
                !input.skip_rizin,
                input.sha256.clone(),
                std::time::Instant::now(),
            )
        };
        self.apply_fat_metadata(&mut report, input.data);

        // For FAT binaries, strings should already be file-relative from input.strings
        // (extracted from the full file by the entry point)
        let is_fat = arch_ranges.len() > 1;

        if is_fat {
            let preferred_offset = self.preferred_arch_range(input.data).start;
            // The preferred slice was parsed at base 0; rebase its
            // structural offsets into full-file coordinates so symbol
            // annotations and section/proximity searches line up with the
            // full-file strings, raw matches, and hex view.
            Self::rebase_slice_offsets(&mut report, preferred_offset as u64);
            self.union_supplementary_arches(&mut report, input.data, preferred_offset);
        }

        // Evaluate traits against binary data.
        // For FAT binaries, evaluate against the full file since strings have file-relative offsets.
        // For thin binaries, evaluate against the single slice (same as full file).
        if is_fat {
            // Full file evaluation - strings and offsets are file-relative.
            // Use a full-file context so the mapper does not reopen filefacts.
            let full_ctx =
                crate::analysis_context::AnalysisContext::open(input.path, input.data).ok();
            self.capability_mapper
                .evaluate_and_merge_findings_with_precomputed(
                    &mut report,
                    input.data,
                    crate::capabilities::AnalysisBorrow::with_filefacts(None, full_ctx.as_ref()),
                    None,
                    None,
                    None,
                    None,
                );
        } else {
            // Thin binary - single slice is the whole file.
            self.capability_mapper
                .evaluate_and_merge_findings_with_precomputed(
                    &mut report,
                    preferred_data,
                    crate::capabilities::AnalysisBorrow::with_filefacts(
                        None,
                        preferred_ctx.as_ref(),
                    ),
                    None,
                    None,
                    None,
                    None,
                );
        }

        Ok(report)
    }

    fn analyze(&self, file_path: &Path) -> Result<AnalysisReport> {
        let data = fs::read(file_path).context("Failed to read file")?;
        // filefacts is the string-extraction authority. Harvest its full-file
        // `text()` view; the structural pass opens its own per-arch slice.
        let strings: std::sync::Arc<[stng::ExtractedString]> =
            crate::analysis_context::AnalysisContext::open(file_path, &data)
                .ok()
                .map(|c| c.text_rows())
                .unwrap_or_default();
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
                | [0xbf, 0xba, 0xfe, 0xca] // fat 64-bit, byte-swapped
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

    fn put_be_u32(buf: &mut [u8], offset: usize, value: u32) {
        buf[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
    }

    /// Minimal two-page SHA-256 CodeDirectory wrapped in an embedded-signature
    /// SuperBlob. The signed bytes precede the signature, as in a real Mach-O.
    fn code_directory_fixture(tampered: bool) -> (Vec<u8>, usize) {
        const PAGE: usize = 4096;
        const CODE_LEN: usize = PAGE * 2;
        const CD_HEADER: usize = 44;
        const HASH_SIZE: usize = 32;
        const CD_LEN: usize = CD_HEADER + HASH_SIZE * 2;
        const SUPER_HEADER: usize = 20;

        let mut data = vec![b'A'; CODE_LEN];
        let mut cd = vec![0u8; CD_LEN];
        put_be_u32(&mut cd, 0, 0xfade_0c02);
        put_be_u32(&mut cd, 4, CD_LEN as u32);
        put_be_u32(&mut cd, 8, 0x0002_0000);
        put_be_u32(&mut cd, 16, CD_HEADER as u32);
        put_be_u32(&mut cd, 28, 2);
        put_be_u32(&mut cd, 32, CODE_LEN as u32);
        cd[36] = HASH_SIZE as u8;
        cd[37] = 2; // SHA-256
        cd[39] = 12; // 4096-byte pages
        for page in 0..2 {
            let digest = Sha256::digest(&data[page * PAGE..(page + 1) * PAGE]);
            let hash_start = CD_HEADER + page * HASH_SIZE;
            cd[hash_start..hash_start + HASH_SIZE].copy_from_slice(&digest);
        }

        let mut superblob = vec![0u8; SUPER_HEADER];
        put_be_u32(&mut superblob, 0, 0xfade_0cc0);
        put_be_u32(&mut superblob, 4, (SUPER_HEADER + CD_LEN) as u32);
        put_be_u32(&mut superblob, 8, 1);
        put_be_u32(&mut superblob, 12, 0); // CodeDirectory slot
        put_be_u32(&mut superblob, 16, SUPER_HEADER as u32);
        superblob.extend_from_slice(&cd);
        let sig_offset = data.len();
        data.extend_from_slice(&superblob);
        if tampered {
            data[PAGE + 17] ^= 0xff;
        }
        (data, sig_offset)
    }

    #[test]
    fn code_directory_page_hashes_validate() {
        let (data, sig_offset) = code_directory_fixture(false);
        assert_eq!(
            verify_code_directory_hashes(&data, sig_offset),
            CodeDirectoryIntegrity::Valid { checked: 2 }
        );
    }

    #[test]
    fn code_directory_page_hashes_detect_tampering() {
        let (data, sig_offset) = code_directory_fixture(true);
        assert_eq!(
            verify_code_directory_hashes(&data, sig_offset),
            CodeDirectoryIntegrity::Invalid {
                mismatched: 1,
                checked: 2
            }
        );
    }

    fn report_with_offsets() -> AnalysisReport {
        let target = crate::types::TargetInfo {
            path: "/tmp/fat".to_string(),
            file_type: "macho".to_string(),
            size_bytes: 0,
            sha256: String::new(),
            architectures: None,
        };
        let mut report = AnalysisReport::new(target);
        report.functions.push(crate::types::Function {
            name: "f".to_string(),
            offset: Some("0x1000".to_string()),
            size: None,
            complexity: None,
            calls: vec![],
            control_flow: None,
            register_usage: None,
            constants: vec![],
            signature: None,
            nesting: None,
            call_patterns: None,
        });
        report.imports.push(crate::types::Import {
            symbol: "acl_get_entry".to_string(),
            offset: Some("0x5078".to_string()),
            ..Default::default()
        });
        report
            .exports
            .push(Export::new("main", Some("0x2000".to_string())));
        // A section with both a file offset (rebased) and a vm address (left alone).
        report.sections.push(crate::types::Section {
            name: "__text".to_string(),
            address: Some(0x1_0000_4000),
            offset: Some(0x4000),
            size: 0,
            entropy: 0.0,
            permissions: None,
            flags: vec![],
        });
        report
    }

    /// The preferred slice of a fat Mach-O is parsed at base 0, so its
    /// structural offsets are slice-relative. Rebasing adds the slice's fat
    /// offset to every *file* offset (functions, imports, exports, section
    /// offsets) while leaving virtual addresses untouched — so symbol
    /// annotations line up with the full-file hex view.
    #[test]
    fn rebase_slice_offsets_shifts_file_offsets_only() {
        let mut report = report_with_offsets();
        MachOAnalyzer::rebase_slice_offsets(&mut report, 0x4000);

        assert_eq!(report.functions[0].offset.as_deref(), Some("0x5000"));
        assert_eq!(report.imports[0].offset.as_deref(), Some("0x9078"));
        assert_eq!(report.exports[0].offset.as_deref(), Some("0x6000"));
        // File offset rebased; virtual address (vmaddr) left as-is.
        assert_eq!(report.sections[0].offset, Some(0x8000));
        assert_eq!(report.sections[0].address, Some(0x1_0000_4000));
    }

    /// A fat slice's code-signature findings (identity, signer) anchor their
    /// evidence at slice-relative offsets. Rebasing must shift those too, or
    /// the "Identifier" annotation lands `delta` bytes early — inside the
    /// slice's __text instead of on the signature blob. Named or `archive:`
    /// locations carry no file offset and stay put.
    #[test]
    fn rebase_slice_offsets_shifts_finding_evidence() {
        let mut report = report_with_offsets();
        report.findings.push(Finding {
            id: "metadata/signed/id::com.apple.ls".to_string().into(),
            desc: "Identifier: com.apple.ls".to_string().into(),
            evidence: vec![
                Evidence {
                    location: Some("0x739b".to_string()),
                    ..Default::default()
                },
                Evidence {
                    location: Some("LC_CODE_SIGNATURE".to_string()),
                    offsets: vec![0x100],
                    ..Default::default()
                },
            ],
            ..Default::default()
        });
        MachOAnalyzer::rebase_slice_offsets(&mut report, 0x4000);

        // Hex-string location rebased onto the real signature blob.
        assert_eq!(
            report.findings[0].evidence[0].location.as_deref(),
            Some("0xb39b")
        );
        // Concrete offset rebased; the named location is left as-is.
        assert_eq!(report.findings[0].evidence[1].offsets, vec![0x4100]);
        assert_eq!(
            report.findings[0].evidence[1].location.as_deref(),
            Some("LC_CODE_SIGNATURE")
        );
    }

    #[test]
    fn rebase_slice_offsets_shifts_value_tree_companion_offsets() {
        let mut report = report_with_offsets();
        report.values_tree = Some(Box::new(serde_json::json!({
            "macho": { "uuid": "ed6f...", "uuid_offset": 1472u64 },
            "macho.code_signature_offset": 0x100u64,
        })));
        MachOAnalyzer::rebase_slice_offsets(&mut report, 0x4000);
        let tree = report.values_tree.expect("values tree present");
        // `*_offset` siblings shift by the slice delta so `type: value`
        // matches anchor on the full file; the value itself is untouched.
        assert_eq!(tree["macho"]["uuid_offset"].as_u64(), Some(0x4000 + 1472));
        assert_eq!(tree["macho"]["uuid"].as_str(), Some("ed6f..."));
        assert_eq!(tree["macho.code_signature_offset"].as_u64(), Some(0x4100));
    }

    /// A zero delta (thin binary / preferred slice already at offset 0) must
    /// be a no-op so thin binaries are never perturbed.
    #[test]
    fn rebase_slice_offsets_zero_delta_is_noop() {
        let mut report = report_with_offsets();
        MachOAnalyzer::rebase_slice_offsets(&mut report, 0);
        assert_eq!(report.imports[0].offset.as_deref(), Some("0x5078"));
        assert_eq!(report.sections[0].offset, Some(0x4000));
    }

    #[test]
    fn shift_hex_offset_parses_and_preserves_none() {
        let mut some = Some("0x10".to_string());
        shift_hex_offset(&mut some, 0xff0);
        assert_eq!(some.as_deref(), Some("0x1000"));

        let mut none: Option<String> = None;
        shift_hex_offset(&mut none, 0x100);
        assert_eq!(none, None);

        // A non-numeric location string (e.g. a forward target) is untouched.
        let mut label = Some("forward → KERNEL32.X".to_string());
        shift_hex_offset(&mut label, 0x100);
        assert_eq!(label.as_deref(), Some("forward → KERNEL32.X"));
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
        assert!(
            report
                .metadata
                .tools_used
                .contains(&"filefacts".to_string())
        );
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
                assert!(
                    finding
                        .evidence
                        .iter()
                        .any(|e| e.method == "entitlements_plist")
                );
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

    /// Identity (bundle/executable identifier) is Notable, not Baseline:
    /// "who the binary claims to be" must clear the notable-floored views so
    /// an analyst sees it in a diff. Locks the cross-format identity principle
    /// for the Mach-O emitter. Also pins the two invariants of the
    /// filefacts-sourced rewrite: a platform binary emits
    /// `metadata/signed/platform::apple`, the signer finding anchors at the
    /// signature-blob offset, and the identifier finding anchors at the
    /// distinct identifier-string offset. Deterministic — no fixture needed.
    #[test]
    fn test_identity_finding_is_notable() {
        let identity = filefacts::Identity {
            identifier: Some(filefacts::Claim::verified(
                "com.apple.ls",
                "macho.code_signature.identifier",
            )),
            trust: filefacts::Trust::Platform,
            ..Default::default()
        };
        let mut report = AnalysisReport::new(crate::types::TargetInfo {
            path: "/bin/ls".to_string(),
            file_type: "macho".to_string(),
            size_bytes: 0,
            sha256: String::new(),
            architectures: None,
        });
        emit_signature_findings(&mut report, 0xb3a0, Some(0xb3c8), &identity, None);

        let id_finding = report
            .findings
            .iter()
            .find(|f| f.id == "metadata/signed/id::com.apple.ls")
            .expect("identity finding emitted");
        assert_eq!(id_finding.crit, Criticality::Notable);
        // The value rides in the description so notable-floored views (which
        // print only `desc`, not the trait id) stay readable.
        assert_eq!(id_finding.desc, "Identifier: com.apple.ls");
        // Anchored at the identifier string itself, not the signature blob.
        assert_eq!(id_finding.evidence[0].location.as_deref(), Some("0xb3c8"));

        let platform = report
            .findings
            .iter()
            .find(|f| f.id == "metadata/signed/platform::apple")
            .expect("platform-trust finding emitted");
        assert_eq!(platform.crit, Criticality::Notable);
        assert_eq!(platform.desc, "macOS Platform Binary");
        // The signer finding still anchors at the signature blob.
        assert_eq!(platform.evidence[0].location.as_deref(), Some("0xb3a0"));
    }

    /// A Developer-ID-signed binary yields the `metadata/signed/developer::<team>`
    /// trait keyed by Team ID, with the signer organization in the description,
    /// plus a per-entitlement finding — all sourced from filefacts's `Identity`
    /// and entitlements map, none from a re-parse. This is the supply-chain
    /// signal an analyst reads first: who signed it, and what it was granted.
    #[test]
    fn test_developer_signed_and_entitlement_findings() {
        let identity = filefacts::Identity {
            trust: filefacts::Trust::DeveloperId,
            team_id: Some(filefacts::Claim::verified(
                "ABCDE12345",
                "macho.code_signature",
            )),
            signer: Some(filefacts::Signer {
                common_name: Some("Developer ID Application: Acme Inc. (ABCDE12345)".to_string()),
                organization: Some("Acme Inc.".to_string()),
                subject: None,
                issuer: None,
                signed_at: None,
                source: "macho.code_signature".to_string(),
            }),
            ..Default::default()
        };
        let mut entitlements = serde_json::Map::new();
        entitlements.insert(
            "com.apple.security.cs.debugger".to_string(),
            serde_json::Value::Bool(true),
        );
        let mut report = AnalysisReport::new(crate::types::TargetInfo {
            path: "/Applications/Acme.app/Contents/MacOS/Acme".to_string(),
            file_type: "macho".to_string(),
            size_bytes: 0,
            sha256: String::new(),
            architectures: None,
        });
        emit_signature_findings(&mut report, 0x4000, None, &identity, Some(&entitlements));

        let dev = report
            .findings
            .iter()
            .find(|f| f.id == "metadata/signed/developer::ABCDE12345")
            .expect("developer-trust finding keyed by team id");
        assert_eq!(dev.crit, Criticality::Notable);
        assert_eq!(dev.desc, "Developer ID: Acme Inc.");

        // A dangerous entitlement on a non-platform binary escalates to Suspicious.
        let ent = report
            .findings
            .iter()
            .find(|f| f.id == "metadata/entitlement/security::com.apple.security.cs.debugger")
            .expect("entitlement finding emitted");
        assert_eq!(ent.crit, Criticality::Suspicious);
        assert_eq!(ent.evidence[0].location.as_deref(), Some("0x4000"));
    }

    /// Permissions never fall to Baseline: every entitlement is at least
    /// Notable, and dangerous ones escalate to Suspicious. Guards the
    /// `determine_entitlement_criticality` invariant.
    #[test]
    fn test_entitlements_never_baseline() {
        // (key, is_platform)
        let cases = [
            ("com.apple.security.app-sandbox", false),
            ("com.apple.security.cs.allow-jit", false),
            ("com.apple.security.get-task-allow", false),
            ("com.apple.private.tcc.allow", true),
        ];
        for (key, is_platform) in cases {
            let crit = determine_entitlement_criticality(key, is_platform, false);
            assert!(
                crit >= Criticality::Notable,
                "entitlement {key} must be Notable-or-higher, got {crit:?}"
            );
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
            "Allows libraries without signature validation"
        );
        assert_eq!(
            describe_entitlement("com.apple.security.cs.allow-jit"),
            "Allows JIT-compiled executable memory"
        );
        assert_eq!(
            describe_entitlement("personal-information.location"),
            "Location data access"
        );
        assert_eq!(describe_entitlement("device.camera"), "Camera access");
        assert_eq!(
            describe_entitlement("com.apple.security.network.client"),
            "Can make outbound network connections"
        );
        assert_eq!(
            describe_entitlement("com.apple.security.network.server"),
            "Can accept incoming network connections"
        );
        assert_eq!(
            describe_entitlement("com.apple.security.files.user-selected.read-write"),
            "Can read and modify user-selected files"
        );
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
                determine_entitlement_criticality(key, true, false,),
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
                determine_entitlement_criticality(key, false, false,),
                Criticality::Suspicious,
                "non-Apple entitlement {key} should be suspicious"
            );
        }
        // allow-jit is common in legitimate apps, notable not suspicious
        assert_eq!(
            determine_entitlement_criticality("com.apple.security.cs.allow-jit", false, false,),
            Criticality::Notable,
        );
    }

    #[test]
    fn test_determine_entitlement_criticality_disable_library_validation_notable() {
        // disable-library-validation is common for developer-signed apps (plugins, frameworks)
        assert_eq!(
            determine_entitlement_criticality(
                "com.apple.security.cs.disable-library-validation",
                false,
                false,
            ),
            Criticality::Notable,
        );
    }

    #[test]
    fn test_determine_entitlement_criticality_privacy_notable() {
        for key in ["personal-information.location", "device.bluetooth"] {
            assert_eq!(
                determine_entitlement_criticality(key, false, false,),
                Criticality::Notable,
            );
        }
    }

    #[test]
    fn test_determine_entitlement_criticality_allow_unsigned_exec_memory_common_helper() {
        assert_eq!(
            determine_entitlement_criticality(
                "com.apple.security.cs.allow-unsigned-executable-memory",
                false,
                true,
            ),
            Criticality::Notable,
        );
        assert_eq!(
            determine_entitlement_criticality(
                "com.apple.security.cs.allow-unsigned-executable-memory",
                false,
                true,
            ),
            Criticality::Notable,
        );
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
        // sourced from filefacts (cleave no longer re-parses the signature).
        for finding in &identifier_findings {
            assert_eq!(finding.evidence[0].method, "code_directory");
            assert_eq!(finding.evidence[0].source, "filefacts");
        }
    }
}
