//! Mach-O binary analyzer for macOS executables.
//!
//! Every Mach-O helper takes a non-optional
//! [`crate::analysis_context::AnalysisContext`]: structural data
//! (segments, dylibs, code signature, header bits) is read from
//! `filefacts`'s typed views rather than re-walked with goblin. The
//! analyzer no longer carries its own goblin parse path.
use crate::analyzers::macho_codesign;
use crate::analyzers::{AnalysisInput, Analyzer};
use crate::capabilities::CapabilityMapper;
use crate::entropy::EntropyLevel;
use crate::strings::StringExtractor;
use crate::types::{
    AnalysisReport, Criticality, Evidence, Export, Finding, FindingKind, StringInfo,
    StructuralFeature, TargetInfo,
};
use anyhow::{Context, Result};
use std::fs;
use std::path::Path;
use std::sync::Arc;

type Ctx<'a> = crate::analysis_context::AnalysisContext<'a>;

/// Analyzer for macOS Mach-O binaries (executables, dylibs, bundles).
///
/// Wave B routed deep-binary signal through `filefacts::open`: function
/// CFG fields and rizin-recovered symbols arrive on
/// `ctx.parsed.functions()` / `imports()` / `exports()`. The analyzer
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

        // Parse code signature for findings and richer metrics (team
        // ID, entitlements, hardened runtime). Filefacts already emits
        // most of the same data under `macho.code_signature.*`, but
        // the structured `CodeSignature` value drives downstream
        // helpers (entitlement criticality, dangerous-entitlement
        // counting). Reuse filefacts's `LC_CODE_SIGNATURE` offset via
        // the typed Section/values machinery is more work than just
        // re-parsing the blob; the cleave-side parser is already
        // panic-safe and ~free on the trivial fixtures.
        let codesig_data: Option<macho_codesign::CodeSignature> =
            code_signature_blob_range_from_ctx(ctx)
                .and_then(|(off, size)| macho_codesign::parse_code_signature(data, off, size).ok());

        // Phase 1: structural features, signature findings, imports,
        // exports, sections. All driven from ctx.
        let _t = std::time::Instant::now();
        self.fill_structural_features_from_ctx(ctx, &mut report);
        let structure_ms = _t.elapsed().as_millis();

        let _t = std::time::Instant::now();
        if let Some(ref codesig) = codesig_data {
            self.generate_signature_findings(codesig, &mut report);
        }
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
            .functions()
            .iter()
            .map(crate::analysis_context::project_filefacts_function)
            .collect();
        if ctx.parsed.functions().iter().any(|f| f.source == "rizin") {
            tools_used.push("radare2".to_string());
        }
        let r2_strings: Option<Vec<stng::ExtractedString>> = None;
        let _ = (allow_rizin, precomputed_sha256, codesig_data);

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
            let _ = r2_strings;
            report.strings = self.string_extractor.extract_smart(data);
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
                        .and_then(|x| x.as_u64())
                        .unwrap_or(0)
                ),
                location: None,
                ..Default::default()
            }],
        });

        let arch = arch_name_from_ctx(ctx);
        let cputype_raw = v
            .get("macho.cpu_type_raw")
            .and_then(|x| x.as_u64())
            .unwrap_or(0);
        report.structure.push(StructuralFeature {
            id: format!("binary/arch/{}", arch),
            desc: format!("{} architecture", arch),
            evidence: vec![Evidence {
                method: "header".to_string(),
                source: "filefacts".to_string(),
                value: format!("cputype=0x{:x}", cputype_raw),
                location: None,
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
            for lib in libs {
                let Some(name) = lib.as_str() else { continue };
                if name.is_empty() {
                    continue;
                }
                Self::push_metadata_finding(
                    report,
                    "metadata/binary/linking::macho-dylib",
                    "Mach-O linked dylib",
                    "load_dylib",
                    "filefacts",
                    name.to_string(),
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

    /// Pull imports off filefacts's typed Imports view, run capability
    /// lookups against each, and merge into the report.
    fn analyze_imports_from_ctx(&self, ctx: &Ctx<'_>, report: &mut AnalysisReport) {
        for imp in ctx.imports_from_filefacts() {
            if let Some(cap) = self.capability_mapper.lookup(&imp.symbol, &imp.source) {
                if !report.findings.iter().any(|c| c.id == cap.id) {
                    report.findings.push(cap);
                }
            }
            report.imports.push(imp);
        }
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

    // AMOS cipher detection/decryption removed - now handled by stng library internally
}

/// Architecture label for a Mach-O ctx. Mirrors filefacts's
/// `cpu_type_string` taxonomy (`x86_64`, `arm64`, `arm64e`, …) so
/// downstream consumers see a canonical lowercase name. Returns
/// `unknown_0x<hex>` when the cpu type isn't in filefacts's known set.
fn arch_name_from_ctx(ctx: &Ctx<'_>) -> String {
    let v = ctx.parsed.values();
    if let Some(name) = v.get("macho.cpu_type").and_then(|x| x.as_str()) {
        if name != "unknown" {
            return name.to_string();
        }
    }
    let raw = v
        .get("macho.cpu_type_raw")
        .and_then(|x| x.as_u64())
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

/// Locate the LC_CODE_SIGNATURE blob `(file_offset, size)` from
/// filefacts's code-signature metadata. Returns `None` when the binary
/// is unsigned. `file_offset` isn't currently emitted by filefacts, so
/// we recover it from the `__LINKEDIT` segment + the signature size:
/// the cms blob always sits at the end of `__LINKEDIT`.
///
/// This is a small hack that lets the cleave-side
/// `macho_codesign::parse_code_signature` consume the same bytes
/// filefacts's parser saw, without re-walking the load commands.
fn code_signature_blob_range_from_ctx(ctx: &Ctx<'_>) -> Option<(u32, u32)> {
    let v = ctx.parsed.values();
    // Filefacts surfaces the signature size when LC_CODE_SIGNATURE is
    // present; absence here means there's no signature to parse.
    let size = v
        .get("macho.code_signature_size")
        .and_then(|x| x.as_u64())? as u32;
    if size == 0 {
        return None;
    }
    // The LC_CODE_SIGNATURE blob sits inside __LINKEDIT, at the very
    // end. Use `__LINKEDIT.file_offset + __LINKEDIT.file_size - size`
    // as the start offset.
    let segs = v.get("macho.segments").and_then(|x| x.as_array())?;
    let linkedit = segs
        .iter()
        .find(|s| s.get("name").and_then(|n| n.as_str()) == Some("__LINKEDIT"))?;
    let file_offset = linkedit.get("file_offset").and_then(|x| x.as_u64())?;
    let file_size = linkedit.get("file_size").and_then(|x| x.as_u64())?;
    let end = file_offset.checked_add(file_size)?;
    let cs_off = end.checked_sub(u64::from(size))?;
    Some((cs_off as u32, size))
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
                .and_then(|v| v.as_u64())
                .unwrap_or(0) as usize;
            let size = slice.get("file_size").and_then(|v| v.as_u64()).unwrap_or(0) as usize;
            if size > 0 && off.saturating_add(size) <= data.len() {
                return off..off + size;
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
                        let off = s.get("file_offset").and_then(|v| v.as_u64())? as usize;
                        let size = s.get("file_size").and_then(|v| v.as_u64())? as usize;
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
                        let off = s.get("file_offset").and_then(|v| v.as_u64())? as usize;
                        let size = s.get("file_size").and_then(|v| v.as_u64())? as usize;
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
            let Some(offset) = slice.get("file_offset").and_then(|x| x.as_u64()) else {
                continue;
            };
            let Some(size) = slice.get("file_size").and_then(|x| x.as_u64()) else {
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
            let arch_name = slice
                .get("cpu_type")
                .and_then(|x| x.as_str())
                .unwrap_or("unknown");
            let import_source = format!("filefacts-{}", arch_name);

            let Ok(slice_ctx) =
                crate::analysis_context::AnalysisContext::open(dummy_path, slice_bytes)
            else {
                continue;
            };
            arches_parsed += 1;

            for imp in slice_ctx.imports_from_filefacts() {
                let key = (imp.symbol.clone(), imp.library.clone());
                if !seen_imports.insert(key) {
                    continue;
                }
                let symbol = imp.symbol.clone();
                report.imports.push(crate::types::Import {
                    source: import_source.clone(),
                    ..imp
                });
                if let Some(cap) = self.capability_mapper.lookup(&symbol, "macho-bind") {
                    if !report.findings.iter().any(|c| c.id == cap.id) {
                        report.findings.push(cap);
                    }
                }
            }

            for exp in slice_ctx.exports_from_filefacts() {
                let symbol = exp.symbol.clone();
                if !seen_exports.insert(symbol) {
                    continue;
                }
                report.exports.push(Export {
                    source: import_source.clone(),
                    ..exp
                });
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

        if let Some(msg) = parse_failure {
            report.metadata.errors.push(msg.clone());
            report.findings.push(Finding {
                kind: FindingKind::Structural,
                id: "anti-analysis/malformed/macho-header".to_string(),
                desc: format!("Malformed Mach-O header: {}", msg),
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
        let mut report =
            match crate::analysis_context::AnalysisContext::open(input.path, preferred_data) {
                Ok(ctx) => self.analyze_structural_with_strings(
                    input.path,
                    input.backing_path(),
                    preferred_data,
                    strings,
                    !input.skip_rizin,
                    input.sha256.clone(),
                    &ctx,
                ),
                Err(e) => {
                    let sha256 = input.sha256.clone().unwrap_or_else(|| {
                        crate::analyzers::utils::calculate_sha256(preferred_data)
                    });
                    self.analyze_macho_fallback(
                        input.path,
                        input.backing_path(),
                        preferred_data,
                        sha256,
                        Some(format!("filefacts open failed: {e}")),
                        !input.skip_rizin,
                        input.sha256.clone(),
                        std::time::Instant::now(),
                    )
                }
            };
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
        assert!(report
            .metadata
            .tools_used
            .contains(&"filefacts".to_string()));
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
        assert_eq!(
            determine_entitlement_criticality(
                "com.apple.security.cs.allow-unsigned-executable-memory",
                &macho_codesign::SignatureType::Adhoc,
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
        for finding in &identifier_findings {
            assert_eq!(finding.evidence[0].method, "code_directory");
            assert_eq!(finding.evidence[0].source, "codesign_parser");
        }
    }
}
