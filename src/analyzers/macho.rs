//! Mach-O binary analyzer for macOS executables.
//!
//! Every Mach-O helper takes a non-optional
//! `AnalysisContext`: structural data
//! (segments, dylibs, code signature, header bits) is read from
//! `filefacts`'s typed views; this analyzer never parses the file itself.
// Parses attacker-controlled bytes: index and offset arithmetic must be
// checked, so a forged header is a parse error rather than a panic.
#![warn(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use crate::analyzers::{AnalysisInput, Analyzer};
use crate::entropy::EntropyLevel;
use crate::strings::StringExtractor;
use crate::types::{
    AnalysisReport, Criticality, Evidence, Export, Finding, FindingKind, StringInfo,
    StructuralFeature, TargetInfo,
};
use anyhow::{Context, Result};
use std::fs;
use std::path::Path;

type Ctx<'a> = crate::analysis_context::AnalysisContext<'a>;

/// Analyzer for macOS Mach-O binaries (executables, dylibs, bundles).
///
/// Function CFG fields and recovered symbols arrive through
/// `filefacts::open` on `ctx.parsed.symbols()` (filtered by kind), and
/// imports come from filefacts's typed Mach-O view.
#[derive(Debug)]
pub(crate) struct MachOAnalyzer {
    engine: crate::Engine,
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
            engine: crate::Engine::empty(),
            string_extractor: StringExtractor::new(),
            preextracted_strings: None,
            cancellation: None,
        }
    }

    /// Analyze under `engine`: its rules and settings.
    #[must_use]
    pub(crate) fn with_engine(mut self, engine: crate::Engine) -> Self {
        self.engine = engine;
        self
    }

    /// Set pre-extracted strings (avoids a redundant stng extraction)
    #[must_use]
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

    /// Inspect an embedded Nuitka distribution on both the direct and
    /// top-level Mach-O paths. Only the preferred thin slice is passed here.
    pub(crate) fn analyze_nuitka_payload(
        &self,
        path: &Path,
        data: &[u8],
        report: &mut AnalysisReport,
        config: &crate::analyzers::archive::ArchiveAnalyzerConfig,
        yara: Option<std::sync::Arc<crate::yara_engine::YaraEngine>>,
    ) {
        if crate::analyzers::sfx_detector::detect_sfx(data, &[])
            != Some(crate::analyzers::sfx_detector::SfxKind::Nuitka)
        {
            return;
        }
        let sfx = crate::analyzers::sfx_detector::analyze_sfx(
            path,
            crate::analyzers::sfx_detector::SfxKind::Nuitka,
            data,
            &self.engine,
            yara,
            Some(config),
            &[],
        );
        report.findings.push(sfx.sfx_finding);
        report.findings.extend(sfx.extraction_findings);
        if let Some(child) = sfx.archive_report {
            report.findings.extend(child.findings);
            let parent = path.to_string_lossy();
            let parent_prefix =
                format!("{parent}{}", crate::types::file_analysis::ARCHIVE_DELIMITER);
            for mut file in child.files {
                if !file.path.starts_with(&parent_prefix) {
                    file.path =
                        crate::types::file_analysis::encode_archive_path(&parent, &file.path);
                }
                report.files.push(file);
            }
            for mut entry in child.archive_contents {
                if !entry
                    .path
                    .contains(crate::types::file_analysis::ARCHIVE_DELIMITER)
                {
                    entry.path =
                        crate::types::file_analysis::encode_archive_path(&parent, &entry.path);
                }
                report.archive_contents.push(entry);
            }
        }
    }

    /// Scan recovered text in this slice, including supplementary FAT slices.
    fn analyze_integer_table_scripts(
        &self,
        logical_path: &Path,
        data: &[u8],
        ctx: &Ctx<'_>,
        report: &mut AnalysisReport,
        base_offset: usize,
    ) {
        for (payload, encoding) in
            crate::extractors::macho_integer_tables::recover(data, &ctx.parsed)
                .into_iter()
                .map(|p| {
                    (
                        p,
                        vec![
                            "integer-sub-xor".to_string(),
                            "hex".to_string(),
                            "custom-base64".to_string(),
                        ],
                    )
                })
                .chain(
                    crate::extractors::macho_hex_scripts::recover(data, &ctx.parsed)
                        .into_iter()
                        .map(|p| (p, vec!["hex".to_string(), "rc4".to_string()])),
                )
                .chain(
                    crate::extractors::macho_hex_scripts::recover_custom(data, &ctx.parsed)
                        .into_iter()
                        .map(|p| (p, vec!["hex".to_string(), "custom-base64".to_string()])),
                )
                .chain(
                    crate::extractors::macho_hex_scripts::recover_lcg(data, &ctx.parsed)
                        .into_iter()
                        .map(|p| (p, vec!["lcg-xor".to_string()])),
                )
        {
            if self
                .cancellation
                .as_ref()
                .is_some_and(|c| c.load(std::sync::atomic::Ordering::Acquire))
            {
                break;
            }
            let Ok(command) = std::str::from_utf8(&payload.data) else {
                continue;
            };
            // Strip only this complete quoted interpreter wrapper. Other
            // recovered text remains visible without guessing its language.
            let Some(source) = crate::extractors::macho_integer_tables::inline_applescript(command)
            else {
                continue;
            };
            // FAT slices can contain identical payloads. Attach one decoded
            // child so the same finding is not reported twice.
            let source_hash = crate::analyzers::utils::calculate_sha256(source.as_bytes());
            if report.files.iter().any(|file| file.sha256 == source_hash) {
                continue;
            }
            let is_lcg = encoding.first().is_some_and(|x| x == "lcg-xor");
            let is_hex_rc4 = encoding.first().is_some_and(|x| x == "hex");
            let is_custom_base64 =
                encoding.last().is_some_and(|x| x == "custom-base64") && is_hex_rc4;
            let chain = encoding;
            let path = crate::types::encode_decoded_path(
                &logical_path.display().to_string(),
                &chain,
                report.files.len(),
            );
            let child_input = AnalysisInput::new(
                Path::new(&path),
                source.as_bytes(),
                crate::FileType::AppleScript,
            )
            .at_depth(1);
            match crate::analyzers::applescript::AppleScriptAnalyzer::new()
                .with_engine(self.engine.clone())
                .analyze_input(&child_input)
            {
                Ok(mut child_report) => {
                    child_report.dedupe_findings();
                    let doomed = self
                        .engine
                        .rules()
                        .doomed_low_value_ids(&child_report.findings);
                    crate::context::capture(
                        &mut child_report,
                        source.as_bytes(),
                        crate::FileType::AppleScript,
                        &doomed,
                    );
                    let (mut child, nested, _) = child_report.into_file_analysis(0, &self.engine);
                    child.path = path;
                    child.depth = 1;
                    child.encoding = Some(chain);
                    child.compute_summary();
                    report.files.push(child);
                    report.files.extend(nested);
                    report.structure.push(StructuralFeature {
                        id: if is_lcg {
                            "data/lcg-xor-script"
                        } else if is_custom_base64 {
                            "data/hex-custom-base64-script"
                        } else if is_hex_rc4 {
                            "data/hex-rc4-script"
                        } else {
                            "data/integer-table-script"
                        }
                        .to_string(),
                        desc: if is_lcg {
                            "Script data recovered from LCG XOR"
                        } else if is_custom_base64 {
                            "Script data recovered from hex and custom Base64"
                        } else if is_hex_rc4 {
                            "Script data recovered from hex and RC4"
                        } else {
                            "Script data recovered from integer tables and custom alphabet"
                        }
                        .to_string(),
                        evidence: vec![Evidence {
                            method: "static-decode".to_string(),
                            source: if is_lcg {
                                "macho_lcg_xor"
                            } else if is_custom_base64 {
                                "macho_hex_custom_base64"
                            } else if is_hex_rc4 {
                                "macho_hex_rc4"
                            } else {
                                "macho_integer_tables"
                            }
                            .to_string(),
                            value: format!(
                                "{} recovered script bytes; no specimen code executed",
                                source.len()
                            ),
                            location: Some(format!(
                                "offset:{}",
                                payload.offset.saturating_add(base_offset)
                            )),
                            offsets: vec![payload.offset.saturating_add(base_offset) as u64],
                            ..Evidence::default()
                        }],
                    });
                }
                Err(error) => report
                    .metadata
                    .errors
                    .push(format!("integer-table-script: {error:#}")),
            }
        }
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
        let ctx = crate::analysis_context::AnalysisContext::open_with(
            self.engine.filefacts_options(),
            file_path,
            data,
        );
        self.analyze_structural_with_ctx(file_path, data, precomputed_sha256, &ctx)
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
    fn analyze_structural_with_strings<'a>(
        &self,
        logical_path: &Path,
        analysis_path: &Path,
        data: &'a [u8],
        stng_strings: Option<&[stng::ExtractedString]>,
        precomputed_sha256: Option<String>,
        ctx: &Ctx<'a>,
    ) -> AnalysisReport {
        let start = std::time::Instant::now();
        let sha256 =
            precomputed_sha256.unwrap_or_else(|| crate::analyzers::utils::calculate_sha256(data));

        // filefacts marks unparseable bytes with `macho.parse_failed` or
        // `macho.parse_panicked` metrics. When neither the parse
        // succeeded nor a fat-slice cpu_type was observed, fall back
        // to the recovery path so the binary still gets baseline metrics
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
            return self.analyze_macho_fallback(logical_path, data, sha256, parse_msg);
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
        report.imports.extend(ctx.imports_from_filefacts());
        let imports_ms = _t.elapsed().as_millis();

        let _t = std::time::Instant::now();
        report.exports.extend(ctx.exports_from_filefacts());
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

        // Functions come from filefacts's typed `Functions` view — CFG
        // fields ride along when binform recovered them (stripped binaries
        // / packed bodies); symbol-table-only entries leave the cleave CFG
        // mirror `None`.
        let _t_functions = std::time::Instant::now();
        report.functions = ctx
            .parsed
            .symbols()
            .iter_kind(filefacts::SymbolKind::Function)
            .filter_map(crate::analysis_context::project_filefacts_function)
            .collect();

        let functions_ms = _t_functions.elapsed().as_millis();

        // Strings: the caller's extraction, then pre-extracted strings, then
        // filefacts.
        let _t = std::time::Instant::now();
        if let Some(strings) = stng_strings {
            self.string_extractor.prioritize_report_symbols(&report);
            report.strings = self.string_extractor.convert_stng_strings(strings);
            self.string_extractor.record_count_metrics(
                report
                    .filefacts_metrics
                    .get_or_insert_with(Default::default),
            );
        } else if let Some(ref strings) = self.preextracted_strings {
            report.strings = strings.clone();
        } else {
            // No pre-extracted strings supplied: source them from filefacts.
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

        // Analyze embedded code in strings
        let _t = std::time::Instant::now();
        let string_count = report.strings.len();
        let (encoded_layers, plain_findings) =
            crate::analyzers::embedded_code_detector::process_all_strings(
                &logical_path.display().to_string(),
                &report.strings,
                &self.engine,
                0,
                Some(&crate::FileType::MachO),
                self.cancellation.as_deref(),
            );
        report.files.extend(encoded_layers);
        report.findings.extend(plain_findings);
        self.analyze_integer_table_scripts(logical_path, data, ctx, &mut report, 0);
        for payload in crate::extractors::macho_chacha::recover(data, &ctx.parsed) {
            if self
                .cancellation
                .as_ref()
                .is_some_and(|c| c.load(std::sync::atomic::Ordering::Acquire))
            {
                break;
            }
            let chain = vec![
                "pbkdf2-sha256".to_string(),
                "hkdf-sha256".to_string(),
                format!("chacha20-poly1305:{}", payload.segments),
            ];
            let path = crate::types::encode_decoded_path(
                &logical_path.display().to_string(),
                &chain,
                report.files.len(),
            );
            let child_input = AnalysisInput::new(
                Path::new(&path),
                &payload.data,
                crate::FileType::AppleScript,
            )
            .at_depth(1);
            match crate::analyzers::applescript::AppleScriptAnalyzer::new()
                .with_engine(self.engine.clone())
                .analyze_input(&child_input)
            {
                Ok(mut child_report) => {
                    child_report.dedupe_findings();
                    let doomed = self
                        .engine
                        .rules()
                        .doomed_low_value_ids(&child_report.findings);
                    crate::context::capture(
                        &mut child_report,
                        &payload.data,
                        crate::FileType::AppleScript,
                        &doomed,
                    );
                    let (mut child, nested, _) = child_report.into_file_analysis(0, &self.engine);
                    child.path = path;
                    child.depth = 1;
                    child.encoding = Some(chain);
                    child.compute_summary();
                    report.files.push(child);
                    report.files.extend(nested);
                    report.structure.push(StructuralFeature {
                        id: "crypto/authenticated-script-payload".to_string(),
                        desc: "Compiled script recovered from authenticated encrypted chunks"
                            .to_string(),
                        evidence: vec![Evidence {
                            method: "crypto".to_string(),
                            source: "macho_chacha".to_string(),
                            value: format!(
                                "segments={}; pbkdf2_iterations={}; all tags verified",
                                payload.segments, payload.iterations
                            ),
                            location: Some(format!("offset:{}", payload.offset)),
                            offsets: vec![payload.offset as u64],
                            ..Evidence::default()
                        }],
                    });
                }
                Err(error) => report
                    .metadata
                    .errors
                    .push(format!("authenticated-script: {error:#}")),
            }
        }
        let embedded_ms = _t.elapsed().as_millis();

        tracing::info!(
            path = %logical_path.display(),
            functions_ms,
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
        // Checked first: code pages that no longer hash to the
        // CodeDirectory mean the signer's identity belongs under
        // `invalid/tampered/`, whatever chain the signature carries.
        let tampered = if let CodeDirectoryIntegrity::Invalid {
            mismatched,
            checked,
        } = verify_code_directory_hashes(data, sig_offset as usize)
        {
            report.findings.push(signature_finding(
                "metadata/signature/invalid/tampered::macho-code-directory".to_string(),
                "Mach-O code pages do not match their code signature".to_string(),
                Criticality::Suspicious,
                "code_directory_hashes",
                format!("{mismatched} of {checked} signed code pages do not match"),
                &format!("0x{sig_offset:x}"),
            ));
            Some(super::signature::Failure::Tampered)
        } else {
            None
        };
        emit_signature_findings(
            report,
            sig_offset,
            identifier_offset,
            &identity,
            entitlements,
            tampered,
            values
                .get("macho.code_signature.cms")
                .and_then(super::signature::pinned_issuer),
        );
    }

    // AMOS cipher detection/decryption removed - now handled by stng library internally
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
/// A fat Mach-O's slice table: filefacts' `macho.slices` entries, with their
/// extent in the fat file. Empty for a thin binary.
#[derive(Debug, Default)]
pub(crate) struct FatSlices(Vec<FatSlice>);

#[derive(Debug)]
struct FatSlice {
    offset: usize,
    size: usize,
    cpu_type: Option<String>,
}

impl FatSlices {
    /// The slice table of `data`, read from `whole` (a parse of exactly
    /// `data`) when the caller has one, else from a parse opened here under
    /// `options`. Reading a fat binary's values runs its whole extraction —
    /// recovery on every slice — so each helper reopening it, as they once did,
    /// repeated that up to four more times per file. Thin binaries have no
    /// table and skip the parse.
    pub(crate) fn of(
        data: &[u8],
        whole: Option<&crate::analysis_context::AnalysisContext<'_>>,
        options: &filefacts::OpenOptions<'_>,
    ) -> Self {
        if !is_fat_macho(data) {
            return Self::default();
        }
        match whole {
            Some(ctx) => Self::from_parsed(&ctx.parsed),
            None => Self::from_parsed(&options.open(data)),
        }
    }

    fn from_parsed(parsed: &filefacts::ParsedFile<'_>) -> Self {
        let Some(entries) = parsed
            .values()
            .get("macho.slices")
            .and_then(|v| v.as_array())
        else {
            return Self::default();
        };
        Self(
            entries
                .iter()
                .filter_map(|s| {
                    Some(FatSlice {
                        offset: s.get("file_offset")?.as_u64()? as usize,
                        size: s.get("file_size")?.as_u64()? as usize,
                        cpu_type: s
                            .get("cpu_type")
                            .and_then(|c| c.as_str())
                            .map(str::to_string),
                    })
                })
                .collect(),
        )
    }
}

fn is_fat_macho(data: &[u8]) -> bool {
    matches!(
        data.get(0..4),
        Some([0xCA, 0xFE, 0xBA, 0xBE]) // FAT_MAGIC
            | Some([0xCA, 0xFE, 0xBA, 0xBF]) // FAT_MAGIC_64
            | Some([0xBE, 0xBA, 0xFE, 0xCA]) // FAT_CIGAM
            | Some([0xBF, 0xBA, 0xFE, 0xCA]) // FAT_CIGAM_64
    )
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
    pub(crate) fn preferred_arch_range(
        &self,
        data: &[u8],
        slices: &FatSlices,
    ) -> std::ops::Range<usize> {
        let pick = slices
            .0
            .iter()
            .find(|s| s.cpu_type.as_deref() == Some("arm64"))
            .or_else(|| slices.0.first());
        if let Some(slice) = pick
            && slice.size > 0
            && slice.offset.saturating_add(slice.size) <= data.len()
        {
            return slice.offset..slice.offset.saturating_add(slice.size);
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
    pub(crate) fn labeled_arch_ranges(
        &self,
        data: &[u8],
        slices: &FatSlices,
    ) -> Vec<(crate::composite_rules::Arch, std::ops::Range<usize>)> {
        use crate::composite_rules::Arch;
        let ranges: Vec<_> = slices
            .0
            .iter()
            .filter_map(|s| {
                let name = s.cpu_type.as_deref()?;
                (s.size > 0 && s.offset.saturating_add(s.size) <= data.len()).then(|| {
                    (
                        Arch::from_report_str(name),
                        s.offset..s.offset.saturating_add(s.size),
                    )
                })
            })
            .collect();
        if !ranges.is_empty() {
            return ranges;
        }
        vec![(Arch::All, 0..data.len())]
    }

    #[allow(clippy::single_range_in_vec_init)] // Intentional: returns single range for thin binaries
    pub(crate) fn all_arch_ranges(
        &self,
        data: &[u8],
        slices: &FatSlices,
    ) -> Vec<std::ops::Range<usize>> {
        let ranges: Vec<_> = slices
            .0
            .iter()
            .filter(|s| s.size > 0 && s.offset.saturating_add(s.size) <= data.len())
            .map(|s| s.offset..s.offset.saturating_add(s.size))
            .collect();
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
        slices: &FatSlices,
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
        let mut arches_parsed = 0usize;

        // The same slice table the range helpers read; each non-preferred
        // slice is parsed on its own, under this analyzer's engine.
        let dummy_path = Path::new("");
        for &FatSlice { offset, size, .. } in &slices.0 {
            if offset == preferred_offset {
                continue;
            }
            if size == 0 {
                continue;
            }
            let Some(slice_bytes) = data.get(offset..offset.saturating_add(size)) else {
                continue;
            };
            let slice_ctx = crate::analysis_context::AnalysisContext::open_with(
                self.engine.filefacts_options(),
                dummy_path,
                slice_bytes,
            );
            arches_parsed = arches_parsed.saturating_add(1);
            let logical_path = report.target.path.clone();
            self.analyze_integer_table_scripts(
                Path::new(&logical_path),
                slice_bytes,
                &slice_ctx,
                report,
                offset,
            );

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

        let extra_imports = report.imports.len().saturating_sub(baseline_imports);
        let extra_exports = report.exports.len().saturating_sub(baseline_exports);
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
    pub(crate) fn apply_fat_metadata(
        &self,
        report: &mut AnalysisReport,
        data: &[u8],
        slices: &FatSlices,
    ) {
        if !is_fat_macho(data) {
            return;
        }
        // The structural pass ran on the preferred slice and stamped the
        // slice length as the target size. The target is the FILE: `size`
        // in the output (and the `file.size` metric derived from it) must
        // be the on-disk byte count (measured: a 712,624-byte universal
        // binary emitted size=352,176 — its x86-64 slice). Both the
        // single-file and archive-member paths come through here with the
        // full-file bytes.
        report.target.size_bytes = data.len() as u64;
        let arch_names: Vec<String> = slices.0.iter().filter_map(|s| s.cpu_type.clone()).collect();
        if !arch_names.is_empty() {
            report.target.architectures = Some(arch_names);
        }
    }

    /// Build a minimal Mach-O analysis report when filefacts couldn't
    /// parse the binary cleanly (the parse failed or panicked, or
    /// no `macho.cpu_type` was emitted). Any functions, imports or sections
    /// filefacts recovered reach the report through
    /// `analyze_structural_with_ctx` instead.
    fn analyze_macho_fallback(
        &self,
        logical_path: &Path,
        data: &[u8],
        sha256: String,
        parse_failure: Option<String>,
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
                precomputed_spans: None,
                src: None,
                kind: FindingKind::Structural,
                id: "metadata/analysis/limitation::macho-parse-failed"
                    .to_string()
                    .into(),
                desc: format!("Mach-O structural parsing failed: {}", msg).into(),
                conf: 1.0,
                crit: Criticality::Notable,
                mbc: None,
                attack: None,
                evidence: vec![],
                match_count: 0,
                trait_refs: vec![],
                source_file: None,
                downgraded: false,
            });
        }

        // Filefacts's recovery already populated the typed `Functions`
        // view by the time the fallback path runs — the analysis context
        // here is built by the caller and projected through
        // `open_with_path`. A caller that needs recovered functions here
        // should pass an `AnalysisContext` instead of bytes.
        report
    }
}

impl Analyzer for MachOAnalyzer {
    fn analyze_input(&self, input: &AnalysisInput<'_>) -> Result<AnalysisReport> {
        // A fat binary needs one parse of the whole file: its slice table,
        // and the full-file evaluation below. Reuse the caller's when it
        // threaded one in; open it once otherwise.
        let opened_full_ctx = (is_fat_macho(input.data) && input.parsed_ctx.is_none())
            .then(|| input.open_ctx_with(self.engine.filefacts_options()));
        let full_ctx = input.parsed_ctx.or(opened_full_ctx.as_ref());
        let slices = FatSlices::of(input.data, full_ctx, &self.engine.filefacts_options());

        // Get all architecture slices (for FAT binaries) or the single slice (for thin binaries)
        let arch_ranges = self.all_arch_ranges(input.data, &slices);

        // Use preferred arch for structural analysis (imports, exports, strings, etc.)
        let preferred_range = self.preferred_arch_range(input.data, &slices);
        let preferred_range_start = preferred_range.start;
        let preferred_is_full_file =
            preferred_range.start == 0 && preferred_range.end == input.data.len();
        // `preferred_arch_range` returns an in-bounds slice range or the whole file.
        let preferred_data = input.data.get(preferred_range).unwrap_or(input.data);
        let strings = if input.strings.is_empty() {
            None
        } else {
            Some(input.strings)
        };
        // Open filefacts-side parse so downstream helpers source structural
        // data from filefacts's typed views. When filefacts can't open the
        // bytes the fallback path (recovery-based metrics + malformed
        // signal) is taken by `analyze_structural_with_strings` via
        // `analyze_structural` synthesising a fresh ctx; either way
        // we never re-walk with goblin from here.
        // Archive and unified entry points already opened a context over the
        // full member. A thin Mach-O's preferred slice is that exact member,
        // so reuse it; reopening used to repeat every filefacts pass,
        // recovery included. Fat slices still need their own slice-relative
        // context so offsets can be rebased correctly below.
        let opened_preferred_ctx = if preferred_is_full_file && input.parsed_ctx.is_some() {
            None
        } else {
            let options = self.engine.filefacts_options();
            Some(crate::analysis_context::AnalysisContext::open_with(
                options,
                input.path,
                preferred_data,
            ))
        };
        let preferred_ctx = if preferred_is_full_file {
            input.parsed_ctx.or(opened_preferred_ctx.as_ref())
        } else {
            opened_preferred_ctx.as_ref()
        };
        let mut report = if let Some(ctx) = preferred_ctx {
            self.analyze_structural_with_strings(
                input.path,
                input.backing_path(),
                preferred_data,
                strings,
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
                preferred_data,
                sha256,
                Some("filefacts open failed".to_string()),
            )
        };
        self.apply_fat_metadata(&mut report, input.data, &slices);

        // For FAT binaries, strings should already be file-relative from input.strings
        // (extracted from the full file by the entry point)
        let is_fat = arch_ranges.len() > 1;

        if is_fat {
            let preferred_offset = preferred_range_start;
            // The preferred slice was parsed at base 0; rebase its
            // structural offsets into full-file coordinates so symbol
            // annotations and section/proximity searches line up with the
            // full-file strings, raw matches, and hex view.
            Self::rebase_slice_offsets(&mut report, preferred_offset as u64);
            self.union_supplementary_arches(&mut report, input.data, preferred_offset, &slices);
        }

        let archive_config = crate::analyzers::archive::ArchiveAnalyzerConfig::default()
            .with_depth(input.depth as usize)
            .with_cancellation(input.cancellation.clone());
        self.analyze_nuitka_payload(
            input.path,
            preferred_data,
            &mut report,
            &archive_config,
            None,
        );

        // Direct calls also serve archive and decoded children. Scan full-file
        // bytes before traits, including every FAT slice.
        // Evaluate traits against binary data.
        // For FAT binaries, evaluate against the full file since strings have file-relative offsets.
        // For thin binaries, evaluate against the single slice (same as full file).
        if is_fat {
            // Full file evaluation - strings and offsets are file-relative.
            // The full-file parse opened above, so the mapper does not reopen filefacts.
            self.engine.evaluate_and_merge_findings_with_precomputed(
                &mut report,
                input.data,
                crate::capabilities::AnalysisBorrow::with_filefacts(None, full_ctx),
                None,
                None,
                None,
                None,
            );
        } else {
            // Thin binary - single slice is the whole file.
            self.engine.evaluate_and_merge_findings_with_precomputed(
                &mut report,
                preferred_data,
                crate::capabilities::AnalysisBorrow::with_filefacts(None, preferred_ctx),
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
        // `text()` view and thread the same context into the structural pass.
        let parsed_ctx = crate::analysis_context::AnalysisContext::open_with(
            self.engine.filefacts_options(),
            file_path,
            &data,
        );
        let strings = parsed_ctx.text_rows();
        let input = AnalysisInput::with_strings(
            file_path,
            &data,
            strings,
            crate::analyzers::FileType::MachO,
        )
        .with_parsed_ctx(&parsed_ctx);
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

mod signing;
use signing::{
    CodeDirectoryIntegrity, emit_signature_findings, signature_finding,
    verify_code_directory_hashes,
};
#[cfg(feature = "lint")]
pub(crate) use signing::{ENTITLEMENT_CATEGORIES, entitlement_category};
#[cfg(test)]
use signing::{describe_entitlement, determine_entitlement_criticality};

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]
mod tests;
