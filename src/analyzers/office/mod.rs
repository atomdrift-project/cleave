//! Microsoft Office document analyzer.
//!
//! Handles both legacy OLE2/CFBF formats (.doc, .xls, .ppt) and modern
//! OOXML formats (.docx, .xlsx, .pptx). Extracts VBA macros as sub-files
//! for analysis through the standard pipeline, and detects Office-specific
//! malware techniques (template injection, DDE, embedded executables).

pub(crate) mod office_kv;
pub(crate) mod ole2;
pub(crate) mod ooxml;
pub(crate) mod vba;
pub(crate) mod vba_symbols;

use super::{analyzer_for_file_type_arc, AnalysisInput, Analyzer, FileType};
use crate::capabilities::CapabilityMapper;
use crate::types::office_metrics::{OleMetrics, OoxmlMetrics, XlmMetrics};
use crate::types::{AnalysisReport, Criticality, Finding, FindingKind, TargetInfo};

/// Cross-format counts surfaced from a parsed OLE2/OOXML document.
///
/// These map onto the top-level `OfficeMetrics` fields (rather than
/// the per-container `ole`/`ooxml` sub-structs) so a trait keyed on
/// `office.external_template_count` resolves regardless of whether
/// the doc is legacy or modern.
#[derive(Debug, Default, Clone, Copy)]
struct OfficeCrossCounts {
    embedded_executable_count: u32,
    external_ref_count: u32,
    external_template_count: u32,
    external_oleobject_count: u32,
    external_frame_count: u32,
    external_image_count: u32,
    dde_link_count: u32,
    is_encrypted: bool,
}
use anyhow::Result;
use regex::Regex;
use sha2::{Digest, Sha256};
use std::collections::{BTreeSet, HashMap};
use std::path::Path;
use std::sync::Arc;

/// Microsoft Office document analyzer.
///
/// Supports both OLE2 (legacy) and OOXML (modern) formats. Extracts VBA macros
/// as sub-files routed through the standard Vbs analyzer, detects template
/// injection, DDE links, and embedded executables.
#[derive(Debug)]
pub(crate) struct OfficeAnalyzer {
    capability_mapper: Arc<CapabilityMapper>,
    cancellation: Option<Arc<std::sync::atomic::AtomicBool>>,
}

impl OfficeAnalyzer {
    #[must_use]
    pub(crate) fn new() -> Self {
        Self {
            capability_mapper: Arc::new(CapabilityMapper::empty()),
            cancellation: None,
        }
    }

    #[must_use]
    pub(crate) fn with_capability_mapper(mut self, mapper: CapabilityMapper) -> Self {
        self.capability_mapper = Arc::new(mapper);
        self
    }

    #[must_use]
    pub(crate) fn with_capability_mapper_arc(mut self, mapper: Arc<CapabilityMapper>) -> Self {
        self.capability_mapper = mapper;
        self
    }

    #[must_use]
    pub(crate) fn with_cancellation(
        mut self,
        flag: Option<Arc<std::sync::atomic::AtomicBool>>,
    ) -> Self {
        self.cancellation = flag;
        self
    }

    fn analyze_office(
        &self,
        file_path: &Path,
        data: &[u8],
        file_type: &FileType,
        cancellation: Option<&Arc<std::sync::atomic::AtomicBool>>,
    ) -> AnalysisReport {
        let mut hasher = Sha256::new();
        hasher.update(data);
        let sha256 = format!("{:x}", hasher.finalize());

        // Route to appropriate parser
        let (
            type_str,
            findings,
            vba_modules,
            embedded_execs,
            ole_metrics,
            ooxml_metrics,
            xlm_metrics,
            cross_counts,
            kv_tree,
        ) = match file_type {
            FileType::OleDoc => {
                let (t, f, v, e, om, cc, kv) = self.analyze_ole2(data);
                (t, f, v, e, Some(om), None, None, cc, kv)
            }
            FileType::Ooxml => {
                let (t, f, v, om, xm, cc, kv) = self.analyze_ooxml(data, file_path);
                (t, f, v, Vec::new(), None, om, xm, cc, kv)
            }
            _ => (
                "unknown".to_string(),
                Vec::new(),
                Vec::new(),
                Vec::new(),
                None,
                None,
                None,
                OfficeCrossCounts::default(),
                serde_json::Value::Null,
            ),
        };

        let target = TargetInfo {
            path: file_path.display().to_string(),
            file_type: type_str,
            size_bytes: data.len() as u64,
            sha256,
            architectures: None,
        };

        let mut report = AnalysisReport::new(target);
        report
            .metadata
            .tools_used
            .push("office-analyzer".to_string());
        report.findings.extend(findings);

        // Stash the synthesized office kv tree on the report so the
        // kv evaluator can consult it (`type: kv path: summary.author`
        // etc.). Empty/null trees are dropped so JSON output stays
        // clean for non-office or unparsable files.
        if !kv_tree.is_null() && kv_tree.as_object().is_none_or(|m| !m.is_empty()) {
            report.kv_tree = Some(Box::new(kv_tree));
        }

        // Surface VBA-extracted imports/functions on the parent report
        // BEFORE the capability mapper runs, so `type: symbol` traits with
        // `for: [oledoc, ooxml]` see the Declare-imported APIs and
        // CreateObject ProgIDs.  Aggregates land on `OfficeMetrics::vba`.
        self.populate_vba_symbols_and_metrics(
            &mut report,
            data.len() as u64,
            file_path,
            &vba_modules,
        );

        // Stash the OLE2 / OOXML / XLM structural sub-metrics into
        // `report.metrics.office.*` so traits keyed on
        // `type: metrics field: office.ole.*` / `office.ooxml.*` /
        // `office.xlm.*` resolve.  Container-format-specific counts
        // (stream count, zip entry count, content-type flags, XLM
        // substring counts) come from the parsers; cross-format counts
        // (embedded executable count, external relationship breakdown)
        // are folded onto the top-level OfficeMetrics here.
        self.populate_structure_metrics(
            &mut report,
            ole_metrics,
            ooxml_metrics,
            xlm_metrics,
            cross_counts,
            embedded_execs.len() as u32,
        );

        // Analyze VBA modules as sub-files through the standard Vbs pipeline
        let doc_name = file_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("document");
        let findings_before_subfiles = report.findings.len();
        self.analyze_vba_subfiles(&mut report, &vba_modules, doc_name, cancellation);

        // Recursively analyze embedded PE/ELF payloads carried in OLE2 streams
        // (e.g., MSI binary custom-action DLLs). Routes them through the standard
        // PE/ELF pipeline and merges findings upward, mirroring the VBA path.
        let embedded_count = embedded_execs.len() as u32;
        self.analyze_embedded_executables(&mut report, &embedded_execs, doc_name, cancellation);

        // Surface count on the cross-format binary metric so ML/scoring can use it.
        if embedded_count > 0 {
            let metrics = report.metrics.get_or_insert_with(Default::default);
            let binary = metrics.binary.get_or_insert_with(Default::default);
            binary.embedded_binary_count =
                binary.embedded_binary_count.saturating_add(embedded_count);
            binary.embedded_file_count = binary
                .embedded_binary_count
                .saturating_add(binary.embedded_archive_count);
        }

        // Delegate pattern detection to capability mapper (YAML traits + YARA)
        self.capability_mapper
            .evaluate_and_merge_findings(&mut report, data, None, None);

        // Evaluate container-level composites that combine parent + sub-file findings
        // (e.g., composites requiring both OOXML metadata markers AND VBA behavioral traits)
        let nested_findings: Vec<_> = report.findings[findings_before_subfiles..].to_vec();
        if !nested_findings.is_empty() {
            let container_findings = self.capability_mapper.evaluate_container_composites(
                &report,
                &nested_findings,
                &report.target.file_type,
            );
            report.findings.extend(container_findings);
        }

        report
    }

    /// Pull `Declare`-imported APIs, `CreateObject`/`GetObject` ProgIDs,
    /// and Sub/Function declarations out of every VBA module and attach
    /// them to the parent report's `imports`/`functions` lists. Folds
    /// per-module aggregates into `OfficeMetrics::vba` and sets the
    /// cross-format `office.*` flags (has_macros, vba_module_count,
    /// vba_source_size, doc_type).
    ///
    /// Runs before the capability mapper so `type: symbol` traits keyed
    /// on the document type fire on the populated symbol set.
    fn populate_vba_symbols_and_metrics(
        &self,
        report: &mut AnalysisReport,
        file_size: u64,
        file_path: &Path,
        modules: &[vba::VbaModule],
    ) {
        // Always seed `office.doc_type` and the macro-enabled-extension
        // flag, regardless of whether VBA modules were recovered. The
        // sub-struct slots stay None when no VBA project is present so
        // the empty-doc JSON output is undisturbed.
        let metrics = report.metrics.get_or_insert_with(Default::default);
        let office = metrics.office.get_or_insert_with(Default::default);
        if office.doc_type.is_empty() {
            if let Some(ext) = file_path
                .extension()
                .and_then(|e| e.to_str())
                .map(str::to_ascii_lowercase)
            {
                office.is_macro_enabled_extension = matches!(
                    ext.as_str(),
                    "docm"
                        | "xlsm"
                        | "pptm"
                        | "dotm"
                        | "xltm"
                        | "potm"
                        | "xla"
                        | "xlam"
                        | "xll"
                        | "xlsb"
                        | "ppam"
                );
                office.doc_type = ext;
            }
        }

        if modules.is_empty() {
            return;
        }

        office.has_macros = true;
        office.vba_module_count = office.vba_module_count.saturating_add(modules.len() as u32);

        let mut vba_source_size: u64 = 0;
        let mut agg = crate::types::office_metrics::VbaMetrics::default();
        let mut distinct_libs = std::collections::BTreeSet::<String>::new();
        let mut distinct_progids = std::collections::BTreeSet::<String>::new();
        let mut distinct_triggers = std::collections::BTreeSet::<String>::new();
        let mut ident_stats = vba_symbols::IdentifierStats::default();

        for module in modules {
            vba_source_size = vba_source_size.saturating_add(module.source_code.len() as u64);

            // Module-name shape: random-looking names are a strong
            // obfuscation signal. Heuristic in `looks_random_module_name`.
            if vba_symbols::looks_random_module_name(&module.name) {
                agg.random_named_module_count = agg.random_named_module_count.saturating_add(1);
            }

            // Per-module logical-line / comment-line counts.
            let shape = vba_symbols::compute_module_shape(&module.source_code);
            agg.total_logical_lines = agg.total_logical_lines.saturating_add(shape.logical_lines);
            agg.comment_lines = agg.comment_lines.saturating_add(shape.comment_lines);

            let extracted = vba_symbols::extract_vba_symbols(&module.source_code);

            // Bump per-DLL counters (high-risk subset only).
            for imp in &extracted.imports {
                if let Some(lib) = &imp.library {
                    // distinct_dll_count tracks Declare-imported native
                    // DLLs only; CreateObject's pseudo-library `com` is
                    // counted separately via distinct_progid_count.
                    if imp.source == "vba-declare" && lib != vba_symbols::NON_LITERAL_SENTINEL {
                        distinct_libs.insert(lib.clone());
                    }
                    match lib.as_str() {
                        "kernel32" | "kernelbase" => {
                            agg.kernel32_ref_count = agg.kernel32_ref_count.saturating_add(1);
                        }
                        "user32" => {
                            agg.user32_ref_count = agg.user32_ref_count.saturating_add(1);
                        }
                        "advapi32" => {
                            agg.advapi32_ref_count = agg.advapi32_ref_count.saturating_add(1);
                        }
                        "urlmon" => {
                            agg.urlmon_ref_count = agg.urlmon_ref_count.saturating_add(1);
                        }
                        "wininet" | "winhttp" => {
                            agg.wininet_ref_count = agg.wininet_ref_count.saturating_add(1);
                        }
                        "ws2_32" => {
                            agg.ws2_32_ref_count = agg.ws2_32_ref_count.saturating_add(1);
                        }
                        "ole32" | "oleaut32" => {
                            agg.ole32_ref_count = agg.ole32_ref_count.saturating_add(1);
                        }
                        "shell32" | "shlwapi" => {
                            agg.shell32_ref_count = agg.shell32_ref_count.saturating_add(1);
                        }
                        _ => {}
                    }
                    if (lib == "com" || lib == "com-getobject")
                        && imp.symbol != vba_symbols::NON_LITERAL_SENTINEL
                    {
                        distinct_progids.insert(imp.symbol.clone());
                    }
                }
            }

            for func in &extracted.functions {
                if vba_symbols::is_trigger_handler(&func.name) {
                    distinct_triggers.insert(func.name.clone());
                }
                ident_stats.record(&func.name);
            }
            for imp in &extracted.imports {
                ident_stats.record(&imp.symbol);
            }

            agg.declare_count = agg
                .declare_count
                .saturating_add(extracted.stats.declare_count);
            agg.declare_non_literal_count = agg
                .declare_non_literal_count
                .saturating_add(extracted.stats.declare_non_literal_count);
            agg.createobject_count = agg
                .createobject_count
                .saturating_add(extracted.stats.createobject_count);
            agg.createobject_non_literal_count = agg
                .createobject_non_literal_count
                .saturating_add(extracted.stats.createobject_non_literal_count);
            agg.getobject_count = agg
                .getobject_count
                .saturating_add(extracted.stats.getobject_count);
            agg.getobject_non_literal_count = agg
                .getobject_non_literal_count
                .saturating_add(extracted.stats.getobject_non_literal_count);
            agg.trigger_handler_count = agg
                .trigger_handler_count
                .saturating_add(extracted.stats.trigger_handler_count);

            report.imports.extend(extracted.imports);
            report.functions.extend(extracted.functions);
        }

        agg.distinct_dll_count = distinct_libs.len() as u32;
        agg.distinct_progid_count = distinct_progids.len() as u32;
        agg.distinct_trigger_count = distinct_triggers.len() as u32;
        agg.mean_identifier_length = ident_stats.mean_length();
        agg.identifier_entropy = ident_stats.entropy_bits();

        office.vba_source_size = office.vba_source_size.saturating_add(vba_source_size);
        let _ = file_size; // Reserved for size-ratio metrics in a later phase.
        office.vba = Some(agg);
    }

    /// Stash structure-level metrics produced by `analyze_ole2` /
    /// `analyze_ooxml` onto `report.metrics.office.{ole,ooxml,xlm}` and
    /// fold cross-format counts (`embedded_executable_count`, the
    /// external-relationship breakdown, `dde_link_count`) into the
    /// top-level `OfficeMetrics` directly.
    ///
    /// Called from `analyze_office` after the parser tuple unpacks,
    /// before `capability_mapper.evaluate` runs so traits keyed on
    /// `office.*` metrics resolve.
    fn populate_structure_metrics(
        &self,
        report: &mut AnalysisReport,
        ole_metrics: Option<OleMetrics>,
        ooxml_metrics: Option<OoxmlMetrics>,
        xlm_metrics: Option<XlmMetrics>,
        cross: OfficeCrossCounts,
        embedded_executable_count: u32,
    ) {
        let metrics = report.metrics.get_or_insert_with(Default::default);
        let office = metrics.office.get_or_insert_with(Default::default);

        // Cross-format counts derived from the parsed doc.  The
        // `embedded_executable_count` argument is what the office
        // analyzer actually routed for sub-analysis (after MSI
        // exemption / size limits), and overrides the raw doc count
        // captured in `cross.embedded_executable_count` so the metric
        // reflects the *analyzed* payload count.
        if embedded_executable_count > 0 {
            office.embedded_executable_count = office
                .embedded_executable_count
                .saturating_add(embedded_executable_count);
        } else if cross.embedded_executable_count > 0 {
            office.embedded_executable_count = office
                .embedded_executable_count
                .saturating_add(cross.embedded_executable_count);
        }
        office.external_ref_count = office
            .external_ref_count
            .saturating_add(cross.external_ref_count);
        office.external_template_count = office
            .external_template_count
            .saturating_add(cross.external_template_count);
        office.external_oleobject_count = office
            .external_oleobject_count
            .saturating_add(cross.external_oleobject_count);
        office.external_frame_count = office
            .external_frame_count
            .saturating_add(cross.external_frame_count);
        office.external_image_count = office
            .external_image_count
            .saturating_add(cross.external_image_count);
        office.dde_link_count = office.dde_link_count.saturating_add(cross.dde_link_count);
        office.is_encrypted = office.is_encrypted || cross.is_encrypted;

        if let Some(om) = ole_metrics {
            office.ole = Some(om);
        }
        if let Some(om) = ooxml_metrics {
            office.ooxml = Some(om);
        }
        if let Some(xm) = xlm_metrics {
            office.xlm = Some(xm);
        }
    }

    /// Analyze extracted VBA modules as sub-files through the standard pipeline.
    ///
    /// Each VBA module is treated like an embedded VBScript file, run through
    /// the Vbs analyzer with the capability mapper, and findings are merged
    /// upward into the parent document report (like SFX overlay analysis).
    fn analyze_vba_subfiles(
        &self,
        report: &mut AnalysisReport,
        modules: &[vba::VbaModule],
        doc_name: &str,
        cancellation: Option<&Arc<std::sync::atomic::AtomicBool>>,
    ) {
        let Some(analyzer) =
            analyzer_for_file_type_arc(&FileType::Vbs, Some(self.capability_mapper.clone()))
        else {
            return;
        };

        for module in modules {
            if cancellation.is_some_and(|c| c.load(std::sync::atomic::Ordering::Acquire)) {
                break;
            }

            let vba_bytes = module.source_code.as_bytes();
            let virtual_path_str = format!("{doc_name}!!vba/{}.vbs", module.name);
            let virtual_path = Path::new(&virtual_path_str);

            // VBA source — text hint so stng skips the XOR scan.
            let strings = stng::extract_strings_with_options(
                vba_bytes,
                &crate::analyzers::attach_stng_cancellation(
                    crate::analyzers::stng_text_opts(4),
                    cancellation,
                ),
            );
            let mut input =
                AnalysisInput::with_strings(virtual_path, vba_bytes, &strings, FileType::Vbs);
            input.cancellation = cancellation.cloned();

            match analyzer.analyze_input(&input) {
                Ok(mut sub_report) => {
                    // Take findings before consuming the report
                    let sub_findings = std::mem::take(&mut sub_report.findings);

                    // Merge findings upward, tagging with source location.
                    // Build a map of existing findings for O(1) dedup with best-wins semantics.
                    let mut by_id: HashMap<String, usize> = report
                        .findings
                        .iter()
                        .enumerate()
                        .map(|(i, f)| (f.id.clone(), i))
                        .collect();

                    for mut finding in sub_findings {
                        for evidence in &mut finding.evidence {
                            if let Some(ref loc) = evidence.location {
                                evidence.location = Some(format!("vba:{}/{}", module.name, loc));
                            } else {
                                evidence.location = Some(format!("vba:{}", module.name));
                            }
                        }
                        match by_id.get(&finding.id) {
                            Some(&idx) => {
                                let existing = &report.findings[idx];
                                if (finding.crit, finding.conf.total_cmp(&existing.conf))
                                    > (existing.crit, std::cmp::Ordering::Equal)
                                {
                                    report.findings[idx] = finding;
                                }
                            }
                            None => {
                                by_id.insert(finding.id.clone(), report.findings.len());
                                report.findings.push(finding);
                            }
                        }
                    }

                    // Convert to FileAnalysis and add as nested file
                    let (mut file_entry, nested_files, _archive_contents) =
                        sub_report.into_file_analysis(0);
                    file_entry.path = virtual_path_str.clone();
                    file_entry.depth = 1;
                    file_entry.compute_summary();
                    report.files.push(file_entry);

                    for mut nested in nested_files {
                        nested.depth += 1;
                        report.files.push(nested);
                    }
                }
                Err(e) => {
                    tracing::warn!(
                        module = %module.name,
                        error = %e,
                        "Failed to analyze VBA module as sub-file"
                    );
                }
            }
        }
    }

    /// Analyze embedded PE/ELF payloads carried in OLE2 streams as sub-files.
    ///
    /// MSI custom-action DLLs and similar binary payloads live in named streams
    /// (e.g., `Binary.<name>`). Routing them through the standard PE/ELF
    /// analyzer surfaces the embedded binary's full trait set on the parent
    /// document — without this, a binary-CA MSI would only show the
    /// `embedded-executable` marker and none of the loader's actual behavior.
    fn analyze_embedded_executables(
        &self,
        report: &mut AnalysisReport,
        executables: &[ole2::EmbeddedExecutable],
        doc_name: &str,
        cancellation: Option<&Arc<std::sync::atomic::AtomicBool>>,
    ) {
        for exec in executables {
            if cancellation.is_some_and(|c| c.load(std::sync::atomic::Ordering::Acquire)) {
                break;
            }

            let (file_type, kind_str) = match exec.kind {
                ole2::EmbeddedExecKind::Pe => (FileType::Pe, "pe"),
                ole2::EmbeddedExecKind::Elf => (FileType::Elf, "elf"),
            };

            let Some(analyzer) =
                analyzer_for_file_type_arc(&file_type, Some(self.capability_mapper.clone()))
            else {
                continue;
            };

            // Sanitize the OLE stream path (which has leading "/" and may
            // contain reserved characters) into a stable virtual filename.
            let stream_label = exec.stream_path.trim_start_matches('/').replace('/', "_");
            let virtual_path_str = format!("{doc_name}!!ole/{stream_label}");
            let virtual_path = Path::new(&virtual_path_str);

            let strings = stng::extract_strings_with_options(
                &exec.data,
                &crate::analyzers::attach_stng_cancellation(
                    crate::analyzers::stng_text_opts(4),
                    cancellation,
                ),
            );
            let mut input =
                AnalysisInput::with_strings(virtual_path, &exec.data, &strings, file_type);
            input.cancellation = cancellation.cloned();
            input.depth = 1;

            match analyzer.analyze_input(&input) {
                Ok(mut sub_report) => {
                    let sub_findings = std::mem::take(&mut sub_report.findings);

                    let mut by_id: HashMap<String, usize> = report
                        .findings
                        .iter()
                        .enumerate()
                        .map(|(i, f)| (f.id.clone(), i))
                        .collect();

                    for mut finding in sub_findings {
                        for evidence in &mut finding.evidence {
                            if let Some(ref loc) = evidence.location {
                                evidence.location = Some(format!("ole:{}/{}", stream_label, loc));
                            } else {
                                evidence.location = Some(format!("ole:{stream_label}"));
                            }
                        }
                        match by_id.get(&finding.id) {
                            Some(&idx) => {
                                let existing = &report.findings[idx];
                                if (finding.crit, finding.conf.total_cmp(&existing.conf))
                                    > (existing.crit, std::cmp::Ordering::Equal)
                                {
                                    report.findings[idx] = finding;
                                }
                            }
                            None => {
                                by_id.insert(finding.id.clone(), report.findings.len());
                                report.findings.push(finding);
                            }
                        }
                    }

                    let (mut file_entry, nested_files, _archive_contents) =
                        sub_report.into_file_analysis(0);
                    file_entry.path = virtual_path_str.clone();
                    file_entry.depth = 1;
                    file_entry.compute_summary();
                    report.files.push(file_entry);

                    for mut nested in nested_files {
                        nested.depth += 1;
                        report.files.push(nested);
                    }
                }
                Err(e) => {
                    tracing::warn!(
                        stream = %exec.stream_path,
                        kind = kind_str,
                        error = %e,
                        "Failed to analyze embedded executable as sub-file"
                    );
                }
            }
        }
    }

    fn analyze_ole2(
        &self,
        data: &[u8],
    ) -> (
        String,
        Vec<Finding>,
        Vec<vba::VbaModule>,
        Vec<ole2::EmbeddedExecutable>,
        OleMetrics,
        OfficeCrossCounts,
        serde_json::Value,
    ) {
        let mut findings = Vec::new();

        // CFB magic. fileid routes by extension, so e.g. Python's Tcl
        // `_tcl_data/msgs/*.msg` (plain-text message catalogs) lands here. Skip
        // quietly when the bytes can't be a CFB document at all; only log when
        // the magic matches but parsing still fails (a real malformed CFB).
        const CFB_MAGIC: [u8; 8] = [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1];
        if !data.starts_with(&CFB_MAGIC) {
            return (
                "ole".to_string(),
                findings,
                Vec::new(),
                Vec::new(),
                OleMetrics::default(),
                OfficeCrossCounts::default(),
                serde_json::Value::Null,
            );
        }

        let doc = match ole2::parse_ole2(data) {
            Ok(doc) => doc,
            Err(e) => {
                tracing::warn!(error = %e, "Failed to parse OLE2 document");
                return (
                    "ole".to_string(),
                    findings,
                    Vec::new(),
                    Vec::new(),
                    OleMetrics::default(),
                    OfficeCrossCounts::default(),
                    serde_json::Value::Null,
                );
            }
        };

        let type_str = doc.doc_subtype.as_str().to_string();

        // VBA presence — metadata finding
        if doc.has_vba {
            let module_count = doc.vba_modules.len();
            let module_names: Vec<&str> = doc.vba_modules.iter().map(|m| m.name.as_str()).collect();

            findings.push(Finding {
                id: "metadata/format/macro::ole2-has-vba".to_string(),
                kind: FindingKind::Structural,
                desc: format!(
                    "OLE2 document contains VBA macros ({module_count} modules: {})",
                    module_names.join(", ")
                ),
                conf: 1.0,
                crit: Criticality::Suspicious,
                mbc: None,
                attack: Some("T1059.005".to_string()),
                trait_refs: vec![],
                evidence: vec![],
                match_count: 0,
                source_file: None,
            });
        }

        // Encryption
        if doc.has_encryption {
            findings.push(Finding {
                id: "metadata/format/encrypted::ole2-encrypted".to_string(),
                kind: FindingKind::Structural,
                desc: "OLE2 document is encrypted".to_string(),
                conf: 1.0,
                crit: Criticality::Notable,
                mbc: None,
                attack: Some("T1027".to_string()),
                trait_refs: vec![],
                evidence: vec![],
                match_count: 0,
                source_file: None,
            });
        }

        // Embedded executables are structural evidence. MSI installers
        // legitimately contain embedded PE DLLs as custom-action components,
        // so skip the generic finding for them and rely on sub-analysis of the
        // extracted payload for actual behavioral classification.
        // The actual payload is also routed through analyze_embedded_executables
        // for full sub-analysis; this finding is the structural marker.
        let is_msi = doc.doc_subtype == ole2::Ole2Subtype::Msi;
        for exec in &doc.embedded_executables {
            if is_msi {
                // MSI custom-action DLLs are normal; the sub-analysis covers
                // any actual malicious behavior in the embedded binary.
                continue;
            }
            findings.push(Finding {
                id: "objectives/command-and-control/dropper/payload::embedded-executable"
                    .to_string(),
                kind: FindingKind::Indicator,
                desc: format!(
                    "Embedded {:?} payload in OLE2 stream: {} ({} bytes)",
                    exec.kind,
                    exec.stream_path,
                    exec.data.len()
                ),
                conf: 0.95,
                crit: Criticality::Notable,
                mbc: None,
                attack: Some("T1027.006".to_string()),
                trait_refs: vec![],
                evidence: vec![],
                match_count: 0,
                source_file: None,
            });
        }

        // OLE10Native embedded objects — notable structural indicator
        for obj in &doc.ole10_native_objects {
            let desc = if let Some(ref fname) = obj.embedded_filename {
                format!(
                    "OLE10Native embedded object: {} ({} bytes) in {}",
                    fname, obj.embedded_size, obj.stream_path
                )
            } else {
                format!(
                    "OLE10Native embedded object: {} bytes in {}",
                    obj.embedded_size, obj.stream_path
                )
            };
            findings.push(Finding {
                id: "metadata/format/embedded::ole10-native-object".to_string(),
                kind: FindingKind::Structural,
                desc,
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

        // Dangerous CLSIDs — suspicious structural indicator (known exploit vectors)
        for clsid_match in &doc.dangerous_clsids {
            findings.push(Finding {
                id: "metadata/format/clsid::dangerous-clsid".to_string(),
                kind: FindingKind::Structural,
                desc: format!(
                    "{} (CLSID: {}) on {}",
                    clsid_match.description, clsid_match.clsid, clsid_match.storage_path
                ),
                conf: 1.0,
                crit: Criticality::Suspicious,
                mbc: None,
                attack: None,
                trait_refs: vec![],
                evidence: vec![],
                match_count: 0,
                source_file: None,
            });
        }

        // Document metadata
        add_metadata_findings(&doc.metadata, &mut findings);

        // Read-only metric population.  Counts come straight off `doc`;
        // CompObj parsing and SummaryInfo expansion (page_count,
        // word_count, revision, edit_time, security_flag) land in a
        // later sub-step.
        let mut stream_count: u32 = 0;
        let mut storage_count: u32 = 0;
        for name in &doc.stream_names {
            if name.ends_with('/') {
                storage_count = storage_count.saturating_add(1);
            } else {
                stream_count = stream_count.saturating_add(1);
            }
        }
        // `max_stream_size` is populated by the CompObj/SummaryInfo
        // pass that has access to per-entry sizes — left at 0 here so
        // the field stays empty in JSON until that pass lands.
        let (compobj_user_type, compobj_clipboard_format, compobj_app_version) = doc
            .compobj
            .as_ref()
            .map_or((String::new(), String::new(), String::new()), |c| {
                (
                    c.user_type.clone(),
                    c.clipboard_format.clone(),
                    c.app_version.clone(),
                )
            });
        let ole_metrics = OleMetrics {
            stream_count,
            storage_count,
            dangerous_clsid_count: doc.dangerous_clsids.len() as u32,
            compobj_user_type,
            compobj_clipboard_format,
            compobj_app_version,
            // SummaryInformation / DocumentSummaryInformation numerics.
            // None values stay zero per `is_zero_*` skip rules so JSON
            // output doesn't carry unset properties.
            page_count: doc.metadata.page_count.unwrap_or(0),
            word_count: doc.metadata.word_count.unwrap_or(0),
            char_count: doc.metadata.char_count.unwrap_or(0),
            revision_number: doc.metadata.revision_number.unwrap_or(0),
            total_edit_time_minutes: doc.metadata.total_edit_time_minutes.unwrap_or(0),
            security_flag: doc.metadata.security_flag.unwrap_or(0),
            ..Default::default()
        };

        let cross = OfficeCrossCounts {
            // OLE2 currently only surfaces embedded execs and OLE10Native
            // through finding emission; cross-format counts mirror that
            // for the metrics path so a `.doc` and `.docx` look uniform
            // to downstream traits.
            embedded_executable_count: doc.embedded_executables.len() as u32,
            is_encrypted: doc.has_encryption,
            ..Default::default()
        };

        // Synthesize the office kv tree before consuming `doc`. Trait
        // authors target this tree via `type: kv` matchers — see
        // `office_kv.rs` for the schema.
        let kv = office_kv::build_ole_kv(&doc);

        (
            type_str,
            findings,
            doc.vba_modules,
            doc.embedded_executables,
            ole_metrics,
            cross,
            kv,
        )
    }

    fn analyze_ooxml(
        &self,
        data: &[u8],
        file_path: &Path,
    ) -> (
        String,
        Vec<Finding>,
        Vec<vba::VbaModule>,
        Option<OoxmlMetrics>,
        Option<XlmMetrics>,
        OfficeCrossCounts,
        serde_json::Value,
    ) {
        let mut findings = Vec::new();

        let doc = match ooxml::parse_ooxml(data) {
            Ok(doc) => doc,
            Err(e) => {
                tracing::warn!(error = %e, "Failed to parse OOXML document");
                let ext = file_path
                    .extension()
                    .and_then(|e| e.to_str())
                    .unwrap_or("ooxml");
                return (
                    ext.to_string(),
                    findings,
                    Vec::new(),
                    None,
                    None,
                    OfficeCrossCounts::default(),
                    serde_json::Value::Null,
                );
            }
        };

        let type_str = doc.doc_subtype.as_str().to_string();

        // VBA presence — metadata finding
        let mut has_word_vba_doc = false;
        if doc.has_vba {
            let module_count = doc.vba_modules.len();
            let module_names: Vec<&str> = doc.vba_modules.iter().map(|m| m.name.as_str()).collect();

            findings.push(Finding {
                id: "metadata/format/macro::ooxml-has-vba".to_string(),
                kind: FindingKind::Structural,
                desc: format!(
                    "OOXML document contains VBA macros ({module_count} modules: {})",
                    module_names.join(", ")
                ),
                conf: 1.0,
                crit: Criticality::Suspicious,
                mbc: None,
                attack: Some("T1059.005".to_string()),
                trait_refs: vec![],
                evidence: vec![],
                match_count: 0,
                source_file: None,
            });

            if doc.doc_subtype == ooxml::OoxmlSubtype::Word {
                has_word_vba_doc = true;
                findings.push(Finding {
                    id: "metadata/document/office/markup::ooxml-word-vba-document".to_string(),
                    kind: FindingKind::Structural,
                    desc: "OOXML Word VBA document".to_string(),
                    conf: 0.99,
                    crit: Criticality::Baseline,
                    mbc: None,
                    attack: None,
                    trait_refs: vec![],
                    evidence: vec![],
                    match_count: 0,
                    source_file: None,
                });
            }
        }

        let vba_surface = if doc.vba_modules.is_empty() {
            doc.vba_project_strings.join("\n")
        } else {
            doc.vba_modules
                .iter()
                .map(|m| m.source_code.as_str())
                .collect::<Vec<_>>()
                .join("\n")
        };
        let word_xml = doc.word_document_xml.as_deref().unwrap_or("");
        let content_types_xml = doc.content_types_xml.as_deref().unwrap_or("");
        let workbook_xml = doc.workbook_xml.as_deref().unwrap_or("");
        // The workbook .rels and styles XML strings are unused by the
        // analyzer now that the matching findings live in trait YAML;
        // the trait base scans the full file content directly via the
        // capability mapper.
        let _ = (&doc.workbook_rels_xml, &doc.excel_styles_xml);
        let excel_macrosheet_xml = doc.excel_macrosheet_xml.as_deref().unwrap_or("");
        let raw_surface = String::from_utf8_lossy(data);

        // XLM (Excel 4.0 macro) substring counts.  Computed once and
        // reused both by the existing inline finding thresholds and by
        // the `office.xlm` metric struct emitted at the end of the
        // function.  Once equivalent traits land in `cleave-traits/`,
        // the inline finding pushes can be removed and the counts will
        // continue to be exposed via metrics for trait authors.
        let xlm_formula_fill = excel_macrosheet_xml.matches("FORMULA.FILL").count();
        let xlm_run = excel_macrosheet_xml.matches("RUN(").count();
        let xlm_char = excel_macrosheet_xml.matches("CHAR(").count();
        let xlm_get_cell = excel_macrosheet_xml.matches("GET.CELL(").count();
        let xlm_day_now = excel_macrosheet_xml.matches("DAY(NOW())").count();
        let xlm_exec = excel_macrosheet_xml.matches("EXEC(").count();
        let xlm_register = excel_macrosheet_xml.matches("REGISTER(").count();
        let xlm_call = excel_macrosheet_xml.matches("CALL(").count();
        let xlm_very_hidden = workbook_xml.matches("state=\"veryHidden\"").count();
        let xlm_auto_open = workbook_xml.matches("_xlnm.Auto_open").count();

        if doc.doc_subtype == ooxml::OoxmlSubtype::Excel {
            // Excel structural findings
            // (excel-workbook-part / excel-macroenabled-content /
            //  excel4-macrosheet-content / excel4-macrosheet-part /
            //  excel4-macrosheet-relationship / excel4-veryhidden-sheet /
            //  excel4-auto-open-name / excel4-style-key-material) are now
            // emitted by the trait base via
            // `metadata/document/office/macro/excel-vba.yaml`.  The
            // capability mapper at the end of `analyze_office` scans
            // for those text patterns and produces the same findings
            // — keeping them inline here would just double-emit and
            // get merged by the dedup pass.
            //
            // The content-type / workbook substring checks remain in the
            // `content_types_xml` / `workbook_xml` strings the analyzer
            // already collects; the trait base scans the same surfaces.
            // XLM count-threshold findings (formula_fill ≥ 8, run ≥ 12,
            // char ≥ 200, get_cell ≥ 3, day_now ≥ 2) are now emitted
            // by the metric-typed traits in
            // `micro-behaviors/process/create/macro/office/compat_missing.yaml`.
            // The counts themselves remain on `office.xlm.*` for any
            // future tuning. Keeping the locals named/used so the
            // capability mapper has consistent values to reference.
            let _ = (
                xlm_formula_fill,
                xlm_run,
                xlm_char,
                xlm_get_cell,
                xlm_day_now,
            );
        }

        let mut has_concealed_script = false;
        if !word_xml.is_empty() {
            let white_count = word_xml
                .matches("w:color w:val=\"FFFFFF\" w:themeColor=\"background1\"")
                .count();
            let bracket_count = word_xml.matches("indexOf('[')").count();
            let has_function = Regex::new(r"function\s+[A-Za-z_][A-Za-z0-9_]{3,}\s*\(")
                .ok()
                .is_some_and(|re| re.is_match(word_xml));
            let has_charcode_builder = Regex::new(r"String\[[^\]]{1,40}\['Char'\]\+\['Code'\]\]")
                .ok()
                .is_some_and(|re| re.is_match(word_xml));
            if white_count >= 20 && has_function && (bracket_count >= 20 || has_charcode_builder) {
                // The concealed-wordprocessingml-script finding is now
                // emitted by the composite in
                // `objectives/anti-static/obfuscation/document/office-wordprocessingml.yaml`,
                // which combines white-on-white-runs / bracket-probe /
                // charcode-builder atomics on the same evidence
                // surface. The local boolean stays so the inline
                // TrickBot composite below can still consume it.
                has_concealed_script = true;
            }
        }

        let mut has_lifecycle_mix = false;
        let mut has_callbyname = false;
        let mut has_createobject = false;
        let mut has_open_for_output = false;
        let mut has_accept_conflict = false;
        if !vba_surface.is_empty() {
            let has_open = vba_surface.contains("Document_Open");
            let has_new = vba_surface.contains("Document_New");
            let has_close = vba_surface.contains("Document_Close");
            if has_open && has_new && has_close {
                // The lifecycle-mix finding itself is now emitted by the
                // composite in `compat_missing.yaml` (three symbol-typed
                // atomics). The local boolean stays so the inline
                // TrickBot composite below can still factor lifecycle
                // mix into its behavior count.
                has_lifecycle_mix = true;
            }
            // The callbyname-call / createobject-call-universal /
            // vba-open-for-output finding emits below previously lived
            // here as inline pushes; they're now handled by the trait
            // base (char-code/vba.yaml, shell/lang/office-vba-ooxml.yaml,
            // fs/write/vba/traits.yaml). Local booleans stay so the
            // inline TrickBot composite below can still consume them.
            if vba_surface.contains("CallByName") {
                has_callbyname = true;
            }
            if vba_surface.contains("CreateObject") {
                has_createobject = true;
            }
            if Regex::new(r"Open.{0,80}For O ?utput")
                .ok()
                .is_some_and(|re| re.is_match(&vba_surface))
            {
                has_open_for_output = true;
            }
            if vba_surface.contains("AcceptConflictAndAdvance") {
                has_accept_conflict = true;
                findings.push(Finding {
                    id: "well-known/malware/trojan/trickbot::accept-conflict-and-advance-marker"
                        .to_string(),
                    kind: FindingKind::Indicator,
                    desc: "AcceptConflictAndAdvance marker".to_string(),
                    conf: 0.99,
                    crit: Criticality::Component,
                    mbc: None,
                    attack: None,
                    trait_refs: vec![],
                    evidence: vec![],
                    match_count: 0,
                    source_file: None,
                });
            }
        }

        let ip_re = Regex::new(r"\b(?:\d{1,3}\.){3}\d{1,3}:\d{2,5}\b").ok();
        let mut endpoints = BTreeSet::new();
        if let Some(re) = &ip_re {
            for text in [word_xml, vba_surface.as_str(), raw_surface.as_ref()] {
                if self
                    .cancellation
                    .as_ref()
                    .is_some_and(|f| f.load(std::sync::atomic::Ordering::Relaxed))
                {
                    break;
                }
                for m in re.find_iter(text) {
                    endpoints.insert(m.as_str().to_string());
                }
            }
        }
        let has_ip_list = endpoints.len() >= 3;
        if endpoints.len() >= 3 {
            findings.push(Finding {
                id:
                    "objectives/command-and-control/infrastructure/ip::hardcoded-ipv4-port-list-any"
                        .to_string(),
                kind: FindingKind::Indicator,
                desc: format!(
                    "Multiple hardcoded external IPv4 endpoints ({})",
                    endpoints.len()
                ),
                conf: 0.9,
                crit: Criticality::Suspicious,
                mbc: Some("B0030".to_string()),
                attack: Some("T1071.001".to_string()),
                trait_refs: vec![],
                evidence: vec![],
                match_count: endpoints.len(),
                source_file: None,
            });
        }

        let behavior_count = [
            has_lifecycle_mix,
            has_callbyname,
            has_open_for_output,
            has_createobject,
        ]
        .into_iter()
        .filter(|b| *b)
        .count();
        if has_word_vba_doc
            && has_concealed_script
            && has_ip_list
            && has_accept_conflict
            && behavior_count >= 2
        {
            findings.push(Finding {
                id: "well-known/malware/trojan/trickbot::concealed-word-vba-loader".to_string(),
                kind: FindingKind::Indicator,
                desc: "TrickBot concealed Word VBA loader".to_string(),
                conf: 0.995,
                crit: Criticality::Hostile,
                mbc: None,
                attack: Some("T1204.002".to_string()),
                trait_refs: vec![],
                evidence: vec![],
                match_count: 0,
                source_file: None,
            });
        }

        // External template references — objective (template injection attack)
        for ext_ref in &doc.external_refs {
            // Skip hyperlinks — normal in documents, not a template injection vector
            if ext_ref.rel_type.contains("hyperlink") {
                continue;
            }

            let is_template = ext_ref.rel_type.contains("attachedTemplate")
                || ext_ref.rel_type.contains("oleObject")
                || ext_ref.rel_type.contains("frame");
            let crit = if is_template {
                Criticality::Hostile
            } else {
                Criticality::Suspicious
            };

            findings.push(Finding {
                id: "objectives/execution/interpreter::template-injection".to_string(),
                kind: FindingKind::Indicator,
                desc: format!(
                    "External reference in {}: {} (type: {})",
                    ext_ref.source,
                    ext_ref.target,
                    ext_ref
                        .rel_type
                        .rsplit('/')
                        .next()
                        .unwrap_or(&ext_ref.rel_type)
                ),
                conf: 0.9,
                crit,
                mbc: None,
                attack: Some("T1221".to_string()),
                trait_refs: vec![],
                evidence: vec![],
                match_count: 0,
                source_file: None,
            });
        }

        // DDE links — objective (execution via DDE)
        for dde in &doc.dde_links {
            findings.push(Finding {
                id: "objectives/execution/interpreter::dde-execution".to_string(),
                kind: FindingKind::Indicator,
                desc: format!("DDE field code detected: {dde}"),
                conf: 0.85,
                crit: Criticality::Hostile,
                mbc: None,
                attack: Some("T1559.002".to_string()),
                trait_refs: vec![],
                evidence: vec![],
                match_count: 0,
                source_file: None,
            });
        }

        // Embedded executables are structural evidence. Malicious delivery intent
        // needs loader or execution behavior from companion traits.
        for entry in &doc.embedded_executables {
            findings.push(Finding {
                id: "objectives/command-and-control/dropper/payload::embedded-executable"
                    .to_string(),
                kind: FindingKind::Indicator,
                desc: format!("Embedded executable in OOXML entry: {entry}"),
                conf: 0.95,
                crit: Criticality::Notable,
                mbc: None,
                attack: Some("T1027.006".to_string()),
                trait_refs: vec![],
                evidence: vec![],
                match_count: 0,
                source_file: None,
            });
        }

        // Encryption
        if doc.has_encryption {
            findings.push(Finding {
                id: "metadata/format/encrypted::ooxml-encrypted".to_string(),
                kind: FindingKind::Structural,
                desc: "OOXML document is encrypted".to_string(),
                conf: 1.0,
                crit: Criticality::Notable,
                mbc: None,
                attack: Some("T1027".to_string()),
                trait_refs: vec![],
                evidence: vec![],
                match_count: 0,
                source_file: None,
            });
        }

        // ZIP topology and content-type flag metric population.
        let suspicious_exts = ["exe", "dll", "hta", "lnk", "bat", "js", "scr", "vbs"];
        let mut suspicious_extension_count: u32 = 0;
        for name in &doc.entry_names {
            if let Some(ext) = name.rsplit('.').next() {
                if suspicious_exts.iter().any(|s| ext.eq_ignore_ascii_case(s)) {
                    suspicious_extension_count = suspicious_extension_count.saturating_add(1);
                }
            }
        }
        let image_part_count = doc
            .entry_names
            .iter()
            .filter(|n| {
                n.starts_with("ppt/media/")
                    || n.starts_with("word/media/")
                    || n.starts_with("xl/media/")
            })
            .count() as u32;
        let embedded_part_count = doc
            .entry_names
            .iter()
            .filter(|n| n.contains("/embeddings/") && n.ends_with(".bin"))
            .count() as u32;
        let ooxml_metrics = OoxmlMetrics {
            entry_count: doc.entry_names.len() as u32,
            max_entry_size: 0, // populated when zip stat exposes uncompressed sizes
            image_part_count,
            embedded_part_count,
            suspicious_extension_count,
            declares_macro_enabled: content_types_xml
                .contains("application/vnd.ms-word.document.macroEnabled")
                || content_types_xml.contains("application/vnd.ms-excel.sheet.macroEnabled")
                || content_types_xml
                    .contains("application/vnd.ms-powerpoint.presentation.macroEnabled"),
            declares_vba_project: content_types_xml
                .contains("application/vnd.ms-office.vbaProject"),
            declares_macrosheet: content_types_xml
                .contains("application/vnd.ms-excel.macrosheet+xml")
                || content_types_xml.contains("application/vnd.ms-excel.intlmacrosheet"),
            // word/vbaProject.bin = Word doc with VBA macros.
            is_word_vba_document: doc.entry_names.iter().any(|n| n == "word/vbaProject.bin"),
            // Template-injection: any external ref that targets an
            // attached-template / oleObject / frame relationship.
            has_template_injection: doc.external_refs.iter().any(|r| {
                !r.rel_type.contains("hyperlink")
                    && (r.rel_type.contains("attachedTemplate")
                        || r.rel_type.contains("oleObject")
                        || r.rel_type.contains("frame"))
            }),
            // DDE execution: any DDE field code observed.
            has_dde_execution: !doc.dde_links.is_empty(),
        };

        // XLM count vector — only emitted when the doc is actually
        // an Excel workbook *and* at least one count is non-zero, so
        // benign .docx/.pptx files don't carry an empty `office.xlm`
        // sub-object.
        let xlm_metrics = if doc.doc_subtype == ooxml::OoxmlSubtype::Excel
            && (xlm_formula_fill
                | xlm_run
                | xlm_char
                | xlm_get_cell
                | xlm_day_now
                | xlm_exec
                | xlm_register
                | xlm_call
                | xlm_very_hidden
                | xlm_auto_open)
                != 0
        {
            Some(XlmMetrics {
                formula_fill_count: xlm_formula_fill as u32,
                run_count: xlm_run as u32,
                char_count: xlm_char as u32,
                get_cell_count: xlm_get_cell as u32,
                day_now_count: xlm_day_now as u32,
                exec_count: xlm_exec as u32,
                register_count: xlm_register as u32,
                call_count: xlm_call as u32,
                very_hidden_sheet_count: xlm_very_hidden as u32,
                auto_open_name_count: xlm_auto_open as u32,
            })
        } else {
            None
        };

        // External-relationship breakdown for the cross-format
        // OfficeMetrics fields. Each rel_type is counted separately so
        // a trait keyed on `office.external_template_count` fires
        // independently of `office.external_image_count`.
        let mut cross = OfficeCrossCounts::default();
        for ext_ref in &doc.external_refs {
            cross.external_ref_count = cross.external_ref_count.saturating_add(1);
            if ext_ref.rel_type.contains("attachedTemplate") {
                cross.external_template_count = cross.external_template_count.saturating_add(1);
            }
            if ext_ref.rel_type.contains("oleObject") {
                cross.external_oleobject_count = cross.external_oleobject_count.saturating_add(1);
            }
            if ext_ref.rel_type.contains("frame") || ext_ref.rel_type.contains("subDocument") {
                cross.external_frame_count = cross.external_frame_count.saturating_add(1);
            }
            if ext_ref.rel_type.contains("image") {
                cross.external_image_count = cross.external_image_count.saturating_add(1);
            }
        }
        cross.dde_link_count = doc.dde_links.len() as u32;
        cross.embedded_executable_count = doc.embedded_executables.len() as u32;
        cross.is_encrypted = doc.has_encryption;

        // Synthesize the office kv tree before moving doc fields out.
        let kv = office_kv::build_ooxml_kv(&doc);

        (
            type_str,
            findings,
            doc.vba_modules,
            Some(ooxml_metrics),
            xlm_metrics,
            cross,
            kv,
        )
    }
}

impl Default for OfficeAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl Analyzer for OfficeAnalyzer {
    fn analyze_input(&self, input: &AnalysisInput<'_>) -> Result<AnalysisReport> {
        let cancellation = self.cancellation.as_ref().or(input.cancellation.as_ref());
        Ok(self.analyze_office(input.path, input.data, &input.file_type, cancellation))
    }

    fn analyze(&self, file_path: &Path) -> Result<AnalysisReport> {
        let data = std::fs::read(file_path)?;
        let file_type = crate::analyzers::detect_file_type_from_data(file_path, &data);
        Ok(self.analyze_office(file_path, &data, &file_type, self.cancellation.as_ref()))
    }

    fn can_analyze(&self, file_path: &Path) -> bool {
        if let Some(ext) = file_path.extension() {
            let ext_lower = ext.to_string_lossy().to_lowercase();
            matches!(
                ext_lower.as_str(),
                "doc"
                    | "xls"
                    | "ppt"
                    | "msg"
                    | "dot"
                    | "xlt"
                    | "docx"
                    | "xlsx"
                    | "pptx"
                    | "docm"
                    | "xlsm"
                    | "pptm"
                    | "dotx"
                    | "dotm"
                    | "xltx"
                    | "xltm"
            )
        } else {
            false
        }
    }
}

/// Add metadata-based findings for OLE2 documents.
fn add_metadata_findings(meta: &ole2::DocumentMetadata, findings: &mut Vec<Finding>) {
    let mut meta_parts = Vec::new();
    if let Some(ref title) = meta.title {
        meta_parts.push(format!("title: {title}"));
    }
    if let Some(ref author) = meta.author {
        meta_parts.push(format!("author: {author}"));
    }
    if let Some(ref app) = meta.application {
        meta_parts.push(format!("app: {app}"));
    }
    if let Some(ref last) = meta.last_author {
        meta_parts.push(format!("last_author: {last}"));
    }

    if !meta_parts.is_empty() {
        findings.push(Finding {
            id: "metadata/format/properties::doc-properties".to_string(),
            kind: FindingKind::Structural,
            desc: format!("Document metadata: {}", meta_parts.join(", ")),
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
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn test_office_analyzer_can_analyze() {
        let analyzer = OfficeAnalyzer::new();
        assert!(analyzer.can_analyze(Path::new("test.doc")));
        assert!(analyzer.can_analyze(Path::new("test.docx")));
        assert!(analyzer.can_analyze(Path::new("test.xls")));
        assert!(analyzer.can_analyze(Path::new("test.xlsx")));
        assert!(analyzer.can_analyze(Path::new("test.ppt")));
        assert!(analyzer.can_analyze(Path::new("test.pptx")));
        assert!(analyzer.can_analyze(Path::new("test.docm")));
        assert!(analyzer.can_analyze(Path::new("test.xlsm")));
        assert!(analyzer.can_analyze(Path::new("test.msg")));
        assert!(!analyzer.can_analyze(Path::new("test.pdf")));
        assert!(!analyzer.can_analyze(Path::new("test.rtf")));
        assert!(!analyzer.can_analyze(Path::new("test.txt")));
    }

    /// Drive `populate_vba_symbols_and_metrics` with synthetic VBA
    /// modules and assert that imports, functions, and `office.vba.*`
    /// aggregates land on the report. This is the end-to-end seam
    /// between the symbol extractor and the metrics container —
    /// breaks here mean a trait keyed on `type: symbol` or
    /// `type: metrics field: office.vba.*` would silently miss.
    #[test]
    fn populate_vba_symbols_threads_to_report() {
        let analyzer = OfficeAnalyzer::new();
        let target = TargetInfo {
            path: "evil.docm".into(),
            file_type: "docm".into(),
            size_bytes: 4096,
            sha256: "0".repeat(64),
            architectures: None,
        };
        let mut report = AnalysisReport::new(target);

        let modules = vec![
            vba::VbaModule {
                name: "ThisDocument".into(),
                source_code: r#"
                    Sub Document_Open()
                        Dim sh As Object
                        Set sh = CreateObject("WScript.Shell")
                        sh.Run "calc.exe"
                    End Sub
                    Declare PtrSafe Function vAlloc Lib "kernel32" _
                        Alias "VirtualAlloc" (ByVal a As LongPtr) As LongPtr
                "#
                .into(),
                module_type: vba::VbaModuleType::Document,
            },
            vba::VbaModule {
                name: "Loader".into(),
                source_code: r#"
                    Declare Function f Lib dllName () As Long
                    Set x = CreateObject(progName)
                "#
                .into(),
                module_type: vba::VbaModuleType::Standard,
            },
        ];

        analyzer.populate_vba_symbols_and_metrics(
            &mut report,
            8192,
            Path::new("evil.docm"),
            &modules,
        );

        // Imports surface on the parent report so type:symbol traits hit.
        let imp_names: Vec<&str> = report.imports.iter().map(|i| i.symbol.as_str()).collect();
        assert!(imp_names.contains(&"VirtualAlloc"));
        assert!(imp_names.contains(&"WScript.Shell"));
        // f's Alias is missing → its declared name is used as the symbol.
        assert!(imp_names.contains(&"f"));

        // Functions surface so trigger-handler `type: symbol` traits hit.
        let fn_names: Vec<&str> = report.functions.iter().map(|f| f.name.as_str()).collect();
        assert!(fn_names.contains(&"Document_Open"));

        // OfficeMetrics is populated and threaded under metrics.office.
        let metrics = report.metrics.as_ref().expect("metrics present");
        let office = metrics.office.as_ref().expect("office metrics present");
        assert_eq!(office.doc_type, "docm");
        assert!(office.is_macro_enabled_extension);
        assert!(office.has_macros);
        assert_eq!(office.vba_module_count, 2);

        let vba = office.vba.as_ref().expect("vba aggregates present");
        assert_eq!(vba.declare_count, 2);
        assert_eq!(vba.declare_non_literal_count, 1);
        assert_eq!(vba.createobject_count, 2);
        assert_eq!(vba.createobject_non_literal_count, 1);
        assert!(vba.kernel32_ref_count >= 1);
        assert_eq!(
            vba.distinct_dll_count, 1,
            "kernel32 only — non-literal lib excluded"
        );
        assert_eq!(vba.distinct_progid_count, 1, "WScript.Shell only");
        assert_eq!(vba.distinct_trigger_count, 1, "Document_Open only");
        assert!(vba.trigger_handler_count >= 1);

        // Shape metrics — the synthetic modules above include
        // `Document_Open` (a trigger handler) plus declared funcs `vAlloc`
        // and `f`, plus CreateObject ProgIDs `WScript.Shell` and
        // `<non-literal>`. mean_identifier_length should be a positive
        // float; identifier_entropy should be in the 3-5 bit range.
        assert!(vba.mean_identifier_length > 0.0);
        assert!(
            vba.identifier_entropy > 0.0 && vba.identifier_entropy < 8.0,
            "entropy {} out of range",
            vba.identifier_entropy
        );
        // Both modules have a few logical lines and zero comments.
        assert!(vba.total_logical_lines > 0);
        // Module names ("ThisDocument", "Loader") aren't randomized.
        assert_eq!(vba.random_named_module_count, 0);
    }

    /// Verify `populate_structure_metrics` threads sub-struct metrics
    /// and cross-format counts onto `report.metrics.office.*`.
    #[test]
    fn populate_structure_metrics_wires_subobjects_and_cross_counts() {
        let analyzer = OfficeAnalyzer::new();
        let target = TargetInfo {
            path: "evil.docx".into(),
            file_type: "docx".into(),
            size_bytes: 1024,
            sha256: "0".repeat(64),
            architectures: None,
        };
        let mut report = AnalysisReport::new(target);

        let cross = OfficeCrossCounts {
            embedded_executable_count: 0,
            external_ref_count: 4,
            external_template_count: 1,
            external_oleobject_count: 1,
            external_frame_count: 1,
            external_image_count: 1,
            dde_link_count: 2,
            is_encrypted: true,
        };
        let xlm = XlmMetrics {
            char_count: 250,
            ..Default::default()
        };
        let ooxml = OoxmlMetrics {
            entry_count: 18,
            declares_macro_enabled: true,
            ..Default::default()
        };
        let ole = OleMetrics {
            stream_count: 9,
            dangerous_clsid_count: 1,
            ..Default::default()
        };

        analyzer.populate_structure_metrics(
            &mut report,
            Some(ole.clone()),
            Some(ooxml.clone()),
            Some(xlm.clone()),
            cross,
            /* embedded_executable_count = */ 2,
        );

        let metrics = report.metrics.as_ref().expect("metrics");
        let office = metrics.office.as_ref().expect("office metrics");
        assert_eq!(office.embedded_executable_count, 2);
        assert_eq!(office.external_ref_count, 4);
        assert_eq!(office.external_template_count, 1);
        assert_eq!(office.external_oleobject_count, 1);
        assert_eq!(office.external_frame_count, 1);
        assert_eq!(office.external_image_count, 1);
        assert_eq!(office.dde_link_count, 2);
        assert!(office.is_encrypted);
        // Sub-struct slots populated.
        assert_eq!(office.ole.as_ref().map(|m| m.stream_count), Some(9));
        assert_eq!(office.ooxml.as_ref().map(|m| m.entry_count), Some(18));
        assert_eq!(office.xlm.as_ref().map(|m| m.char_count), Some(250));
    }

    #[test]
    fn test_finding_ids_follow_taxonomy() {
        // Verify all finding IDs use the taxonomy :: separator format
        let ids = [
            "metadata/format/macro::ole2-has-vba",
            "metadata/format/macro::ooxml-has-vba",
            "metadata/format/encrypted::ole2-encrypted",
            "metadata/format/encrypted::ooxml-encrypted",
            "metadata/format/properties::doc-properties",
            "objectives/execution/interpreter::template-injection",
            "objectives/execution/interpreter::dde-execution",
            "objectives/command-and-control/dropper/payload::embedded-executable",
        ];
        for id in &ids {
            assert!(id.contains("::"), "Finding ID missing :: separator: {id}");
            assert!(
                id.starts_with("metadata/")
                    || id.starts_with("objectives/")
                    || id.starts_with("micro-behaviors/"),
                "Finding ID not in taxonomy tier: {id}"
            );
        }
    }
}
