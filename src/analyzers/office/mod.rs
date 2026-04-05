//! Microsoft Office document analyzer.
//!
//! Handles both legacy OLE2/CFBF formats (.doc, .xls, .ppt) and modern
//! OOXML formats (.docx, .xlsx, .pptx). Extracts VBA macros as sub-files
//! for analysis through the standard pipeline, and detects Office-specific
//! malware techniques (template injection, DDE, embedded executables).

pub(crate) mod ole2;
pub(crate) mod ooxml;
pub(crate) mod vba;

use super::{analyzer_for_file_type_arc, AnalysisInput, Analyzer, FileType};
use crate::capabilities::CapabilityMapper;
use crate::types::{AnalysisReport, Criticality, Finding, FindingKind, TargetInfo};
use anyhow::Result;
use regex::Regex;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
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
        let (type_str, findings, vba_modules) = match file_type {
            FileType::OleDoc => self.analyze_ole2(data),
            FileType::Ooxml => self.analyze_ooxml(data, file_path),
            _ => ("unknown".to_string(), Vec::new(), Vec::new()),
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

        // Analyze VBA modules as sub-files through the standard Vbs pipeline
        let doc_name = file_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("document");
        let findings_before_vba = report.findings.len();
        self.analyze_vba_subfiles(&mut report, &vba_modules, doc_name, cancellation);

        // Delegate pattern detection to capability mapper (YAML traits + YARA)
        self.capability_mapper
            .evaluate_and_merge_findings(&mut report, data, None, None);

        // Evaluate container-level composites that combine parent + VBA sub-file findings
        // (e.g., composites requiring both OOXML metadata markers AND VBA behavioral traits)
        let nested_findings: Vec<_> = report.findings[findings_before_vba..].to_vec();
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
            if cancellation.is_some_and(|c| c.load(std::sync::atomic::Ordering::Relaxed)) {
                break;
            }

            let vba_bytes = module.source_code.as_bytes();
            let virtual_path_str = format!("{doc_name}!!vba/{}.vbs", module.name);
            let virtual_path = Path::new(&virtual_path_str);

            let strings = stng::extract_strings_with_options(
                vba_bytes,
                &crate::analyzers::stng_analysis_opts(4),
            );
            let mut input =
                AnalysisInput::with_strings(virtual_path, vba_bytes, &strings, FileType::Vbs);
            input.cancellation = cancellation.cloned();

            match analyzer.analyze_input(&input) {
                Ok(mut sub_report) => {
                    // Take findings before consuming the report
                    let sub_findings = std::mem::take(&mut sub_report.findings);

                    // Merge findings upward, tagging with source location
                    for mut finding in sub_findings {
                        for evidence in &mut finding.evidence {
                            if let Some(ref loc) = evidence.location {
                                evidence.location = Some(format!("vba:{}/{}", module.name, loc));
                            } else {
                                evidence.location = Some(format!("vba:{}", module.name));
                            }
                        }
                        report.findings.push(finding);
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

    fn analyze_ole2(&self, data: &[u8]) -> (String, Vec<Finding>, Vec<vba::VbaModule>) {
        let mut findings = Vec::new();

        let doc = match ole2::parse_ole2(data) {
            Ok(doc) => doc,
            Err(e) => {
                tracing::warn!(error = %e, "Failed to parse OLE2 document");
                return ("ole".to_string(), findings, Vec::new());
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

        // Embedded executables — objective (implies payload delivery intent)
        for stream in &doc.embedded_executables {
            findings.push(Finding {
                id: "objectives/command-and-control/dropper/payload::embedded-executable"
                    .to_string(),
                kind: FindingKind::Indicator,
                desc: format!("Embedded executable in OLE2 stream: {stream}"),
                conf: 0.95,
                crit: Criticality::Hostile,
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

        (type_str, findings, doc.vba_modules)
    }

    fn analyze_ooxml(
        &self,
        data: &[u8],
        file_path: &Path,
    ) -> (String, Vec<Finding>, Vec<vba::VbaModule>) {
        let mut findings = Vec::new();

        let doc = match ooxml::parse_ooxml(data) {
            Ok(doc) => doc,
            Err(e) => {
                tracing::warn!(error = %e, "Failed to parse OOXML document");
                let ext = file_path
                    .extension()
                    .and_then(|e| e.to_str())
                    .unwrap_or("ooxml");
                return (ext.to_string(), findings, Vec::new());
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
        let workbook_rels_xml = doc.workbook_rels_xml.as_deref().unwrap_or("");
        let excel_styles_xml = doc.excel_styles_xml.as_deref().unwrap_or("");
        let excel_macrosheet_xml = doc.excel_macrosheet_xml.as_deref().unwrap_or("");
        let raw_surface = String::from_utf8_lossy(data);

        if doc.doc_subtype == ooxml::OoxmlSubtype::Excel {
            if !workbook_xml.is_empty() {
                findings.push(Finding {
                    id: "metadata/document/office/macro::excel-workbook-part".to_string(),
                    kind: FindingKind::Structural,
                    desc: "Excel workbook XML part".to_string(),
                    conf: 0.98,
                    crit: Criticality::Baseline,
                    mbc: None,
                    attack: None,
                    trait_refs: vec![],
                    evidence: vec![],
                    match_count: 0,
                    source_file: None,
                });
            }
            if content_types_xml.contains("application/vnd.ms-excel.sheet.macroEnabled") {
                findings.push(Finding {
                    id: "metadata/document/office/macro::excel-macroenabled-content".to_string(),
                    kind: FindingKind::Structural,
                    desc: "Excel macro-enabled content type".to_string(),
                    conf: 0.97,
                    crit: Criticality::Baseline,
                    mbc: None,
                    attack: None,
                    trait_refs: vec![],
                    evidence: vec![],
                    match_count: 0,
                    source_file: None,
                });
            }
            if content_types_xml.contains("application/vnd.ms-excel.macrosheet+xml")
                || content_types_xml.contains("application/vnd.ms-excel.intlmacrosheet")
            {
                findings.push(Finding {
                    id: "metadata/document/office/macro::excel4-macrosheet-content".to_string(),
                    kind: FindingKind::Structural,
                    desc: "Excel 4.0 macro sheet content type".to_string(),
                    conf: 0.97,
                    crit: Criticality::Baseline,
                    mbc: None,
                    attack: None,
                    trait_refs: vec![],
                    evidence: vec![],
                    match_count: 0,
                    source_file: None,
                });
            }
            if doc
                .entry_names
                .iter()
                .any(|n| n.starts_with("xl/macrosheets/") && n.ends_with(".xml"))
            {
                findings.push(Finding {
                    id: "metadata/document/office/macro::excel4-macrosheet-part".to_string(),
                    kind: FindingKind::Structural,
                    desc: "Excel 4.0 macro sheet part".to_string(),
                    conf: 0.97,
                    crit: Criticality::Baseline,
                    mbc: None,
                    attack: None,
                    trait_refs: vec![],
                    evidence: vec![],
                    match_count: 0,
                    source_file: None,
                });
            }
            if workbook_rels_xml.contains("relationships/xlMacrosheet") {
                findings.push(Finding {
                    id: "metadata/document/office/macro::excel4-macrosheet-relationship"
                        .to_string(),
                    kind: FindingKind::Structural,
                    desc: "Excel macro sheet relationship".to_string(),
                    conf: 0.98,
                    crit: Criticality::Baseline,
                    mbc: None,
                    attack: None,
                    trait_refs: vec![],
                    evidence: vec![],
                    match_count: 0,
                    source_file: None,
                });
            }
            if workbook_xml.contains("state=\"veryHidden\"") {
                findings.push(Finding {
                    id: "metadata/document/office/macro::excel4-veryhidden-sheet".to_string(),
                    kind: FindingKind::Structural,
                    desc: "VeryHidden worksheet state".to_string(),
                    conf: 0.97,
                    crit: Criticality::Baseline,
                    mbc: None,
                    attack: None,
                    trait_refs: vec![],
                    evidence: vec![],
                    match_count: 0,
                    source_file: None,
                });
            }
            if workbook_xml.contains("_xlnm.Auto_open") {
                findings.push(Finding {
                    id: "metadata/document/office/macro::excel4-auto-open-name".to_string(),
                    kind: FindingKind::Structural,
                    desc: "Excel auto-open defined name".to_string(),
                    conf: 0.98,
                    crit: Criticality::Baseline,
                    mbc: None,
                    attack: None,
                    trait_refs: vec![],
                    evidence: vec![],
                    match_count: 0,
                    source_file: None,
                });
            }
            if excel_styles_xml.contains("<sz val=\"20\"")
                && excel_styles_xml.contains("rgb=\"FFFF00FF\"")
            {
                findings.push(Finding {
                    id: "metadata/document/office/macro::excel4-style-key-material".to_string(),
                    kind: FindingKind::Structural,
                    desc: "Excel styles key material".to_string(),
                    conf: 0.97,
                    crit: Criticality::Baseline,
                    mbc: None,
                    attack: None,
                    trait_refs: vec![],
                    evidence: vec![],
                    match_count: 0,
                    source_file: None,
                });
            }
            let formula_fill_count = excel_macrosheet_xml.matches("FORMULA.FILL").count();
            if formula_fill_count >= 8 {
                findings.push(Finding {
                    id: "micro-behaviors/process/create/macro/office::formula-fill-runtime-write"
                        .to_string(),
                    kind: FindingKind::Indicator,
                    desc: "XLM formula runtime write".to_string(),
                    conf: 0.98,
                    crit: Criticality::Suspicious,
                    mbc: None,
                    attack: None,
                    trait_refs: vec![],
                    evidence: vec![],
                    match_count: formula_fill_count,
                    source_file: None,
                });
            }
            let run_count = excel_macrosheet_xml.matches("RUN(").count();
            if run_count >= 12 {
                findings.push(Finding {
                    id: "micro-behaviors/process/create/macro/office::run-dispatch-chain"
                        .to_string(),
                    kind: FindingKind::Indicator,
                    desc: "XLM RUN dispatch chain".to_string(),
                    conf: 0.97,
                    crit: Criticality::Notable,
                    mbc: None,
                    attack: None,
                    trait_refs: vec![],
                    evidence: vec![],
                    match_count: run_count,
                    source_file: None,
                });
            }
            let char_count = excel_macrosheet_xml.matches("CHAR(").count();
            if char_count >= 200 {
                findings.push(Finding {
                    id: "micro-behaviors/process/create/macro/office::char-obfuscation-burst"
                        .to_string(),
                    kind: FindingKind::Indicator,
                    desc: "XLM dense CHAR obfuscation".to_string(),
                    conf: 0.98,
                    crit: Criticality::Suspicious,
                    mbc: None,
                    attack: Some("T1027".to_string()),
                    trait_refs: vec![],
                    evidence: vec![],
                    match_count: char_count,
                    source_file: None,
                });
            }
            let get_cell_count = excel_macrosheet_xml.matches("GET.CELL(").count();
            if get_cell_count >= 3 {
                findings.push(Finding {
                    id: "micro-behaviors/process/create/macro/office::get-cell-style-keying"
                        .to_string(),
                    kind: FindingKind::Indicator,
                    desc: "XLM GET.CELL style keying".to_string(),
                    conf: 0.97,
                    crit: Criticality::Suspicious,
                    mbc: None,
                    attack: Some("T1497".to_string()),
                    trait_refs: vec![],
                    evidence: vec![],
                    match_count: get_cell_count,
                    source_file: None,
                });
            }
            let day_now_count = excel_macrosheet_xml.matches("DAY(NOW())").count();
            if day_now_count >= 2 {
                findings.push(Finding {
                    id: "micro-behaviors/process/create/macro/office::date-keyed-now-math"
                        .to_string(),
                    kind: FindingKind::Indicator,
                    desc: "XLM date-keyed NOW math".to_string(),
                    conf: 0.97,
                    crit: Criticality::Suspicious,
                    mbc: None,
                    attack: Some("T1497.003".to_string()),
                    trait_refs: vec![],
                    evidence: vec![],
                    match_count: day_now_count,
                    source_file: None,
                });
            }
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
                has_concealed_script = true;
                findings.push(Finding {
                    id: "objectives/anti-static/obfuscation/document::concealed-wordprocessingml-script".to_string(),
                    kind: FindingKind::Indicator,
                    desc: "Concealed script in WordprocessingML".to_string(),
                    conf: 0.98,
                    crit: Criticality::Suspicious,
                    mbc: Some("B0032".to_string()),
                    attack: Some("T1027".to_string()),
                    trait_refs: vec![],
                    evidence: vec![],
                    match_count: 0,
                    source_file: None,
                });
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
                has_lifecycle_mix = true;
                findings.push(Finding {
                    id: "micro-behaviors/process/create/macro/office::document-lifecycle-trigger-mix".to_string(),
                    kind: FindingKind::Indicator,
                    desc: "Multiple document lifecycle triggers".to_string(),
                    conf: 0.94,
                    crit: Criticality::Suspicious,
                    mbc: None,
                    attack: None,
                    trait_refs: vec![],
                    evidence: vec![],
                    match_count: 0,
                    source_file: None,
                });
            }
            if vba_surface.contains("CallByName") {
                has_callbyname = true;
                findings.push(Finding {
                    id: "micro-behaviors/data/encode/char-code::callbyname-call".to_string(),
                    kind: FindingKind::Indicator,
                    desc: "VBA CallByName indirect invocation".to_string(),
                    conf: 0.92,
                    crit: Criticality::Suspicious,
                    mbc: None,
                    attack: None,
                    trait_refs: vec![],
                    evidence: vec![],
                    match_count: 0,
                    source_file: None,
                });
            }
            if vba_surface.contains("CreateObject") {
                has_createobject = true;
                findings.push(Finding {
                    id: "micro-behaviors/process/create/shell/lang::createobject-call-universal"
                        .to_string(),
                    kind: FindingKind::Indicator,
                    desc: "VBA CreateObject invocation".to_string(),
                    conf: 0.88,
                    crit: Criticality::Notable,
                    mbc: None,
                    attack: None,
                    trait_refs: vec![],
                    evidence: vec![],
                    match_count: 0,
                    source_file: None,
                });
            }
            if Regex::new(r"Open.{0,80}For O ?utput")
                .ok()
                .is_some_and(|re| re.is_match(&vba_surface))
            {
                has_open_for_output = true;
                findings.push(Finding {
                    id: "micro-behaviors/fs/write/vba::vba-open-for-output".to_string(),
                    kind: FindingKind::Indicator,
                    desc: "VBA Open For Output file write".to_string(),
                    conf: 0.85,
                    crit: Criticality::Notable,
                    mbc: None,
                    attack: None,
                    trait_refs: vec![],
                    evidence: vec![],
                    match_count: 0,
                    source_file: None,
                });
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

        // Embedded executables — objective (payload delivery)
        for entry in &doc.embedded_executables {
            findings.push(Finding {
                id: "objectives/command-and-control/dropper/payload::embedded-executable"
                    .to_string(),
                kind: FindingKind::Indicator,
                desc: format!("Embedded executable in OOXML entry: {entry}"),
                conf: 0.95,
                crit: Criticality::Hostile,
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

        (type_str, findings, doc.vba_modules)
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
        let file_type = if ole2::is_ole2(&data) {
            FileType::OleDoc
        } else {
            FileType::Ooxml
        };
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
