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
use sha2::{Digest, Sha256};
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
}

impl OfficeAnalyzer {
    #[must_use]
    pub(crate) fn new() -> Self {
        Self {
            capability_mapper: Arc::new(CapabilityMapper::empty()),
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

    fn analyze_office(
        &self,
        file_path: &Path,
        data: &[u8],
        file_type: &FileType,
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
        self.analyze_vba_subfiles(&mut report, &vba_modules, doc_name);

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
    ) {
        let Some(analyzer) =
            analyzer_for_file_type_arc(&FileType::Vbs, Some(self.capability_mapper.clone()))
        else {
            return;
        };

        for module in modules {
            let vba_bytes = module.source_code.as_bytes();
            let virtual_path_str = format!("{doc_name}!!vba/{}.vbs", module.name);
            let virtual_path = Path::new(&virtual_path_str);

            let strings =
                stng::extract_strings_with_options(
                    vba_bytes,
                    &crate::analyzers::stng_analysis_opts(4),
                );
            let input =
                AnalysisInput::with_strings(virtual_path, vba_bytes, &strings, FileType::Vbs);

            match analyzer.analyze_input(&input) {
                Ok(mut sub_report) => {
                    // Take findings before consuming the report
                    let sub_findings = std::mem::take(&mut sub_report.findings);

                    // Merge findings upward, tagging with source location
                    for mut finding in sub_findings {
                        for evidence in &mut finding.evidence {
                            if let Some(ref loc) = evidence.location {
                                evidence.location =
                                    Some(format!("vba:{}/{}", module.name, loc));
                            } else {
                                evidence.location =
                                    Some(format!("vba:{}", module.name));
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
            let module_names: Vec<&str> =
                doc.vba_modules.iter().map(|m| m.name.as_str()).collect();

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
        if doc.has_vba {
            let module_count = doc.vba_modules.len();
            let module_names: Vec<&str> =
                doc.vba_modules.iter().map(|m| m.name.as_str()).collect();

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
        }

        // External template references — objective (template injection attack)
        for ext_ref in &doc.external_refs {
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
        Ok(self.analyze_office(input.path, input.data, &input.file_type))
    }

    fn analyze(&self, file_path: &Path) -> Result<AnalysisReport> {
        let data = std::fs::read(file_path)?;
        let file_type = if ole2::is_ole2(&data) {
            FileType::OleDoc
        } else {
            FileType::Ooxml
        };
        Ok(self.analyze_office(file_path, &data, &file_type))
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
