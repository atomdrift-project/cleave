//! PDF analyzer entry point.
//!
//! All PDF metric extraction (lenient byte-scan parser, stream
//! anomaly detection, form-field overlap analysis, action/embedded
//! file/info dict surfacing, JavaScript payload resolution) lives in
//! filefacts. This module:
//!
//! 1. Lets the capability mapper run trait evaluation against the
//!    `pdf.*` metrics filefacts surfaces.
//! 2. After the merge, looks at `report.values_tree.pdf.javascript[]`
//!    — filefacts resolves every `/JS` site (inline literal, hex
//!    string, or indirect ref into a Flate-encoded stream) to the
//!    full JavaScript bytes — and routes each entry through the
//!    standard JavaScript analyzer as a depth-1 sub-file, mirroring
//!    the VBA-module pattern in `office::analyze_vba_subfiles`. This
//!    promotes JS-specific traits (eval-chain density, unescape /
//!    fromCharCode obfuscation, identifier entropy, etc.) on the
//!    actual code rather than the bare metadata count.

use super::{analyzer_for_file_type_arc, AnalysisInput, Analyzer, FileType};
use crate::capabilities::CapabilityMapper;
use crate::types::{AnalysisReport, TargetInfo};
use anyhow::Result;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

/// PDF analyzer — defers extraction to filefacts and runs trait
/// evaluation against the merged metric set.
#[derive(Debug)]
pub(crate) struct PdfAnalyzer {
    capability_mapper: Arc<CapabilityMapper>,
}

impl PdfAnalyzer {
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

    fn analyze_pdf(&self, file_path: &Path, data: &[u8]) -> AnalysisReport {
        let mut hasher = Sha256::new();
        hasher.update(data);
        let sha256 = format!("{:x}", hasher.finalize());

        let target = TargetInfo {
            path: file_path.display().to_string(),
            file_type: "pdf".to_string(),
            size_bytes: data.len() as u64,
            sha256,
            architectures: None,
        };
        let mut report = AnalysisReport::new(target);
        report.metadata.tools_used.push("pdf-analyzer".to_string());

        // Filefacts's dual-emission inside `evaluate_and_merge_findings`
        // populates every `pdf.*` metric onto `report.filefacts_metrics`
        // and merges the structured kv view onto `report.values_tree`
        // for the trait engine.
        self.capability_mapper
            .evaluate_and_merge_findings(&mut report, data, None, None);

        // Route each embedded JavaScript payload through the standard
        // JS analyzer as a depth-1 sub-file. Runs *after* the
        // capability mapper so the parent PDF's own findings stay
        // visible; the sub-file's findings get tagged with a
        // `pdf-js:object:<id>` location prefix on the way up.
        let doc_name = file_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("document");
        let findings_before_subfiles = report.findings.len();
        self.analyze_javascript_subfiles(&mut report, doc_name);

        // Container composites — if both a PDF-level signal and a
        // JS-side signal fire, the composite layer can combine them.
        // Matches the office analyzer's pattern.
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

    /// Walk `report.values_tree.pdf.javascript[]` (populated by
    /// filefacts) and analyze each payload as a virtual JavaScript
    /// sub-file at depth 1.
    ///
    /// Mirrors `office::analyze_vba_subfiles`:
    /// 1. Build a virtual path `<doc>!!pdf/object<id>.js` so the
    ///    JS analyzer sees it as a freestanding file.
    /// 2. Run the cancellation-aware string extractor (text hint —
    ///    JavaScript source is ASCII-shaped; no XOR scan).
    /// 3. Invoke the JS analyzer via `analyzer_for_file_type_arc`.
    /// 4. Merge findings upward with `pdf-js:object:<id>` location
    ///    prefix, best-wins on `(crit, conf)` collision.
    /// 5. Push the sub-report as a `FileAnalysis` at depth 1 so the
    ///    JSON output shows the JS as a nested file.
    fn analyze_javascript_subfiles(&self, report: &mut AnalysisReport, doc_name: &str) {
        let payloads = collect_js_payloads(report);
        if payloads.is_empty() {
            return;
        }

        let Some(analyzer) = analyzer_for_file_type_arc(
            &FileType::JavaScript,
            Some(self.capability_mapper.clone()),
        ) else {
            tracing::warn!("JavaScript analyzer unavailable; skipping PDF JS sub-files");
            return;
        };

        for payload in payloads {
            let js_bytes = payload.content.as_bytes();
            // Source-object-id is the natural identifier — the same
            // payload can be referenced from multiple actions but we
            // dedupe upstream in collect_js_payloads. Virtual path
            // uses `!!pdf/` so it visually parallels archive
            // members (`!!inner/file.py`) and the office VBA path
            // (`!!vba/Module1.vbs`).
            let object_label = payload
                .source_object_id
                .map_or_else(|| "anon".to_string(), |id| format!("object{id}"));
            let virtual_path_str = format!("{doc_name}!!pdf/{object_label}.js");
            let virtual_path = Path::new(&virtual_path_str);

            // Text-shaped extractor — JS is ASCII-friendly source,
            // so the XOR scan and binary heuristics aren't needed.
            // 4-char minimum matches the VBA path.
            let strings = stng::extract_strings_with_options(
                js_bytes,
                &crate::analyzers::attach_stng_cancellation(
                    crate::analyzers::stng_text_opts(4),
                    None,
                ),
            );
            let input = AnalysisInput::with_strings(
                virtual_path,
                js_bytes,
                &strings,
                FileType::JavaScript,
            );

            match analyzer.analyze_input(&input) {
                Ok(mut sub_report) => {
                    let sub_findings = std::mem::take(&mut sub_report.findings);
                    let mut by_id: HashMap<String, usize> = report
                        .findings
                        .iter()
                        .enumerate()
                        .map(|(i, f)| (f.id.clone(), i))
                        .collect();
                    let location_prefix = format!("pdf-js:{object_label}");
                    for mut finding in sub_findings {
                        for evidence in &mut finding.evidence {
                            evidence.location = Some(match evidence.location.as_deref() {
                                Some(loc) => format!("{location_prefix}/{loc}"),
                                None => location_prefix.clone(),
                            });
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
                        object = %object_label,
                        error = %e,
                        "Failed to analyze PDF JavaScript payload as sub-file",
                    );
                }
            }
        }
    }
}

/// One decoded JavaScript payload extracted by filefacts.
///
/// Identified by the *carrier* object id (where the `/JS` key was
/// declared) rather than the target stream id — when the same JS
/// blob is referenced from multiple `/JS` sites, we still produce
/// one sub-file per carrier so per-site findings stay distinguishable.
#[derive(Debug, Clone)]
struct JsPayload {
    source_object_id: Option<u32>,
    content: String,
}

/// Read the `pdf.javascript[]` array out of a report's values tree.
///
/// Each entry is `{source, target_object_id?, filters?, content,
/// content_bytes}` per filefacts's schema. We extract the source
/// object id (parsed from the `"object:N"` string) and the raw
/// content; everything else has already informed filefacts's own
/// metrics and we don't re-emit it here.
fn collect_js_payloads(report: &AnalysisReport) -> Vec<JsPayload> {
    let Some(tree) = report.values_tree.as_deref() else {
        return Vec::new();
    };
    let Some(arr) = tree
        .get("pdf")
        .and_then(|v| v.get("javascript"))
        .and_then(|v| v.as_array())
    else {
        return Vec::new();
    };
    let mut out = Vec::with_capacity(arr.len());
    for entry in arr {
        let Some(obj) = entry.as_object() else {
            continue;
        };
        let content = obj
            .get("content")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        if content.is_empty() {
            continue;
        }
        let source_object_id = obj
            .get("source")
            .and_then(|v| v.as_str())
            .and_then(|s| s.strip_prefix("object:"))
            .and_then(|s| s.parse::<u32>().ok());
        out.push(JsPayload {
            source_object_id,
            content,
        });
    }
    out
}

impl Default for PdfAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl Analyzer for PdfAnalyzer {
    fn analyze_input(&self, input: &AnalysisInput<'_>) -> Result<AnalysisReport> {
        Ok(self.analyze_pdf(input.path, input.data))
    }

    fn analyze(&self, file_path: &Path) -> Result<AnalysisReport> {
        let data = std::fs::read(file_path)?;
        Ok(self.analyze_pdf(file_path, &data))
    }

    fn can_analyze(&self, file_path: &Path) -> bool {
        file_path
            .extension()
            .and_then(|e| e.to_str())
            .map(|e| e.eq_ignore_ascii_case("pdf"))
            .unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn can_analyze_pdf_extension() {
        let analyzer = PdfAnalyzer::new();
        assert!(analyzer.can_analyze(Path::new("/tmp/test.pdf")));
        assert!(analyzer.can_analyze(Path::new("/tmp/test.PDF")));
        assert!(!analyzer.can_analyze(Path::new("/tmp/test.png")));
    }

    /// `collect_js_payloads` returns an empty list when filefacts didn't
    /// populate `pdf.javascript[]` (PDF without any /JS sites).
    #[test]
    fn collect_js_payloads_empty_when_no_javascript() {
        let mut report = AnalysisReport::new(TargetInfo {
            path: "x.pdf".into(),
            file_type: "pdf".into(),
            size_bytes: 0,
            sha256: String::new(),
            architectures: None,
        });
        // Even with a pdf subtree, no `.javascript` array → empty.
        report.merge_kv_subtree("pdf", json!({"shape": {"object_count": 3}}));
        assert!(collect_js_payloads(&report).is_empty());
    }

    /// `collect_js_payloads` parses every entry in the filefacts-shaped
    /// JSON, recovering the source object id from `"object:N"`.
    #[test]
    fn collect_js_payloads_parses_filefacts_shape() {
        let mut report = AnalysisReport::new(TargetInfo {
            path: "x.pdf".into(),
            file_type: "pdf".into(),
            size_bytes: 0,
            sha256: String::new(),
            architectures: None,
        });
        report.merge_kv_subtree(
            "pdf",
            json!({
                "javascript": [
                    {"source": "object:11", "content": "app.alert('one');", "content_bytes": 17},
                    {"source": "object:42", "target_object_id": 99, "content": "var x = 1;", "content_bytes": 10},
                    {"source": "object:unknown", "content": "", "content_bytes": 0}
                ]
            }),
        );
        let payloads = collect_js_payloads(&report);
        assert_eq!(payloads.len(), 2, "empty content entry should be skipped");
        assert_eq!(payloads[0].source_object_id, Some(11));
        assert_eq!(payloads[0].content, "app.alert('one');");
        assert_eq!(payloads[1].source_object_id, Some(42));
        assert_eq!(payloads[1].content, "var x = 1;");
    }

    /// End-to-end smoke test — a PDF with an inline `/JS (literal)`
    /// produces a depth-1 sub-file analysis. The virtual path uses the
    /// archive-delimiter convention so downstream consumers can show
    /// it as a nested entry.
    #[test]
    fn pdf_with_inline_javascript_emits_subfile() {
        let pdf = b"%PDF-1.5\n5 0 obj << /Type /Action /S /JavaScript /JS (app.alert('hi from inline')) >> endobj\n%%EOF";
        let analyzer = PdfAnalyzer::new();
        let report = analyzer.analyze_pdf(Path::new("/tmp/inline.pdf"), pdf);
        assert!(
            !report.files.is_empty(),
            "expected at least one JS sub-file entry, got {} files",
            report.files.len(),
        );
        let js_file = &report.files[0];
        assert_eq!(js_file.depth, 1);
        assert!(
            js_file.path.contains("!!pdf/object5.js"),
            "virtual path was {:?}",
            js_file.path,
        );
    }

    /// Stream-encoded JS — `/JS 4 0 R` referencing a FlateDecode'd
    /// stream — must also surface as a sub-file. This is the malware-
    /// realistic shape (inline literals are unusual for obfuscated
    /// payloads since they're size-limited).
    #[test]
    fn pdf_with_flate_javascript_stream_emits_subfile() {
        use std::io::Write;
        // Compress a recognizable JS blob with zlib (=Flate).
        let js = b"app.alert('this is in a compressed stream'); var pwned = true;";
        let mut encoder =
            flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(js).unwrap();
        let flate = encoder.finish().unwrap();
        let mut pdf: Vec<u8> = Vec::new();
        pdf.extend_from_slice(b"%PDF-1.5\n");
        pdf.extend_from_slice(b"3 0 obj << /Type /Action /S /JavaScript /JS 4 0 R >> endobj\n");
        pdf.extend_from_slice(
            format!(
                "4 0 obj << /Length {} /Filter /FlateDecode >>\nstream\n",
                flate.len()
            )
            .as_bytes(),
        );
        pdf.extend_from_slice(&flate);
        pdf.extend_from_slice(b"\nendstream endobj\n%%EOF\n");
        let analyzer = PdfAnalyzer::new();
        let report = analyzer.analyze_pdf(Path::new("/tmp/stream.pdf"), &pdf);
        assert!(
            !report.files.is_empty(),
            "expected JS sub-file for FlateDecode'd /JS stream, got {} files",
            report.files.len(),
        );
        // The carrier object id is 3 (where the /JS key sits).
        let js_file = &report.files[0];
        assert!(
            js_file.path.contains("!!pdf/object3.js"),
            "virtual path was {:?}",
            js_file.path,
        );
    }

    /// A PDF without any JavaScript must NOT add sub-files. This
    /// guards against the analyzer running JS over arbitrary content.
    #[test]
    fn pdf_without_javascript_has_no_subfiles() {
        let pdf = b"%PDF-1.5\n5 0 obj << /Type /Page /MediaBox [0 0 100 100] >> endobj\n%%EOF";
        let analyzer = PdfAnalyzer::new();
        let report = analyzer.analyze_pdf(Path::new("/tmp/nojs.pdf"), pdf);
        assert!(
            report.files.is_empty(),
            "expected no sub-files for PDF without JavaScript, got {:?}",
            report.files.iter().map(|f| &f.path).collect::<Vec<_>>(),
        );
    }

    /// Two distinct `/JS` sites on the same PDF must each produce
    /// their own sub-file entry — `report.files` should contain two
    /// nested entries with distinct `object<N>.js` paths.
    #[test]
    fn multiple_javascript_actions_emit_one_subfile_each() {
        let pdf = b"%PDF-1.5\n\
                    5 0 obj << /Type /Action /S /JavaScript /JS (var first = 1;) >> endobj\n\
                    8 0 obj << /Type /Action /S /JavaScript /JS (var second = 2;) >> endobj\n\
                    %%EOF";
        let analyzer = PdfAnalyzer::new();
        let report = analyzer.analyze_pdf(Path::new("/tmp/two.pdf"), pdf);
        let paths: Vec<&str> = report.files.iter().map(|f| f.path.as_str()).collect();
        assert_eq!(
            report.files.len(),
            2,
            "expected one sub-file per /JS site, got {paths:?}",
        );
        assert!(paths.iter().any(|p| p.contains("!!pdf/object5.js")));
        assert!(paths.iter().any(|p| p.contains("!!pdf/object8.js")));
    }

    /// The JS sub-analyzer's tree-sitter parse populates the sub-file's
    /// AST projections. That's the canonical "the JS bytes really were
    /// handed to the JavaScript analyzer" signal — if the sub-file came
    /// back with no AST keys we'd know we routed bytes to the wrong
    /// analyzer (or analyze_input bailed early). We use AST presence
    /// rather than findings count because traits change over time and
    /// would make this test brittle.
    #[test]
    fn js_subfile_receives_actual_javascript_analysis() {
        // Real JS with multiple call-shaped tokens — tree-sitter will
        // parse this as JS, populate `ast.call_targets`, and the sub-
        // analyzer will emit a Source code-metrics row.
        let pdf = b"%PDF-1.5\n5 0 obj << /Type /Action /S /JavaScript /JS \
            (function pwn() { eval(atob('YWxlcnQoMSk=')); document.write('x'); }) \
            >> endobj\n%%EOF";
        let analyzer = PdfAnalyzer::new();
        let report = analyzer.analyze_pdf(Path::new("/tmp/realjs.pdf"), pdf);
        assert_eq!(report.files.len(), 1);
        let js_file = &report.files[0];
        // file_type was set by AnalysisInput::with_strings(... JavaScript).
        assert_eq!(
            js_file.file_type, "javascript",
            "sub-file should be tagged as JS, was {:?}",
            js_file.file_type,
        );
        // The unified JS analyzer routes through filefacts which emits
        // `source.language`, `source.functions[]`, `source.imports[]`
        // for any parsed JS file. Their presence is proof the sub-file
        // went through real source-code extraction (and not, say, a
        // generic binary path that wouldn't tree-sitter-parse).
        let language = js_file
            .kv
            .get("source.language")
            .and_then(|v| v.as_str());
        assert_eq!(
            language,
            Some("javascript"),
            "expected `source.language=javascript` after JS sub-analysis; got {:?}",
            js_file.kv.keys().collect::<Vec<_>>(),
        );
        let has_function_extraction = js_file
            .kv
            .keys()
            .any(|k| k.starts_with("source.functions"));
        assert!(
            has_function_extraction,
            "expected `source.functions[]` from tree-sitter parse; got {:?}",
            js_file.kv.keys().collect::<Vec<_>>(),
        );
    }

    /// Findings from the JS sub-analysis must be tagged with a
    /// `pdf-js:object<id>` location prefix so analysts can map each
    /// finding back to the carrier object. This mirrors how
    /// `analyze_vba_subfiles` tags `vba:<module>` on every evidence.
    #[test]
    fn js_subfile_findings_get_location_tagged() {
        // The same JS as the AST test, but here we assert any findings
        // surfaced from the sub-analyzer carry the location prefix.
        // We don't require any specific finding ID — just that *if*
        // findings exist, they're tagged correctly.
        let pdf = b"%PDF-1.5\n9 0 obj << /Type /Action /S /JavaScript /JS \
            (function pwn() { eval(atob('YWxlcnQoMSk=')); document.write('x'); }) \
            >> endobj\n%%EOF";
        let analyzer = PdfAnalyzer::new();
        let report = analyzer.analyze_pdf(Path::new("/tmp/loc.pdf"), pdf);
        // Walk every top-level finding's evidence list. Any evidence
        // whose location was set by the sub-file path must start with
        // the expected prefix.
        let mut tagged_count = 0;
        let mut untagged_count = 0;
        for finding in &report.findings {
            for evidence in &finding.evidence {
                if let Some(loc) = &evidence.location {
                    if loc.starts_with("pdf-js:object9") {
                        tagged_count += 1;
                    } else if loc.starts_with("pdf-js:") {
                        // Sub-file came from a different carrier — not
                        // possible here since this PDF has only one /JS
                        // site. Fail loudly if it happens.
                        panic!("unexpected pdf-js location prefix: {loc}");
                    } else {
                        untagged_count += 1;
                    }
                }
            }
        }
        // If nothing fires today, that's also fine — but if it does
        // fire, the tagging must be in place. Don't require a count.
        assert!(
            tagged_count > 0 || untagged_count == 0 || report.findings.is_empty(),
            "JS sub-findings exist but were not tagged: {tagged_count} tagged, {untagged_count} untagged",
        );
    }
}
