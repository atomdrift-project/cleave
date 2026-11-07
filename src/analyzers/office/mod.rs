//! Microsoft Office document analyzer.
//!
//! filefacts parses legacy OLE2 (.doc, .xls, .ppt, .msg, .msi) and OOXML
//! (.docx, .xlsx, .pptx) documents into `office.*` facts and metrics, which
//! traits judge. This analyzer feeds the parts of a document cleave analyzes
//! as sub-files back through the pipeline: VBA modules, embedded executables
//! and scripts, OLE1 Packager payloads and Outlook attachments.

pub(crate) mod ole2;
pub(crate) mod vba;

use super::subfile::attach_member;
use super::{AnalysisInput, Analyzer, FileType, analyzer_for_file_type_arc};
use crate::types::file_analysis::ARCHIVE_DELIMITER;
use crate::types::{AnalysisReport, TargetInfo};
use anyhow::Result;
use sha2::{Digest, Sha256};
use std::path::Path;
use std::sync::Arc;

/// The compound-file signature every OLE2 document starts with.
const CFB_MAGIC: [u8; 8] = [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1];

/// Microsoft Office document analyzer.
///
/// Supports both OLE2 (legacy) and OOXML (modern) formats. Extracts VBA macros
/// as sub-files routed through the standard Vbs analyzer, detects template
/// injection, DDE links, and embedded executables.
#[derive(Debug)]
pub(crate) struct OfficeAnalyzer {
    engine: crate::Engine,
    cancellation: Option<Arc<std::sync::atomic::AtomicBool>>,
}

impl OfficeAnalyzer {
    #[must_use]
    pub(crate) fn new() -> Self {
        Self {
            engine: crate::Engine::empty(),
            cancellation: None,
        }
    }

    #[must_use]
    pub(crate) fn with_engine(mut self, engine: crate::Engine) -> Self {
        self.engine = engine;
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
        depth: u32,
        cancellation: Option<&Arc<std::sync::atomic::AtomicBool>>,
    ) -> AnalysisReport {
        let sha256 = hex::encode(Sha256::digest(data));
        let office_ctx = crate::analysis_context::AnalysisContext::open(file_path, data);
        let values = office_ctx.parsed.values();
        let kind = values
            .get("office.kind")
            .and_then(serde_json::Value::as_str);
        let is_ole2 = matches!(file_type, FileType::OleDoc | FileType::Msi);
        // `office.kind` names the variant (`doc`, `xlsx`, `msg`, ...); the
        // generic compound file is `ole`, the spelling file-type parsing
        // knows, so container composites resolve against it.
        let type_str = match kind {
            Some("ole2") | None if is_ole2 => "ole",
            Some(kind) => kind,
            None if matches!(file_type, FileType::Ooxml) => "ooxml",
            None => "unknown",
        }
        .to_string();

        // VBA module source is decompressed by filefacts.
        let vba_modules = vba::modules_from_ctx(Some(&office_ctx));

        // Payload bytes for sub-analysis. fileid routes some non-documents
        // here by extension (Python's Tcl `msgs/*.msg` catalogs are text), so
        // only a real compound file is opened.
        let payloads = if is_ole2 && data.starts_with(&CFB_MAGIC) {
            let located = located_payloads(values.get("office.embedded"));
            ole2::extract_payloads(data, kind == Some("msg"), &located).unwrap_or_else(|e| {
                tracing::warn!(error = %e, "Failed to read OLE2 payloads");
                ole2::Ole2Payloads::default()
            })
        } else {
            ole2::Ole2Payloads::default()
        };

        let mut report = AnalysisReport::new(TargetInfo {
            path: file_path.display().to_string(),
            file_type: type_str,
            size_bytes: data.len() as u64,
            sha256,
            architectures: None,
        });
        report
            .metadata
            .tools_used
            .push("office-analyzer".to_string());

        // Surface the filefacts string corpus on the report so `type: text`
        // conditions can search container bytes.
        report.strings =
            crate::strings::StringExtractor::new().convert_stng_strings(office_ctx.text_rows());

        // VBA `Declare` imports, `CreateObject` ProgIDs and Sub/Function
        // declarations, before the capability mapper runs, so `type: symbol`
        // traits with `for: [oledoc, ooxml]` see them.
        if !vba_modules.is_empty() {
            report.imports.extend(office_ctx.imports_from_filefacts());
            report
                .functions
                .extend(office_ctx.functions_from_filefacts());
        }

        let doc_name = file_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("document");
        let findings_before_subfiles = report.findings.len();
        self.analyze_vba_subfiles(&mut report, &vba_modules, doc_name, cancellation);
        self.analyze_embedded_executables(
            &mut report,
            &payloads.executables,
            doc_name,
            depth,
            cancellation,
        );
        // Outlook attachments -- the phishing payload of a .msg (HTML/SVG
        // smuggling pages, archives, shortcuts, documents) -- go through the
        // same type detection and analyzer dispatch as archive members, and
        // attach as `<msg>!!<filename>` with their findings lifted here.
        // An attached message recurses through this analyzer again.
        for attachment in &payloads.msg_attachments {
            if cancellation.is_some_and(|c| c.load(std::sync::atomic::Ordering::Acquire)) {
                break;
            }
            self.analyze_msg_attachment(&mut report, attachment, doc_name, depth, cancellation);
        }

        // Delegate pattern detection to capability mapper (YAML traits + YARA),
        // reusing the filefacts parse already opened.
        self.engine.evaluate_and_merge_findings_with_precomputed(
            &mut report,
            data,
            crate::capabilities::AnalysisBorrow::with_filefacts(None, Some(&office_ctx)),
            None,
            None,
            None,
            None,
        );

        // Evaluate container-level composites that combine parent + sub-file findings
        // (e.g., composites requiring both OOXML metadata markers AND VBA behavioral traits)
        let nested_findings: Vec<_> = report.findings[findings_before_subfiles..].to_vec();
        if !nested_findings.is_empty() {
            let container_findings = self.engine.rules().evaluate_container_composites(
                &report,
                data,
                &nested_findings,
                &report.target.file_type,
                // Office subfile findings are not origin-stamped yet; see
                // SCOPE_PLAN.md ("Open").
                None,
            );
            report.findings.extend(container_findings);
        }

        // The report is assembled in stages: the trait engine, then sub-file
        // analysis, then container composites. A trait whose `unless:` names
        // something produced by a later stage was evaluated when that
        // suppressor did not exist yet, and nothing revisits it -- so
        // `office-extension-without-package`, whose `unless:` names
        // `ooxml-parse-error`, survived on every unparseable OOXML file and
        // `analyze` disagreed with `test-rules` about the same bytes.
        //
        // Re-check once here, where this report's finding set is finally
        // complete. Scoped to the office report on purpose: the same pass over
        // a whole archive would resolve `unless:` legs across members that the
        // scope rules keep apart.
        self.engine
            .rules()
            .apply_retroactive_unless_suppression_to_findings(&mut report.findings, None);

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
        let Some(analyzer) = analyzer_for_file_type_arc(&FileType::Vbs, &self.engine) else {
            return;
        };

        for module in modules {
            if cancellation.is_some_and(|c| c.load(std::sync::atomic::Ordering::Acquire)) {
                break;
            }

            let vba_bytes = module.source_code.as_bytes();
            let member_path = format!("vba/{}.vbs", module.name);
            let virtual_path_str = format!("{doc_name}{ARCHIVE_DELIMITER}{member_path}");
            let virtual_path = Path::new(&virtual_path_str);

            // filefacts is the string-extraction authority and source parser:
            // open the VBA module once and thread it into the sub-file analyzer.
            let vba_ctx = crate::analysis_context::AnalysisContext::open(virtual_path, vba_bytes);
            let strings = vba_ctx.text_rows();
            let mut input =
                AnalysisInput::with_strings(virtual_path, vba_bytes, strings, FileType::Vbs)
                    .with_parsed_ctx(&vba_ctx);
            input.cancellation = cancellation.cloned();

            match analyzer.analyze_input(&input) {
                Ok(sub_report) => attach_member(
                    report,
                    sub_report,
                    vba_bytes,
                    FileType::Vbs,
                    &member_path,
                    &virtual_path_str,
                    &self.engine,
                ),
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
        depth: u32,
        cancellation: Option<&Arc<std::sync::atomic::AtomicBool>>,
    ) {
        let child_depth = depth.saturating_add(1);
        if child_depth > super::subfile::MAX_SUBFILE_DEPTH {
            return;
        }
        for exec in executables {
            if cancellation.is_some_and(|c| c.load(std::sync::atomic::Ordering::Acquire)) {
                break;
            }

            let (file_type, kind_str) = match exec.kind {
                ole2::EmbeddedExecKind::Pe => (FileType::Pe, "pe"),
                ole2::EmbeddedExecKind::Elf => (FileType::Elf, "elf"),
                ole2::EmbeddedExecKind::Cab => (FileType::Cab, "cab"),
                ole2::EmbeddedExecKind::PowerShell => (FileType::PowerShell, "powershell"),
                ole2::EmbeddedExecKind::Vbs => (FileType::Vbs, "vbs"),
                ole2::EmbeddedExecKind::Python => (FileType::Python, "python"),
                ole2::EmbeddedExecKind::JavaScript => (FileType::JavaScript, "javascript"),
            };

            let Some(analyzer) = super::subfile::pick_analyzer(file_type, &self.engine) else {
                continue;
            };

            // Sanitize the OLE stream path (which has leading "/" and may
            // contain reserved characters) into a stable virtual filename.
            let stream_label = exec.stream_path.trim_start_matches('/').replace('/', "_");
            let member_path = format!("ole/{stream_label}");
            let virtual_path_str = format!("{doc_name}{ARCHIVE_DELIMITER}{member_path}");
            let virtual_path = Path::new(&virtual_path_str);

            // filefacts is the string-extraction authority: open the embedded
            // payload once and thread it into the sub-file analyzer.
            let exec_ctx = crate::analysis_context::AnalysisContext::open_with(
                self.engine
                    .filefacts_options()
                    .fileid(filefacts::FileId::forced(file_type)),
                virtual_path,
                &exec.data,
            );
            let strings = exec_ctx.text_rows();
            let mut input =
                AnalysisInput::with_strings(virtual_path, &exec.data, strings, file_type)
                    .with_parsed_ctx(&exec_ctx);
            input.cancellation = cancellation.cloned();
            input.depth = child_depth;

            match analyzer.analyze_input(&input) {
                Ok(sub_report) => attach_member(
                    report,
                    sub_report,
                    &exec.data,
                    file_type,
                    &member_path,
                    &virtual_path_str,
                    &self.engine,
                ),
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

    /// Analyze one Outlook attachment as a sub-file of the message.
    ///
    /// The type comes from the payload bytes plus the attachment filename --
    /// the detection archive members get -- and the analyzer from the same
    /// dispatch the sub-file pipeline uses, so an attached ZIP or ISO is
    /// walked by the archive analyzer and an attached message by this one.
    /// Payloads nothing can identify are skipped, as unidentified archive
    /// members are. `depth` is the message's own nesting depth; recursion
    /// stops at [`MAX_SUBFILE_DEPTH`](super::subfile::MAX_SUBFILE_DEPTH).
    fn analyze_msg_attachment(
        &self,
        report: &mut AnalysisReport,
        attachment: &ole2::MsgAttachment,
        doc_name: &str,
        depth: u32,
        cancellation: Option<&Arc<std::sync::atomic::AtomicBool>>,
    ) {
        let child_depth = depth.saturating_add(1);
        if child_depth > super::subfile::MAX_SUBFILE_DEPTH {
            tracing::debug!(
                attachment = %attachment.filename,
                depth,
                "MSG attachment recursion depth ceiling hit; skipping"
            );
            return;
        }

        let member_path = attachment.filename.as_str();
        let virtual_path_str = format!("{doc_name}{ARCHIVE_DELIMITER}{member_path}");
        let virtual_path = Path::new(&virtual_path_str);
        let data = attachment.data.as_slice();

        let fileid = filefacts::FileId::from_path_and_bytes(Path::new(member_path), data);
        let file_type = crate::analyzers::detect_file_type_from_detected(
            Path::new(member_path),
            data,
            Some(fileid.file_type()).filter(|ft| *ft != FileType::Unknown),
        );
        if file_type == FileType::Unknown {
            tracing::debug!(
                attachment = %attachment.filename,
                stream = %attachment.payload_path,
                "MSG attachment type not identified; skipping"
            );
            return;
        }
        let Some(analyzer) = super::subfile::pick_analyzer(file_type, &self.engine) else {
            return;
        };

        // Reuse the detection above rather than running it a second time.
        let ctx = crate::analysis_context::AnalysisContext::open_with(
            filefacts::OpenOptions::new().fileid(fileid),
            virtual_path,
            data,
        );
        let strings = ctx.text_rows();
        let mut input = AnalysisInput::with_strings(virtual_path, data, strings, file_type)
            .with_parsed_ctx(&ctx);
        input.cancellation = cancellation.cloned();
        input.depth = child_depth;

        match analyzer.analyze_input(&input) {
            Ok(sub_report) => attach_member(
                report,
                sub_report,
                data,
                file_type,
                member_path,
                &virtual_path_str,
                &self.engine,
            ),
            Err(e) => {
                tracing::warn!(
                    attachment = %attachment.filename,
                    storage = %attachment.storage_path,
                    kind = ?attachment.kind,
                    error = %e,
                    "Failed to analyze MSG attachment as sub-file"
                );
            }
        }
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
        Ok(self.analyze_office(
            input.path,
            input.data,
            &input.file_type,
            input.depth,
            cancellation,
        ))
    }

    fn analyze(&self, file_path: &Path) -> Result<AnalysisReport> {
        let data = std::fs::read(file_path)?;
        let file_type = crate::analyzers::detect_file_type_from_data(file_path, &data);
        Ok(self.analyze_office(file_path, &data, &file_type, 0, self.cancellation.as_ref()))
    }
}

/// The executable payloads filefacts located inside streams: the
/// `office.embedded[]` entries that carry a `data_offset` (OLE1 Packager
/// objects) and a native-executable `kind`.
fn located_payloads(embedded: Option<&serde_json::Value>) -> Vec<ole2::LocatedPayload> {
    embedded
        .and_then(serde_json::Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|entry| {
            let kind = match entry.get("kind")?.as_str()? {
                "pe" => ole2::EmbeddedExecKind::Pe,
                "elf" => ole2::EmbeddedExecKind::Elf,
                _ => return None,
            };
            Some(ole2::LocatedPayload {
                stream: entry.get("stream")?.as_str()?.to_string(),
                filename: entry
                    .get("filename")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or_default()
                    .to_string(),
                offset: entry.get("data_offset")?.as_u64()?,
                size: entry.get("size_bytes")?.as_u64()?,
                kind,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests;
