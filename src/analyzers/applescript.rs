//! AppleScript analyzer.
//!
//! Analyzes AppleScript files for macOS-specific threats.

use crate::analyzers::{AnalysisInput, Analyzer};
use crate::capabilities::CapabilityMapper;
use crate::strings::StringExtractor;
use crate::types::{AnalysisReport, Import, TargetInfo};
use anyhow::Result;
use std::fs;
use std::path::Path;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

#[derive(Debug)]
pub(crate) struct AppleScriptAnalyzer {
    capability_mapper: Arc<CapabilityMapper>,
    string_extractor: StringExtractor,
    cancellation: Option<Arc<AtomicBool>>,
}

impl AppleScriptAnalyzer {
    #[must_use]
    pub(crate) fn new() -> Self {
        Self {
            capability_mapper: Arc::new(CapabilityMapper::new()),
            string_extractor: StringExtractor::new(),
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

    /// Extract symbols from compiled AppleScript using the scpt parser
    fn extract_scpt_symbols(&self, data: &[u8], report: &mut AnalysisReport) {
        if let Ok(parser) = scpt::ScptParser::new(data) {
            // Extract all symbols
            for symbol in parser.symbols() {
                let (source, library) = match symbol.kind {
                    scpt::SymbolKind::Variable => ("scpt_variable", None),
                    scpt::SymbolKind::AppleEvent => ("scpt_event", Some("AppleEvents")),
                    scpt::SymbolKind::FourCharCode => ("scpt_fourcc", Some("OSType")),
                    scpt::SymbolKind::Application => ("scpt_app", Some("Applications")),
                    scpt::SymbolKind::StringLiteral => continue, // Skip string literals for imports
                };

                report.imports.push(Import {
                    symbol: symbol.name,
                    library: library.map(String::from),
                    source: source.to_string(),
                    offset: None,
                });
            }

            // Add Apple Event details as special imports for rule matching
            for event in parser.apple_events() {
                // Add the combined class.event format
                report.imports.push(Import {
                    symbol: format!("{}.{}", event.class_code, event.event_code),
                    library: Some("AppleEvents".to_string()),
                    source: "scpt_event".to_string(),
                    offset: None,
                });

                // Also add the description for easier rule matching
                if event.desc != "unknown" {
                    report.imports.push(Import {
                        symbol: event.desc.to_string(),
                        library: Some("AppleScript".to_string()),
                        source: "scpt_command".to_string(),
                        offset: None,
                    });
                }
            }
        }
    }
}

impl Default for AppleScriptAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl Analyzer for AppleScriptAnalyzer {
    fn analyze_input(&self, input: &AnalysisInput<'_>) -> Result<AnalysisReport> {
        let target = TargetInfo {
            path: input.path.display().to_string(),
            file_type: "applescript".to_string(),
            size_bytes: input.data.len() as u64,
            sha256: crate::analyzers::utils::calculate_sha256(input.data),
            architectures: None,
        };

        let mut report = AnalysisReport::new(target);

        // Extract symbols from compiled AppleScript
        self.extract_scpt_symbols(input.data, &mut report);

        // Use pre-extracted strings if available, otherwise extract
        if !input.strings.is_empty() {
            report.strings = self.string_extractor.convert_stng_strings(input.strings);
        } else {
            report.strings = self.string_extractor.extract_smart(input.data);
        }

        // Prefer the struct's cancellation flag; fall back to the input's flag.
        let cancellation = self.cancellation.as_ref().or(input.cancellation.as_ref());

        // Analyze embedded code in strings
        let (encoded_layers, plain_findings) =
            crate::analyzers::embedded_code_detector::process_all_strings(
                &input.path.display().to_string(),
                &report.strings,
                &self.capability_mapper,
                0,
                Some(&crate::FileType::AppleScript),
                cancellation.map(Arc::as_ref),
            );
        report.files.extend(encoded_layers);
        report.findings.extend(plain_findings);

        // Evaluate all rules (atomic + composite) and merge into report
        let filefacts_ctx =
            crate::analysis_context::AnalysisContext::open(input.path, input.data).ok();
        self.capability_mapper
            .evaluate_and_merge_findings_with_precomputed(
                &mut report,
                input.data,
                crate::capabilities::AnalysisBorrow::with_filefacts(None, filefacts_ctx.as_ref()),
                None,
                None,
                None,
                None,
            );

        Ok(report)
    }

    fn can_analyze(&self, file_path: &Path) -> bool {
        if let Ok(metadata) = fs::metadata(file_path) {
            if metadata.is_file() {
                // Check for compiled AppleScript magic bytes "Fasd" or file extension
                if let Ok(mut file) = fs::File::open(file_path) {
                    use std::io::Read;
                    let mut magic = [0u8; 4];
                    if file.read_exact(&mut magic).is_ok() && &magic == b"Fasd" {
                        return true;
                    }
                }

                if let Some(ext) = file_path.extension() {
                    return ext == "scpt";
                }
            }
        }
        false
    }

    fn analyze(&self, file_path: &Path) -> Result<AnalysisReport> {
        let data = fs::read(file_path)?;

        let target = TargetInfo {
            path: file_path.display().to_string(),
            file_type: "applescript".to_string(),
            size_bytes: data.len() as u64,
            sha256: crate::analyzers::utils::calculate_sha256(&data),
            architectures: None,
        };

        let mut report = AnalysisReport::new(target);

        // Extract symbols from compiled AppleScript
        self.extract_scpt_symbols(&data, &mut report);

        // Use intelligent string extraction
        report.strings = self.string_extractor.extract_smart(&data);

        // Analyze embedded code in strings
        let (encoded_layers, plain_findings) =
            crate::analyzers::embedded_code_detector::process_all_strings(
                &file_path.display().to_string(),
                &report.strings,
                &self.capability_mapper,
                0,
                Some(&crate::FileType::AppleScript),
                self.cancellation.as_deref(),
            );
        report.files.extend(encoded_layers);
        report.findings.extend(plain_findings);

        // Evaluate all rules (atomic + composite) and merge into report
        let filefacts_ctx = crate::analysis_context::AnalysisContext::open(file_path, &data).ok();
        self.capability_mapper
            .evaluate_and_merge_findings_with_precomputed(
                &mut report,
                &data,
                crate::capabilities::AnalysisBorrow::with_filefacts(None, filefacts_ctx.as_ref()),
                None,
                None,
                None,
                None,
            );

        Ok(report)
    }
}
