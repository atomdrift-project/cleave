//! Files whose analysis is entirely what filefacts reports: images, fonts,
//! media containers, RTF documents, extension manifests, pickles and Java
//! class files.
//!
//! filefacts identifies and parses the file; this analyzer attaches its
//! strings, imports, functions and parser literals to the report and runs the rules
//! over its facts. Nothing here knows a format: a new format filefacts
//! learns needs no code in cleave.

use super::{AnalysisInput, Analyzer, FileTypeExt};
use crate::strings::StringExtractor;
use crate::types::{AnalysisReport, TargetInfo};
use anyhow::Result;

/// Rule evaluation over filefacts' view of one file.
#[derive(Debug)]
pub(crate) struct FactsAnalyzer {
    engine: crate::Engine,
    string_extractor: StringExtractor,
}

impl FactsAnalyzer {
    #[must_use]
    pub(crate) fn new() -> Self {
        Self {
            engine: crate::Engine::empty(),
            string_extractor: StringExtractor::new(),
        }
    }

    /// Analyze under `engine`: its rules and settings.
    #[must_use]
    pub(crate) fn with_engine(mut self, engine: crate::Engine) -> Self {
        self.engine = engine;
        self
    }
}

impl Default for FactsAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl Analyzer for FactsAnalyzer {
    fn analyze_input(&self, input: &AnalysisInput<'_>) -> Result<AnalysisReport> {
        // Reuse the threaded context, else open one on the same `input.data`.
        let fallback = input.open_ctx_fallback();
        let ctx = input.parsed_ctx.or(fallback.as_ref());
        let mut report = AnalysisReport::new(TargetInfo {
            path: input.path.display().to_string(),
            file_type: input.file_type.report_file_type(),
            size_bytes: input.data.len() as u64,
            sha256: input
                .sha256
                .clone()
                .unwrap_or_else(|| crate::analyzers::utils::calculate_sha256(input.data)),
            architectures: None,
        });
        report.metadata.tools_used.push("filefacts".to_string());
        report.strings = self.string_extractor.convert_stng_strings(input.strings);
        if let Some(ctx) = ctx {
            report.imports = ctx.imports_from_filefacts();
            report.functions = ctx.functions_from_filefacts();
            report
                .strings
                .extend(crate::strings::parser_literal_strings(ctx));
        }
        self.engine.evaluate_and_merge_findings_with_precomputed(
            &mut report,
            input.data,
            crate::capabilities::AnalysisBorrow::with_filefacts(None, ctx),
            None,
            None,
            None,
            None,
        );
        Ok(report)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use std::path::Path;

    /// Analyze `data` as a scan would: typed and parsed by filefacts.
    fn analyze(name: &str, data: &[u8]) -> AnalysisReport {
        let path = Path::new(name);
        let ctx = crate::analysis_context::AnalysisContext::open(path, data);
        let file_type = crate::analyzers::detect_file_type_from_data(path, data);
        let input = AnalysisInput::with_strings(path, data, ctx.text_rows(), file_type)
            .with_parsed_ctx(&ctx);
        FactsAnalyzer::new().analyze_input(&input).unwrap()
    }

    #[test]
    fn report_is_labelled_with_the_filefacts_type() {
        let report = analyze("test.rtf", b"{\\rtf1\\ansi\\ansicpg1252}");
        assert_eq!(report.target.file_type, "rtf");
    }

    /// `type: text` rules need the document's text; an absent corpus reads
    /// the same as a corpus with no hit in it.
    #[test]
    fn report_carries_the_documents_text() {
        let report = analyze(
            "letter.rtf",
            b"{\\rtf1\\ansi\\deff0{\\fonttbl{\\f0\\fnil Arial;}}\
\\pard\\f0\\fs22 This is DHL courier Delivery Company\\par\n}",
        );
        assert!(
            report
                .strings
                .iter()
                .any(|s| s.value.contains("DHL courier")),
            "document text missing: {:?}",
            report.strings.iter().map(|s| &s.value).collect::<Vec<_>>()
        );
    }

    /// Documents that run to megabytes on one line still yield text.
    #[test]
    fn long_single_line_rtf_still_yields_text() {
        let mut data = b"{\\rtf1\\ansi{\\object\\objdata ".to_vec();
        data.extend(std::iter::repeat_n(b'A', 300_000));
        data.extend_from_slice(b"}\\objupdate}");
        assert!(!analyze("big.rtf", &data).strings.is_empty());
    }

    /// Java method references reach the report owner-qualified, for symbol
    /// traits.
    #[test]
    fn java_method_references_are_owner_qualified_imports() {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/java/Suspicious.class"
        );
        let report = analyze(path, &std::fs::read(path).unwrap());
        assert_eq!(report.target.file_type, "java_class");
        let symbols: std::collections::BTreeSet<&str> =
            report.imports.iter().map(|i| i.symbol.as_str()).collect();
        assert!(symbols.contains("java/lang/Runtime.exec"), "{symbols:?}");
        assert!(
            symbols.contains("java/lang/ProcessBuilder.start"),
            "{symbols:?}"
        );
    }

    /// Strings a caller already extracted are kept for text traits.
    #[test]
    fn preextracted_strings_are_kept() {
        let path = Path::new(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/java/Suspicious.class"
        ));
        let data = std::fs::read(path).unwrap();
        let strings = [stng::ExtractedString::new(
            "java-text-regression-marker".to_string(),
            42,
            stng::StringMethod::RawScan,
        )];
        let input = AnalysisInput::with_strings(
            path,
            &data,
            &strings,
            crate::analyzers::FileType::JavaClass,
        );
        let report = FactsAnalyzer::new().analyze_input(&input).unwrap();
        assert!(
            report
                .strings
                .iter()
                .any(|row| &*row.value == "java-text-regression-marker")
        );
    }

    /// The callables a pickle imports reach the report as imports.
    #[test]
    fn pickle_globals_are_imports() {
        let report = analyze(
            "evil.pkl",
            b"\x80\x02cos\nsystem\nq\x00X\x02\x00\x00\x00ls\x85R.",
        );
        assert_eq!(report.target.file_type, "pickle");
        assert!(report.imports.iter().any(|i| i.symbol == "os.system"));
    }
}
