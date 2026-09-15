//! Analyze format-declared script bodies as independent logical source units.
//! filefacts selects the bodies and languages; this adapter owns traversal and
//! budgets. No extra YAML parser, interpreter process or security heuristic.
use super::unified::UnifiedSourceAnalyzer;
use crate::capabilities::CapabilityMapper;
use crate::types::{AnalysisGap, AnalysisReport};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

const MAX_SCRIPTS: usize = 100;
const MAX_SCRIPT_BYTES: usize = 1024 * 1024;
const MAX_TOTAL_BYTES: usize = 10 * 1024 * 1024;

pub(super) fn append(
    parsed: &filefacts::ParsedFile<'_>,
    mapper: &Arc<CapabilityMapper>,
    report: &mut AnalysisReport,
    cancelled: Option<&Arc<AtomicBool>>,
) {
    let mut total = 0;
    for (index, script) in parsed.embedded_sources().enumerate() {
        if index >= MAX_SCRIPTS || cancelled.is_some_and(|flag| flag.load(Ordering::Acquire)) {
            report
                .analysis_gaps
                .record(AnalysisGap::EmbeddedSourceIncomplete);
            break;
        }
        if script.source.len() > MAX_SCRIPT_BYTES || script.source.len() > MAX_TOTAL_BYTES - total {
            report
                .analysis_gaps
                .record(AnalysisGap::EmbeddedSourceIncomplete);
            continue;
        }
        let Some(analyzer) = script
            .file_type
            .and_then(|ft| UnifiedSourceAnalyzer::for_file_type(&ft))
        else {
            report
                .analysis_gaps
                .record(AnalysisGap::EmbeddedSourceIncomplete);
            continue;
        };
        total += script.source.len();
        if parsed.fileid().file_type() == filefacts::FileType::GithubActions
            && script.source.contains("${{")
        {
            // The literal body is still useful, but runner expression
            // substitution is outside source-local static analysis.
            report
                .analysis_gaps
                .record(AnalysisGap::EmbeddedSourceIncomplete);
        }
        // JSON Pointer identifies the decoded scalar. Escape container/path
        // delimiters from untrusted keys; retain the pointer's slash structure.
        // `!!`, not `##`: different run steps must not share file-scope facts.
        let locator: String = script
            .pointer
            .bytes()
            .map(|b| {
                if b.is_ascii_alphanumeric() || b"/_-~".contains(&b) {
                    char::from(b).to_string()
                } else {
                    format!("%{b:02X}")
                }
            })
            .collect();
        let path = format!("{}!!{locator}", report.target.path);
        let child = analyzer
            .with_capability_mapper_arc(Arc::clone(mapper))
            .without_embedded_detection()
            .with_cancellation(cancelled.cloned())
            .analyze_source_as_configured(Path::new(&path), script.source);
        let (mut file, nested, _) = child.into_file_analysis(0);
        // Embedded detection is deliberately disabled here: one declared body
        // is one independent source scope, not an unbounded recursive container.
        debug_assert!(nested.is_empty());
        file.depth = 1;
        file.compute_summary();
        report.files.push(file);
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use crate::analyzers::{AnalysisInput, Analyzer, FileType, generic::GenericAnalyzer};

    fn analyze(yaml: &str) -> AnalysisReport {
        GenericAnalyzer::new(FileType::GithubActions)
            .analyze_input(&AnalysisInput::new(
                Path::new("action.yml"),
                yaml.as_bytes(),
                FileType::GithubActions,
            ))
            .unwrap()
    }

    #[test]
    fn declared_sources_are_separate_unencoded_logical_members() {
        let report = analyze(
            "runs:\n  using: composite\n  steps:\n    - shell: bash\n      run: echo first\n    - shell: python\n      run: print('second')\n",
        );
        assert_eq!(report.files.len(), 2);
        assert_eq!(report.files[0].path, "action.yml!!/runs/steps/0/run");
        assert_eq!(report.files[0].file_type, "shell");
        assert_eq!(report.files[1].file_type, "python");
        assert!(report.files.iter().all(|f| f.encoding.is_none()));
        assert!(report.analysis_gaps.is_empty());
    }

    #[test]
    fn unsupported_shells_and_budgets_leave_a_gap() {
        let unknown = analyze(
            "runs:\n  using: composite\n  steps: [{shell: '${{ inputs.shell }}', run: echo example}]\n",
        );
        assert!(unknown.files.is_empty());
        assert!(
            unknown
                .analysis_gaps
                .iter()
                .any(|g| g == AnalysisGap::EmbeddedSourceIncomplete)
        );
        let many = format!(
            "runs:\n  using: composite\n  steps:\n{}",
            "    - {shell: bash, run: echo ready}\n".repeat(MAX_SCRIPTS + 1)
        );
        let limited = analyze(&many);
        assert_eq!(limited.files.len(), MAX_SCRIPTS);
        assert!(!limited.analysis_gaps.is_empty());
    }

    #[test]
    fn cancelled_source_traversal_is_not_a_clean_result() {
        let mut input = AnalysisInput::new(
            Path::new("action.yml"),
            b"runs:\n  using: composite\n  steps: [{shell: bash, run: echo ready}]\n",
            FileType::GithubActions,
        );
        input.cancellation = Some(Arc::new(AtomicBool::new(true)));
        let report = GenericAnalyzer::new(FileType::GithubActions)
            .analyze_input(&input)
            .unwrap();
        assert!(report.files.is_empty());
        assert!(!report.analysis_gaps.is_empty());
    }

    #[test]
    fn oversized_body_is_skipped_and_later_small_body_survives() {
        let yaml = format!(
            "runs:\n  using: composite\n  steps:\n    - shell: bash\n      run: '{}'\n    - {{shell: bash, run: echo ready}}\n",
            "x".repeat(MAX_SCRIPT_BYTES + 1)
        );
        let report = analyze(&yaml);
        assert_eq!(report.files.len(), 1);
        assert!(report.files[0].path.ends_with("/steps/1/run"));
        assert!(!report.analysis_gaps.is_empty());
    }
}
