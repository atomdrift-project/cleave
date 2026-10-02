//! Report adapters only. Language/package semantics belong to filefacts.
use crate::types::AnalysisReport;
use filefacts::package_context::{ContextLimits, Coverage, SourceFile, SourceMember};

pub(super) fn attach(report: &mut AnalysisReport) {
    let members: Vec<_> = report
        .files
        .iter()
        .map(|file| SourceMember {
            path: &file.path,
            values: &file.kv,
        })
        .collect();
    let context =
        filefacts::package_context::cargo_source_context(&members, &ContextLimits::default());
    if (context.truncated || !context.targets.is_empty())
        && let Ok(facts) = serde_json::to_value(&context)
    {
        report.merge_kv_subtree("cargo_context", facts);
    }
}

pub(super) fn attach_go(
    report: &mut AnalysisReport,
    sources: &[(String, String)],
    incomplete: bool,
) {
    let files: Vec<_> = sources
        .iter()
        .map(|(path, source)| SourceFile { path, source })
        .collect();
    let coverage = if incomplete {
        Coverage::Incomplete
    } else {
        Coverage::Complete
    };
    let context = filefacts::go_source_context(&files, coverage, &ContextLimits::default());
    if (context.truncated || !context.packages.is_empty())
        && let Ok(facts) = serde_json::to_value(&context)
    {
        report.merge_kv_subtree("go_context", facts);
    }
}
