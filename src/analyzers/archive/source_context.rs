//! Report adapters only. Language/package semantics belong to filefacts.
use crate::types::AnalysisReport;

pub(super) fn attach(report: &mut AnalysisReport) {
    let members: Vec<_> = report
        .files
        .iter()
        .map(|file| filefacts::package_context::SourceMember {
            path: &file.path,
            values: &file.kv,
        })
        .collect();
    let facts = filefacts::package_context::cargo_source_context(&members);
    if facts["truncated"] == true || facts["targets"].as_array().is_some_and(|a| !a.is_empty()) {
        report.merge_kv_subtree("cargo_context", facts);
    }
}

pub(super) fn attach_go(
    report: &mut AnalysisReport,
    sources: &[(String, String)],
    incomplete: bool,
) {
    let facts = filefacts::go_source_context(sources, incomplete);
    if facts["truncated"] == true || facts["packages"].as_array().is_some_and(|a| !a.is_empty()) {
        report.merge_kv_subtree("go_context", facts);
    }
}
