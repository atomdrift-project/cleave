//! Source an anonymous range of a file carries, analyzed beside its host.
//!
//! filefacts lists each range as `embedded.sources` (language, byte offset,
//! byte size); this module analyzes every one as that language and attaches
//! it as a layer named `<host>##<language>@<offset>`. `##` marks
//! an anonymous view of the host's own bytes; a source a format names (an
//! archive member, a VBA module) is a `!!` member instead.
//!
//! Plaintext views in another language, not concealment: each is analyzed
//! as its language and does not lift findings into the host.

use crate::analysis_context::AnalysisContext;
use crate::analyzers::FileType;
use crate::analyzers::unified::UnifiedSourceAnalyzer;
use crate::types::AnalysisReport;
use std::path::Path;

/// One range filefacts located.
struct Source<'a> {
    file_type: FileType,
    language: &'a str,
    offset: usize,
    bytes: &'a [u8],
}

/// The `embedded.sources` of `ctx`, with the bytes each names. Entries that
/// name an unknown language or fall outside the file are skipped.
fn sources<'a>(ctx: &'a AnalysisContext<'_>) -> Vec<Source<'a>> {
    let Some(list) = ctx
        .parsed
        .values()
        .get("embedded.sources")
        .and_then(serde_json::Value::as_array)
    else {
        return Vec::new();
    };
    list.iter()
        .filter_map(|entry| {
            let language = entry.get("language")?.as_str()?;
            let field = |key| {
                entry
                    .get(key)
                    .and_then(serde_json::Value::as_u64)
                    .and_then(|n| usize::try_from(n).ok())
            };
            let (offset, size) = (field("offset")?, field("size")?);
            Some(Source {
                file_type: filefacts::FileType::from_label(language)?,
                language,
                offset,
                bytes: ctx.content.get(offset..offset.checked_add(size)?)?,
            })
        })
        .collect()
}

/// Analyze each source `ctx` lists as a depth-1 layer of `host` (a file of
/// type `host_type`) and attach it to `report`.
pub(crate) fn attach(
    report: &mut AnalysisReport,
    host: &str,
    host_type: crate::analyzers::FileType,
    ctx: &AnalysisContext<'_>,
    engine: &crate::Engine,
) {
    for source in sources(ctx) {
        let Some(analyzer) = UnifiedSourceAnalyzer::for_file_type(&source.file_type) else {
            continue;
        };
        tracing::debug!(
            path = %host,
            language = source.language,
            offset = source.offset,
            "analyzing embedded source"
        );
        let path = format!("{host}##{}@{}", source.language, source.offset);
        let text = String::from_utf8_lossy(source.bytes);
        let view = analyzer
            .with_engine(engine.clone())
            .without_embedded_detection()
            .with_fragment_host(Some(host_type))
            .analyze_source_as_configured(Path::new(&path), &text);
        let (mut entry, _, _) = view.into_file_analysis(0, engine);
        entry.path = path;
        entry.depth = 1;
        entry.encoding = None;
        entry.compute_summary();
        report.files.push(entry);
    }
}
