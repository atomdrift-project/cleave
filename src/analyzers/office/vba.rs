//! VBA module access.
//!
//! VBA macro source is decompressed by filefacts (MS-OVBA §2.4.1) and
//! surfaced under `office.vba.modules[]` for both legacy OLE2 documents
//! and OOXML `vbaProject.bin` containers. cleave reads those typed rows
//! here rather than re-implementing the decompressor.

use crate::analysis_context::AnalysisContext;

/// A single VBA module: its name and decompressed source text.
#[derive(Debug, Clone)]
pub(crate) struct VbaModule {
    pub name: String,
    pub source_code: String,
}

/// Read decompressed VBA modules from filefacts' `office.vba.modules[]`.
///
/// Returns empty when no context is available or the document carries no
/// macros. Filefacts populates the same schema for OLE2 and OOXML, so a
/// single read covers both container formats.
pub(crate) fn modules_from_ctx(ctx: Option<&AnalysisContext<'_>>) -> Vec<VbaModule> {
    let Some(ctx) = ctx else {
        return Vec::new();
    };
    let Some(modules) = ctx
        .parsed
        .values()
        .get("office.vba.modules")
        .and_then(|v| v.as_array())
    else {
        return Vec::new();
    };
    modules
        .iter()
        .filter_map(|m| {
            Some(VbaModule {
                name: m.get("name")?.as_str()?.to_string(),
                source_code: m.get("source")?.as_str()?.to_string(),
            })
        })
        .collect()
}
