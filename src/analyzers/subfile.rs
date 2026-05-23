//! Unified sub-file dispatcher.
//!
//! Cleave produces fresh bytes from several places: decoded base64
//! blobs in shell scripts, archive members, format-embedded
//! payloads (PDF `/JS` actions, Office VBA modules, OLE2
//! executables, …). Each case eventually wants the same thing:
//! "given these bytes and a [`FileType`], hand them to the right
//! analyzer, merge findings back, attach the result as a nested
//! file at the next depth."
//!
//! Before this module existed, four sites in the codebase had each
//! re-implemented that loop — `analyze_vba_subfiles`,
//! `analyze_embedded_executables`, `embedded_code_detector`'s
//! payload routing, and the new PDF JS extractor. Each had its own
//! drift on (a) which analyzers to dispatch to, (b) how to tag
//! evidence locations, (c) how to bound recursion. The unified
//! helper here collapses the dispatch decision to one match
//! statement and one merge routine — caller still owns *when* to
//! call (it knows the virtual path, source location, and the
//! parent report it wants to merge into), but *how* analysis runs
//! is no longer scattered.
//!
//! ## Recursion bound
//!
//! Every entry point passes the parent's depth. We refuse to
//! recurse past [`MAX_SUBFILE_DEPTH`] — protects against
//! base64-inside-base64-inside-base64 chains and tar-bombs nesting
//! deeper than the policy ceiling.

use crate::analyzers::archive::ArchiveAnalyzer;
use crate::analyzers::{analyzer_for_file_type_arc, AnalysisInput, FileType};
use crate::capabilities::CapabilityMapper;
use crate::types::FileAnalysis;
use std::path::Path;
use std::sync::Arc;

/// Hard cap on sub-file recursion. Each layer adds one — base64
/// (1) → tar.gz (2) → tar member (3) → embedded base64 inside that
/// member (4). Real samples rarely exceed 3; deeper chains are
/// almost certainly a zip-bomb / decoder-storm and not worth the
/// memory.
pub const MAX_SUBFILE_DEPTH: u32 = 6;

/// Run the appropriate analyzer over `bytes`, then return the
/// resulting [`FileAnalysis`] entries at `parent_depth + 1`,
/// flattened into a single vec (sub-files of the analysis itself
/// come back in the same list, with their depths already bumped).
///
/// The caller is responsible for pushing the returned entries into
/// `parent.files` and folding any findings they want lifted into
/// the parent's finding stream — different call sites want
/// different lift semantics (best-wins dedup vs.
/// container-composite re-evaluation vs. straight append). Keeping
/// that policy out of the dispatcher means one shape change here
/// doesn't ripple through every caller.
///
/// `location_prefix` is prepended to every sub-finding's
/// `evidence.location`, with the original location appended after
/// a `:`. Conventions:
/// - `pdf-js:object<id>` — PDF `/JS` action
/// - `vba:<module-name>` — Office VBA module
/// - `embedded@<offset>` — base64-decoded payload at byte offset
/// - `archive:<member-path>` — archive member
///
/// Returns an empty vec on any failure (analyzer unavailable,
/// depth exceeded, parse error). Sub-file analysis is best-effort
/// — caller's parent report stays intact regardless.
pub fn analyze_subfile_bytes(
    bytes: &[u8],
    virtual_path: &str,
    file_type: FileType,
    location_prefix: &str,
    parent_depth: u32,
    mapper: &Arc<CapabilityMapper>,
) -> Vec<FileAnalysis> {
    let child_depth = parent_depth.saturating_add(1);
    if child_depth > MAX_SUBFILE_DEPTH {
        tracing::debug!(
            virtual_path,
            parent_depth,
            "sub-file recursion depth ceiling hit; skipping",
        );
        return Vec::new();
    }

    let Some(analyzer) = pick_analyzer(file_type, mapper) else {
        tracing::debug!(
            ?file_type,
            "no analyzer available for sub-file type; skipping",
        );
        return Vec::new();
    };

    // Construct the AnalysisInput against the virtual path so the
    // sub-analyzer's filefacts call uses the right path-based hints
    // (extension classification, etc.) without ever touching disk.
    let path = Path::new(virtual_path);
    let report = match analyzer.analyze_input(&AnalysisInput::new(path, bytes, file_type)) {
        Ok(r) => r,
        Err(e) => {
            tracing::debug!(virtual_path, error = %e, "sub-file analysis failed; skipping");
            return Vec::new();
        }
    };

    flatten_subreport(report, virtual_path, location_prefix, child_depth)
}

/// Pick the right analyzer for a [`FileType`]. Archives go through
/// [`ArchiveAnalyzer`] (which has its own recursion machinery for
/// the tar.gz → tar → member case); everything else goes through
/// [`analyzer_for_file_type_arc`] (binaries, source code, Office,
/// PDF). Returns `None` for types with no analyzer at all
/// (`FileType::Unknown`, certain meta-types).
fn pick_analyzer(
    file_type: FileType,
    mapper: &Arc<CapabilityMapper>,
) -> Option<Box<dyn crate::analyzers::Analyzer>> {
    if file_type.is_archive() {
        // Cleave's archive analyzer handles tar / zip / tar.gz /
        // tar.xz / .gem / .crate / .apk / … with in-memory extraction
        // when the input path doesn't exist (which is always the
        // case for synthesized sub-paths).
        Some(Box::new(
            ArchiveAnalyzer::new().with_capability_mapper_arc(mapper.clone()),
        ))
    } else {
        analyzer_for_file_type_arc(&file_type, Some(mapper.clone()))
    }
}

/// Convert a sub-analyzer's [`AnalysisReport`] into a list of
/// [`FileAnalysis`] entries ready to attach to the parent:
/// - The primary entry sits at `child_depth` with `virtual_path`.
/// - Every evidence location on every finding is tagged with
///   `location_prefix:<orig>` (or just `location_prefix` when the
///   sub-analyzer didn't set one).
/// - Nested files the sub-analyzer produced (archive members,
///   sub-sub-files) come along with their depths bumped by
///   `child_depth` so the lineage stays correct.
fn flatten_subreport(
    report: crate::types::AnalysisReport,
    virtual_path: &str,
    location_prefix: &str,
    child_depth: u32,
) -> Vec<FileAnalysis> {
    let (mut primary, nested, _archive) = report.into_file_analysis(0);
    primary.path = virtual_path.to_string();
    primary.depth = child_depth;
    tag_findings(&mut primary, location_prefix);
    primary.compute_summary();

    let mut out = Vec::with_capacity(1 + nested.len());
    out.push(primary);
    for mut entry in nested {
        // Nested files already carry their relative depth from the
        // sub-analyzer (e.g. archive member is depth 1 inside the
        // archive's own report). Shift by child_depth so the depth
        // reflects the full lineage from the root.
        entry.depth = entry.depth.saturating_add(child_depth);
        tag_findings_chain(&mut entry, location_prefix);
        out.push(entry);
    }
    out
}

fn tag_findings(file: &mut FileAnalysis, location_prefix: &str) {
    for finding in &mut file.findings {
        for evidence in &mut finding.evidence {
            evidence.location = Some(match evidence.location.as_deref() {
                Some(loc) => format!("{location_prefix}:{loc}"),
                None => location_prefix.to_string(),
            });
        }
    }
}

fn tag_findings_chain(file: &mut FileAnalysis, location_prefix: &str) {
    // For doubly-nested entries (archive-of-base64-of-tar.gz),
    // chain the prefix so locations read top-down. We don't
    // overwrite — each layer's caller adds its own prefix.
    for finding in &mut file.findings {
        for evidence in &mut finding.evidence {
            evidence.location = Some(match evidence.location.as_deref() {
                Some(loc) => format!("{location_prefix}:{loc}"),
                None => location_prefix.to_string(),
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Recursion ceiling is enforced — at depth `MAX_SUBFILE_DEPTH`
    /// the helper refuses to dispatch (returns empty) regardless of
    /// the bytes' contents.
    #[test]
    fn refuses_to_recurse_past_ceiling() {
        let mapper = Arc::new(CapabilityMapper::empty());
        let result = analyze_subfile_bytes(
            b"print('hi')\n",
            "deep.py",
            FileType::Python,
            "ceiling-test",
            MAX_SUBFILE_DEPTH, // parent already at ceiling → child > ceiling
            &mapper,
        );
        assert!(
            result.is_empty(),
            "expected no entries at recursion ceiling, got {} files",
            result.len(),
        );
    }

    /// Unknown FileType returns empty — no analyzer to dispatch to.
    /// Caller stays intact.
    #[test]
    fn unknown_filetype_returns_empty() {
        let mapper = Arc::new(CapabilityMapper::empty());
        let result = analyze_subfile_bytes(
            b"\x00\x00\x00\x00",
            "x.bin",
            FileType::Unknown,
            "unknown-test",
            0,
            &mapper,
        );
        assert!(result.is_empty());
    }

    /// Source-language path: a tiny Python snippet routes through
    /// `UnifiedSourceAnalyzer` (via `analyzer_for_file_type_arc`)
    /// and comes back as a single `FileAnalysis` at child depth.
    #[test]
    fn source_language_returns_single_entry_at_child_depth() {
        let mapper = Arc::new(CapabilityMapper::empty());
        let result = analyze_subfile_bytes(
            b"import os\nprint(os.environ)\n",
            "parent.sh!!script.py",
            FileType::Python,
            "embedded-py",
            0,
            &mapper,
        );
        assert_eq!(result.len(), 1, "expected one entry, got {result:?}");
        assert_eq!(result[0].depth, 1);
        assert_eq!(result[0].path, "parent.sh!!script.py");
        assert_eq!(result[0].file_type, "python");
    }
}
