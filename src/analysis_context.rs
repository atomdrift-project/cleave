//! Single integration point with `expose`.
//!
//! `AnalysisContext` opens the file *once* through
//! `expose::open_with_path` and lends the resulting `ParsedFile`
//! plus a few cached projections (file-id, values tree) to every
//! downstream consumer — the trait engine, the `cleave kv`
//! subcommand, the binary/source analyzer post-processing, …
//!
//! Before this existed, each consumer called
//! `expose::open_with_path` independently, which meant a PE file
//! got parsed by `goblin` twice (once for the analyzer crate, once
//! for the dual-emission) and the same lazy view scaffolding was
//! rebuilt on every entry. Funneling through this struct collapses
//! the work to one parse per file.

use serde_json::Value;
use std::path::Path;

use crate::types::{Export, Function, Import, Section};

/// Files opened once via expose for the whole analysis pipeline.
///
/// The `expose::ParsedFile` it wraps holds four lazy views
/// (`fileid`, `values`, `strings`, `metrics`); accessing them
/// through this struct realizes each view at most once.
#[derive(Debug)]
pub struct AnalysisContext<'a> {
    /// Source path the bytes came from. Carried so format detectors
    /// that need filename hints can read it without an additional
    /// FS round-trip.
    pub path: &'a Path,
    /// Raw file bytes. Borrowed; the parser doesn't take ownership.
    pub content: &'a [u8],
    /// Single-pass projection of `content` by `expose`. See its
    /// `ParsedFile` docs for the available views.
    pub parsed: expose::ParsedFile<'a>,
}

impl<'a> AnalysisContext<'a> {
    /// Open the file through expose, returning a context borrowing
    /// the provided `path` and `content`.
    ///
    /// Returns the expose error verbatim on failure — callers that
    /// need to fall back to a legacy code path can match on it.
    pub fn open(path: &'a Path, content: &'a [u8]) -> Result<Self, expose::Error> {
        let parsed = expose::open_with_path(path, content)?;
        Ok(Self {
            path,
            content,
            parsed,
        })
    }

    /// Format-native values tree as JSON, with the `strings` /
    /// `ast` / `sections` namespaces stripped — those have richer
    /// typed accessors on `ParsedFile` and consumers should read
    /// them through those rather than re-walking JSON.
    ///
    /// Returns `Value::Null` when expose has nothing structured to
    /// say about the file.
    #[must_use]
    pub fn values_tree(&self) -> Value {
        match self.parsed.values().as_json() {
            Value::Object(map) => {
                let mut out = serde_json::Map::new();
                for (k, v) in map {
                    if matches!(k.as_str(), "strings" | "ast" | "sections") {
                        continue;
                    }
                    out.insert(k.to_string(), v.clone());
                }
                Value::Object(out)
            }
            other => other.clone(),
        }
    }

    /// Convenience helper for callers that want `None` instead of
    /// `Value::Object({})` when the values tree is empty.
    #[must_use]
    pub fn values_tree_if_nonempty(&self) -> Option<Value> {
        match self.values_tree() {
            Value::Object(m) if !m.is_empty() => Some(Value::Object(m)),
            _ => None,
        }
    }

    /// Project expose's typed `Imports` view into cleave's
    /// `Vec<Import>` shape. Symbol names are normalized (leading
    /// underscores stripped) and offsets are formatted as the
    /// `0xHEX` strings cleave's downstream consumers expect.
    ///
    /// Callers wiring expose-emitted symbols into `report.imports`
    /// are responsible for not double-counting when an analyzer
    /// has already populated entries for the same source — see
    /// the module docs for the dedupe contract.
    #[must_use]
    pub fn imports_from_expose(&self) -> Vec<Import> {
        self.parsed
            .imports()
            .iter()
            .map(|i| Import {
                symbol: crate::types::binary::normalize_symbol(&i.name),
                library: i.library.clone(),
                source: i.source.to_string(),
                offset: i.offset.map(|o| format!("0x{o:x}")),
            })
            .collect()
    }

    /// Project expose's typed `Exports` view into cleave's
    /// `Vec<Export>` shape. PE forwarded-export targets
    /// (`KERNEL32.LoadLibraryA`, `NTDLL.#123`) carry through via
    /// `forward_to`; normal exports leave that field `None`.
    #[must_use]
    pub fn exports_from_expose(&self) -> Vec<Export> {
        self.parsed
            .exports()
            .iter()
            .map(|e| Export {
                symbol: crate::types::binary::normalize_symbol(&e.name),
                offset: e.offset.map(|o| format!("0x{o:x}")),
                source: e.source.to_string(),
                forward_to: e.forward_to.clone(),
            })
            .collect()
    }

    /// Project expose's typed `Sections` view into cleave's
    /// `Vec<Section>` shape. Per-section Shannon entropy comes
    /// straight from expose's metric map (keyed
    /// `sections[N].entropy`) so no second pass over the bytes is
    /// needed. Permission flags are flattened to the conventional
    /// `"rwx"` / `"r-x"` / `"rw-"` triplet that cleave's downstream
    /// finders expect.
    #[must_use]
    pub fn sections_from_expose(&self) -> Vec<Section> {
        let metrics = self.parsed.metrics();
        self.parsed
            .sections()
            .iter()
            .enumerate()
            .map(|(idx, s)| {
                let entropy = metrics
                    .get(&format!("sections[{idx}].entropy"))
                    .unwrap_or(0.0);
                let is_read = s.flags.iter().any(|f| f == "readable" || f == "alloc");
                let is_write = s.flags.iter().any(|f| f == "writable" || f == "write");
                let is_exec = s
                    .flags
                    .iter()
                    .any(|f| f == "executable" || f == "execinstr");
                let permissions = format!(
                    "{}{}{}",
                    if is_read { "r" } else { "-" },
                    if is_write { "w" } else { "-" },
                    if is_exec { "x" } else { "-" },
                );
                Section {
                    name: s.name.clone(),
                    address: Some(s.vaddr),
                    offset: Some(s.file_offset),
                    size: s.file_size,
                    entropy,
                    permissions: Some(permissions),
                    flags: s.flags.clone(),
                }
            })
            .collect()
    }

    /// Project expose's typed `Functions` view into cleave's
    /// `Vec<Function>` shape, threading the CFG metrics rizin
    /// recovered (complexity, basic blocks, edges, instruction
    /// count, resolved call edges) into cleave's
    /// `ControlFlowMetrics` mirror when they're present on the
    /// expose entry.
    ///
    /// For symbol-table-sourced functions (PE export table, ELF
    /// `.dynsym`, VBA `Public Sub`, etc.) the CFG fields are absent
    /// on expose's side and the cleave projection leaves the nested
    /// block `None`. The fuller per-function rizin data
    /// (instructions, stack frame, recursive / noreturn flags) lives
    /// on `expose::Function` and ships in `report.expose.functions`
    /// for diff/ML consumers.
    #[must_use]
    pub fn functions_from_expose(&self) -> Vec<Function> {
        self.parsed
            .functions()
            .iter()
            .map(project_expose_function)
            .collect()
    }
}

/// Pure projection: `expose::Function` → cleave's typed `Function`
/// mirror. Lives at module scope so the binary analyzers can call
/// it without going back through an `AnalysisContext`.
#[must_use]
pub fn project_expose_function(f: &expose::Function) -> Function {
    use crate::types::ml_features::ControlFlowMetrics;

    let nbbs = f.basic_blocks;
    let edges = f.edges;
    let ninstr = f.instructions;

    // Build control-flow metrics only when rizin gave us at least
    // one shape signal (basic_blocks or edges).
    let control_flow = if nbbs.is_some() || edges.is_some() {
        let nbbs = nbbs.unwrap_or(1);
        let edges = edges.unwrap_or(0);
        let ninstr = ninstr.unwrap_or(0);
        Some(ControlFlowMetrics {
            basic_blocks: nbbs,
            edges,
            cyclomatic_complexity: f.complexity.unwrap_or(1),
            max_block_size: ninstr.checked_div(nbbs).unwrap_or(0),
            avg_block_size: if nbbs > 0 {
                ninstr as f32 / nbbs as f32
            } else {
                0.0
            },
            is_linear: f.is_linear.unwrap_or(false),
            loop_count: if edges >= nbbs { edges - nbbs + 1 } else { 0 },
            branch_density: if ninstr > 0 {
                edges as f32 / ninstr as f32
            } else {
                0.0
            },
            in_degree: 0,
            out_degree: f.calls.len() as u32,
        })
    } else {
        None
    };

    Function {
        name: f.name.trim_start_matches('_').to_string(),
        offset: f.offset.map(|o| format!("0x{o:x}")),
        size: None,
        complexity: f.complexity,
        calls: f.calls.clone(),
        source: f.source.to_string(),
        control_flow,
        register_usage: None,
        constants: Vec::new(),
        signature: None,
        nesting: None,
        call_patterns: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// PE imports come back library-tagged (lowercase, no `.dll`)
    /// with hex-formatted offsets, matching what cleave's PE
    /// analyzer used to emit via goblin directly.
    #[test]
    fn imports_from_expose_normalises_pe_fixture() {
        let path = std::path::Path::new("tests/fixtures/test.exe");
        let bytes = std::fs::read(path).expect("fixture present");
        let ctx = AnalysisContext::open(path, &bytes).expect("expose opens PE");
        // Force the parse so .imports() is populated.
        let _ = ctx.values_tree();
        let imports = ctx.imports_from_expose();
        assert!(!imports.is_empty(), "PE fixture should have imports");
        for imp in &imports {
            assert_eq!(imp.source, "pe");
            let lib = imp.library.as_deref().expect("PE imports carry a library");
            assert_eq!(lib, &lib.to_ascii_lowercase());
            assert!(!lib.ends_with(".dll"));
            let off = imp.offset.as_deref().expect("offset always set for PE");
            assert!(off.starts_with("0x"));
        }
    }

    /// Exports map through with hex offsets and the expose source
    /// tag intact. PE exports always carry an offset; the
    /// projection mirrors that into `Option<String>`.
    #[test]
    fn exports_from_expose_normalises_pe_fixture() {
        let path = std::path::Path::new("tests/fixtures/test.exe");
        let bytes = std::fs::read(path).expect("fixture present");
        let ctx = AnalysisContext::open(path, &bytes).expect("expose opens PE");
        let _ = ctx.values_tree();
        let exports = ctx.exports_from_expose();
        for exp in &exports {
            assert_eq!(exp.source, "pe");
            assert!(exp.forward_to.is_none());
            if let Some(off) = exp.offset.as_deref() {
                assert!(off.starts_with("0x"));
            }
        }
    }
}
