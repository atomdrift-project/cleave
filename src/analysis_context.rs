//! Single integration point with `filefacts`.
//!
//! `AnalysisContext` opens bytes once through `filefacts::open_with_path`
//! and lends the resulting `ParsedFile` to downstream consumers. Anything
//! that needs filefacts-derived identity, values, metrics, strings, sections,
//! symbols, archive indexes, or AST projections should pass this context
//! instead of reopening or reparsing the same byte slice.

use serde_json::Value;
use std::path::Path;

use crate::types::{ArchiveEntry, Export, Function, Import, Section};

/// Files opened once via filefacts for the whole analysis pipeline.
#[derive(Debug)]
pub struct AnalysisContext<'a> {
    /// Source path the bytes came from. Carried so format detectors that need
    /// filename hints can use it without another filesystem read.
    pub path: &'a Path,
    /// Raw file bytes. Borrowed; filefacts does not take ownership.
    pub content: &'a [u8],
    /// Single-pass projection of `content` by filefacts.
    pub parsed: filefacts::ParsedFile<'a>,
}

impl<'a> AnalysisContext<'a> {
    /// Open the file through filefacts, returning a context borrowing the
    /// provided `path` and `content`.
    pub fn open(path: &'a Path, content: &'a [u8]) -> Result<Self, filefacts::Error> {
        let parsed = filefacts::open_with_path(path, content)?;
        Ok(Self {
            path,
            content,
            parsed,
        })
    }

    /// Format-native residual values tree as JSON.
    ///
    /// Current filefacts releases do not mirror typed fact families into this
    /// tree. The namespace filter remains as a defensive guard for stale cache
    /// entries or older filefacts output that duplicated typed views under
    /// values.
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

    /// Return `Some(values_tree)` when filefacts emitted residual values.
    #[must_use]
    pub fn values_tree_if_nonempty(&self) -> Option<Value> {
        let value = self.values_tree();
        match &value {
            Value::Null => None,
            Value::Object(map) if map.is_empty() => None,
            _ => Some(value),
        }
    }

    /// Borrow filefacts's cached tree-sitter source parse, when available.
    #[must_use]
    pub fn source_ast(&self) -> Option<filefacts::SourceAst<'_>> {
        self.parsed.source_ast()
    }

    /// Archive member index emitted by filefacts.
    ///
    /// ZIP entries include header/data/central-directory offsets when
    /// available. Cleave uses those offsets to read supported member payloads
    /// from the already-loaded archive bytes without walking the central
    /// directory a second time.
    #[must_use]
    pub fn archive_entries(&self) -> Vec<ArchiveEntry> {
        let Some(members) = self
            .parsed
            .values()
            .get("archive.members")
            .and_then(serde_json::Value::as_array)
        else {
            return Vec::new();
        };

        members
            .iter()
            .filter_map(archive_entry_from_filefacts)
            .collect()
    }

    /// Project filefacts imports into cleave's import representation.
    #[must_use]
    pub fn imports_from_filefacts(&self) -> Vec<Import> {
        self.parsed
            .imports()
            .iter()
            .map(|i| match i.offset {
                Some(offset) => Import::with_offset(&i.name, i.library.clone(), i.source, offset),
                None => Import::new(&i.name, i.library.clone(), i.source),
            })
            .collect()
    }

    /// Project filefacts exports into cleave's export representation.
    #[must_use]
    pub fn exports_from_filefacts(&self) -> Vec<Export> {
        self.parsed
            .exports()
            .iter()
            .map(|e| {
                let mut out = Export::new(&e.name, e.offset.map(hex_offset), e.source);
                out.forward_to = e.forward_to.clone();
                out
            })
            .collect()
    }

    /// Project filefacts sections into cleave's section representation.
    #[must_use]
    pub fn sections_from_filefacts(&self) -> Vec<Section> {
        self.parsed
            .sections()
            .iter()
            .map(|s| Section {
                name: s.name.clone(),
                address: Some(s.vaddr),
                offset: Some(s.file_offset),
                size: s.file_size,
                entropy: s.entropy.unwrap_or(0.0),
                permissions: flags_to_permissions(&s.flags),
                flags: s.flags.clone(),
            })
            .collect()
    }

    /// Project filefacts functions into cleave's function representation.
    #[must_use]
    pub fn functions_from_filefacts(&self) -> Vec<Function> {
        self.parsed
            .functions()
            .iter()
            .map(project_filefacts_function)
            .collect()
    }
}

/// Project one filefacts function into cleave's public function shape.
#[must_use]
pub fn project_filefacts_function(f: &filefacts::Function) -> Function {
    Function {
        name: f.name.clone(),
        offset: f.offset.map(hex_offset),
        size: None,
        complexity: f.complexity,
        calls: f.calls.clone(),
        source: f.source.to_string(),
        control_flow: None,
        register_usage: None,
        constants: Vec::new(),
        signature: None,
        nesting: None,
        call_patterns: None,
    }
}

fn archive_entry_from_filefacts(value: &Value) -> Option<ArchiveEntry> {
    let path = value.get("path")?.as_str()?.to_string();
    let size_bytes = value.get("size_bytes").and_then(Value::as_u64).unwrap_or(0);

    Some(ArchiveEntry {
        path,
        file_type: "unknown".to_string(),
        sha256: String::new(),
        size_bytes,
        compressed_size: value.get("compressed_size").and_then(Value::as_u64),
        compression_method: value
            .get("compression_method")
            .and_then(Value::as_str)
            .map(ToString::to_string),
        mtime_unix: value.get("mtime_unix").and_then(Value::as_i64),
        mode_octal: value
            .get("mode_octal")
            .and_then(Value::as_u64)
            .and_then(|v| u32::try_from(v).ok()),
        uid: value.get("uid").and_then(Value::as_u64),
        gid: value.get("gid").and_then(Value::as_u64),
        uname: value
            .get("uname")
            .and_then(Value::as_str)
            .map(ToString::to_string),
        gname: value
            .get("gname")
            .and_then(Value::as_str)
            .map(ToString::to_string),
        entry_type: value
            .get("entry_type")
            .and_then(Value::as_str)
            .map(ToString::to_string),
        linkname: value
            .get("linkname")
            .and_then(Value::as_str)
            .map(ToString::to_string),
        host_os: value
            .get("host_os")
            .and_then(Value::as_str)
            .map(ToString::to_string),
        header_offset: value.get("header_offset").and_then(Value::as_u64),
        data_offset: value.get("data_offset").and_then(Value::as_u64),
        central_header_offset: value.get("central_header_offset").and_then(Value::as_u64),
        crc32: value
            .get("crc32")
            .and_then(Value::as_u64)
            .and_then(|v| u32::try_from(v).ok()),
        encrypted: value
            .get("encrypted")
            .and_then(Value::as_bool)
            .unwrap_or(false),
    })
}

fn hex_offset(offset: u64) -> String {
    format!("0x{offset:x}")
}

fn flags_to_permissions(flags: &[String]) -> Option<String> {
    if flags.is_empty() {
        return None;
    }
    let r = flags
        .iter()
        .any(|f| f == "readable" || f == "read" || f == "alloc");
    let w = flags.iter().any(|f| f == "writable" || f == "write");
    let x = flags
        .iter()
        .any(|f| f == "executable" || f == "execinstr" || f == "code");
    Some(format!(
        "{}{}{}",
        if r { 'r' } else { '-' },
        if w { 'w' } else { '-' },
        if x { 'x' } else { '-' }
    ))
}
