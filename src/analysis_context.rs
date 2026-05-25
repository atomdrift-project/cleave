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
        self.parsed
            .archive_members()
            .iter()
            .map(archive_entry_from_filefacts_member)
            .collect()
    }

    /// Project filefacts Import symbols into cleave's import representation.
    #[must_use]
    pub fn imports_from_filefacts(&self) -> Vec<Import> {
        self.parsed
            .symbols()
            .iter_kind(filefacts::SymbolKind::Import)
            .filter_map(|s| match s {
                filefacts::Symbol::Import {
                    name,
                    library,
                    source,
                    offset,
                    ..
                } => Some(match offset {
                    Some(off) => Import::with_offset(name, library.clone(), source.clone(), *off),
                    None => Import::new(name, library.clone(), source.clone()),
                }),
                _ => None,
            })
            .collect()
    }

    /// Project filefacts Export symbols into cleave's export representation.
    #[must_use]
    pub fn exports_from_filefacts(&self) -> Vec<Export> {
        self.parsed
            .symbols()
            .iter_kind(filefacts::SymbolKind::Export)
            .filter_map(|s| match s {
                filefacts::Symbol::Export {
                    name,
                    source,
                    offset,
                    forward_to,
                    ..
                } => {
                    let mut out = Export::new(name, offset.map(hex_offset), source.clone());
                    out.forward_to = forward_to.clone();
                    Some(out)
                }
                _ => None,
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

    /// Project filefacts Function symbols into cleave's function
    /// representation.
    #[must_use]
    pub fn functions_from_filefacts(&self) -> Vec<Function> {
        self.parsed
            .symbols()
            .iter_kind(filefacts::SymbolKind::Function)
            .filter_map(project_filefacts_function)
            .collect()
    }
}

/// Project one filefacts Function symbol into cleave's public function
/// shape. Returns None for non-Function variants (defensive — callers
/// should already pre-filter).
#[must_use]
pub fn project_filefacts_function(sym: &filefacts::Symbol) -> Option<Function> {
    let filefacts::Symbol::Function {
        name,
        offset,
        complexity,
        callees,
        source,
        ..
    } = sym
    else {
        return None;
    };
    Some(Function {
        name: name.clone(),
        offset: offset.map(hex_offset),
        size: None,
        complexity: *complexity,
        calls: callees.clone(),
        source: source.clone(),
        control_flow: None,
        register_usage: None,
        constants: Vec::new(),
        signature: None,
        nesting: None,
        call_patterns: None,
    })
}

fn archive_entry_from_filefacts_member(member: &filefacts::ArchiveMember) -> ArchiveEntry {
    ArchiveEntry {
        path: member.path.clone(),
        file_type: "unknown".to_string(),
        sha256: String::new(),
        size_bytes: member.size_bytes,
        compressed_size: member.compressed_size,
        compression_method: member.compression_method.clone(),
        mtime_unix: member.mtime_unix,
        mode_octal: member.mode_octal,
        uid: member.uid,
        gid: member.gid,
        uname: member.uname.clone(),
        gname: member.gname.clone(),
        entry_type: member.entry_type.clone(),
        linkname: member.linkname.clone(),
        host_os: member.host_os.clone(),
        header_offset: member.header_offset,
        data_offset: member.data_offset,
        central_header_offset: member.central_header_offset,
        crc32: member.crc32,
        encrypted: member.encrypted,
    }
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
