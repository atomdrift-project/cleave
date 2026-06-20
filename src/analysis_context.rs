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

    /// Open `content` forcing a caller-known `file_type`, bypassing
    /// detection. For embedded code whose language is already known but
    /// whose virtual path / extracted body carries no detectable shebang,
    /// extension, or magic (e.g. the inner source of `python3 -c "<code>"`).
    /// Without this, filefacts re-detects the type from the virtual path,
    /// lands on `Unknown`, and produces no source AST — so the payload's
    /// capabilities never surface.
    pub fn open_as(
        path: &'a Path,
        content: &'a [u8],
        file_type: filefacts::FileType,
    ) -> Result<Self, filefacts::Error> {
        let parsed = filefacts::open_as(path, content, file_type)?;
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

    /// The shared extracted-string rows from filefacts' `text()` view — the
    /// single string-extraction authority. Returns an `Arc` clone (a refcount
    /// bump, not a copy of the string data) of the allocation stng owns and
    /// filefacts holds, so analyzers thread it through `AnalysisInput` and
    /// convert to `StringInfo` without duplicating the bytes. Rows are in
    /// stng's offset-sorted order.
    #[must_use]
    pub fn text_rows(&self) -> std::sync::Arc<[stng::ExtractedString]> {
        self.parsed.text().rows().clone()
    }

    /// Normalized identity claims filefacts derived, when the file
    /// asserts any identity or carries a signature. Returns `None` for
    /// the empty case so reports don't carry a bare `unsigned` record on
    /// every file.
    #[must_use]
    pub fn identity(&self) -> Option<filefacts::Identity> {
        let identity = self.parsed.identity();
        (!identity.is_empty()).then(|| identity.clone())
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
        let mut imports = Vec::new();
        for sym in self
            .parsed
            .symbols()
            .iter_kind(filefacts::SymbolKind::Import)
        {
            let Some(import) = (match sym {
                filefacts::Symbol::Import {
                    name,
                    library,
                    offset,
                    alias,
                    ..
                } => Some(project_filefacts_import(
                    name,
                    library,
                    *offset,
                    alias.clone(),
                )),
                _ => None,
            }) else {
                continue;
            };
            extend_with_owner_qualified_import(&mut imports, &import);
            imports.push(import);
        }
        imports
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
                    offset,
                    forward_to,
                    ..
                } => {
                    let mut out = Export::new(name, offset.map(hex_offset));
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

fn project_filefacts_import(
    name: &str,
    library: &Option<String>,
    offset: Option<u64>,
    alias: Option<String>,
) -> Import {
    match offset {
        Some(off) => Import::with_offset(name, library.clone(), off),
        None => Import::new(name, library.clone()),
    }
    .with_alias(alias)
}

fn extend_with_owner_qualified_import(imports: &mut Vec<Import>, import: &Import) {
    let Some(owner) = import.library.as_deref() else {
        return;
    };
    if !is_jvm_internal_owner(owner) {
        return;
    }
    let qualified = format!("{owner}.{}", import.symbol);
    let mut synthetic = match import.offset.as_deref().and_then(parse_hex_offset) {
        Some(off) => Import::with_offset(qualified, import.library.clone(), off),
        None => Import::new(qualified, import.library.clone()),
    };
    synthetic.alias = import.alias.clone();
    imports.push(synthetic);
}

fn is_jvm_internal_owner(owner: &str) -> bool {
    owner.contains('/') && !owner.contains('\\') && !owner.contains(' ')
}

fn parse_hex_offset(s: &str) -> Option<u64> {
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).ok()
    } else {
        s.parse().ok()
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
        control_flow: None,
        register_usage: None,
        constants: Vec::new(),
        signature: None,
        nesting: None,
        call_patterns: None,
    })
}

fn archive_entry_from_filefacts_member(member: &filefacts::ArchiveMember) -> ArchiveEntry {
    let compression = member.compression.as_ref();
    let ownership = member.ownership.as_ref();
    ArchiveEntry {
        path: member.path.clone(),
        file_type: "unknown".to_string(),
        sha256: String::new(),
        size_bytes: member.size_bytes,
        compressed_size: compression.and_then(|c| c.compressed_size),
        compression_method: compression.and_then(|c| c.method.clone()),
        mtime_unix: member.mtime_unix,
        mode_octal: ownership.and_then(|o| o.mode_octal),
        uid: ownership.and_then(|o| o.uid),
        gid: ownership.and_then(|o| o.gid),
        uname: ownership.and_then(|o| o.uname.clone()),
        gname: ownership.and_then(|o| o.gname.clone()),
        entry_type: member.entry_type.clone(),
        linkname: member.linkname.clone(),
        host_os: member.host_os.clone(),
        header_offset: member.offsets.header,
        data_offset: member.offsets.data,
        central_header_offset: member.offsets.central_header,
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

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::panic)]

    use super::*;

    #[test]
    fn imports_include_owner_qualified_jvm_method_refs() {
        let path = Path::new(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/java/Suspicious.class"
        ));
        let bytes = std::fs::read(path).expect("read Java class fixture");
        let ctx = AnalysisContext::open(path, &bytes).expect("parse Java class fixture");

        let imports = ctx.imports_from_filefacts();
        let symbols: std::collections::BTreeSet<&str> =
            imports.iter().map(|i| i.symbol.as_str()).collect();

        assert!(
            symbols.contains("exec"),
            "plain method import should remain"
        );
        assert!(
            symbols.contains("java/lang/Runtime.exec"),
            "Runtime.exec should be owner-qualified for bytecode traits"
        );
        assert!(
            symbols.contains("java/lang/ProcessBuilder.start"),
            "ProcessBuilder.start should be owner-qualified for bytecode traits"
        );
        assert!(
            symbols.contains("javax/crypto/Cipher.getInstance"),
            "JVM-style owners outside java/ should also qualify"
        );
    }

    #[test]
    fn owner_qualification_is_limited_to_jvm_internal_names() {
        let mut imports = Vec::new();
        let libc = Import::new("printf", Some("libc.so.6".to_string()));

        extend_with_owner_qualified_import(&mut imports, &libc);

        assert!(
            imports.is_empty(),
            "native shared-library imports should not gain synthetic dotted symbols"
        );
    }
}
