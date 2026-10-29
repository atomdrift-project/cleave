//! Single integration point with `filefacts`.
//!
//! `AnalysisContext` opens bytes once through `filefacts::OpenOptions`
//! and lends the resulting `ParsedFile` to downstream consumers. Anything
//! that needs filefacts-derived identity, values, metrics, strings, sections,
//! symbols, archive indexes, or AST projections should pass this context
//! instead of reopening or reparsing the same byte slice.

use serde_json::Value;
use std::path::Path;

use crate::types::{ArchiveEntry, Export, Function, Import, Section};

/// Isolate large native fact extraction from unrelated archive/AST jobs.
/// stng's nested joins otherwise steal those jobs before starting Rizin,
/// stretching a short string pass across most of a directory scan.
/// Opt-in while measuring throughput and detection parity.
fn native_facts_threads() -> Option<usize> {
    static THREADS: std::sync::OnceLock<Option<usize>> = std::sync::OnceLock::new();
    *THREADS.get_or_init(|| {
        std::env::var("CLEAVE_NATIVE_FACTS_THREADS")
            .ok()?
            .parse::<usize>()
            .ok()
            .filter(|&n| n > 0)
    })
}

fn native_facts_pool() -> Option<&'static rayon::ThreadPool> {
    static POOL: std::sync::OnceLock<Option<rayon::ThreadPool>> = std::sync::OnceLock::new();
    POOL.get_or_init(|| {
        let threads = native_facts_threads()?;
        match rayon::ThreadPoolBuilder::new()
            .num_threads(threads)
            .thread_name(|i| format!("native-facts-{i}"))
            .start_handler(|_| crate::leaf_affinity::apply())
            .build()
        {
            Ok(pool) => Some(pool),
            Err(error) => {
                tracing::warn!(%error, "native fact pool unavailable; using scan pool");
                None
            }
        }
    })
    .as_ref()
}

fn run_native_facts(threads: usize, f: impl FnOnce() + Send) {
    if crate::rayon_nest::on_isolated_leaf_pool() {
        f();
    } else if crate::env::flag("CLEAVE_NATIVE_FACTS_ISOLATED") {
        // A shared native pool can still nest one binary's long Rizin call
        // inside another's string pass. Keep each pool exclusive, and wait
        // off Rayon so the scan caller cannot bury its return under a bundle.
        std::thread::scope(|scope| {
            let result = scope
                .spawn(move || {
                    match rayon::ThreadPoolBuilder::new()
                        .num_threads(threads)
                        .thread_name(|i| format!("native-file-{i}"))
                        .start_handler(|_| crate::leaf_affinity::apply())
                        .build()
                    {
                        Ok(pool) => pool.install(f),
                        Err(error) => {
                            tracing::warn!(%error, "native file pool unavailable; using scan pool");
                            f();
                        }
                    }
                })
                .join();
            if let Err(panic) = result {
                std::panic::resume_unwind(panic);
            }
        });
    } else if let Some(pool) = native_facts_pool() {
        pool.install(f);
    } else {
        f();
    }
}

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
    /// Open `content` through filefacts under `options`, identifying it from
    /// `path` and the bytes unless `options` forces a type or a `FileId`.
    /// Every filefacts setting (rizin, disk cache, cancellation) belongs to
    /// the parse it is given to, so engines with different settings can parse
    /// side by side; see [`crate::Engine`] for the options an analysis uses.
    #[must_use]
    pub fn open_with(
        options: filefacts::OpenOptions<'a>,
        path: &'a Path,
        content: &'a [u8],
    ) -> Self {
        let timing = content.len() >= 16 * 1024 * 1024;
        let started = std::time::Instant::now();
        if timing {
            tracing::info!(target: "cleave::native_timing", path = %path.display(), bytes = content.len(), "context open begin");
        }
        let parsed = options.path(path).open(content);
        if timing {
            tracing::info!(target: "cleave::native_timing", path = %path.display(), kind = ?parsed.fileid().file_type(), ms = started.elapsed().as_millis() as u64, "context identified");
        }
        if content.len() >= 16 * 1024 * 1024
            && matches!(
                parsed.fileid().file_type(),
                filefacts::FileType::Pe | filefacts::FileType::Elf | filefacts::FileType::MachO
            )
            && let Some(threads) = native_facts_threads()
        {
            // Materialize the shared extraction once, before any consumer on
            // the scan pool can initiate its nested string-extraction joins.
            run_native_facts(threads, || {
                tracing::info!(target: "cleave::native_timing", path = %path.display(), ms = started.elapsed().as_millis() as u64, "native extraction begin");
                let _ = parsed.text();
                tracing::info!(target: "cleave::native_timing", path = %path.display(), ms = started.elapsed().as_millis() as u64, "native extraction complete");
            });
            tracing::info!(target: "cleave::native_timing", path = %path.display(), ms = started.elapsed().as_millis() as u64, "native extraction returned to scan");
        }
        Self {
            path,
            content,
            parsed,
        }
    }

    /// Open with filefacts' defaults: rizin on, the disk cache as
    /// `FILEFACTS_CACHE` says, no cancellation.
    #[must_use]
    pub fn open(path: &'a Path, content: &'a [u8]) -> Self {
        Self::open_with(filefacts::OpenOptions::new(), path, content)
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
        let mut identity = self.parsed.identity().clone();
        if identity.title.is_none()
            && let Some(description) = self
                .parsed
                .values()
                .get("pe.version.description")
                .and_then(Value::as_str)
                .filter(|description| !description.trim().is_empty())
        {
            identity.title = Some(filefacts::Claim::claimed(
                description,
                "pe.version.description",
            ));
        }
        (!identity.is_empty()).then_some(identity)
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
                flags: section_flag_names(&s.flags),
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
    if !owner.contains('/') || owner.contains('\\') || owner.contains(' ') {
        return;
    }
    let qualified = format!("{owner}.{}", import.symbol);
    let offset = import.offset.as_deref().and_then(|value| {
        if let Some(hex) = value
            .strip_prefix("0x")
            .or_else(|| value.strip_prefix("0X"))
        {
            u64::from_str_radix(hex, 16).ok()
        } else {
            value.parse().ok()
        }
    });
    let mut synthetic = match offset {
        Some(off) => Import::with_offset(qualified, import.library.clone(), off),
        None => Import::new(qualified, import.library.clone()),
    };
    synthetic.alias = import.alias.clone();
    imports.push(synthetic);
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
    let compression = &member.compression;
    let ownership = &member.ownership;
    ArchiveEntry {
        path: member.path.clone(),
        file_type: "unknown".to_string(),
        sha256: String::new(),
        size_bytes: member.size_bytes,
        compressed_size: compression.compressed_size,
        compression_method: compression.method.clone(),
        mtime_unix: member.mtime_unix,
        mode_octal: ownership.mode_octal,
        uid: ownership.uid,
        gid: ownership.gid,
        uname: ownership.uname.clone(),
        gname: ownership.gname.clone(),
        entry_type: Some(member.entry_type.as_str().to_owned()),
        linkname: member.linkname.clone(),
        host_os: member.host_os.clone(),
        header_offset: member.offsets.header,
        data_offset: member.offsets.data,
        central_header_offset: member.offsets.central_header,
        crc32: member.crc32,
        encrypted: member.encrypted,
        ..ArchiveEntry::default()
    }
}

fn hex_offset(offset: u64) -> String {
    format!("0x{offset:x}")
}

/// filefacts' section flags as cleave reports them: their serialized names.
pub(crate) fn section_flag_names(flags: &[filefacts::SectionFlag]) -> Vec<String> {
    flags.iter().map(|f| f.as_str().to_owned()).collect()
}

fn flags_to_permissions(flags: &[filefacts::SectionFlag]) -> Option<String> {
    use filefacts::SectionFlag;
    if flags.is_empty() {
        return None;
    }
    let r = flags
        .iter()
        .any(|f| matches!(f, SectionFlag::Readable | SectionFlag::Alloc));
    let w = flags.contains(&SectionFlag::Writable);
    // `code` describes section contents (PE IMAGE_SCN_CNT_CODE), not loader
    // protection. Only explicit execute flags contribute the x permission.
    let x = flags.contains(&SectionFlag::Executable);
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
    fn pe_code_flag_does_not_imply_execute_permission() {
        use filefacts::SectionFlag::{Code, Readable, Writable};
        assert_eq!(
            flags_to_permissions(&[Code, Readable, Writable]).as_deref(),
            Some("rw-")
        );
    }

    #[test]
    fn explicit_execute_flags_project_to_execute_permission() {
        use filefacts::SectionFlag::{Alloc, Executable, Readable};
        assert_eq!(
            flags_to_permissions(&[Readable, Executable]).as_deref(),
            Some("r-x")
        );
        assert_eq!(
            flags_to_permissions(&[Alloc, Executable]).as_deref(),
            Some("r-x")
        );
    }

    #[test]
    fn imports_include_owner_qualified_jvm_method_refs() {
        let path = Path::new(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/java/Suspicious.class"
        ));
        let bytes = std::fs::read(path).expect("read Java class fixture");
        let ctx = AnalysisContext::open(path, &bytes);

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

    #[test]
    fn pe_description_projects_to_identity_title() {
        let path = Path::new(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/dotnet_utf16_clipboard.dll"
        ));
        let bytes = std::fs::read(path).expect("read PE fixture");
        let ctx = AnalysisContext::open(path, &bytes);
        let identity = ctx.identity().expect("PE identity");
        let title = identity.title.expect("PE description title");

        assert_eq!(title.value, "DotCarbon.Plugins.Clipboard");
        assert_eq!(title.source, "pe.version.description");
        assert!(!title.verified);
    }
}
