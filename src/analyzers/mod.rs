//! File format analyzers.
//!
//! This module contains analyzers for various file formats:
//! - Binary formats: ELF, PE, Mach-O (dedicated analyzers)
//! - Java bytecode: .class files and JARs (dedicated analyzer)
//! - Package manifests: package.json, vsixmanifest (dedicated analyzers)
//! - Archive formats: ZIP, TAR, 7z, etc. (see archive/ submodule)
//! - Source code: All tree-sitter languages via unified analyzer (Python, JavaScript,
//!   TypeScript, Go, Rust, Ruby, PHP, Shell, Lua, Perl, PowerShell, Java, C#, C,
//!   Swift, Objective-C, Groovy, Scala, Zig, Elixir)
//! - Fallback: Generic analyzer for unsupported file types (Batch, Unknown)
//!
//! Each analyzer implements the `Analyzer` trait for consistent interface.
//!
//! ## Unified Data Flow
//!
//! All analyzers receive an `AnalysisInput` containing pre-extracted data:
//! - File bytes (read once at entry point)
//! - Pre-extracted strings (stng called once)
//! - File type (detected once)
//!
//! This eliminates redundant I/O and string extraction across the codebase.

pub(crate) mod applescript;
pub(crate) mod archive;
pub(crate) mod ast_walker;
pub(crate) mod chm;

// Unified analysis input type
mod input;
pub use input::AnalysisInput;

// `text_metrics`, `identifier_metrics`, `string_metrics`,
// `comment_metrics`, `function_metrics`, `import_metrics` retired —
// all source-text metric extraction now lives in
// `filefacts/src/formats/source/`.
pub(crate) mod symbol_extraction;
pub(crate) mod utils;

// Source-code kv-tree synthesis (imports/exports/functions).
pub(crate) mod source_kv;
// Python `.pyc` bytecode kv-tree synthesis (header + co_filename).
// B0.5 quick-win extractors: ELF .comment, sanitizer detection, etc.
pub(crate) mod binary_extractors;
// B1: Go buildinfo extractor (cross-format PE/ELF/Mach-O/raw).
pub(crate) mod go_buildinfo;
// Cross-format builder-path / builder-username recovery.
pub(crate) mod builder_paths;
// B2: PE-specific extractors (Rich header, imphash, VERSIONINFO).
pub(crate) mod pe_extractors;
// B4: Mach-O load command extractors (UUID, build_version, dylibs, rpath, source_version).
pub(crate) mod macho_extractors;
// B3.7: DWARF DW_AT_producer / DW_AT_comp_dir for unstripped ELF.
pub(crate) mod dwarf_extractors;
// B2.5: PE side-by-side assembly manifest (RT_MANIFEST resource).
pub(crate) mod pe_manifest;

// Dedicated analyzers for binary/bytecode/manifest formats
pub(crate) mod chrome_manifest;
pub(crate) mod elf;
pub(crate) mod embedded_binary_detector;
pub(crate) mod java_class;
pub(crate) mod jpeg;
pub(crate) mod macho;
pub(crate) mod macho_codesign;
pub(crate) mod office;
pub(crate) mod package_json;
pub mod pdf;
pub mod pe;
pub(crate) mod pickle;
pub(crate) mod png;
pub(crate) mod rtf;
pub(crate) mod sfx_detector;
pub(crate) mod vsix_manifest;

// Unified source analyzer (handles all tree-sitter languages)
pub(crate) mod unified;

// Fallback for languages without tree-sitter support
pub(crate) mod generic;

// Embedded code detector (analyzes code found in strings)
pub mod embedded_code_detector;

// Overlay data analyzer (self-extracting archives)
pub(crate) mod overlay;

use crate::capabilities::CapabilityMapper;
use crate::types::AnalysisReport;
use anyhow::Result;
use std::path::Path;
use std::sync::Arc;

/// Standard stng extraction options for analysis.
///
/// All analysis code paths MUST use this to ensure consistent string
/// extraction. XOR scanning is enabled so decoded strings are available for
/// trait matching (string_value conditions); stng internally gates the scan
/// on platform-signed/Go heuristics so unproductive scans are cheap.
///
/// Parallelism is left at stng's default (ambient rayon pool).  Rayon's
/// work-stealing scheduler handles oversubscription correctly for `par_iter`;
/// the only deadlock-prone primitive is `rayon::in_place_scope`, which stng
/// does not use.  An earlier revision forced `with_parallelism(false)` when
/// `rayon::current_thread_index().is_some()` — but `rayon::join(stng, yara)`
/// at `lib.rs:1134` enrolls the calling thread into the pool, so the check
/// returned `Some` even for single-file runs and regressed throughput by
/// pinning stng to a 1-thread pool.
#[must_use]
pub fn stng_analysis_opts(min_length: usize) -> stng::ExtractOptions {
    stng::ExtractOptions::new(min_length)
        .with_garbage_filter(true)
        .with_xor(None)
}

/// Variant of [`stng_analysis_opts`] for text / script inputs.
///
/// Setting `FormatHint::Text` skips stng's XOR scan — a pure waste on source
/// code, minified JS, HTML, JSON, etc. where XOR obfuscation is vanishingly
/// rare but the scanner would still walk the full file.
#[must_use]
pub fn stng_text_opts(min_length: usize) -> stng::ExtractOptions {
    stng_analysis_opts(min_length).with_format_hint(stng::FormatHint::Text)
}

/// Attach a cancellation flag to an [`stng::ExtractOptions`] if one is available.
///
/// stng honours the flag at phase boundaries (before XOR, between decoder
/// passes) so a user-interrupted scan can stop mid-file instead of finishing
/// every decoder on a multi-megabyte binary.
#[must_use]
pub fn attach_stng_cancellation(
    opts: stng::ExtractOptions,
    cancel: Option<&std::sync::Arc<std::sync::atomic::AtomicBool>>,
) -> stng::ExtractOptions {
    match cancel {
        Some(c) => opts.with_cancellation(c.clone()),
        None => opts,
    }
}

/// Heuristic: does this byte slice look like a Go binary?
///
/// Go binaries (ELF, PE, Mach-O) embed a Go-buildinfo blob that starts with
/// the 14-byte magic `\xffGo buildinf:`. It lives in a dedicated section
/// (`.go.buildinfo` / `__go_buildinfo` / `_go_buildinfo`) and is present in
/// every Go binary since Go 1.13 — it's the canonical runtime-agnostic marker.
///
/// Used by rizin routing: Go binaries get `aap` instead of `aa` to avoid
/// the pathological per-symbol crawl over Go's large runtime symbol table.
#[must_use]
pub fn looks_like_go_binary(data: &[u8]) -> bool {
    const GO_BUILDINFO_MAGIC: &[u8] = b"\xffGo buildinf:";
    // Scan only the first ~16 MB — the buildinfo section is always near the
    // start of the file in practice, and unbounded scans would defeat the
    // purpose of this cheap check.
    let horizon = data.len().min(16 * 1024 * 1024);
    memchr::memmem::find(&data[..horizon], GO_BUILDINFO_MAGIC).is_some()
}

/// Create an analyzer for the given file type.
///
/// Uses the unified source analyzer for all tree-sitter based languages.
/// Dedicated analyzers are only used for:
/// - Binary formats (ELF, PE, Mach-O) - fundamentally different analysis
/// - Package manifests (package.json, vsixmanifest) - structured data, not code
/// - Java class files (bytecode, not source)
/// - AppleScript (compiled binary format)
///
/// Returns None only for Archive (which requires special ArchiveAnalyzer config).
pub fn analyzer_for_file_type(
    file_type: &FileType,
    mapper: Option<CapabilityMapper>,
) -> Option<Box<dyn Analyzer>> {
    let mapper_or_empty = mapper.unwrap_or_else(CapabilityMapper::empty);

    match file_type {
        // Binary formats - need dedicated analyzers
        FileType::MachO => Some(Box::new(
            macho::MachOAnalyzer::new().with_capability_mapper(mapper_or_empty),
        )),
        FileType::Elf => Some(Box::new(
            elf::ElfAnalyzer::new().with_capability_mapper(mapper_or_empty),
        )),
        FileType::Pe => Some(Box::new(
            pe::PEAnalyzer::new().with_capability_mapper(mapper_or_empty),
        )),

        // Java bytecode - not source code
        FileType::JavaClass | FileType::Jar => Some(Box::new(
            java_class::JavaClassAnalyzer::new().with_capability_mapper(mapper_or_empty),
        )),

        // Compiled AppleScript - binary format
        FileType::AppleScript => Some(Box::new(
            applescript::AppleScriptAnalyzer::new().with_capability_mapper(mapper_or_empty),
        )),

        // RTF documents - parse for embedded OLE objects
        FileType::Rtf => Some(Box::new(
            rtf::RtfAnalyzer::new().with_capability_mapper(mapper_or_empty),
        )),

        // Microsoft Office documents (OLE2 and OOXML)
        FileType::OleDoc | FileType::Ooxml => Some(Box::new(
            office::OfficeAnalyzer::new().with_capability_mapper(mapper_or_empty),
        )),

        // PDF documents — lenient byte-scan extractor for action /
        // info / embedded-file / filter-chain surfacing.
        FileType::Pdf => Some(Box::new(
            pdf::PdfAnalyzer::new().with_capability_mapper(mapper_or_empty),
        )),

        // Image analyzers - steganography detection
        FileType::Jpeg => Some(Box::new(
            jpeg::JpegAnalyzer::new().with_capability_mapper(mapper_or_empty),
        )),
        FileType::Png => Some(Box::new(
            png::PngAnalyzer::new().with_capability_mapper(mapper_or_empty),
        )),

        // Pickle - deserialization attack detection
        FileType::Pickle => Some(Box::new(
            pickle::PickleAnalyzer::new().with_capability_mapper(mapper_or_empty),
        )),

        // Package manifests - structured data parsers
        FileType::VsixManifest => Some(Box::new(
            vsix_manifest::VsixManifestAnalyzer::new().with_capability_mapper(mapper_or_empty),
        )),
        FileType::PackageJson => Some(Box::new(
            package_json::PackageJsonAnalyzer::new().with_capability_mapper(mapper_or_empty),
        )),
        FileType::ChromeManifest => Some(Box::new(
            chrome_manifest::ChromeManifestAnalyzer::new().with_capability_mapper(mapper_or_empty),
        )),

        // Text-based formats without tree-sitter - use generic analyzer
        FileType::PkgInfo
        | FileType::CargoToml
        | FileType::PyProjectToml
        | FileType::PackageLockJson
        | FileType::Plist
        | FileType::SystemdService
        | FileType::DesktopEntry
        | FileType::Xml
        | FileType::Html
        | FileType::Markdown
        | FileType::Text
        | FileType::Data => Some(Box::new(
            generic::GenericAnalyzer::new(*file_type).with_capability_mapper(mapper_or_empty),
        )),

        // Archives need special handling (depth limits, nested analysis)
        ft if ft.is_archive() => None,

        // All source code languages - use unified analyzer
        _ => {
            if let Some(analyzer) = unified::UnifiedSourceAnalyzer::for_file_type(file_type) {
                Some(Box::new(analyzer.with_capability_mapper(mapper_or_empty)))
            } else {
                // Fallback to generic for types without tree-sitter (e.g. Batch).
                // Unknown file types are skipped — analysing unrecognised data
                // produces noise and wastes resources.
                if *file_type == FileType::Unknown {
                    None
                } else {
                    Some(Box::new(
                        generic::GenericAnalyzer::new(*file_type)
                            .with_capability_mapper(mapper_or_empty),
                    ))
                }
            }
        }
    }
}

/// Create an analyzer for the given file type with a shared capability mapper.
///
/// Same as `analyzer_for_file_type` but accepts an Arc to avoid cloning.
#[must_use]
pub(crate) fn analyzer_for_file_type_arc(
    file_type: &FileType,
    mapper: Option<Arc<CapabilityMapper>>,
) -> Option<Box<dyn Analyzer>> {
    let mapper_or_empty = mapper.unwrap_or_else(|| Arc::new(CapabilityMapper::empty()));

    match file_type {
        // Binary formats - need dedicated analyzers
        FileType::MachO => Some(Box::new(
            macho::MachOAnalyzer::new().with_capability_mapper_arc(mapper_or_empty),
        )),
        FileType::Elf => Some(Box::new(
            elf::ElfAnalyzer::new().with_capability_mapper_arc(mapper_or_empty),
        )),
        FileType::Pe => Some(Box::new(
            pe::PEAnalyzer::new().with_capability_mapper_arc(mapper_or_empty),
        )),

        // Java bytecode - not source code
        FileType::JavaClass | FileType::Jar => Some(Box::new(
            java_class::JavaClassAnalyzer::new().with_capability_mapper_arc(mapper_or_empty),
        )),

        // Compiled AppleScript - binary format
        FileType::AppleScript => Some(Box::new(
            applescript::AppleScriptAnalyzer::new().with_capability_mapper_arc(mapper_or_empty),
        )),

        // RTF documents - parse for embedded OLE objects
        FileType::Rtf => Some(Box::new(
            rtf::RtfAnalyzer::new().with_capability_mapper_arc(mapper_or_empty),
        )),

        // Microsoft Office documents (OLE2 and OOXML)
        FileType::OleDoc | FileType::Ooxml => Some(Box::new(
            office::OfficeAnalyzer::new().with_capability_mapper_arc(mapper_or_empty),
        )),

        // PDF documents — lenient byte-scan extractor.
        FileType::Pdf => Some(Box::new(
            pdf::PdfAnalyzer::new().with_capability_mapper_arc(mapper_or_empty),
        )),

        // Image analyzers - steganography detection
        FileType::Jpeg => Some(Box::new(
            jpeg::JpegAnalyzer::new().with_capability_mapper_arc(mapper_or_empty),
        )),
        FileType::Png => Some(Box::new(
            png::PngAnalyzer::new().with_capability_mapper_arc(mapper_or_empty),
        )),

        // Pickle - deserialization attack detection
        FileType::Pickle => Some(Box::new(
            pickle::PickleAnalyzer::new().with_capability_mapper_arc(mapper_or_empty),
        )),

        // Package manifests - structured data parsers
        FileType::VsixManifest => Some(Box::new(
            vsix_manifest::VsixManifestAnalyzer::new().with_capability_mapper_arc(mapper_or_empty),
        )),
        FileType::PackageJson => Some(Box::new(
            package_json::PackageJsonAnalyzer::new().with_capability_mapper_arc(mapper_or_empty),
        )),
        FileType::ChromeManifest => Some(Box::new(
            chrome_manifest::ChromeManifestAnalyzer::new()
                .with_capability_mapper_arc(mapper_or_empty),
        )),

        // Text-based formats without tree-sitter - use generic analyzer
        FileType::PkgInfo
        | FileType::CargoToml
        | FileType::PyProjectToml
        | FileType::PackageLockJson
        | FileType::Plist
        | FileType::SystemdService
        | FileType::DesktopEntry
        | FileType::Xml
        | FileType::Html
        | FileType::Markdown
        | FileType::Text
        | FileType::Data => Some(Box::new(
            generic::GenericAnalyzer::new(*file_type).with_capability_mapper_arc(mapper_or_empty),
        )),

        // Archives need special handling (depth limits, nested analysis)
        ft if ft.is_archive() => None,

        // All source code languages - use unified analyzer
        _ => {
            if let Some(analyzer) = unified::UnifiedSourceAnalyzer::for_file_type(file_type) {
                Some(Box::new(
                    analyzer.with_capability_mapper_arc(mapper_or_empty),
                ))
            } else {
                // Fallback to generic for types without tree-sitter (e.g. Batch).
                // Unknown file types are skipped — analysing unrecognised data
                // produces noise and wastes resources.
                if *file_type == FileType::Unknown {
                    None
                } else {
                    Some(Box::new(
                        generic::GenericAnalyzer::new(*file_type)
                            .with_capability_mapper_arc(mapper_or_empty),
                    ))
                }
            }
        }
    }
}

/// Trait for file analyzers.
///
/// Analyzers can implement either:
/// - `analyze_input()` - receives pre-extracted data (preferred, no redundant I/O)
/// - `analyze()` - reads file from path (legacy, for backwards compatibility)
///
/// The default implementations call each other, so implementors only need one.
/// New analyzers should implement `analyze_input()`.
#[allow(dead_code)] // Used by tests and archive_utils, false positive from lib/bin split
pub trait Analyzer {
    /// Analyze with pre-extracted input (preferred method).
    ///
    /// Default implementation calls legacy `analyze()` method.
    /// Analyzers should override this to use `input.data` and `input.strings`
    /// instead of reading files and extracting strings internally.
    fn analyze_input(&self, input: &AnalysisInput<'_>) -> Result<AnalysisReport> {
        // Default: delegate to legacy analyze() method
        // This allows incremental migration - analyzers can be updated one by one
        self.analyze(input.path)
    }

    /// Analyze from file path (legacy method).
    ///
    /// Default implementation reads file, extracts strings, and calls `analyze_input()`.
    /// Once all analyzers implement `analyze_input()`, this default will be the only
    /// implementation needed.
    fn analyze(&self, file_path: &Path) -> Result<AnalysisReport> {
        let data = std::fs::read(file_path)?;
        let file_type = detect_file_type(file_path)?;
        let opts = stng_analysis_opts(4);
        let strings = stng::extract_strings_with_options(&data, &opts);

        let input = AnalysisInput::with_strings(file_path, &data, &strings, file_type);
        self.analyze_input(&input)
    }

    /// Check if this analyzer can handle the given file.
    fn can_analyze(&self, file_path: &Path) -> bool;
}

/// Detect file type from path/extension only (no file access needed).
#[must_use]
#[inline]
pub(crate) fn detect_file_type_from_path(file_path: &Path) -> FileType {
    fileid::detect_path(file_path)
        .map(|d| d.file_type)
        .filter(|ft| *ft != FileType::Unknown)
        .or_else(|| known_manifest_type_from_basename(file_path))
        .unwrap_or(FileType::Unknown)
}

/// Detect file type from already-loaded data (content first, extension fallback).
#[inline]
pub(crate) fn detect_file_type_from_data(file_path: &Path, file_data: &[u8]) -> FileType {
    fileid::detect(file_path, file_data)
        .map(|d| d.file_type)
        .filter(|ft| *ft != FileType::Unknown)
        .or_else(|| known_manifest_type_from_basename(file_path))
        .unwrap_or(FileType::Unknown)
}

fn known_manifest_type_from_basename(file_path: &Path) -> Option<FileType> {
    let name = file_path.file_name()?.to_str()?.to_ascii_lowercase();
    match name.as_str() {
        "cargo.toml" => Some(FileType::CargoToml),
        "pyproject.toml" => Some(FileType::PyProjectToml),
        _ => None,
    }
}

/// Detect file type by reading the first 1KB from disk.
pub fn detect_file_type(file_path: &Path) -> Result<FileType> {
    use std::io::Read;
    let mut file = std::fs::File::open(file_path)?;
    let mut buf = [0u8; 1024];
    let bytes_read = file.read(&mut buf).unwrap_or(0);
    Ok(detect_file_type_from_data(file_path, &buf[..bytes_read]))
}

/// Returns true if cleave can analyze this file.
///
/// Delegates to `fileid::FileType::is_program()` which is the single source of
/// truth for whether a file type is supported for analysis.
#[must_use]
pub(crate) fn is_analyzable(_path: &Path, file_type: &FileType) -> bool {
    file_type.is_program()
}

/// Check if file content matches its extension's expected type.
/// Returns (expected_type, actual_type_hint) if mismatch detected.
///
/// For shebang-juke overrides (e.g. `.js` file with `#!/bin/bash`) the
/// `expected` slot holds the extension's implied type (the file's *real*
/// language) and the `actual` slot holds the type the shebang tried to
/// claim. Callers should phrase this as "shebang claims X but file is Y"
/// when `is_shebang_juke()` is true.
#[must_use]
#[allow(dead_code)]
pub fn check_extension_content_mismatch(
    file_path: &Path,
    file_data: &[u8],
) -> Option<(String, String, bool)> {
    if file_data.len() < 4 {
        return None;
    }
    let det = fileid::detect(file_path, file_data)?;
    // Only flag when the extension explicitly maps to a *different* known type.
    // Unknown/unrecognized extensions (e.g. .elf, .so, .ko, .bin) are not mismatches.
    let ext_type = det.extension_type()?;
    if det.is_shebang_juke() {
        // file_type is what the extension says; ext_type is what the shebang claimed.
        return Some((
            format!("{:?}", det.file_type),
            format!("{ext_type:?}"),
            true,
        ));
    }
    if is_linux_apk_archive(file_path, det.file_type, ext_type) {
        return None;
    }
    if is_xhtml_html_document(file_data, det.file_type, ext_type) {
        return None;
    }
    if is_appledouble_sidecar(file_path) {
        // macOS pollutes tarballs with `._<name>` sidecars carrying xattrs and
        // resource forks. The body is intentionally not the same type as the
        // extension's claim — that's the AppleDouble convention, not evasion.
        return None;
    }
    let content_desc = format!("{:?}", det.file_type);
    let ext_desc = format!("{ext_type:?}");
    Some((ext_desc, content_desc, false))
}

fn is_appledouble_sidecar(file_path: &Path) -> bool {
    file_path
        .file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name.starts_with("._"))
}

fn is_xhtml_html_document(file_data: &[u8], content_type: FileType, ext_type: FileType) -> bool {
    if content_type != FileType::Xml || ext_type != FileType::Html {
        return false;
    }
    let prefix_len = file_data.len().min(4096);
    let prefix = String::from_utf8_lossy(&file_data[..prefix_len]).to_ascii_lowercase();
    prefix.contains("<!doctype html") || prefix.contains("<html")
}

fn is_linux_apk_archive(file_path: &Path, content_type: FileType, ext_type: FileType) -> bool {
    path_ends_with_ci(file_path, ".apk")
        && ext_type == FileType::Zip
        && matches!(
            content_type,
            FileType::Tar | FileType::TarGz | FileType::TarBz2 | FileType::TarXz | FileType::TarZst
        )
}

fn path_ends_with_ci(path: &Path, suffix: &str) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| {
            name.len() >= suffix.len()
                && name[name.len() - suffix.len()..].eq_ignore_ascii_case(suffix)
        })
}

/// Re-export the canonical file type from the fileid crate.
///
/// Previously cleave maintained a parallel `FileType` enum that had to be kept
/// in sync with fileid via a tedious `From` conversion.  Now there is a single
/// source of truth: `fileid::FileType`.
pub type FileType = fileid::FileType;

/// Cleave-specific extensions on `FileType` (report labels, YARA tags).
///
/// These don't belong in the fileid crate because they encode cleave's analysis
/// policy rather than generic file identification.
pub(crate) trait FileTypeExt {
    /// Canonical file type string used in analysis reports.
    fn report_file_type(&self) -> String;

    /// YARA rule filetypes relevant for this file type.
    fn yara_filetypes(&self) -> Vec<&'static str>;
}

impl FileTypeExt for FileType {
    fn report_file_type(&self) -> String {
        match self {
            FileType::SystemdService => "systemd".to_string(),
            FileType::DesktopEntry => "desktop-entry".to_string(),
            FileType::Xml => "xml".to_string(),
            FileType::Tar => "tar".to_string(),
            FileType::TarGz => "tar.gz".to_string(),
            FileType::TarBz2 => "tar.bz2".to_string(),
            FileType::TarXz => "tar.xz".to_string(),
            FileType::TarZst => "tar.zst".to_string(),
            FileType::SevenZ => "7z".to_string(),
            FileType::PythonBytecode => "python-bytecode".to_string(),
            FileType::PackageLockJson => "package-lock.json".to_string(),
            _ => format!("{:?}", self).to_lowercase(),
        }
    }

    fn yara_filetypes(&self) -> Vec<&'static str> {
        match self {
            FileType::MachO => vec!["macho", "dylib", "kext"],
            FileType::Elf => vec!["elf", "so", "ko"],
            FileType::Pe => vec!["pe", "exe", "dll", "bat", "ps1"],
            FileType::Shell => {
                vec!["sh", "bash", "zsh", "application/x-sh", "application/x-zsh"]
            }
            FileType::Batch => vec!["bat", "cmd", "batch"],
            FileType::Vbs => vec!["vbs", "vbe", "wsf", "wsc", "vba", "vbscript"],
            FileType::Python => vec!["py"],
            FileType::JavaScript => vec!["js", "mjs", "cjs", "jsx", "ts"],
            FileType::TypeScript => vec!["ts", "tsx", "mts", "cts", "js"],
            FileType::Go => vec!["go"],
            FileType::Rust => vec!["rs"],
            FileType::Java => vec!["java"],
            FileType::JavaClass => vec!["class", "java"],
            FileType::PythonBytecode => vec!["pyc", "python-bytecode"],
            FileType::Jar => vec!["jar", "war", "ear", "class", "java"],
            FileType::Ruby => vec!["rb"],
            FileType::Php => vec!["php"],
            FileType::Perl => vec!["pl", "pm"],
            FileType::Lua => vec!["lua"],
            FileType::CSharp => vec!["cs", "csharp"],
            FileType::PowerShell => vec!["ps1", "psm1", "psd1"],
            FileType::Swift => vec!["swift"],
            FileType::ObjectiveC => vec!["m", "mm", "objc"],
            FileType::Groovy => vec!["groovy", "gradle"],
            FileType::Scala => vec!["scala", "sc"],
            FileType::Kotlin => vec!["kt", "kts"],
            FileType::Zig => vec!["zig"],
            FileType::Elixir => vec!["ex", "exs"],
            FileType::C => vec!["c", "h", "hh"],
            FileType::PackageJson => vec!["json", "package.json", "npm"],
            FileType::PackageLockJson => vec!["json", "package-lock.json", "npm"],
            FileType::PkgInfo => vec!["pkg-info", "metadata", "dist-info"],
            FileType::VsixManifest => vec!["xml", "vsix", "vscode"],
            FileType::ChromeManifest => vec!["json", "manifest.json", "chrome", "extension"],
            FileType::CargoToml => vec!["toml", "cargo.toml", "rust"],
            FileType::PyProjectToml => vec!["toml", "pyproject.toml", "python"],
            FileType::ComposerJson => vec!["json", "composer.json", "php"],
            FileType::GithubActions => vec!["yaml", "yml", "github-actions"],
            FileType::SystemdService => vec!["service", "systemd", "unit"],
            FileType::DesktopEntry => vec!["desktop", "desktop-entry", "freedesktop", "xdg"],
            FileType::Xml => vec!["xml", "csproj", "xaml", "svg", "msbuild"],
            FileType::Zip => vec!["zip", "archive"],
            FileType::Tar
            | FileType::TarGz
            | FileType::TarBz2
            | FileType::TarXz
            | FileType::TarZst => vec!["tar", "archive"],
            FileType::Gz
            | FileType::Bz2
            | FileType::Xz
            | FileType::Zst
            | FileType::Pkg
            | FileType::Cab => {
                vec!["archive"]
            }
            FileType::SevenZ => vec!["7z", "archive"],
            FileType::Rar => vec!["rar", "archive"],
            FileType::Deb => vec!["deb", "archive"],
            FileType::Rpm => vec!["rpm", "archive"],
            FileType::Crx => vec!["crx", "archive"],
            FileType::AppleScript => vec!["scpt", "applescript"],
            FileType::Plist => vec!["plist", "xml", "apple"],
            FileType::Rtf => vec!["rtf", "doc"],
            FileType::OleDoc => vec!["doc", "xls", "ppt", "ole", "msg"],
            FileType::Ooxml => vec!["docx", "xlsx", "pptx", "doc", "xls", "ole"],
            FileType::Lnk => vec!["lnk", "shortcut"],
            FileType::Jpeg => vec!["jpeg", "jpg"],
            FileType::Png => vec!["png"],
            FileType::Pickle => vec!["pkl", "pickle", "joblib"],
            FileType::Pdf => vec!["pdf"],
            FileType::Html => vec!["html", "htm"],
            FileType::Markdown => vec!["md", "markdown"],
            FileType::Makefile => vec!["makefile", "make", "mk"],
            FileType::Text => vec!["txt", "text"],
            FileType::Data => vec!["dat", "bin", "payload", "raw"],
            _ => vec![],
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn bridge_path_detection() {
        assert_eq!(
            detect_file_type_from_path(Path::new("script.py")),
            FileType::Python
        );
        assert_eq!(
            detect_file_type_from_path(Path::new("app.js")),
            FileType::JavaScript
        );
        assert_eq!(
            detect_file_type_from_path(Path::new("Component.jsx")),
            FileType::JavaScript
        );
        assert_eq!(
            detect_file_type_from_path(Path::new("data.xyz")),
            FileType::Unknown
        );
        assert_eq!(
            detect_file_type_from_path(Path::new("page.html")),
            FileType::Html
        );
        assert_eq!(
            detect_file_type_from_path(Path::new("evil.service")),
            FileType::SystemdService
        );
        assert_eq!(
            detect_file_type_from_path(Path::new("README.md")),
            FileType::Markdown
        );
        assert_eq!(
            detect_file_type_from_path(Path::new("notes.txt")),
            FileType::Text
        );
        assert_eq!(
            detect_file_type_from_path(Path::new("Makefile")),
            FileType::Makefile
        );
        assert_eq!(
            detect_file_type_from_path(Path::new("rules.mk")),
            FileType::Makefile
        );
    }

    #[test]
    fn bridge_magic_detection() {
        let elf = b"\x7fELF\x02\x01\x01\x00";
        assert_eq!(
            detect_file_type_from_data(Path::new("bin"), elf),
            FileType::Elf
        );

        let pe = [b'M', b'Z', 0x90, 0x00, 0x03, 0x00, 0x00, 0x00];
        assert_eq!(
            detect_file_type_from_data(Path::new("a.exe"), &pe),
            FileType::Pe
        );

        let pyc = [0x55, 0x0d, 0x0d, 0x0a, 0x00, 0x00, 0x00, 0x00];
        assert_eq!(
            detect_file_type_from_data(Path::new("c/s.dat"), &pyc),
            FileType::PythonBytecode
        );
    }

    #[test]
    fn bridge_shebang() {
        assert_eq!(
            detect_file_type_from_data(Path::new("s"), b"#!/bin/bash\necho hi\n"),
            FileType::Shell,
        );
    }

    #[test]
    fn bridge_extension_fallback() {
        assert_eq!(
            detect_file_type_from_data(Path::new("app.js"), b"x = 1\n"),
            FileType::JavaScript
        );
    }

    #[test]
    fn bridge_unknown() {
        // Unknown extension with no magic match falls through to Unknown.
        assert_eq!(
            detect_file_type_from_data(Path::new("d.xyz"), &[0, 0, 0, 0]),
            FileType::Unknown
        );
    }

    #[test]
    fn bridge_data_extension() {
        // Opaque binary extensions (.bin/.dat/.payload/.raw) map to Data so
        // the generic analyzer runs string extraction and data-file rules.
        assert_eq!(
            detect_file_type_from_data(Path::new("d.bin"), &[0, 0, 0, 0]),
            FileType::Data
        );
        assert_eq!(
            detect_file_type_from_data(Path::new("Canon.dat"), &[0, 0, 0, 0]),
            FileType::Data
        );
    }

    #[test]
    fn bridge_html_requires_content() {
        assert_eq!(
            detect_file_type_from_data(Path::new("p.html"), b"<html><body>hi</body></html>"),
            FileType::Html
        );
        assert_eq!(
            detect_file_type_from_data(Path::new("p.html"), b"just text"),
            FileType::Unknown
        );
    }

    #[test]
    fn bridge_yaml_skip() {
        assert_eq!(
            detect_file_type_from_data(Path::new("c.yaml"), b"name: test\n"),
            FileType::Unknown
        );
    }

    #[test]
    fn bridge_ooxml() {
        let mut data = b"PK\x03\x04".to_vec();
        data.resize(12, 0);
        assert_eq!(
            detect_file_type_from_data(Path::new("s.pptx"), &data),
            FileType::Ooxml
        );
    }

    #[test]
    fn bridge_heuristic_python() {
        let data = b"import os\nimport sys\ndef main():\n    print(\x27hello\x27)\n";
        assert_eq!(
            detect_file_type_from_data(Path::new("script"), data),
            FileType::Python
        );
    }

    #[test]
    fn bridge_detect_from_disk() {
        use std::io::Write;
        let mut f = tempfile::NamedTempFile::with_suffix(".py").unwrap();
        f.write_all(b"import os\n").unwrap();
        assert_eq!(detect_file_type(f.path()).unwrap(), FileType::Python);
    }

    #[test]
    fn bridge_known_toml_manifests_by_basename() {
        assert_eq!(
            detect_file_type_from_path(Path::new("Cargo.toml")),
            FileType::CargoToml
        );
        assert_eq!(
            detect_file_type_from_data(Path::new("nested/Cargo.toml"), b"[package]\nname='x'\n"),
            FileType::CargoToml
        );
        assert_eq!(
            detect_file_type_from_data(Path::new("pyproject.toml"), b"[project]\nname='x'\n"),
            FileType::PyProjectToml
        );
        assert_eq!(
            detect_file_type_from_data(Path::new("config.toml"), b"[package]\nname='x'\n"),
            FileType::Unknown
        );
    }

    #[test]
    fn bridge_mismatch() {
        let elf = b"\x7fELF\x02\x01\x01\x00";
        assert!(check_extension_content_mismatch(Path::new("image.jpg"), elf).is_some());
        assert!(check_extension_content_mismatch(Path::new("binary"), elf).is_none());
    }

    #[test]
    fn bridge_msi_oledoc_is_not_mismatch() {
        let oledoc = b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1";
        assert!(check_extension_content_mismatch(Path::new("setup.msi"), oledoc).is_none());
    }

    #[test]
    fn bridge_linux_apk_targz_is_not_mismatch() {
        let gzip = [0x1f, 0x8b, 0x08, 0x00];
        assert!(check_extension_content_mismatch(Path::new("package.apk"), &gzip).is_none());
    }

    #[test]
    fn bridge_xhtml_html_is_not_mismatch() {
        let xhtml = br#"<?xml version="1.0" encoding="ascii"?>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN">
<html xmlns="http://www.w3.org/1999/xhtml"></html>"#;
        assert!(check_extension_content_mismatch(Path::new("api.html"), xhtml).is_none());
    }

    #[test]
    fn bridge_android_apk_zip_is_not_mismatch() {
        let zip = b"PK\x03\x04android package";
        assert!(check_extension_content_mismatch(Path::new("package.apk"), zip).is_none());
    }

    #[test]
    fn bridge_from_roundtrip() {
        assert_eq!(FileType::from(fileid::FileType::MachO), FileType::MachO);
        assert_eq!(
            FileType::from(fileid::FileType::Markdown),
            FileType::Markdown
        );
    }

    #[test]
    fn bridge_report_file_type_uses_systemd_alias() {
        assert_eq!(FileType::SystemdService.report_file_type(), "systemd");
        assert_eq!(
            FileType::PythonBytecode.report_file_type(),
            "python-bytecode"
        );
        assert_eq!(FileType::Elf.report_file_type(), "elf");
    }

    #[test]
    fn appledouble_sidecar_predicate_matches_dot_underscore_prefix() {
        // Basename starts with `._` → macOS AppleDouble sidecar by convention.
        assert!(is_appledouble_sidecar(Path::new("._index.php")));
        assert!(is_appledouble_sidecar(Path::new("foo/bar/._index.php")));
        assert!(is_appledouble_sidecar(Path::new(
            "/tmp/extracted/wundii-flowcrafter/._FlowConsole.php"
        )));
        // Plain hidden files (`.foo`), or `._` mid-name, are NOT sidecars.
        assert!(!is_appledouble_sidecar(Path::new(".env")));
        assert!(!is_appledouble_sidecar(Path::new("real._not_sidecar.php")));
        assert!(!is_appledouble_sidecar(Path::new("index.php")));
    }

    #[test]
    fn check_extension_mismatch_suppresses_appledouble_sidecar() {
        // `._foo.php` extension claims PHP, content is AppleDouble magic →
        // fileid returns Unknown. Pre-fix this fired the
        // `metadata/file-extension-mismatch` trait at suspicious for every
        // `._` file in a macOS-built tarball, lighting up benign Composer
        // archives. The is_appledouble_sidecar guard must short-circuit.
        let ad = b"\x00\x05\x16\x07\x00\x02\x00\x00Mac OS X        \x00\x00\x00\x00";
        assert!(
            check_extension_content_mismatch(Path::new("wundii/._index.php"), ad).is_none(),
            "AppleDouble sidecars must not trigger the extension-mismatch trait — \
             the mismatch is by macOS convention, not evasion"
        );
        // Sanity: a real PHP file with PE magic still fires the trait so this
        // suppression isn't accidentally broader than intended.
        let pe = b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xff\xff\x00\x00";
        assert!(
            check_extension_content_mismatch(Path::new("legit.php"), pe).is_some(),
            "non-sidecar files with extension/content mismatch must still flag"
        );
    }
}
