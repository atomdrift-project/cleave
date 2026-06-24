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
//! - Pre-extracted strings (filefacts `text()`, the single extraction authority)
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

// Dedicated analyzers for binary/bytecode/manifest formats
pub(crate) mod chrome_manifest;
pub(crate) mod elf;
pub(crate) mod embedded_binary_detector;
pub(crate) mod java_class;
pub(crate) mod jpeg;
pub(crate) mod macho;
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

// Unified sub-file dispatcher — one place that decides how fresh
// bytes (decoded payload, archive member, format-embedded blob)
// route to the right analyzer.
pub mod subfile;

// Overlay data analyzer (self-extracting archives)
pub(crate) mod overlay;

use crate::capabilities::CapabilityMapper;
use crate::types::AnalysisReport;
use anyhow::Result;
use std::path::Path;
use std::sync::Arc;

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
        | FileType::GoMod
        | FileType::PyProjectToml
        | FileType::PackageLockJson
        | FileType::Json
        | FileType::Plist
        | FileType::SystemdService
        | FileType::DesktopEntry
        | FileType::Xml
        | FileType::Svg
        | FileType::Html
        | FileType::Markdown
        | FileType::Text
        | FileType::Dockerfile
        | FileType::Wasm
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
        | FileType::GoMod
        | FileType::PyProjectToml
        | FileType::PackageLockJson
        | FileType::Json
        | FileType::Plist
        | FileType::SystemdService
        | FileType::DesktopEntry
        | FileType::Xml
        | FileType::Svg
        | FileType::Html
        | FileType::Markdown
        | FileType::Text
        | FileType::Dockerfile
        | FileType::Wasm
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
        // Strings come from filefacts' `text()` view — the single
        // string-extraction authority. Thread the context into the input so
        // an analyzer that reads it reuses this parse.
        let ctx = crate::analysis_context::AnalysisContext::open(file_path, &data).ok();
        let strings: std::sync::Arc<[stng::ExtractedString]> = ctx
            .as_ref()
            .map(crate::analysis_context::AnalysisContext::text_rows)
            .unwrap_or_default();
        let mut input = AnalysisInput::with_strings(file_path, &data, &strings, file_type);
        if let Some(ctx) = ctx {
            input = input.with_parsed_ctx(ctx);
        }
        self.analyze_input(&input)
    }

    /// Check if this analyzer can handle the given file.
    fn can_analyze(&self, file_path: &Path) -> bool;
}

/// Detect file type from path/extension only (no file access needed).
#[must_use]
#[inline]
pub(crate) fn detect_file_type_from_path(file_path: &Path) -> FileType {
    if is_dotenv_name(file_path) {
        return FileType::Text;
    }
    if is_arch_package_metadata_name(file_path) {
        return FileType::Text;
    }
    if is_routeros_script_name(file_path) {
        return FileType::Text;
    }

    filefacts::fileid::detect_path(file_path)
        .map(|d| d.file_type)
        .filter(|ft| *ft != FileType::Unknown)
        .or_else(|| known_manifest_type_from_basename(file_path))
        .unwrap_or(FileType::Unknown)
}

/// Detect file type from already-loaded data (content first, extension fallback).
#[inline]
pub(crate) fn detect_file_type_from_data(file_path: &Path, file_data: &[u8]) -> FileType {
    if is_dotenv_name(file_path) {
        return FileType::Text;
    }
    if is_arch_package_metadata_name(file_path) {
        return FileType::Text;
    }
    if is_routeros_script_name(file_path) {
        return FileType::Text;
    }

    filefacts::fileid::detect(file_path, file_data)
        .map(|d| d.file_type)
        .filter(|ft| *ft != FileType::Pe || looks_like_pe_image(file_data))
        .filter(|ft| *ft != FileType::Unknown)
        .or_else(|| sniff_script_type_from_content(file_data))
        .or_else(|| known_manifest_type_from_basename(file_path))
        .unwrap_or(FileType::Unknown)
}

fn sniff_script_type_from_content(data: &[u8]) -> Option<FileType> {
    let text = if let Some(decoded) = decode_probable_utf16le(data) {
        decoded
    } else {
        String::from_utf8_lossy(data).into_owned()
    };
    let lower = text.to_ascii_lowercase();

    let vbscript_markers = [
        "on error resume next",
        "createobject(",
        "createobject (",
        "wscript.shell",
        "wscript.scriptfullname",
        "function ",
        "end function",
        ".run ",
    ];
    let hits = vbscript_markers
        .iter()
        .filter(|marker| lower.contains(**marker))
        .count();
    if hits >= 3 {
        return Some(FileType::Vbs);
    }

    None
}

fn is_dotenv_name(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|s| s.to_str()) else {
        return false;
    };
    name == ".env" || name == ".env.backup" || name.starts_with(".env.backup.")
}

fn decode_probable_utf16le(data: &[u8]) -> Option<String> {
    if data.len() < 16 {
        return None;
    }
    let pairs = data.len() / 2;
    let sample_pairs = pairs.min(4096);
    let mut nul_high = 0usize;
    let mut printable_low = 0usize;
    for chunk in data.chunks_exact(2).take(sample_pairs) {
        if chunk[1] == 0 {
            nul_high += 1;
        }
        if chunk[0].is_ascii_graphic() || chunk[0].is_ascii_whitespace() {
            printable_low += 1;
        }
    }
    if nul_high * 100 / sample_pairs < 60 || printable_low * 100 / sample_pairs < 50 {
        return None;
    }

    let units = data
        .chunks_exact(2)
        .map(|chunk| u16::from_le_bytes([chunk[0], chunk[1]]))
        .collect::<Vec<_>>();
    String::from_utf16(&units).ok()
}

fn looks_like_pe_image(data: &[u8]) -> bool {
    if data.len() < 0x40 || &data[0..2] != b"MZ" {
        return false;
    }

    let e_lfanew = u32::from_le_bytes([data[60], data[61], data[62], data[63]]) as usize;
    data.get(e_lfanew..e_lfanew.saturating_add(4)) == Some(b"PE\0\0")
}

fn known_manifest_type_from_basename(file_path: &Path) -> Option<FileType> {
    let name = file_path.file_name()?.to_str()?.to_ascii_lowercase();
    match name.as_str() {
        "cargo.toml" => Some(FileType::CargoToml),
        "go.mod" => Some(FileType::GoMod),
        "pyproject.toml" => Some(FileType::PyProjectToml),
        _ => None,
    }
}

fn is_arch_package_metadata_name(file_path: &Path) -> bool {
    let Some(name) = file_path.file_name().and_then(|name| name.to_str()) else {
        return false;
    };
    matches!(
        name.to_ascii_lowercase().as_str(),
        ".pkginfo" | ".buildinfo" | ".mtree"
    )
}

fn is_routeros_script_name(file_path: &Path) -> bool {
    file_path
        .extension()
        .and_then(|ext| ext.to_str())
        .is_some_and(|ext| ext.eq_ignore_ascii_case("rsc"))
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
/// Delegates to `filefacts::FileType::is_program()` which is the single source of
/// truth for whether a file type is supported for analysis.
#[must_use]
pub(crate) fn is_analyzable(_path: &Path, file_type: &FileType) -> bool {
    file_type.is_program()
}

// Extension/content mismatch detection moved to filefacts (the
// consistency.extension_content_mismatch metric, with the AppleDouble / APK /
// XHTML / FreeBSD-pkg carve-outs applied there) and is emitted by YAML traits
// under objectives/evasion/masquerade/extension-mismatch/.

/// Re-export the canonical file type from filefacts.
pub type FileType = filefacts::FileType;

/// Cleave-specific extensions on `FileType` (report labels, YARA tags).
///
/// These don't belong in filefacts because they encode cleave's analysis
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
            // Package types whose snake_case serialization the Debug-lowercase
            // fallback can't reproduce (it drops the underscore). These strings
            // are the downstream contract: litmus routes on them and collimator
            // tokenizes them, so they must match filefacts's serde form exactly.
            FileType::Gem => "gem".to_string(),
            FileType::ApkAndroid => "apk_android".to_string(),
            FileType::ApkAlpine => "apk_alpine".to_string(),
            FileType::PkgMacos => "pkg_macos".to_string(),
            FileType::PkgFreebsd => "pkg_freebsd".to_string(),
            FileType::PkgArch => "pkg_arch".to_string(),
            // Npm/Crate/Conda/Egg/Nupkg/Ipa/Vsix are single words whose
            // Debug-lowercase form already matches their snake_case serde token,
            // so they fall through to the default arm below.
            FileType::PythonBytecode => "python-bytecode".to_string(),
            FileType::PackageLockJson => "package-lock.json".to_string(),
            FileType::Json => "json".to_string(),
            FileType::Gyp => "gyp".to_string(),
            // Explicit forms below differ from the Debug-lowercase fallback;
            // kept here so this stays the single source of truth for the report
            // type string (generic.rs delegates to it instead of duplicating).
            FileType::ObjectiveC => "objc".to_string(),
            FileType::GithubActions => "github-actions".to_string(),
            FileType::PkgInfo => "pkg-info".to_string(),
            FileType::GoMod => "go.mod".to_string(),
            FileType::CargoToml => "cargo.toml".to_string(),
            FileType::PyProjectToml => "pyproject.toml".to_string(),
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
            FileType::Jcl => vec!["jcl"],
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
            FileType::Json => vec!["json"],
            FileType::PkgInfo => vec!["pkg-info", "metadata", "dist-info"],
            FileType::VsixManifest => vec!["xml", "vsix", "vscode"],
            FileType::ChromeManifest => vec!["json", "manifest.json", "chrome", "extension"],
            FileType::GoMod => vec!["go.mod", "gomod", "go"],
            FileType::CargoToml => vec!["toml", "cargo.toml", "rust"],
            FileType::PyProjectToml => vec!["toml", "pyproject.toml", "python"],
            FileType::ComposerJson => vec!["json", "composer.json", "php"],
            FileType::GithubActions => vec!["yaml", "yml", "github-actions"],
            FileType::SystemdService => vec!["service", "systemd", "unit"],
            FileType::DesktopEntry => vec!["desktop", "desktop-entry", "freedesktop", "xdg"],
            FileType::Xml => vec!["xml", "csproj", "xaml", "svg", "msbuild"],
            FileType::Svg => vec!["svg", "xml", "image/svg+xml"],
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
            | FileType::PkgMacos
            | FileType::Cab => {
                vec!["archive"]
            }
            FileType::Gem => vec!["gem", "archive"],
            FileType::ApkAndroid => vec!["apk", "android", "archive"],
            FileType::ApkAlpine => vec!["apk", "alpine", "archive"],
            FileType::Npm => vec!["npm", "tgz", "archive"],
            FileType::Crate => vec!["crate", "rust", "archive"],
            FileType::Conda => vec!["conda", "archive"],
            FileType::Egg => vec!["egg", "python", "archive"],
            FileType::Nupkg => vec!["nupkg", "nuget", "archive"],
            FileType::Ipa => vec!["ipa", "ios", "archive"],
            FileType::Vsix => vec!["vsix", "vscode", "archive"],
            FileType::PkgFreebsd => vec!["pkg", "freebsd", "archive"],
            FileType::PkgArch => vec!["pkg", "arch", "archive"],
            FileType::SevenZ => vec!["7z", "archive"],
            FileType::Rar => vec!["rar", "archive"],
            FileType::Deb => vec!["deb", "archive"],
            FileType::Rpm => vec!["rpm", "archive"],
            FileType::Crx => vec!["crx", "archive"],
            FileType::Asar => vec!["asar", "archive"],
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
            FileType::Dockerfile => vec!["dockerfile", "docker", "containerfile"],
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
            FileType::Unknown
        );

        let pyc = [0x55, 0x0d, 0x0d, 0x0a, 0x00, 0x00, 0x00, 0x00];
        assert_eq!(
            detect_file_type_from_data(Path::new("c/s.dat"), &pyc),
            FileType::PythonBytecode
        );
    }

    #[test]
    fn bridge_pe_magic_requires_valid_nt_header() {
        let mut pe = vec![0u8; 0x84];
        pe[0..2].copy_from_slice(b"MZ");
        pe[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        pe[0x80..0x84].copy_from_slice(b"PE\0\0");
        assert_eq!(
            detect_file_type_from_data(Path::new("a.exe"), &pe),
            FileType::Pe
        );

        assert_eq!(
            detect_file_type_from_data(Path::new("BOUT.inp"), b"MZ = 8    # Z size\n"),
            FileType::Unknown
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
    fn bridge_heuristic_utf16le_vbscript_without_extension() {
        let script = "On Error Resume Next\r\nSet sh = CreateObject(\"WScript.Shell\")\r\nself = WScript.ScriptFullName\r\nFunction repl(x)\r\nrepl = Replace(x, \"a\", \"\")\r\nEnd Function\r\nsh.Run \"powershell -command echo ok\", 0, true\r\n";
        let data = script
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect::<Vec<_>>();
        assert_eq!(
            detect_file_type_from_data(Path::new("payload"), &data),
            FileType::Vbs
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
    fn bridge_dotenv_files_are_text() {
        assert_eq!(
            detect_file_type_from_path(Path::new(".env")),
            FileType::Text
        );
        assert_eq!(
            detect_file_type_from_data(Path::new(".env"), b"API_KEY=abc123\n"),
            FileType::Text
        );
        assert_eq!(
            detect_file_type_from_path(Path::new(".env.backup.20260617_154013")),
            FileType::Text
        );
        assert_eq!(
            detect_file_type_from_data(
                Path::new(".env.backup.20260617_154013"),
                b"CLOUDFLOW_CENTER_API_KEY=7e83812d309d3954a6fcdc5482aca2da73125828ab0d1e4a781e30404a718cfe\n"
            ),
            FileType::Text
        );
    }

    #[test]
    fn bridge_arch_package_metadata_stays_text() {
        assert_eq!(
            detect_file_type_from_path(Path::new(".PKGINFO")),
            FileType::Text
        );
        assert_eq!(
            detect_file_type_from_data(
                Path::new(".PKGINFO"),
                b"pkgdesc = Tools to package up Wasm Components\n"
            ),
            FileType::Text
        );
        assert_eq!(
            detect_file_type_from_data(Path::new(".BUILDINFO"), b"format = 2\n"),
            FileType::Text
        );
        assert_eq!(
            detect_file_type_from_data(Path::new(".MTREE"), b"#mtree\n"),
            FileType::Text
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
}
