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

// Unified analysis input type
mod input;
pub use input::AnalysisInput;

// Universal metrics analyzers
pub(crate) mod comment_metrics;
pub(crate) mod function_metrics;
pub(crate) mod identifier_metrics;
pub(crate) mod import_metrics;
pub(crate) mod metrics_utils;
pub(crate) mod string_metrics;
pub(crate) mod symbol_extraction;
pub(crate) mod text_metrics;
pub(crate) mod utils;

// Dedicated analyzers for binary/bytecode/manifest formats
pub(crate) mod chrome_manifest;
pub(crate) mod elf;
pub(crate) mod embedded_binary_detector;
pub(crate) mod java_class;
pub(crate) mod jpeg;
pub(crate) mod lnk;
pub(crate) mod macho;
pub(crate) mod macho_codesign;
pub(crate) mod office;
pub(crate) mod package_json;
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
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::sync::Arc;

/// Standard stng extraction options for analysis.
///
/// All analysis code paths MUST use this to ensure consistent string extraction.
/// In particular, XOR scanning must always be enabled so that decoded strings
/// are available for trait matching (string_value conditions).
#[must_use]
pub fn stng_analysis_opts(min_length: usize) -> stng::ExtractOptions {
    stng::ExtractOptions::new(min_length)
        .with_garbage_filter(true)
        .with_xor(None)
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

        // LNK files - Windows shortcuts
        FileType::Lnk => Some(Box::new(
            lnk::LnkAnalyzer::new().with_capability_mapper(mapper_or_empty),
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
        FileType::PkgInfo | FileType::Plist | FileType::Html | FileType::Markdown => {
            Some(Box::new(
                generic::GenericAnalyzer::new(file_type.clone())
                    .with_capability_mapper(mapper_or_empty),
            ))
        }

        // Archive needs special handling (depth limits, nested analysis)
        FileType::Archive => None,

        // All source code languages - use unified analyzer
        _ => {
            if let Some(analyzer) = unified::UnifiedSourceAnalyzer::for_file_type(file_type) {
                Some(Box::new(analyzer.with_capability_mapper(mapper_or_empty)))
            } else {
                // Fallback to generic for types without tree-sitter (Batch, Unknown)
                Some(Box::new(
                    generic::GenericAnalyzer::new(file_type.clone())
                        .with_capability_mapper(mapper_or_empty),
                ))
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

        // LNK files - Windows shortcuts
        FileType::Lnk => Some(Box::new(
            lnk::LnkAnalyzer::new().with_capability_mapper_arc(mapper_or_empty),
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
        FileType::PkgInfo | FileType::Plist | FileType::Html | FileType::Markdown => {
            Some(Box::new(
                generic::GenericAnalyzer::new(file_type.clone())
                    .with_capability_mapper_arc(mapper_or_empty),
            ))
        }

        // Archive needs special handling (depth limits, nested analysis)
        FileType::Archive => None,

        // All source code languages - use unified analyzer
        _ => {
            if let Some(analyzer) = unified::UnifiedSourceAnalyzer::for_file_type(file_type) {
                Some(Box::new(
                    analyzer.with_capability_mapper_arc(mapper_or_empty),
                ))
            } else {
                // Fallback to generic for types without tree-sitter (Batch, Unknown)
                Some(Box::new(
                    generic::GenericAnalyzer::new(file_type.clone())
                        .with_capability_mapper_arc(mapper_or_empty),
                ))
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
    fileid::detect_path(file_path).map_or(FileType::Unknown, |d| FileType::from(d.file_type))
}

/// Detect file type from already-loaded data (content first, extension fallback).
#[inline]
pub(crate) fn detect_file_type_from_data(file_path: &Path, file_data: &[u8]) -> FileType {
    fileid::detect(file_path, file_data).map_or(FileType::Unknown, |d| FileType::from(d.file_type))
}

/// Detect file type by reading the first 1KB from disk.
pub fn detect_file_type(file_path: &Path) -> Result<FileType> {
    use std::io::Read;
    let mut file = std::fs::File::open(file_path)?;
    let mut buf = [0u8; 1024];
    let bytes_read = file.read(&mut buf).unwrap_or(0);
    Ok(detect_file_type_from_data(file_path, &buf[..bytes_read]))
}

/// Check if file content matches its extension's expected type.
/// Returns (expected_type, actual_type_hint) if mismatch detected.
#[must_use]
#[allow(dead_code)]
pub fn check_extension_content_mismatch(
    file_path: &Path,
    file_data: &[u8],
) -> Option<(String, String)> {
    if file_data.len() < 4 {
        return None;
    }
    let det = fileid::detect(file_path, file_data)?;
    if !det.extension_mismatch() {
        return None;
    }
    let content_desc = format!("{:?}", det.file_type);
    let ext_desc = det.extension_type().map_or_else(
        || {
            file_path.extension().map_or("unknown".to_string(), |e| {
                format!("{} file", e.to_string_lossy())
            })
        },
        |ft| format!("{ft:?}"),
    );
    let ext = file_path
        .extension()
        .map(|e| e.to_string_lossy().to_ascii_lowercase());
    if matches!(ext.as_deref(), Some("exe") | Some("dll")) && det.file_type == fileid::FileType::Pe
    {
        return None;
    }
    Some((ext_desc, content_desc))
}

/// File type detected by magic bytes, extension, and content analysis
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum FileType {
    /// Mach-O binary (macOS/iOS executable or library)
    MachO,
    /// ELF binary (Linux/Unix executable or shared library)
    Elf,
    /// PE binary (Windows executable)
    Pe,
    /// Unix shell script (bash, sh, zsh, etc.)
    Shell,
    /// Windows batch file (.bat, .cmd)
    Batch,
    /// VBScript source file (.vbs, .vbe, .wsf, .wsc)
    Vbs,
    /// Python source file (.py)
    Python,
    /// JavaScript source file (.js, .mjs, .cjs)
    JavaScript,
    /// TypeScript source file (.ts, .tsx)
    TypeScript,
    /// Go source file (.go)
    Go,
    /// Rust source file (.rs)
    Rust,
    /// Java source file (.java)
    Java,
    /// Compiled Java bytecode (.class)
    JavaClass,
    /// Python compiled bytecode (.pyc)
    PythonBytecode,
    /// Java archive (.jar, .war, .ear)
    Jar,
    /// Ruby source file (.rb)
    Ruby,
    /// PHP source file (.php)
    Php,
    /// Perl source file (.pl, .pm)
    Perl,
    /// Lua source file (.lua)
    Lua,
    /// C# source file (.cs)
    CSharp,
    /// PowerShell script (.ps1, .psm1)
    PowerShell,
    /// Swift source file (.swift)
    Swift,
    /// Objective-C source file (.m, .mm)
    ObjectiveC,
    /// Groovy source file (.groovy)
    Groovy,
    /// Scala source file (.scala)
    Scala,
    /// Zig source file (.zig)
    Zig,
    /// Elixir source file (.ex, .exs)
    Elixir,
    /// C source file (.c, .h)
    C,
    /// npm package.json manifest
    PackageJson,
    /// VSCode extension manifest (.vsixmanifest)
    VsixManifest,
    /// Chrome extension manifest.json
    ChromeManifest,
    /// Rust Cargo.toml manifest
    CargoToml,
    /// Python pyproject.toml manifest
    PyProjectToml,
    /// PHP composer.json manifest
    ComposerJson,
    /// GitHub Actions workflow YAML
    GithubActions,
    /// Python package metadata (PKG-INFO, METADATA)
    PkgInfo,
    /// Archive file (zip, tar, gz, etc.)
    Archive,
    /// AppleScript source file (.applescript, .scpt)
    AppleScript,
    /// Apple Property List (.plist)
    Plist,
    /// Rich Text Format document (.rtf)
    Rtf,
    /// Legacy Microsoft Office document (OLE2/CFBF: .doc, .xls, .ppt, .msg)
    OleDoc,
    /// Modern Microsoft Office document (OOXML: .docx, .xlsx, .pptx)
    Ooxml,
    /// Windows Shell Link file (.lnk)
    Lnk,
    /// JPEG image
    Jpeg,
    /// PNG image
    Png,
    /// Python pickle serialized data (.pkl, .pickle, .joblib)
    Pickle,
    /// PDF document
    Pdf,
    /// HTML document (.html, .htm)
    Html,
    /// Markdown document (.md, .markdown)
    Markdown,
    /// File type could not be determined
    Unknown,
}

impl FileType {
    /// Returns true if this file type represents executable code (binaries, scripts, etc.)
    /// as opposed to data files (images, documents, etc.)
    #[must_use]
    #[allow(dead_code)]
    pub(crate) fn is_program(&self) -> bool {
        match self {
            FileType::MachO
            | FileType::Elf
            | FileType::Pe
            | FileType::Shell
            | FileType::Batch
            | FileType::Vbs
            | FileType::Python
            | FileType::JavaScript
            | FileType::TypeScript
            | FileType::Go
            | FileType::Rust
            | FileType::Java
            | FileType::JavaClass
            | FileType::PythonBytecode
            | FileType::Jar
            | FileType::Ruby
            | FileType::Php
            | FileType::Perl
            | FileType::Lua
            | FileType::CSharp
            | FileType::PowerShell
            | FileType::Swift
            | FileType::ObjectiveC
            | FileType::Groovy
            | FileType::Scala
            | FileType::Zig
            | FileType::Elixir
            | FileType::C
            | FileType::PackageJson
            | FileType::PkgInfo
            | FileType::VsixManifest
            | FileType::ChromeManifest
            | FileType::CargoToml
            | FileType::PyProjectToml
            | FileType::ComposerJson
            | FileType::GithubActions
            | FileType::AppleScript
            | FileType::Plist
            | FileType::Rtf
            | FileType::OleDoc
            | FileType::Ooxml
            | FileType::Lnk
            | FileType::Jpeg
            | FileType::Png
            | FileType::Pickle // Pickle can contain arbitrary code execution
            | FileType::Archive // Archives can contain malware
            | FileType::Pdf => true, // Included as they can carry exploits/malware
            FileType::Unknown | FileType::Html | FileType::Markdown => false, // Skip unknown and non-program text files in dir scans
        }
    }

    /// Returns true if this file type represents source code with AST support.
    /// These file types extract strings via AST parsing for accuracy.
    #[allow(dead_code)] // Used by binary target
    #[must_use]
    pub(crate) fn is_source_code(&self) -> bool {
        matches!(
            self,
            FileType::Python
                | FileType::Ruby
                | FileType::JavaScript
                | FileType::TypeScript
                | FileType::Php
                | FileType::Perl
                | FileType::Lua
                | FileType::CSharp
                | FileType::C
                | FileType::Rust
                | FileType::Shell
                | FileType::PowerShell
        )
    }

    /// Get YARA rule filetypes that are relevant for this file type
    /// Returns a list of filetype identifiers to match against YARA metadata
    #[must_use]
    #[allow(dead_code)]
    pub(crate) fn yara_filetypes(&self) -> Vec<&'static str> {
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
            FileType::Zig => vec!["zig"],
            FileType::Elixir => vec!["ex", "exs"],
            FileType::C => vec!["c", "h", "hh"],
            FileType::PackageJson => vec!["json", "package.json", "npm"],
            FileType::PkgInfo => vec!["pkg-info", "metadata", "dist-info"],
            FileType::VsixManifest => vec!["xml", "vsix", "vscode"],
            FileType::ChromeManifest => vec!["json", "manifest.json", "chrome", "extension"],
            FileType::CargoToml => vec!["toml", "cargo.toml", "rust"],
            FileType::PyProjectToml => vec!["toml", "pyproject.toml", "python"],
            FileType::ComposerJson => vec!["json", "composer.json", "php"],
            FileType::GithubActions => vec!["yaml", "yml", "github-actions"],
            FileType::Archive => vec!["zip", "tar", "gz"],
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
            FileType::Unknown => vec![], // No filtering for unknown types
        }
    }
}

impl From<fileid::FileType> for FileType {
    fn from(ft: fileid::FileType) -> Self {
        match ft {
            fileid::FileType::MachO => Self::MachO,
            fileid::FileType::Elf => Self::Elf,
            fileid::FileType::Pe => Self::Pe,
            fileid::FileType::Shell => Self::Shell,
            fileid::FileType::Batch => Self::Batch,
            fileid::FileType::Vbs => Self::Vbs,
            fileid::FileType::Python => Self::Python,
            fileid::FileType::JavaScript => Self::JavaScript,
            fileid::FileType::TypeScript => Self::TypeScript,
            fileid::FileType::Go => Self::Go,
            fileid::FileType::Rust => Self::Rust,
            fileid::FileType::Java => Self::Java,
            fileid::FileType::JavaClass => Self::JavaClass,
            fileid::FileType::PythonBytecode => Self::PythonBytecode,
            fileid::FileType::Jar => Self::Jar,
            fileid::FileType::Ruby => Self::Ruby,
            fileid::FileType::Php => Self::Php,
            fileid::FileType::Perl => Self::Perl,
            fileid::FileType::Lua => Self::Lua,
            fileid::FileType::CSharp => Self::CSharp,
            fileid::FileType::PowerShell => Self::PowerShell,
            fileid::FileType::Swift => Self::Swift,
            fileid::FileType::ObjectiveC => Self::ObjectiveC,
            fileid::FileType::Groovy => Self::Groovy,
            fileid::FileType::Scala => Self::Scala,
            fileid::FileType::Zig => Self::Zig,
            fileid::FileType::Elixir => Self::Elixir,
            fileid::FileType::C => Self::C,
            fileid::FileType::PackageJson => Self::PackageJson,
            fileid::FileType::VsixManifest => Self::VsixManifest,
            fileid::FileType::ChromeManifest => Self::ChromeManifest,
            fileid::FileType::CargoToml => Self::CargoToml,
            fileid::FileType::PyProjectToml => Self::PyProjectToml,
            fileid::FileType::ComposerJson => Self::ComposerJson,
            fileid::FileType::GithubActions => Self::GithubActions,
            fileid::FileType::PkgInfo => Self::PkgInfo,
            fileid::FileType::Archive => Self::Archive,
            fileid::FileType::AppleScript => Self::AppleScript,
            fileid::FileType::Plist => Self::Plist,
            fileid::FileType::Rtf => Self::Rtf,
            fileid::FileType::OleDoc => Self::OleDoc,
            fileid::FileType::Ooxml => Self::Ooxml,
            fileid::FileType::Lnk => Self::Lnk,
            fileid::FileType::Jpeg => Self::Jpeg,
            fileid::FileType::Png => Self::Png,
            fileid::FileType::Pickle => Self::Pickle,
            fileid::FileType::Pdf => Self::Pdf,
            fileid::FileType::Html => Self::Html,
            fileid::FileType::Markdown => Self::Markdown,
            _ => Self::Unknown,
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
            detect_file_type_from_path(Path::new("README.md")),
            FileType::Markdown
        );
        assert_eq!(
            detect_file_type_from_path(Path::new("notes.txt")),
            FileType::Unknown
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
        assert_eq!(
            detect_file_type_from_data(Path::new("d.bin"), &[0, 0, 0, 0]),
            FileType::Unknown
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
    fn bridge_mismatch() {
        let elf = b"\x7fELF\x02\x01\x01\x00";
        assert!(check_extension_content_mismatch(Path::new("image.jpg"), elf).is_some());
        assert!(check_extension_content_mismatch(Path::new("binary"), elf).is_none());
    }

    #[test]
    fn bridge_from_roundtrip() {
        assert_eq!(FileType::from(fileid::FileType::MachO), FileType::MachO);
        assert_eq!(
            FileType::from(fileid::FileType::Markdown),
            FileType::Markdown
        );
    }
}
