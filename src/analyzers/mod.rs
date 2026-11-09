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
// Python `.pyc` bytecode kv-tree synthesis (header + co_filename).
// B0.5 quick-win extractors: ELF .comment, sanitizer detection, etc.
// B1: Go buildinfo extractor (cross-format PE/ELF/Mach-O/raw).
// Cross-format builder-path / builder-username recovery.
// B2: PE-specific extractors (Rich header, imphash, VERSIONINFO).

// Dedicated analyzers for binary/bytecode/manifest formats
pub(crate) mod elf;
pub(crate) mod embedded_images;
pub(crate) mod embedded_layers;
pub(crate) mod facts;
pub(crate) mod macho;
pub(crate) mod office;
pub(crate) mod package_json;
pub mod pdf;
pub mod pe;
pub(crate) mod sfx_detector;
pub(crate) mod signature;

// Unified source analyzer (handles all tree-sitter languages)
pub(crate) mod unified;

// Fallback for languages without tree-sitter support
pub(crate) mod ci_secret_file_flow;
mod declared_sources;
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
    // One table, so the two entry points cannot drift: they once disagreed on
    // YAML, PGP signatures and Flatpak bundles.
    let engine = mapper.map_or_else(crate::Engine::empty, |m| {
        crate::Engine::from_rules(Arc::new(m))
    });
    analyzer_for_file_type_arc(file_type, &engine)
}

/// Create an analyzer for the given file type, analyzing under `engine`.
#[must_use]
pub(crate) fn analyzer_for_file_type_arc(
    file_type: &FileType,
    engine: &crate::Engine,
) -> Option<Box<dyn Analyzer>> {
    match file_type {
        // Binary formats - need dedicated analyzers
        FileType::MachO => Some(Box::new(
            macho::MachOAnalyzer::new().with_engine(engine.clone()),
        )),
        FileType::Elf => Some(Box::new(
            elf::ElfAnalyzer::new().with_engine(engine.clone()),
        )),
        FileType::Pe => Some(Box::new(
            pe::PEAnalyzer::new().with_engine(engine.clone()),
        )),

        // Compiled AppleScript - binary format
        FileType::AppleScript => Some(Box::new(
            applescript::AppleScriptAnalyzer::new().with_engine(engine.clone()),
        )),

        // Microsoft Office documents (OLE2 and OOXML)
        FileType::OleDoc | FileType::Msi | FileType::Ooxml => Some(Box::new(
            office::OfficeAnalyzer::new().with_engine(engine.clone()),
        )),

        // PDF documents — lenient byte-scan extractor.
        FileType::Pdf => Some(Box::new(
            pdf::PdfAnalyzer::new().with_engine(engine.clone()),
        )),

        // Formats whose analysis is entirely filefacts' facts.
        FileType::Rtf
        | FileType::Jpeg
        | FileType::Png
        | FileType::Font
        | FileType::Wav
        | FileType::Aiff
        | FileType::Mp3
        | FileType::Mp4
        | FileType::Avif
        | FileType::Tiff
        | FileType::Ico
        | FileType::Gif
        | FileType::Bmp
        | FileType::Webp
        | FileType::Pickle
        | FileType::VsixManifest
        | FileType::JavaClass => Some(Box::new(
            facts::FactsAnalyzer::new().with_engine(engine.clone()),
        )),

        // Package manifests - structured data parsers
        FileType::PackageJson => Some(Box::new(
            package_json::PackageJsonAnalyzer::new().with_engine(engine.clone()),
        )),

        // Text-based formats without tree-sitter - use generic analyzer
        FileType::PkgInfo
        | FileType::CargoToml
        | FileType::GoMod
        | FileType::PyProjectToml
        | FileType::PackageLockJson
        | FileType::ChromeManifest
        | FileType::Json
        | FileType::Plist
        | FileType::Nib
        | FileType::Pbxproj
        | FileType::Cmake
        | FileType::SystemdService
        | FileType::DesktopEntry
        | FileType::Xml
        | FileType::Yaml
        | FileType::PgpSignature
        | FileType::Svg
        | FileType::Html
        | FileType::Jsp
        | FileType::Asp
        | FileType::Cfml
        | FileType::Tex
        | FileType::Yara
        | FileType::PostScript
        | FileType::Mirc
        | FileType::IrcII
        | FileType::Markdown
        | FileType::Text
        | FileType::Dockerfile
        | FileType::Wasm
        | FileType::Dex
        // Flatpak bundles remain opaque until their container format is
        // supported by the archive extractor.
        | FileType::Flatpak
        | FileType::Data => Some(Box::new(
            generic::GenericAnalyzer::new(*file_type).with_engine(engine.clone()),
        )),

        // Archives need special handling (depth limits, nested analysis)
        ft if ft.is_archive() => None,

        // All source code languages - use unified analyzer
        _ => {
            if let Some(analyzer) = unified::UnifiedSourceAnalyzer::for_file_type(file_type) {
                Some(Box::new(
                    analyzer.with_engine(engine.clone()),
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
                            .with_engine(engine.clone()),
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
/// Implementors must provide `analyze_input()`; `analyze()` has a default that
/// reads the file and delegates to it.
pub trait Analyzer {
    /// Analyze with pre-extracted input (preferred method).
    ///
    /// Analyzers use `input.data` and `input.strings` instead of reading files
    /// and extracting strings internally.
    ///
    /// Required: the default [`Self::analyze`] delegates here, so a default for
    /// this method too would let an implementation that overrides neither
    /// compile and recurse until the stack overflows.
    fn analyze_input(&self, input: &AnalysisInput<'_>) -> Result<AnalysisReport>;

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
        let ctx = crate::analysis_context::AnalysisContext::open(file_path, &data);
        let strings = ctx.text_rows();
        let input =
            AnalysisInput::with_strings(file_path, &data, strings, file_type).with_parsed_ctx(&ctx);
        self.analyze_input(&input)
    }
}

// What a file is comes from filefacts alone; cleave keeps these names for
// its call sites.
pub(crate) use filefacts::fileid::{
    declared_file_type as declared_file_type_from_name, file_type as detect_file_type_from_data,
    file_type_with as detect_file_type_from_detected,
};

/// Detect a file's type from its full contents, exactly as a scan does.
///
/// Identification can depend on bytes anywhere in the file (a shellcode
/// `call` target past the first KiB, a zip directory at the end), so every
/// command types a file from the same bytes the scan pipeline reads — never a
/// prefix — and a subcommand can never disagree with `cleave scan`.
pub fn detect_file_type(file_path: &Path) -> Result<FileType> {
    let data = crate::file_io::read_file_smart(file_path)?;
    Ok(detect_file_type_from_data(file_path, data.as_slice()))
}

/// Returns true if cleave can analyze this file.
///
/// Delegates to `filefacts::FileType::is_program()` which is the single source of
/// truth for whether a file type is supported for analysis.
#[must_use]
pub(crate) fn is_analyzable(_path: &Path, file_type: &FileType) -> bool {
    file_type.is_analyzed()
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

    /// YARA buckets this file type scans (plus the always-on fallback).
    ///
    /// Buckets are keyed by the canonical filefacts label and nothing else, so
    /// a rule routed by [`yara_buckets_for_tags`] always reaches the files it
    /// names. Legacy YARA metadata spellings are translated on the rule side.
    fn yara_filetypes(&self) -> Vec<&'static str>;

    /// Legacy YARA metadata spellings (`exe`, `js`, `archive`...) that
    /// community rules use to mean this file type. Input vocabulary only:
    /// never a bucket key.
    fn yara_aliases(&self) -> Vec<&'static str>;
}

/// Canonical YARA buckets for a rule's filetype tags.
///
/// A tag that is a filefacts label routes to that type; any tag also routes to
/// every type that lists it as a legacy alias. Tags that name no type
/// contribute nothing, and an empty result means the rule belongs in the
/// always-scanned fallback bucket — so no rule can be routed to a bucket that
/// no file type scans.
pub(crate) fn yara_buckets_for_tags<S: AsRef<str>>(tags: &[S]) -> Vec<String> {
    static TAG_BUCKETS: std::sync::OnceLock<
        std::collections::HashMap<&'static str, Vec<&'static str>>,
    > = std::sync::OnceLock::new();
    let index = TAG_BUCKETS.get_or_init(|| {
        let mut index: std::collections::HashMap<&'static str, Vec<&'static str>> =
            std::collections::HashMap::new();
        for ft in FileType::ALL {
            let label = ft.label();
            for tag in std::iter::once(label).chain(ft.yara_aliases()) {
                let entry = index.entry(tag).or_default();
                if !entry.contains(&label) {
                    entry.push(label);
                }
            }
        }
        index
    });
    let mut buckets: Vec<String> = Vec::new();
    for tag in tags {
        let tag = tag.as_ref().trim().to_ascii_lowercase();
        for label in index.get(tag.as_str()).into_iter().flatten() {
            if !buckets.iter().any(|b| b == label) {
                buckets.push((*label).to_string());
            }
        }
    }
    buckets
}

impl FileTypeExt for FileType {
    fn report_file_type(&self) -> String {
        // filefacts is the single source of truth for the canonical label.
        // The report `type`, an embedding host's routing keys, and the ML pipeline's tokens
        // are all this one string — no separate hand-rolled vocabulary, and
        // no fragile Debug-lowercase fallback that silently drops underscores.
        self.label().to_string()
    }

    fn yara_filetypes(&self) -> Vec<&'static str> {
        // Unidentified input keeps the untyped-scan behavior of its callers.
        if matches!(self, FileType::Unknown) {
            return Vec::new();
        }
        vec![self.label()]
    }

    fn yara_aliases(&self) -> Vec<&'static str> {
        match self {
            FileType::MachO => vec!["macho", "dylib", "kext"],
            FileType::Elf => vec!["elf", "so", "ko"],
            FileType::Pe => vec!["pe", "exe", "dll", "bat", "ps1"],
            FileType::Ne => vec!["ne", "exe", "windows"],
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
            // Generic YAML shares the workflow keys, so a rule written `for:
            // [yaml]` reaches an ordinary config as well as an Actions file.
            FileType::Yaml => vec!["yaml", "yml"],
            FileType::SystemdService => vec!["service", "systemd", "unit"],
            FileType::DesktopEntry => vec!["desktop", "desktop-entry", "freedesktop", "xdg"],
            FileType::Xml => vec![
                "xml",
                "csproj",
                "xaml",
                "svg",
                "msbuild",
                "xib",
                "storyboard",
            ],
            FileType::Svg => vec!["svg", "xml", "image/svg+xml"],
            FileType::Zip => vec!["zip", "archive"],
            FileType::GoModule => vec!["go_module", "zip", "archive"],
            FileType::Composer => vec!["composer", "zip", "archive"],
            FileType::Hex => vec!["hex", "tar", "archive"],
            FileType::Pub => vec!["pub", "tar", "archive"],
            FileType::Cran => vec!["cran", "tar", "archive"],
            FileType::Cpan => vec!["cpan", "tar", "archive"],
            FileType::Hackage => vec!["hackage", "tar", "archive"],

            FileType::Tar
            | FileType::TarGz
            | FileType::TarBz2
            | FileType::TarXz
            | FileType::TarZst => vec!["tar", "archive"],
            FileType::Gz
            | FileType::Bz2
            | FileType::Xz
            | FileType::Lzma
            | FileType::Zst
            | FileType::PkgMacos
            | FileType::Cab => {
                vec!["archive"]
            }
            FileType::Gem => vec!["gem", "archive"],
            FileType::ApkAndroid => vec!["apk", "android", "archive"],
            FileType::ApkAlpine => vec!["apk", "alpine", "archive"],
            FileType::Dex => vec!["dex"],
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
            // Optical-disc images route to the archive YARA tier. Their
            // members are analyzed on their own, but an image can also be
            // reached as a payload (a PE overlay, a zip member), and those
            // paths scan the container itself.
            FileType::Iso => vec!["iso", "archive"],
            FileType::Rar => vec!["rar", "archive"],
            FileType::Rpa => vec!["rpa", "archive"],
            FileType::Rpyc => vec!["rpyc", "rpymc"],
            FileType::Deb => vec!["deb", "archive"],
            FileType::Rpm => vec!["rpm", "archive"],
            FileType::Cpio => vec!["cpio", "archive"],
            FileType::Crx => vec!["crx", "archive"],
            FileType::Dmg => vec!["dmg", "archive"],
            FileType::Vhd => vec!["vhd", "archive"],
            FileType::OciImage => vec!["oci_image", "archive"],
            FileType::Xbps => vec!["xbps", "archive"],
            FileType::GentooBinpkg => vec!["gentoo_binpkg", "archive"],
            FileType::Asar => vec!["asar", "archive"],
            FileType::Phar => vec!["phar", "archive"],
            // Compressed images we identify but do not unpack. They take the
            // archive tier like the other opaque containers (iso, dmg): their
            // members are out of reach, but the container itself is scanned.
            FileType::Snap => vec!["snap", "squashfs", "archive"],
            FileType::SquashFs => vec!["squashfs", "archive"],
            FileType::Flatpak => vec!["flatpak", "archive"],
            FileType::AppleScript => vec!["scpt", "applescript"],
            FileType::Plist => vec!["plist", "xml", "apple"],
            FileType::Nib => vec!["nib", "xib", "apple"],
            FileType::Pbxproj => vec!["pbxproj", "xcodeproj", "plist", "apple"],
            FileType::Cmake => vec!["cmake", "cmakelists", "build"],
            FileType::Rtf => vec!["rtf", "doc"],
            FileType::OleDoc => vec!["doc", "xls", "ppt", "ole", "msg"],
            FileType::Msi => vec!["msi", "msp", "mst", "msm", "ole"],
            FileType::Ooxml => vec!["docx", "xlsx", "pptx", "doc", "xls", "ole"],
            FileType::Lnk => vec!["lnk", "shortcut"],
            FileType::Jpeg => vec!["jpeg", "jpg"],
            FileType::Png => vec!["png"],
            FileType::Tiff => vec!["tiff", "tif"],
            FileType::Avif => vec!["avif", "avifs"],
            FileType::Font => vec!["ttf", "otf", "ttc", "otc", "woff", "woff2", "eot"],
            FileType::Wav => vec!["wav", "wave"],
            FileType::Aiff => vec!["aiff", "aif", "aifc"],
            FileType::Mp3 => vec!["mp3"],
            FileType::Mp4 => vec!["mp4", "m4a", "m4v", "mov"],
            FileType::Ico => vec!["ico", "cur"],
            FileType::Gif => vec!["gif"],
            FileType::Bmp => vec!["bmp", "dib"],
            FileType::Webp => vec!["webp"],
            FileType::Pickle => vec!["pkl", "pickle", "joblib"],
            FileType::Pdf => vec!["pdf"],
            FileType::Html => vec!["html", "htm"],
            FileType::Jsp => vec!["jsp", "jspx"],
            FileType::Asp => vec!["asp", "aspx"],
            FileType::Cfml => vec!["cfm", "cfc", "cfml"],
            FileType::Tex => vec!["tex", "sty", "ltx", "dtx"],
            FileType::Yara => vec!["yar", "yara"],
            FileType::PostScript => vec!["ps", "eps", "postscript"],
            FileType::DosCom => vec!["com", "dos"],
            FileType::Mirc => vec!["mrc", "mirc"],
            FileType::IrcII => vec!["ircii"],
            FileType::Markdown => vec!["md", "markdown"],
            FileType::Makefile => vec!["makefile", "make", "mk"],
            FileType::Dockerfile => vec!["dockerfile", "docker", "containerfile"],
            FileType::PgpSignature => vec!["sig", "asc", "pgp"],
            FileType::Text => vec!["txt", "text"],
            FileType::Data => vec!["dat", "bin", "payload", "raw", "map"],
            _ => vec![],
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests;
