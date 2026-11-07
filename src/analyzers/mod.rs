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
pub(crate) mod cfml;
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
pub(crate) mod chrome_manifest;
pub(crate) mod dos_word_xor;
pub(crate) mod elf;
pub(crate) mod embedded_binary_detector;
pub(crate) mod font;
pub(crate) mod java_class;
pub(crate) mod jpeg;
pub(crate) mod js_decimal_packer;
pub(crate) mod js_edge_source;
pub(crate) mod js_joined_module;
pub(crate) mod js_literal_catalog;
pub(crate) mod js_permutation;
pub(crate) mod js_string_table;
pub(crate) mod js_xor_command;
pub(crate) mod literal_program;
pub(crate) mod macho;
pub(crate) mod media;
pub(crate) mod office;
pub(crate) mod package_json;
pub mod pdf;
pub mod pe;
pub(crate) mod php_blocks;
pub(crate) mod pickle;
mod png;
pub(crate) mod python_char_array;
pub(crate) mod python_encoded_command;
pub(crate) mod python_literal_catalog;
pub(crate) mod rtf;
pub(crate) mod sfx_detector;
pub(crate) mod signature;
pub(crate) mod vsix_manifest;

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

        // Java bytecode - not source code
        FileType::JavaClass | FileType::Jar => Some(Box::new(
            java_class::JavaClassAnalyzer::new().with_engine(engine.clone()),
        )),

        // Compiled AppleScript - binary format
        FileType::AppleScript => Some(Box::new(
            applescript::AppleScriptAnalyzer::new().with_engine(engine.clone()),
        )),

        // RTF documents - parse for embedded OLE objects
        FileType::Rtf => Some(Box::new(
            rtf::RtfAnalyzer::new().with_engine(engine.clone()),
        )),

        // Microsoft Office documents (OLE2 and OOXML)
        FileType::OleDoc | FileType::Msi | FileType::Ooxml => Some(Box::new(
            office::OfficeAnalyzer::new().with_engine(engine.clone()),
        )),

        // PDF documents — lenient byte-scan extractor.
        FileType::Pdf => Some(Box::new(
            pdf::PdfAnalyzer::new().with_engine(engine.clone()),
        )),

        // Image analyzers - steganography detection
        FileType::Jpeg => Some(Box::new(
            jpeg::JpegAnalyzer::new().with_engine(engine.clone()),
        )),
        FileType::Png => Some(Box::new(
            png::PngAnalyzer::new().with_engine(engine.clone()),
        )),
        FileType::Font => Some(Box::new(
            font::FontAnalyzer::new().with_engine(engine.clone()),
        )),
        // One analyzer for every non-font, non-raster container: they all
        // defer to filefacts and read the same shared `media.*` facts.
        FileType::Wav
        | FileType::Aiff
        | FileType::Mp3
        | FileType::Mp4
        | FileType::Avif
        | FileType::Tiff
        | FileType::Ico
        | FileType::Gif
        | FileType::Bmp
        | FileType::Webp => Some(Box::new(
            media::MediaAnalyzer::new().with_engine(engine.clone()),
        )),

        // Pickle - deserialization attack detection
        FileType::Pickle => Some(Box::new(
            pickle::PickleAnalyzer::new().with_engine(engine.clone()),
        )),

        // Package manifests - structured data parsers
        FileType::VsixManifest => Some(Box::new(
            vsix_manifest::VsixManifestAnalyzer::new().with_engine(engine.clone()),
        )),
        FileType::PackageJson => Some(Box::new(
            package_json::PackageJsonAnalyzer::new().with_engine(engine.clone()),
        )),
        FileType::ChromeManifest => Some(Box::new(
            chrome_manifest::ChromeManifestAnalyzer::new()
                .with_engine(engine.clone()),
        )),

        // Text-based formats without tree-sitter - use generic analyzer
        FileType::PkgInfo
        | FileType::CargoToml
        | FileType::GoMod
        | FileType::PyProjectToml
        | FileType::PackageLockJson
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

/// The type a file's *name* claims (extension or well-known filename).
///
/// This is a claim, never an identity: use it to report what a name declares
/// (`declared_type`, extension-mismatch metadata) or to retry a member whose
/// detected format failed to parse. To know what a file *is*, use
/// [`detect_file_type`] / [`detect_file_type_from_data`], which every command
/// and the scan pipeline share.
#[must_use]
#[inline]
pub(crate) fn declared_file_type_from_name(file_path: &Path) -> FileType {
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
        .or_else(|| known_data_type_from_extension(file_path))
        .unwrap_or(FileType::Unknown)
}

/// Detect file type from already-loaded data (content first, extension fallback).
#[inline]
pub(crate) fn detect_file_type_from_data(file_path: &Path, file_data: &[u8]) -> FileType {
    detect_file_type_from_detected(
        file_path,
        file_data,
        filefacts::fileid::detect(file_path, file_data).map(|d| d.file_type),
    )
}

/// [`detect_file_type_from_data`] with the filefacts detection already done
/// (`detected` is `filefacts::fileid::detect(..).map(|d| d.file_type)`).
/// Lets a caller that also needs the full [`filefacts::FileId`] run the
/// detection pipeline once — on a compressed tar it inflates up to 64 MiB
/// to decide npm/sdist.
pub(crate) fn detect_file_type_from_detected(
    file_path: &Path,
    file_data: &[u8],
    detected: Option<FileType>,
) -> FileType {
    // A name like `.env`, `.PKGINFO` or `*.rsc` says "inert text", and the
    // caller chooses the name: letting it outrank the bytes would let a script
    // saved as `.env` — or an ELF, or a zip — be read as text. So for those
    // names the bytes are asked alone, and code, binaries and archives are
    // typed by what they are; content nothing recognizes keeps the name's type.
    let inert_name = is_dotenv_name(file_path)
        || is_arch_package_metadata_name(file_path)
        || is_routeros_script_name(file_path);
    let detected = inert_name
        .then(|| filefacts::fileid::detect(Path::new("content"), file_data))
        .flatten()
        .map(|d| d.file_type)
        .filter(|ft| ft.is_source_code() || ft.is_executable_code() || ft.is_archive())
        .or(detected);
    let detected = detected
        .filter(|ft| *ft != FileType::Pe || looks_like_pe_image(file_data))
        .filter(|ft| *ft != FileType::Unknown);

    detected
        .or_else(|| sniff_script_type_from_content(file_data))
        .or_else(|| inert_name.then_some(FileType::Text))
        .or_else(|| known_manifest_type_from_basename(file_path))
        .or_else(|| known_data_type_from_extension(file_path))
        .unwrap_or(FileType::Unknown)
}

/// VBScript idioms, lowercase ASCII spelling. A file is called VBScript when
/// [`VBS_MARKER_THRESHOLD`] *distinct* markers appear anywhere in it.
const VBS_MARKERS: [&str; 8] = [
    "on error resume next",
    "createobject(",
    "createobject (",
    "wscript.shell",
    "wscript.scriptfullname",
    "function ",
    "end function",
    ".run ",
];

const VBS_MARKER_THRESHOLD: u32 = 3;

/// Markers in both ASCII and UTF-16LE spelling: pattern `i` is
/// `VBS_MARKERS[i]`, pattern `i + VBS_MARKERS.len()` is its wide form, so
/// `index % VBS_MARKERS.len()` recovers the marker either way. Matching is
/// ASCII-case-insensitive, which leaves the wide form's interleaved NULs
/// untouched.
fn vbs_marker_automaton() -> Option<&'static aho_corasick::AhoCorasick> {
    static AUTOMATON: std::sync::OnceLock<Option<aho_corasick::AhoCorasick>> =
        std::sync::OnceLock::new();
    AUTOMATON
        .get_or_init(|| {
            let ascii = VBS_MARKERS.iter().map(|m| m.as_bytes().to_vec());
            let wide = VBS_MARKERS
                .iter()
                .map(|m| m.bytes().flat_map(|b| [b, 0]).collect::<Vec<u8>>());
            aho_corasick::AhoCorasick::builder()
                .ascii_case_insensitive(true)
                .build(ascii.chain(wide).collect::<Vec<_>>())
                .ok()
        })
        .as_ref()
}

/// Largest input the script sniff will look at. See
/// [`sniff_script_type_from_content`] for why it is capped.
const SCRIPT_SNIFF_MAX_BYTES: usize = 4 << 20;

/// Last-resort VBScript sniff, for content that magic bytes, extension, and
/// filefacts' prefix heuristics all left unidentified.
///
/// Scans the raw bytes once for VBScript idioms in both ASCII and UTF-16LE
/// spelling, case-insensitively — the needle is transcoded, never the
/// haystack, the same way stng matches wide strings. Overlapping iteration is
/// required: markers nest (`end function` contains `function `), and
/// non-overlapping matching would let the outer one consume the inner one's
/// occurrence, which is not what "does this marker appear?" means.
///
/// **Capped by size**, because this sniff's precision collapses as inputs grow.
/// Several markers are generic (`function `, `.run `), so the chance that a
/// large file contains three of them *somewhere* approaches 1 regardless of
/// what it holds. A 1.5 GB APFS partition image inside a `.dmg` hit exactly
/// `function `, `end function`, and `.run ` — at offsets 157 MB, 268 MB and
/// 397 MB, none within 100 MB of another — and was analyzed as VBScript, which
/// pushed the whole disk image through the source-code path. Delivered
/// VBScript is kilobytes; a file over the cap is not a script this fallback
/// was built to catch, and both the magic and extension paths still see it.
fn sniff_script_type_from_content(data: &[u8]) -> Option<FileType> {
    if data.len() > SCRIPT_SNIFF_MAX_BYTES {
        return None;
    }

    // Compiled YARA-X databases contain fragments from many unrelated scripts.
    // Their binary header is not script source, even when those fragments
    // satisfy the fallback VBScript marker threshold.
    if data.starts_with(b"YARA-X\0\0") {
        return None;
    }

    let mut seen: u32 = 0;
    for m in vbs_marker_automaton()?.find_overlapping_iter(data) {
        seen |= 1 << (m.pattern().as_usize() % VBS_MARKERS.len());
        if seen.count_ones() >= VBS_MARKER_THRESHOLD {
            return Some(FileType::Vbs);
        }
    }

    None
}

fn is_dotenv_name(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|s| s.to_str()) else {
        return false;
    };
    name == ".env" || name == ".env.backup" || name.starts_with(".env.backup.")
}

fn looks_like_pe_image(data: &[u8]) -> bool {
    if data.len() < 0x40 || &data[0..2] != b"MZ" {
        return false;
    }

    let e_lfanew = u32::from_le_bytes([data[60], data[61], data[62], data[63]]) as usize;
    if data.get(e_lfanew..e_lfanew.saturating_add(4)) == Some(b"PE\0\0") {
        return true;
    }

    // A reflective loader can replace the NT signature while retaining a
    // coherent image. Do not discard it before PEAnalyzer can report header
    // tampering and scan the original bytes. MZ-prefixed text and truncated
    // DOS headers still need to fail this gate: require bounded COFF/optional
    // headers, all raw sections, and an entry point in executable content.
    coherent_pe_with_damaged_signature(data, e_lfanew)
}

fn coherent_pe_with_damaged_signature(data: &[u8], nt: usize) -> bool {
    fn u16_at(data: &[u8], at: usize) -> Option<u16> {
        Some(u16::from_le_bytes(
            data.get(at..at.checked_add(2)?)?.try_into().ok()?,
        ))
    }
    fn u32_at(data: &[u8], at: usize) -> Option<u32> {
        Some(u32::from_le_bytes(
            data.get(at..at.checked_add(4)?)?.try_into().ok()?,
        ))
    }
    let check = || -> Option<bool> {
        if nt < 0x40 {
            return Some(false);
        }
        let coff = nt.checked_add(4)?;
        let machine = u16_at(data, coff)?;
        let count = usize::from(u16_at(data, coff.checked_add(2)?)?);
        let opt_size = usize::from(u16_at(data, coff.checked_add(16)?)?);
        let characteristics = u16_at(data, coff.checked_add(18)?)?;
        let opt = coff.checked_add(20)?;
        let magic = u16_at(data, opt)?;
        let min_opt = match (machine, magic) {
            (0x014c, 0x010b) => 0xe0,
            (0x8664 | 0xaa64, 0x020b) => 0xf0,
            _ => return Some(false),
        };
        if !(1..=96).contains(&count) || opt_size < min_opt || characteristics & 2 == 0 {
            return Some(false);
        }
        let entry = u32_at(data, opt.checked_add(16)?)?;
        let image_size = u32_at(data, opt.checked_add(56)?)?;
        let headers_size = usize::try_from(u32_at(data, opt.checked_add(60)?)?).ok()?;
        let table = opt.checked_add(opt_size)?;
        let table_end = table.checked_add(count.checked_mul(40)?)?;
        if entry == 0
            || entry >= image_size
            || table_end > headers_size
            || headers_size > data.len()
        {
            return Some(false);
        }
        let sections = data.get(table..table_end)?;
        let mut executable_entry = false;
        for section in sections.as_chunks::<40>().0 {
            let virtual_size = u32_at(section, 8)?;
            let virtual_start = u32_at(section, 12)?;
            let raw_size = u32_at(section, 16)?;
            let raw_start = u32_at(section, 20)?;
            let flags = u32_at(section, 36)?;
            let virtual_end = virtual_start.checked_add(virtual_size.max(raw_size))?;
            if virtual_end > image_size {
                return Some(false);
            }
            if raw_size != 0 {
                let start = usize::try_from(raw_start).ok()?;
                let end = start.checked_add(usize::try_from(raw_size).ok()?)?;
                if start < headers_size || end > data.len() {
                    return Some(false);
                }
                // Require actual stored executable bytes at the entry point,
                // not a virtual-only zero-fill section with fabricated flags.
                executable_entry |= flags & 0x2000_0000 != 0
                    && entry >= virtual_start
                    && entry < virtual_start.checked_add(raw_size)?;
            }
        }
        Some(executable_entry)
    };
    check().unwrap_or(false)
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

fn known_data_type_from_extension(file_path: &Path) -> Option<FileType> {
    let extension = file_path.extension()?.to_str()?.to_ascii_lowercase();
    matches!(
        extension.as_str(),
        "dat" | "bin" | "payload" | "raw" | "map"
    )
    .then_some(FileType::Data)
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
