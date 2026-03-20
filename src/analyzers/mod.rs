//! File format analyzers.
#![allow(clippy::unwrap_used, clippy::expect_used)]
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

/// Detect file type from path/extension only (no file access needed)
/// This is useful for archive entries that don't exist on disk
#[must_use]
pub(crate) fn detect_file_type_from_path(file_path: &Path) -> FileType {
    // Check by filename first (for manifest files)
    if let Some(file_name) = file_path.file_name() {
        let name = file_name.to_string_lossy().to_lowercase();
        if name == "package.json" {
            return FileType::PackageJson;
        }
        if name == "composer.json" {
            return FileType::ComposerJson;
        }
        if name == "cargo.toml" {
            return FileType::CargoToml;
        }
        if name == "pyproject.toml" {
            return FileType::PyProjectToml;
        }
        if name == "pkg-info" || name == "metadata" {
            return FileType::PkgInfo;
        }
        // Note: manifest.json detection requires content inspection for Chrome manifests,
        // so we can't reliably detect ChromeManifest from path alone - it will be detected
        // during content-based analysis if the file is read
        if name == "extension.vsixmanifest" || name.ends_with(".vsixmanifest") {
            return FileType::VsixManifest;
        }
        // GitHub Actions composite action manifests (action.yml / action.yaml at any path depth)
        if name == "action.yml" || name == "action.yaml" {
            return FileType::GithubActions;
        }
    }

    // Check for GitHub Actions workflow files
    let path_str_lower = file_path.to_string_lossy().to_lowercase();
    if (path_str_lower.contains(".github/workflows/")
        || path_str_lower.contains(".github\\workflows\\"))
        && (path_str_lower.ends_with(".yml") || path_str_lower.ends_with(".yaml"))
    {
        return FileType::GithubActions;
    }

    // Check archives by path pattern
    let path_str = file_path.to_string_lossy().to_lowercase();
    if path_str.ends_with(".jar") || path_str.ends_with(".war") || path_str.ends_with(".ear") {
        return FileType::Jar;
    }
    if path_str.ends_with(".tar.gz")
        || path_str.ends_with(".tgz")
        || path_str.ends_with(".tar.bz2")
        || path_str.ends_with(".tar.xz")
        || path_str.ends_with(".tar.zst")
        || path_str.ends_with(".tar")
    {
        return FileType::Archive;
    }

    if let Some(ext) = file_path.extension() {
        let ext_str = ext.to_str().unwrap_or("").to_lowercase();
        match ext_str.as_str() {
            "sh" => return FileType::Shell,
            "py" => return FileType::Python,
            "js" | "mjs" | "cjs" | "jsx" => return FileType::JavaScript,
            "ts" | "tsx" | "mts" | "cts" => return FileType::TypeScript,
            "go" => return FileType::Go,
            "rs" => return FileType::Rust,
            "java" => return FileType::Java,
            "pyc" => return FileType::PythonBytecode,
            "rb" => return FileType::Ruby,
            "php" => return FileType::Php,
            "pl" | "pm" | "t" => return FileType::Perl,
            "ps1" | "psm1" | "psd1" => return FileType::PowerShell,
            "bat" | "cmd" => return FileType::Batch,
            "vbs" | "vbe" | "wsf" | "wsc" => return FileType::Vbs,
            "c" | "h" | "cpp" | "hpp" | "cc" | "cxx" | "hxx" | "hh" | "pas" | "dpr" => {
                return FileType::C;
            }
            "lua" => return FileType::Lua,
            "cs" => return FileType::CSharp,
            "swift" => return FileType::Swift,
            "m" | "mm" => return FileType::ObjectiveC,
            "groovy" | "gradle" => return FileType::Groovy,
            "scala" | "sc" => return FileType::Scala,
            "zig" => return FileType::Zig,
            "ex" | "exs" => return FileType::Elixir,
            "scpt" | "applescript" => return FileType::AppleScript,
            "plist" => return FileType::Plist,
            "rtf" => return FileType::Rtf,
            "doc" | "xls" | "ppt" | "msg" | "dot" | "xlt" => return FileType::OleDoc,
            "docx" | "xlsx" | "pptx" | "docm" | "xlsm" | "pptm" | "dotx" | "dotm" | "xltx"
            | "xltm" => return FileType::Ooxml,
            "lnk" => return FileType::Lnk,
            "pdf" => return FileType::Pdf,
            "zip" | "7z" | "rar" | "deb" | "rpm" | "apk" | "ipa" | "xpi" | "epub" | "nupkg"
            | "vsix" | "aar" | "egg" | "whl" | "phar" => return FileType::Archive,
            "html" | "htm" => return FileType::Html,
            "md" | "markdown" => return FileType::Markdown,
            _ => {}
        }
    }

    FileType::Unknown
}

/// Detect file type from already-loaded data.
///
/// This is the core detection logic. Use `detect_file_type` when you need to read from disk.
pub(crate) fn detect_file_type_from_data(file_path: &Path, file_data: &[u8]) -> FileType {
    if file_data.len() < 4 {
        return detect_file_type_from_path(file_path);
    }
    match detect_file_type_inner(file_path, file_data) {
        Some(ft) => ft,
        None => FileType::Unknown,
    }
}

/// Detect file type and route to appropriate analyzer
pub fn detect_file_type(file_path: &Path) -> Result<FileType> {
    let file_data = std::fs::read(file_path)?;
    Ok(detect_file_type_from_data(file_path, &file_data))
}

fn detect_file_type_inner(file_path: &Path, file_data: &[u8]) -> Option<FileType> {
    tracing::debug!(
        "detect_file_type_inner: path={}, data_len={}, magic={:02x?}{:02x?}{:02x?}{:02x?}",
        file_path.display(),
        file_data.len(),
        file_data.first(),
        file_data.get(1),
        file_data.get(2),
        file_data.get(3)
    );
    // Check for RAR magic bytes "Rar!" (0x52 0x61 0x72 0x21)
    if file_data.starts_with(b"Rar!") {
        tracing::debug!("Detected RAR archive by magic");
        return Some(FileType::Archive);
    }

    // Check for compiled AppleScript magic bytes "Fasd"
    if file_data.starts_with(b"Fasd") {
        return Some(FileType::AppleScript);
    }

    // Check for RTF magic bytes
    if file_data.starts_with(b"{\\rtf") {
        return Some(FileType::Rtf);
    }

    // Check for PDF magic bytes (%PDF-)
    if file_data.starts_with(b"%PDF-") {
        return Some(FileType::Pdf);
    }

    // Check for LNK magic bytes (Windows Shell Link)
    if lnk::is_lnk(file_data) {
        return Some(FileType::Lnk);
    }

    // Check for JPEG magic bytes (FF D8 FF)
    if file_data.len() >= 3 && file_data[0] == 0xFF && file_data[1] == 0xD8 && file_data[2] == 0xFF
    {
        return Some(FileType::Jpeg);
    }

    // Check for PNG magic bytes (89 50 4E 47 0D 0A 1A 0A)
    if file_data.starts_with(b"\x89PNG\r\n\x1a\n") {
        return Some(FileType::Png);
    }

    // Check for Java class files BEFORE Mach-O (both use 0xCAFEBABE)
    if is_java_class(file_data) {
        return Some(FileType::JavaClass);
    }

    // Check for JAR files (ZIP with .jar extension) - check extension first
    let path_str = file_path.to_string_lossy().to_lowercase();
    if path_str.ends_with(".jar") || path_str.ends_with(".war") || path_str.ends_with(".ear") {
        // Verify it's a ZIP file (PK signature)
        if file_data.starts_with(b"PK") {
            return Some(FileType::Jar);
        }
    }

    // Check for OOXML documents before PE tampering heuristics.
    //
    // OOXML files are ZIP containers and can legitimately contain `MZ` inside
    // embedded previews or document streams near the start of the file. If we
    // search for displaced `MZ` first, benign `.pptx`/`.docx` samples get
    // misclassified as tampered PEs.
    if file_data.starts_with(b"PK") {
        let is_ooxml_ext = path_str.ends_with(".docx")
            || path_str.ends_with(".xlsx")
            || path_str.ends_with(".pptx")
            || path_str.ends_with(".docm")
            || path_str.ends_with(".xlsm")
            || path_str.ends_with(".pptm")
            || path_str.ends_with(".dotx")
            || path_str.ends_with(".dotm")
            || path_str.ends_with(".xltx")
            || path_str.ends_with(".xltm");
        if is_ooxml_ext || office::ooxml::is_ooxml(file_data) {
            return Some(FileType::Ooxml);
        }
    }

    // Check for Mach-O magic bytes
    if is_macho(file_data) {
        return Some(FileType::MachO);
    }

    // Check for ELF magic bytes
    if file_data.starts_with(b"\x7fELF") {
        return Some(FileType::Elf);
    }

    // Check for PE magic bytes - also detect tampered PEs with junk prefix
    // Malware often prepends bytes before the MZ header to evade detection
    if file_data.starts_with(b"MZ") {
        return Some(FileType::Pe);
    }
    // Check for MZ within first 64 bytes (tampered PE with junk prefix)
    if let Some(mz_offset) = find_mz_header(file_data, 64) {
        tracing::debug!("Detected PE with MZ at offset {} (junk prefix)", mz_offset);
        return Some(FileType::Pe);
    }

    // Check for Binary Plist
    if file_data.starts_with(b"bplist") {
        return Some(FileType::Plist);
    }

    // Check for XML Plist (byte-level search, no allocation)
    let head = &file_data[..file_data.len().min(100)];
    if memchr::memmem::find(head, b"<plist").is_some() {
        return Some(FileType::Plist);
    }

    // Check for OLE2/CFBF magic bytes (D0 CF 11 E0 A1 B1 1A E1)
    // Legacy Microsoft Office documents (.doc, .xls, .ppt, .msg)
    if file_data.len() >= 8 && office::ole2::is_ole2(file_data) {
        return Some(FileType::OleDoc);
    }

    // Check for Python bytecode (Python 3.5+): magic is XX 0D 0D 0A
    // Bytes 1-3 are always \r\r\n for all Python 3.5+ versions.
    if file_data.len() >= 4 && file_data[1] == 0x0d && file_data[2] == 0x0d && file_data[3] == 0x0a
    {
        return Some(FileType::PythonBytecode);
    }

    // Check for shell script shebang (various shells)
    if file_data.starts_with(b"#!/bin/sh")
        || file_data.starts_with(b"#!/bin/bash")
        || file_data.starts_with(b"#!/bin/zsh")
        || file_data.starts_with(b"#!/bin/dash")
        || file_data.starts_with(b"#!/usr/bin/env sh")
        || file_data.starts_with(b"#!/usr/bin/env bash")
        || file_data.starts_with(b"#!/usr/bin/env zsh")
        || file_data.starts_with(b"#!/usr/bin/env dash")
    {
        return Some(FileType::Shell);
    }

    // Check for Python script shebang
    if file_data.starts_with(b"#!/usr/bin/env python")
        || file_data.starts_with(b"#!/usr/bin/python")
        || file_data.starts_with(b"#!/usr/bin/env python3")
        || file_data.starts_with(b"#!/usr/bin/python3")
    {
        return Some(FileType::Python);
    }

    // Check for Node.js/JavaScript shebang
    if file_data.starts_with(b"#!/usr/bin/env node") || file_data.starts_with(b"#!/usr/bin/node") {
        return Some(FileType::JavaScript);
    }

    // Check for Ruby shebang
    if file_data.starts_with(b"#!/usr/bin/env ruby") || file_data.starts_with(b"#!/usr/bin/ruby") {
        return Some(FileType::Ruby);
    }

    // Check for Perl shebang
    if file_data.starts_with(b"#!/usr/bin/env perl")
        || file_data.starts_with(b"#!/usr/bin/perl")
        || file_data.starts_with(b"#!/usr/local/bin/perl")
    {
        return Some(FileType::Perl);
    }

    // Check for PHP opening tag or shebang
    if file_data.starts_with(b"<?php")
        || file_data.starts_with(b"#!/usr/bin/env php")
        || file_data.starts_with(b"#!/usr/bin/php")
    {
        return Some(FileType::Php);
    }

    // Check for Lua shebang
    if file_data.starts_with(b"#!/usr/bin/lua")
        || file_data.starts_with(b"#!/usr/bin/env lua")
        || file_data.starts_with(b"#!/usr/local/bin/lua")
    {
        return Some(FileType::Lua);
    }

    // Check for package.json (npm manifest) and manifest.json (Chrome extension)
    if let Some(file_name) = file_path.file_name() {
        let name = file_name.to_string_lossy().to_lowercase();
        if name == "package.json" {
            return Some(FileType::PackageJson);
        }
        if name == "manifest.json" {
            // Check if it's a Chrome extension manifest (byte-level, no allocation)
            if memchr::memmem::find(file_data, b"\"manifest_version\"").is_some()
                && (memchr::memmem::find(file_data, b"\"permissions\"").is_some()
                    || memchr::memmem::find(file_data, b"\"content_scripts\"").is_some()
                    || memchr::memmem::find(file_data, b"\"background\"").is_some()
                    || memchr::memmem::find(file_data, b"\"host_permissions\"").is_some())
            {
                return Some(FileType::ChromeManifest);
            }
        }
        if name == "extension.vsixmanifest" || name.ends_with(".vsixmanifest") {
            return Some(FileType::VsixManifest);
        }
        if name == "action.yml" || name == "action.yaml" {
            return Some(FileType::GithubActions);
        }
        if name == "pkg-info" || name == "metadata" {
            return Some(FileType::PkgInfo);
        }
        if name.ends_with(".plist") {
            return Some(FileType::Plist);
        }
        // Debian/Ubuntu package maintainer scripts (often lack shebang)
        // But only if they don't have a recognized source code extension
        let name = file_name.to_string_lossy().to_lowercase();
        let has_code_extension = file_path.extension().is_some_and(|ext| {
            matches!(
                ext.to_str(),
                Some(
                    "js" | "mjs"
                        | "cjs"
                        | "ts"
                        | "tsx"
                        | "py"
                        | "rb"
                        | "go"
                        | "rs"
                        | "java"
                        | "php"
                        | "pl"
                        | "pm"
                        | "lua"
                        | "cs"
                        | "swift"
                        | "m"
                        | "mm"
                        | "groovy"
                        | "gradle"
                        | "scala"
                        | "sc"
                        | "zig"
                        | "ex"
                        | "exs"
                        | "c"
                        | "h"
                        | "cpp"
                        | "hpp"
                        | "cc"
                        | "cxx"
                        | "hxx"
                        | "hh"
                )
            )
        });
        if !has_code_extension
            && (name.contains("postinst")
                || name.contains("preinst")
                || name.contains("postrm")
                || name.contains("prerm"))
        {
            return Some(FileType::Shell);
        }
    }

    // Heuristic shell detection for files without shebang
    // Look for common shell patterns in first few lines
    // Skip if file has a known code extension (will be handled later)
    let has_known_extension = file_path.extension().is_some_and(|ext| {
        matches!(
            ext.to_str(),
            Some(
                "js" | "mjs"
                    | "cjs"
                    | "ts"
                    | "tsx"
                    | "py"
                    | "rb"
                    | "go"
                    | "rs"
                    | "java"
                    | "php"
                    | "pl"
                    | "pm"
                    | "lua"
                    | "cs"
                    | "swift"
                    | "m"
                    | "mm"
                    | "groovy"
                    | "gradle"
                    | "scala"
                    | "sc"
                    | "zig"
                    | "ex"
                    | "exs"
                    | "c"
                    | "h"
                    | "cpp"
                    | "hpp"
                    | "cc"
                    | "cxx"
                    | "hxx"
                    | "hh"
                    | "sh"
                    | "bat"
                    | "cmd"
                    | "ps1"
                    | "psm1"
                    | "psd1"
            )
        )
    });
    if !has_known_extension && looks_like_shell(file_data) {
        return Some(FileType::Shell);
    }

    // Check for archives by file extension (need to check path, not just extension)
    if path_str.ends_with(".zip")
        || path_str.ends_with(".tar")
        || path_str.ends_with(".tar.gz")
        || path_str.ends_with(".tgz")
        || path_str.ends_with(".tar.bz2")
        || path_str.ends_with(".tbz2")
        || path_str.ends_with(".tar.xz")
        || path_str.ends_with(".txz")
        || path_str.ends_with(".xz")
        || path_str.ends_with(".gz")
        || path_str.ends_with(".bz2")
        || path_str.ends_with(".zst")
        || path_str.ends_with(".egg")
        || path_str.ends_with(".whl")
        || path_str.ends_with(".gem")
        || path_str.ends_with(".phar")
        || path_str.ends_with(".nupkg")
        || path_str.ends_with(".crate")
        || path_str.ends_with(".vsix")
        || path_str.ends_with(".xpi")
        || path_str.ends_with(".crx")
        || path_str.ends_with(".ipa")
        || path_str.ends_with(".apk")
        || path_str.ends_with(".aar")
        || path_str.ends_with(".epub")
        || path_str.ends_with(".7z")
        || path_str.ends_with(".rar")
        || path_str.ends_with(".pkg")
        || path_str.ends_with(".deb")
        || path_str.ends_with(".rpm")
    {
        return Some(FileType::Archive);
    }

    if let Some(ext) = file_path.extension() {
        let ext_str = ext.to_str().unwrap_or("").to_lowercase();
        if ext_str == "sh" {
            return Some(FileType::Shell);
        }
        if ext_str == "py" {
            return Some(FileType::Python);
        }
        if ext_str == "pyc" {
            return Some(FileType::PythonBytecode);
        }
        if matches!(ext_str.as_str(), "js" | "mjs" | "cjs" | "jsx") {
            return Some(FileType::JavaScript);
        }
        if matches!(ext_str.as_str(), "ts" | "tsx" | "mts" | "cts") {
            return Some(FileType::TypeScript);
        }
        if ext_str == "go" {
            return Some(FileType::Go);
        }
        if ext_str == "rs" {
            return Some(FileType::Rust);
        }
        if ext_str == "java" {
            return Some(FileType::Java);
        }
        if ext_str == "rb" {
            return Some(FileType::Ruby);
        }
        if ext_str == "php" {
            return Some(FileType::Php);
        }
        if matches!(ext_str.as_str(), "pl" | "pm" | "t") {
            return Some(FileType::Perl);
        }
        if matches!(ext_str.as_str(), "ps1" | "psm1" | "psd1") {
            return Some(FileType::PowerShell);
        }
        if matches!(ext_str.as_str(), "bat" | "cmd") {
            return Some(FileType::Batch);
        }
        if matches!(ext_str.as_str(), "vbs" | "vbe" | "wsf" | "wsc") {
            return Some(FileType::Vbs);
        }
        if matches!(
            ext_str.as_str(),
            "c" | "h" | "cpp" | "hpp" | "cc" | "cxx" | "hxx" | "hh"
        ) {
            return Some(FileType::C);
        }
        if ext_str == "lua" {
            return Some(FileType::Lua);
        }
        if ext_str == "cs" {
            return Some(FileType::CSharp);
        }
        if ext_str == "swift" {
            return Some(FileType::Swift);
        }
        if matches!(ext_str.as_str(), "m" | "mm") {
            return Some(FileType::ObjectiveC);
        }
        if matches!(ext_str.as_str(), "groovy" | "gradle") {
            return Some(FileType::Groovy);
        }
        if matches!(ext_str.as_str(), "scala" | "sc") {
            return Some(FileType::Scala);
        }
        if ext_str == "zig" {
            return Some(FileType::Zig);
        }
        if matches!(ext_str.as_str(), "ex" | "exs") {
            return Some(FileType::Elixir);
        }
        if ext_str == "scpt" || ext_str == "applescript" {
            return Some(FileType::AppleScript);
        }
        if ext_str == "html" || ext_str == "htm" {
            // Check if it actually contains HTML markup
            if looks_like_html(file_data) {
                return Some(FileType::Html);
            }
            // HTML extension but no markup - not analyzed
            return None;
        }
        if matches!(ext_str.as_str(), "md" | "markdown") {
            return Some(FileType::Markdown);
        }
        if matches!(ext_str.as_str(), "txt" | "rst" | "csv" | "log" | "json") {
            return None;
        }
    }

    // Content-based detection for files without recognized extensions
    // Check for Python code patterns (e.g., .dat files that are actually Python)
    if looks_like_python(file_data) {
        return Some(FileType::Python);
    }

    if looks_like_powershell(file_data) {
        return Some(FileType::PowerShell);
    }

    if looks_like_perl(file_data) {
        return Some(FileType::Perl);
    }

    if looks_like_batch(file_data) {
        return Some(FileType::Batch);
    }

    if looks_like_vbs(file_data) {
        return Some(FileType::Vbs);
    }

    if looks_like_c(file_data) {
        return Some(FileType::C);
    }

    None
}

/// Check if content looks like HTML (has actual markup tags)
/// Uses case-insensitive Aho-Corasick search on raw bytes — no allocation.
fn looks_like_html(data: &[u8]) -> bool {
    use aho_corasick::AhoCorasick;
    use std::sync::OnceLock;

    static AC: OnceLock<Option<AhoCorasick>> = OnceLock::new();
    let ac = AC.get_or_init(|| {
        AhoCorasick::builder()
            .ascii_case_insensitive(true)
            .build([
                "<!doctype html",
                "<html",
                "<head",
                "<body",
                "<script",
                "<div",
                "<span",
                "<p>",
                "<a ",
                "<img",
                "<form",
                "<table",
                "<meta",
                "<link",
                "<style",
            ])
            .ok()
    });

    ac.as_ref().is_some_and(|ac| ac.is_match(data))
}

/// Heuristic detection for PowerShell files without .ps1 extension
fn looks_like_powershell(data: &[u8]) -> bool {
    let s = String::from_utf8_lossy(data);
    let content = s.lines().take(100).collect::<Vec<_>>().join("\n");

    // PowerShell indicators
    let indicators = [
        "$",
        "Write-Host",
        "Invoke-",
        "New-Object",
        "Get-",
        "Set-",
        " -bxor ",
        " -bor ",
        " -band ",
        "[System.Convert]",
        "Param(",
    ];

    let count = indicators
        .iter()
        .filter(|&&pattern| content.contains(pattern))
        .count();

    // Need at least 3 indicators for confidence
    count >= 3
}

/// Heuristic detection for Python files without .py extension
/// Checks for common Python patterns like imports, function definitions, etc.
fn looks_like_python(data: &[u8]) -> bool {
    let s = String::from_utf8_lossy(data);
    let first_lines: Vec<&str> = s.lines().take(50).collect();
    let content = first_lines.join("\n");

    // Strong Python indicators (must have at least 2)
    let strong_indicators = [
        "import ",
        "from ",
        "def ",
        "class ",
        "if __name__",
        "print(",
    ];
    let strong_count = strong_indicators
        .iter()
        .filter(|&&pattern| content.contains(pattern))
        .count();

    // Secondary Python indicators
    let secondary_indicators = [
        "    ", // 4-space indentation (common in Python)
        "try:", "except", "return ", "self.", "None", "True", "False",
    ];
    let secondary_count = secondary_indicators
        .iter()
        .filter(|&&pattern| content.contains(pattern))
        .count();

    // Need at least 2 strong indicators or 1 strong + 3 secondary
    (strong_count >= 2) || (strong_count >= 1 && secondary_count >= 3)
}

/// Check if data is a Java class file
/// Java class files start with 0xCAFEBABE followed by minor/major version
fn is_java_class(data: &[u8]) -> bool {
    if data.len() < 8 {
        return false;
    }

    // Java class magic: CA FE BA BE
    if data[0] != 0xCA || data[1] != 0xFE || data[2] != 0xBA || data[3] != 0xBE {
        return false;
    }

    // Check major version (bytes 6-7, big-endian)
    // Java 1.0 = 45, Java 1.1 = 45, Java 1.2 = 46, ... Java 21 = 65
    // Mach-O fat binaries have nfat_arch in bytes 4-7 which is typically < 10
    let major_version = u16::from_be_bytes([data[6], data[7]]);

    // Valid Java class major versions are 45-70 (covering Java 1.0 through future versions)
    // Mach-O fat headers have small values (number of architectures) in this position
    (45..=70).contains(&major_version)
}

fn is_macho(data: &[u8]) -> bool {
    if data.len() < 4 {
        return false;
    }

    // Mach-O magic numbers (excluding 0xcafebabe which is handled by is_java_class first)
    let magic = u32::from_ne_bytes([data[0], data[1], data[2], data[3]]);

    // For 0xcafebabe (fat binary), we only match if is_java_class returned false
    if magic == 0xcafebabe || magic == 0xbebafeca {
        // This is a fat binary (not a Java class since is_java_class is called first)
        return true;
    }

    matches!(magic, 0xfeedface | 0xcefaedfe | 0xfeedfacf | 0xcffaedfe)
}

fn looks_like_shell(data: &[u8]) -> bool {
    // Only search the first ~2KB (covers first 5 lines in any reasonable file)
    let head = &data[..data.len().min(2048)];
    memchr::memmem::find(head, b"export ").is_some()
        || memchr::memmem::find(head, b"alias ").is_some()
        || memchr::memmem::find(head, b"set -e").is_some()
        || memchr::memmem::find(head, b"if [").is_some()
        || memchr::memmem::find(head, b"case $").is_some()
}

/// Heuristic detection for Perl files without .pl/.pm extension
fn looks_like_perl(data: &[u8]) -> bool {
    let head = &data[..data.len().min(300)];
    // Strong single-indicator: strict/warnings pragmas are almost exclusively Perl
    if memchr::memmem::find(head, b"use strict;").is_some()
        || memchr::memmem::find(head, b"use warnings;").is_some()
        || memchr::memmem::find(head, b"use strict\n").is_some()
        || memchr::memmem::find(head, b"use warnings\n").is_some()
    {
        return true;
    }
    // Secondary: need 3+ common Perl idioms
    let indicators: &[&[u8]] = &[
        b"my $", b"my @", b"my %", b"chomp", b"local $", b"@_", b"$_",
    ];
    indicators
        .iter()
        .filter(|&&p| memchr::memmem::find(head, p).is_some())
        .count()
        >= 3
}

/// Heuristic detection for Windows Batch files without .bat/.cmd extension
fn looks_like_batch(data: &[u8]) -> bool {
    let head = &data[..data.len().min(300)];
    // @echo and %~dp0 are exclusively Batch syntax
    if memchr::memmem::find(head, b"@echo").is_some()
        || memchr::memmem::find(head, b"@ECHO").is_some()
        || memchr::memmem::find(head, b"%~dp0").is_some()
    {
        return true;
    }
    // Secondary: need 2+ common Batch idioms
    let indicators: &[&[u8]] = &[
        b"SETLOCAL",
        b"ENDLOCAL",
        b"GOTO ",
        b"IF EXIST",
        b"IF NOT EXIST",
        b"SET /P",
        b"SET /A",
        b"FOR /F",
        b"CALL :",
        b"setlocal",
        b"endlocal",
    ];
    indicators
        .iter()
        .filter(|&&p| memchr::memmem::find(head, p).is_some())
        .count()
        >= 2
}

/// Heuristic detection for VBScript files without .vbs extension
fn looks_like_vbs(data: &[u8]) -> bool {
    let head = &data[..data.len().min(300)];
    // WScript and CreateObject are almost exclusively VBScript/WSH
    if memchr::memmem::find(head, b"WScript.").is_some()
        || memchr::memmem::find(head, b"Option Explicit").is_some()
    {
        return true;
    }
    // Secondary: need 2+ VBScript-specific patterns
    let indicators: &[&[u8]] = &[
        b"CreateObject(",
        b"End Sub",
        b"End Function",
        b"MsgBox ",
        b"InputBox(",
        b"WSH.",
        b"Dim ",
    ];
    indicators
        .iter()
        .filter(|&&p| memchr::memmem::find(head, p).is_some())
        .count()
        >= 2
}

/// Heuristic detection for C/C++ source files without .c/.cpp extension
fn looks_like_c(data: &[u8]) -> bool {
    let head = &data[..data.len().min(300)];
    memchr::memmem::find(head, b"#include <").is_some()
        || memchr::memmem::find(head, b"#include \"").is_some()
}

/// Find MZ header within the first `max_offset` bytes
/// Returns the offset where MZ was found, or None
#[allow(clippy::manual_find)]
fn find_mz_header(data: &[u8], max_offset: usize) -> Option<usize> {
    let search_limit = data.len().min(max_offset);
    for i in 1..search_limit.saturating_sub(1) {
        if data[i] == b'M' && data.get(i + 1) == Some(&b'Z') {
            return Some(i);
        }
    }
    None
}

/// Check if file content matches its extension's expected magic bytes
/// Returns (expected_type, actual_type_hint) if mismatch detected
#[must_use]
#[allow(dead_code)] // Used by lib.rs and commands/shared.rs, false positive from lib/bin split
pub fn check_extension_content_mismatch(
    file_path: &Path,
    file_data: &[u8],
) -> Option<(String, String)> {
    if file_data.len() < 4 {
        return None;
    }

    let _path_lower = file_path.to_string_lossy().to_lowercase();
    let extension = file_path.extension()?.to_str()?;

    // Define expected magic bytes for extensions commonly spoofed by malware
    let expected_magic: Option<(&str, &[u8])> = match extension {
        // Font formats
        "woff" => Some(("WOFF font", b"wOFF")),
        "woff2" => Some(("WOFF2 font", b"wOF2")),
        "ttf" | "ttc" => {
            // TrueType: version number 0x00010000 or 'true' or 'typ1'
            if file_data.len() >= 4
                && (file_data.starts_with(b"\x00\x01\x00\x00")
                    || file_data.starts_with(b"true")
                    || file_data.starts_with(b"typ1")
                    || file_data.starts_with(b"ttcf"))
            {
                None // Valid TTF/TTC
            } else {
                Some(("TrueType font", &[])) // Trigger mismatch
            }
        }
        "otf" => {
            // OpenType: 'OTTO' or TrueType signature
            if file_data.starts_with(b"OTTO")
                || file_data.starts_with(b"\x00\x01\x00\x00")
                || file_data.starts_with(b"true")
            {
                None // Valid OTF
            } else {
                Some(("OpenType font", &[]))
            }
        }

        // Image formats
        "gif" => Some(("GIF image", b"GIF89a")), // Also accepts GIF87a
        "bmp" => Some(("BMP image", b"BM")),
        "ico" => Some(("ICO image", b"\x00\x00\x01\x00")),
        "webp" => Some(("WebP image", b"RIFF")), // Also needs "WEBP" at offset 8
        "svg" => {
            // SVG is XML, check for <svg tag (byte-level, no allocation)
            let head = &file_data[..file_data.len().min(200)];
            if memchr::memmem::find(head, b"<svg").is_some() || head.starts_with(b"<?xml") {
                None
            } else {
                Some(("SVG image", &[]))
            }
        }

        // Audio/Video (less commonly abused, but worth checking)
        "mp3" => {
            // MP3: ID3v2 tag or sync word FF Fx
            if file_data.starts_with(b"ID3")
                || (file_data[0] == 0xFF && (file_data[1] & 0xE0) == 0xE0)
            {
                None
            } else {
                Some(("MP3 audio", &[]))
            }
        }
        "wav" => Some(("WAV audio", b"RIFF")), // Also needs "WAVE" at offset 8

        _ => None,
    };

    let (expected_desc, expected_bytes) = expected_magic?;

    // For complex checks (empty expected_bytes), we already determined there's a mismatch
    // For simple prefix checks, verify the magic bytes match
    if !expected_bytes.is_empty() && !file_data.starts_with(expected_bytes) {
        // Special cases for formats that start with alternate magic
        if extension == "gif" && file_data.starts_with(b"GIF87a") {
            return None; // GIF87a is also valid
        }

        // Try to identify what it actually is
        let actual_hint = if file_data.starts_with(b"PK") {
            "ZIP archive"
        } else if file_data.starts_with(b"\x7fELF") {
            "ELF binary"
        } else if file_data.starts_with(b"MZ") {
            "PE executable"
        } else if file_data.starts_with(b"wOFF") {
            "WOFF font"
        } else if file_data.starts_with(b"wOF2") {
            "WOFF2 font"
        } else if file_data.starts_with(b"\x89PNG") {
            "PNG image"
        } else if file_data.starts_with(b"\xFF\xD8\xFF") {
            "JPEG image"
        } else if file_data.starts_with(b"GIF8") {
            "GIF image"
        } else if file_data[0..file_data.len().min(100)]
            .iter()
            .all(|&b| b.is_ascii())
        {
            // Check if it's hex-encoded data (common obfuscation, byte-level)
            if file_data[..file_data.len().min(200)]
                .iter()
                .all(|b| b.is_ascii_hexdigit() || b.is_ascii_whitespace())
            {
                "hex-encoded data"
            } else {
                "ASCII text"
            }
        } else {
            "binary data"
        };

        return Some((expected_desc.to_string(), actual_hint.to_string()));
    }

    // For empty expected_bytes (complex validation already done above)
    if expected_bytes.is_empty() {
        // Determine actual content type
        let actual_hint = if file_data.starts_with(b"PK") {
            "ZIP archive"
        } else if file_data.starts_with(b"\x7fELF") {
            "ELF binary"
        } else if file_data.starts_with(b"MZ") {
            "PE executable"
        } else if file_data.starts_with(b"wOFF") {
            "WOFF font"
        } else if file_data.starts_with(b"wOF2") {
            "WOFF2 font"
        } else if file_data.starts_with(b"\x89PNG") {
            "PNG image"
        } else if file_data.starts_with(b"\xFF\xD8\xFF") {
            "JPEG image"
        } else if file_data.starts_with(b"GIF8") {
            "GIF image"
        } else if file_data[0..file_data.len().min(100)]
            .iter()
            .all(|&b| b.is_ascii())
        {
            // Check if it's hex-encoded data (common obfuscation, byte-level)
            if file_data[..file_data.len().min(200)]
                .iter()
                .all(|b| b.is_ascii_hexdigit() || b.is_ascii_whitespace())
            {
                "hex-encoded data"
            } else {
                "ASCII text"
            }
        } else {
            "binary data"
        };

        return Some((expected_desc.to_string(), actual_hint.to_string()));
    }

    None
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
            FileType::Pdf => vec!["pdf"],
            FileType::Html => vec!["html", "htm"],
            FileType::Markdown => vec!["md", "markdown"],
            FileType::Unknown => vec![], // No filtering for unknown types
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_woff2_mismatch_hex_encoded() {
        // Hex-encoded JavaScript disguised as WOFF2
        let hex_js = b"636F6E7374205F3078316331303030";
        let path = PathBuf::from("fonts/malware.woff2");

        let result = check_extension_content_mismatch(&path, hex_js);
        assert!(result.is_some());
        let (expected, actual) = result.unwrap();
        assert_eq!(expected, "WOFF2 font");
        assert_eq!(actual, "hex-encoded data");
    }

    #[test]
    fn test_woff_mismatch_ascii() {
        // ASCII text disguised as WOFF
        let text = b"const _0x1c1000 = function() { /* malware */ };";
        let path = PathBuf::from("fonts/fake.woff");

        let result = check_extension_content_mismatch(&path, text);
        assert!(result.is_some());
        let (expected, actual) = result.unwrap();
        assert_eq!(expected, "WOFF font");
        assert_eq!(actual, "ASCII text");
    }

    #[test]
    fn test_ttf_mismatch() {
        // PNG image disguised as TTF
        let png = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR";
        let path = PathBuf::from("fonts/fake.ttf");

        let result = check_extension_content_mismatch(&path, png);
        assert!(result.is_some());
        let (expected, actual) = result.unwrap();
        assert_eq!(expected, "TrueType font");
        assert_eq!(actual, "PNG image");
    }

    #[test]
    fn test_valid_woff2() {
        // Valid WOFF2 file
        let woff2 = b"wOF2\x00\x01\x00\x00";
        let path = PathBuf::from("fonts/real.woff2");

        let result = check_extension_content_mismatch(&path, woff2);
        assert!(result.is_none());
    }

    #[test]
    fn test_valid_ttf() {
        // Valid TrueType font
        let ttf = b"\x00\x01\x00\x00\x00\x0f\x00\x80";
        let path = PathBuf::from("fonts/real.ttf");

        let result = check_extension_content_mismatch(&path, ttf);
        assert!(result.is_none());
    }

    #[test]
    fn test_gif_mismatch() {
        // JPEG disguised as GIF
        let jpeg = b"\xFF\xD8\xFF\xE0\x00\x10JFIF";
        let path = PathBuf::from("images/fake.gif");

        let result = check_extension_content_mismatch(&path, jpeg);
        assert!(result.is_some());
        let (expected, actual) = result.unwrap();
        assert_eq!(expected, "GIF image");
        assert_eq!(actual, "JPEG image");
    }

    #[test]
    fn test_svg_valid() {
        // Valid SVG
        let svg = b"<svg xmlns=\"http://www.w3.org/2000/svg\"><path d=\"M0,0\"/></svg>";
        let path = PathBuf::from("images/real.svg");

        let result = check_extension_content_mismatch(&path, svg);
        assert!(result.is_none());
    }

    #[test]
    fn test_no_extension() {
        // File without extension - should return None
        let data = b"some random data";
        let path = PathBuf::from("README");

        let result = check_extension_content_mismatch(&path, data);
        assert!(result.is_none());
    }

    #[test]
    fn test_unsupported_extension() {
        // Extension we don't validate - should return None
        let data = b"some random data";
        let path = PathBuf::from("data.txt");

        let result = check_extension_content_mismatch(&path, data);
        assert!(result.is_none());
    }

    #[test]
    fn test_jsx_extension_support() {
        // Test that .jsx extension is recognized as JavaScript
        let path = PathBuf::from("Component.jsx");

        let file_type = detect_file_type_from_path(&path);
        assert_eq!(file_type, FileType::JavaScript);
    }

    #[test]
    fn test_html_extension_detection() {
        // .html extension should be detected
        let path = PathBuf::from("page.html");
        assert_eq!(detect_file_type_from_path(&path), FileType::Html);

        let path = PathBuf::from("index.htm");
        assert_eq!(detect_file_type_from_path(&path), FileType::Html);
    }

    #[test]
    fn test_markdown_extension_detection() {
        let path = PathBuf::from("README.md");
        assert_eq!(detect_file_type_from_path(&path), FileType::Markdown);

        let path = PathBuf::from("docs.markdown");
        assert_eq!(detect_file_type_from_path(&path), FileType::Markdown);
    }

    #[test]
    fn test_text_extension_detection() {
        let path = PathBuf::from("notes.txt");
        assert_eq!(detect_file_type_from_path(&path), FileType::Unknown);

        let path = PathBuf::from("data.csv");
        assert_eq!(detect_file_type_from_path(&path), FileType::Unknown);

        let path = PathBuf::from("app.log");
        assert_eq!(detect_file_type_from_path(&path), FileType::Unknown);
    }

    #[test]
    fn test_looks_like_html_with_markup() {
        // Various HTML patterns should be detected
        assert!(looks_like_html(b"<!DOCTYPE html><html></html>"));
        assert!(looks_like_html(b"<html><body></body></html>"));
        assert!(looks_like_html(b"<head><title>Test</title></head>"));
        assert!(looks_like_html(b"<body><p>Hello</p></body>"));
        assert!(looks_like_html(b"<script>alert('xss')</script>"));
        assert!(looks_like_html(b"<div class='container'></div>"));
        assert!(looks_like_html(b"<a href='http://evil.com'>click</a>"));
        assert!(looks_like_html(b"<img src='payload.png'>"));
        assert!(looks_like_html(b"<form action='steal.php'></form>"));
        assert!(looks_like_html(b"<style>.hidden{display:none}</style>"));
    }

    #[test]
    fn test_looks_like_html_without_markup() {
        // Plain text should not be detected as HTML
        assert!(!looks_like_html(b"https://example.com/page.html"));
        assert!(!looks_like_html(b"Just some plain text"));
        assert!(!looks_like_html(b"Hello, world!"));
        assert!(!looks_like_html(b"192.168.1.1"));
        assert!(!looks_like_html(b"user@example.com"));
    }

    #[test]
    fn test_html_content_detection() {
        use std::io::Write;
        use tempfile::NamedTempFile;

        // HTML file with actual markup -> Html
        let mut html_file = NamedTempFile::with_suffix(".html").unwrap();
        html_file
            .write_all(b"<html><body>Hello</body></html>")
            .unwrap();
        let file_type = detect_file_type(html_file.path()).unwrap();
        assert_eq!(file_type, FileType::Html);

        // HTML file without markup -> Unknown (not analyzed)
        let mut text_file = NamedTempFile::with_suffix(".html").unwrap();
        text_file.write_all(b"https://example.com/c2").unwrap();
        let file_type = detect_file_type(text_file.path()).unwrap();
        assert_eq!(file_type, FileType::Unknown);
    }

    #[test]
    fn test_markdown_content_detection() {
        use std::io::Write;
        use tempfile::NamedTempFile;

        let mut md_file = NamedTempFile::with_suffix(".md").unwrap();
        md_file.write_all(b"# Heading\n\nSome text").unwrap();
        let file_type = detect_file_type(md_file.path()).unwrap();
        assert_eq!(file_type, FileType::Markdown);
    }

    #[test]
    fn test_text_content_detection() {
        use std::io::Write;
        use tempfile::NamedTempFile;

        let mut txt_file = NamedTempFile::with_suffix(".txt").unwrap();
        txt_file.write_all(b"Plain text content").unwrap();
        let file_type = detect_file_type(txt_file.path()).unwrap();
        assert_eq!(file_type, FileType::Unknown);
    }

    // --- Python bytecode ---

    #[test]
    fn test_python_bytecode_magic_py38() {
        // Python 3.8 magic: 55 0D 0D 0A
        let data = b"\x55\x0d\x0d\x0a\x00\x00\x00\x00rest of bytecode";
        let path = PathBuf::from("cache/script.dat");
        assert_eq!(
            detect_file_type_from_data(&path, data),
            FileType::PythonBytecode
        );
    }

    #[test]
    fn test_python_bytecode_magic_py311() {
        // Python 3.11 magic: A7 0D 0D 0A
        let data = b"\xa7\x0d\x0d\x0a\x00\x00\x00\x00rest of bytecode";
        let path = PathBuf::from("__pycache__/app.cpython-311");
        assert_eq!(
            detect_file_type_from_data(&path, data),
            FileType::PythonBytecode
        );
    }

    #[test]
    fn test_python_bytecode_extension() {
        // .pyc by extension (archive entry path — no content check)
        let path = PathBuf::from("__pycache__/app.cpython-312.pyc");
        assert_eq!(detect_file_type_from_path(&path), FileType::PythonBytecode);
    }

    #[test]
    fn test_ooxml_beats_displaced_mz_heuristic() {
        let mut data = b"PK\x03\x04".to_vec();
        data.resize(12, 0);
        data.extend_from_slice(b"MZ");

        let path = PathBuf::from("slides/output.pptx");
        assert_eq!(detect_file_type_from_data(&path, &data), FileType::Ooxml);
    }

    // --- Perl ---

    #[test]
    fn test_looks_like_perl_strict() {
        assert!(looks_like_perl(b"use strict;\nuse warnings;\nmy $x = 1;\n"));
    }

    #[test]
    fn test_looks_like_perl_warnings_only() {
        assert!(looks_like_perl(b"use warnings;\nprint \"hello\\n\";\n"));
    }

    #[test]
    fn test_looks_like_perl_secondary_indicators() {
        // No strict/warnings but enough secondary idioms
        assert!(looks_like_perl(
            b"my $foo = 1;\nmy @bar = ();\nmy %baz = ();\nchomp $foo;\n"
        ));
    }

    #[test]
    fn test_looks_like_perl_negative() {
        assert!(!looks_like_perl(
            b"fn main() {\n    println!(\"hello\");\n}\n"
        ));
        assert!(!looks_like_perl(b"package main\n\nfunc main() {}\n"));
        assert!(!looks_like_perl(b"console.log('hello');\n"));
    }

    #[test]
    fn test_perl_extensionless_file_detected() {
        use std::io::Write;
        use tempfile::NamedTempFile;

        let mut f = NamedTempFile::new().unwrap();
        f.write_all(b"use strict;\nuse warnings;\n\nmy $x = 42;\nprint \"$x\\n\";\n")
            .unwrap();
        let file_type = detect_file_type(f.path()).unwrap();
        assert_eq!(file_type, FileType::Perl);
    }

    // --- Batch ---

    #[test]
    fn test_looks_like_batch_echo() {
        assert!(looks_like_batch(
            b"@echo off\nSET NAME=world\necho Hello %NAME%\n"
        ));
    }

    #[test]
    fn test_looks_like_batch_dp0() {
        assert!(looks_like_batch(
            b"SET SCRIPT_DIR=%~dp0\ncd /d %SCRIPT_DIR%\n"
        ));
    }

    #[test]
    fn test_looks_like_batch_secondary() {
        assert!(looks_like_batch(
            b"SETLOCAL\nSET /A count=0\nGOTO :end\n:end\nENDLOCAL\n"
        ));
    }

    #[test]
    fn test_looks_like_batch_negative() {
        assert!(!looks_like_batch(
            b"#!/bin/sh\nexport PATH=/usr/local/bin:$PATH\n"
        ));
        assert!(!looks_like_batch(b"use strict;\nmy $x = 1;\n"));
    }

    #[test]
    fn test_batch_extensionless_file_detected() {
        use std::io::Write;
        use tempfile::NamedTempFile;

        let mut f = NamedTempFile::new().unwrap();
        f.write_all(b"@echo off\nSETLOCAL\nSET /A x=1\nGOTO :eof\n")
            .unwrap();
        let file_type = detect_file_type(f.path()).unwrap();
        assert_eq!(file_type, FileType::Batch);
    }

    // --- VBScript ---

    #[test]
    fn test_looks_like_vbs_wscript() {
        assert!(looks_like_vbs(b"WScript.Echo \"Hello\"\nWScript.Quit 0\n"));
    }

    #[test]
    fn test_looks_like_vbs_option_explicit() {
        assert!(looks_like_vbs(b"Option Explicit\nDim x\nx = 42\n"));
    }

    #[test]
    fn test_looks_like_vbs_secondary() {
        assert!(looks_like_vbs(
            b"Dim objShell\nSet objShell = CreateObject(\"WScript.Shell\")\nEnd Sub\n"
        ));
    }

    #[test]
    fn test_looks_like_vbs_negative() {
        assert!(!looks_like_vbs(b"fn main() {}\n"));
        assert!(!looks_like_vbs(b"@echo off\nSET x=1\n"));
    }

    #[test]
    fn test_vbs_extensionless_file_detected() {
        use std::io::Write;
        use tempfile::NamedTempFile;

        let mut f = NamedTempFile::new().unwrap();
        f.write_all(b"Option Explicit\nDim msg\nmsg = \"Hello\"\nMsgBox msg\n")
            .unwrap();
        let file_type = detect_file_type(f.path()).unwrap();
        assert_eq!(file_type, FileType::Vbs);
    }

    // --- C/C++ ---

    #[test]
    fn test_looks_like_c_system_include() {
        assert!(looks_like_c(
            b"#include <stdio.h>\n#include <stdlib.h>\nint main() { return 0; }\n"
        ));
    }

    #[test]
    fn test_looks_like_c_quoted_include() {
        assert!(looks_like_c(b"#include \"myheader.h\"\nvoid foo() {}\n"));
    }

    #[test]
    fn test_looks_like_c_negative() {
        assert!(!looks_like_c(b"fn main() {}\n"));
        assert!(!looks_like_c(b"package main\nfunc main() {}\n"));
        assert!(!looks_like_c(b"use strict;\nmy $x = 1;\n"));
    }

    #[test]
    fn test_c_extensionless_file_detected() {
        use std::io::Write;
        use tempfile::NamedTempFile;

        let mut f = NamedTempFile::new().unwrap();
        f.write_all(b"#include <stdio.h>\nint main(void) { printf(\"hi\\n\"); return 0; }\n")
            .unwrap();
        let file_type = detect_file_type(f.path()).unwrap();
        assert_eq!(file_type, FileType::C);
    }
}
