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

pub(crate) mod applescript;
pub(crate) mod archive;
pub(crate) mod ast_walker;

// Universal metrics analyzers
pub(crate) mod comment_metrics;
pub(crate) mod function_metrics;
pub(crate) mod identifier_metrics;
pub(crate) mod import_metrics;
pub(crate) mod string_metrics;
pub(crate) mod symbol_extraction;
pub(crate) mod text_metrics;
pub(crate) mod utils;

// Dedicated analyzers for binary/bytecode/manifest formats
pub(crate) mod chrome_manifest;
pub(crate) mod elf;
pub(crate) mod java_class;
pub(crate) mod lnk;
pub(crate) mod macho;
pub(crate) mod macho_codesign;
pub(crate) mod package_json;
pub mod pe;
pub(crate) mod png;
pub(crate) mod rtf;
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

        // LNK files - Windows shortcuts
        FileType::Lnk => Some(Box::new(
            lnk::LnkAnalyzer::new().with_capability_mapper(mapper_or_empty),
        )),

        // PNG images - steganography detection
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

        // Python package metadata - use generic analyzer for string/trait matching
        FileType::PkgInfo | FileType::Plist => Some(Box::new(
            generic::GenericAnalyzer::new(file_type.clone())
                .with_capability_mapper(mapper_or_empty),
        )),

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

        // LNK files - Windows shortcuts
        FileType::Lnk => Some(Box::new(
            lnk::LnkAnalyzer::new().with_capability_mapper_arc(mapper_or_empty),
        )),

        // PNG images - steganography detection
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

        // Python package metadata - use generic analyzer for string/trait matching
        FileType::PkgInfo | FileType::Plist => Some(Box::new(
            generic::GenericAnalyzer::new(file_type.clone())
                .with_capability_mapper_arc(mapper_or_empty),
        )),

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

/// Trait for file analyzers
#[allow(dead_code)] // Used by tests and archive_utils, false positive from lib/bin split
pub trait Analyzer {
    /// Analyze a file and return a report
    fn analyze(&self, file_path: &Path) -> Result<AnalysisReport>;

    /// Check if this analyzer can handle the given file
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
            "rb" => return FileType::Ruby,
            "php" => return FileType::Php,
            "pl" | "pm" | "t" => return FileType::Perl,
            "ps1" | "psm1" | "psd1" => return FileType::PowerShell,
            "bat" | "cmd" => return FileType::Batch,
            "c" | "h" => return FileType::C,
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
            "lnk" => return FileType::Lnk,
            "zip" | "7z" | "rar" | "deb" | "rpm" | "apk" | "ipa" | "xpi" | "epub" | "nupkg"
            | "vsix" | "aar" | "egg" | "whl" | "phar" => return FileType::Archive,
            _ => {}
        }
    }

    FileType::Unknown
}

/// Detect file type and route to appropriate analyzer
pub fn detect_file_type(file_path: &Path) -> Result<FileType> {
    let file_data = std::fs::read(file_path)?;

    if file_data.len() < 4 {
        // Fall back to extension-based detection for tiny/empty files
        return Ok(detect_file_type_from_path(file_path));
    }

    // Check for compiled AppleScript magic bytes "Fasd"
    if file_data.starts_with(b"Fasd") {
        return Ok(FileType::AppleScript);
    }

    // Check for RTF magic bytes
    if file_data.starts_with(b"{\\rtf") {
        return Ok(FileType::Rtf);
    }

    // Check for LNK magic bytes (Windows Shell Link)
    if lnk::is_lnk(&file_data) {
        return Ok(FileType::Lnk);
    }

    // Check for JPEG magic bytes (FF D8 FF)
    if file_data.len() >= 3 && file_data[0] == 0xFF && file_data[1] == 0xD8 && file_data[2] == 0xFF
    {
        return Ok(FileType::Jpeg);
    }

    // Check for PNG magic bytes (89 50 4E 47 0D 0A 1A 0A)
    if file_data.starts_with(b"\x89PNG\r\n\x1a\n") {
        return Ok(FileType::Png);
    }

    // Check for Java class files BEFORE Mach-O (both use 0xCAFEBABE)
    if is_java_class(&file_data) {
        return Ok(FileType::JavaClass);
    }

    // Check for JAR files (ZIP with .jar extension) - check extension first
    let path_str = file_path.to_string_lossy().to_lowercase();
    if path_str.ends_with(".jar") || path_str.ends_with(".war") || path_str.ends_with(".ear") {
        // Verify it's a ZIP file (PK signature)
        if file_data.starts_with(b"PK") {
            return Ok(FileType::Jar);
        }
    }

    // Check for Mach-O magic bytes
    if is_macho(&file_data) {
        return Ok(FileType::MachO);
    }

    // Check for ELF magic bytes
    if file_data.starts_with(b"\x7fELF") {
        return Ok(FileType::Elf);
    }

    // Check for PE magic bytes
    if file_data.starts_with(b"MZ") {
        return Ok(FileType::Pe);
    }

    // Check for Binary Plist
    if file_data.starts_with(b"bplist") {
        return Ok(FileType::Plist);
    }

    // Check for XML Plist
    let content_start = String::from_utf8_lossy(&file_data[..file_data.len().min(100)]);
    if (content_start.contains("<?xml") && content_start.contains("<plist"))
        || content_start.contains("<plist")
    {
        return Ok(FileType::Plist);
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
        return Ok(FileType::Shell);
    }

    // Check for Python script shebang
    if file_data.starts_with(b"#!/usr/bin/env python")
        || file_data.starts_with(b"#!/usr/bin/python")
        || file_data.starts_with(b"#!/usr/bin/env python3")
        || file_data.starts_with(b"#!/usr/bin/python3")
    {
        return Ok(FileType::Python);
    }

    // Check for Node.js/JavaScript shebang
    if file_data.starts_with(b"#!/usr/bin/env node") || file_data.starts_with(b"#!/usr/bin/node") {
        return Ok(FileType::JavaScript);
    }

    // Check for Ruby shebang
    if file_data.starts_with(b"#!/usr/bin/env ruby") || file_data.starts_with(b"#!/usr/bin/ruby") {
        return Ok(FileType::Ruby);
    }

    // Check for Perl shebang
    if file_data.starts_with(b"#!/usr/bin/env perl")
        || file_data.starts_with(b"#!/usr/bin/perl")
        || file_data.starts_with(b"#!/usr/local/bin/perl")
    {
        return Ok(FileType::Perl);
    }

    // Check for PHP opening tag or shebang
    if file_data.starts_with(b"<?php")
        || file_data.starts_with(b"#!/usr/bin/env php")
        || file_data.starts_with(b"#!/usr/bin/php")
    {
        return Ok(FileType::Php);
    }

    // Check for Lua shebang
    if file_data.starts_with(b"#!/usr/bin/lua")
        || file_data.starts_with(b"#!/usr/bin/env lua")
        || file_data.starts_with(b"#!/usr/local/bin/lua")
    {
        return Ok(FileType::Lua);
    }

    // Check for package.json (npm manifest) and manifest.json (Chrome extension)
    if let Some(file_name) = file_path.file_name() {
        let name = file_name.to_string_lossy().to_lowercase();
        if name == "package.json" {
            return Ok(FileType::PackageJson);
        }
        if name == "manifest.json" {
            // Check if it's a Chrome extension manifest by looking for manifest_version
            let content = String::from_utf8_lossy(&file_data);
            if content.contains("\"manifest_version\"")
                && (content.contains("\"permissions\"")
                    || content.contains("\"content_scripts\"")
                    || content.contains("\"background\"")
                    || content.contains("\"host_permissions\""))
            {
                return Ok(FileType::ChromeManifest);
            }
        }
        if name == "extension.vsixmanifest" || name.ends_with(".vsixmanifest") {
            return Ok(FileType::VsixManifest);
        }
        if name == "pkg-info" || name == "metadata" {
            return Ok(FileType::PkgInfo);
        }
        if name.ends_with(".plist") {
            return Ok(FileType::Plist);
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
                )
            )
        });
        if !has_code_extension
            && (name.contains("postinst")
                || name.contains("preinst")
                || name.contains("postrm")
                || name.contains("prerm"))
        {
            return Ok(FileType::Shell);
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
                    | "sh"
                    | "bat"
                    | "cmd"
                    | "ps1"
                    | "psm1"
                    | "psd1"
            )
        )
    });
    if !has_known_extension && looks_like_shell(&file_data) {
        return Ok(FileType::Shell);
    }

    // Check for archives by file extension (need to check path, not just extension)
    let path_str = file_path.to_string_lossy().to_lowercase();
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
        || path_str.ends_with(".pkg")
        || path_str.ends_with(".deb")
        || path_str.ends_with(".rpm")
    {
        return Ok(FileType::Archive);
    }

    if let Some(ext) = file_path.extension() {
        let ext_str = ext.to_str().unwrap_or("").to_lowercase();
        if ext_str == "sh" {
            return Ok(FileType::Shell);
        }
        if ext_str == "py" {
            return Ok(FileType::Python);
        }
        if matches!(ext_str.as_str(), "js" | "mjs" | "cjs" | "jsx") {
            return Ok(FileType::JavaScript);
        }
        if matches!(ext_str.as_str(), "ts" | "tsx" | "mts" | "cts") {
            return Ok(FileType::TypeScript);
        }
        if ext_str == "go" {
            return Ok(FileType::Go);
        }
        if ext_str == "rs" {
            return Ok(FileType::Rust);
        }
        if ext_str == "java" {
            return Ok(FileType::Java);
        }
        if ext_str == "rb" {
            return Ok(FileType::Ruby);
        }
        if ext_str == "php" {
            return Ok(FileType::Php);
        }
        if matches!(ext_str.as_str(), "pl" | "pm" | "t") {
            return Ok(FileType::Perl);
        }
        if matches!(ext_str.as_str(), "ps1" | "psm1" | "psd1") {
            return Ok(FileType::PowerShell);
        }
        if matches!(ext_str.as_str(), "bat" | "cmd") {
            return Ok(FileType::Batch);
        }
        if ext_str == "c" || ext_str == "h" {
            return Ok(FileType::C);
        }
        if ext_str == "lua" {
            return Ok(FileType::Lua);
        }
        if ext_str == "cs" {
            return Ok(FileType::CSharp);
        }
        if ext_str == "swift" {
            return Ok(FileType::Swift);
        }
        if matches!(ext_str.as_str(), "m" | "mm") {
            return Ok(FileType::ObjectiveC);
        }
        if matches!(ext_str.as_str(), "groovy" | "gradle") {
            return Ok(FileType::Groovy);
        }
        if matches!(ext_str.as_str(), "scala" | "sc") {
            return Ok(FileType::Scala);
        }
        if ext_str == "zig" {
            return Ok(FileType::Zig);
        }
        if matches!(ext_str.as_str(), "ex" | "exs") {
            return Ok(FileType::Elixir);
        }
        if ext_str == "scpt" || ext_str == "applescript" {
            return Ok(FileType::AppleScript);
        }
    }

    // Content-based detection for files without recognized extensions
    // Check for Python code patterns (e.g., .dat files that are actually Python)
    if looks_like_python(&file_data) {
        return Ok(FileType::Python);
    }

    if looks_like_powershell(&file_data) {
        return Ok(FileType::PowerShell);
    }

    Ok(FileType::Unknown)
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
    let s = String::from_utf8_lossy(data);
    let first_lines: String = s.lines().take(5).collect::<Vec<_>>().join("\n");

    first_lines.contains("export ")
        || first_lines.contains("alias ")
        || first_lines.contains("set -e")
        || first_lines.contains("if [")
        || first_lines.contains("case $")
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
            // SVG is XML, check for <svg tag
            let s = String::from_utf8_lossy(&file_data[..file_data.len().min(200)]);
            if s.contains("<svg") || s.starts_with("<?xml") {
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
            // Check if it's hex-encoded data (common obfuscation)
            let preview = String::from_utf8_lossy(&file_data[..file_data.len().min(200)]);
            if preview
                .chars()
                .all(|c| c.is_ascii_hexdigit() || c.is_ascii_whitespace())
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
            // Check if it's hex-encoded data (common obfuscation)
            let preview = String::from_utf8_lossy(&file_data[..file_data.len().min(200)]);
            if preview
                .chars()
                .all(|c| c.is_ascii_hexdigit() || c.is_ascii_whitespace())
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
#[derive(Debug, Clone, PartialEq)]
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
    /// Windows Shell Link file (.lnk)
    Lnk,
    /// X.509 / DER certificate file
    #[allow(dead_code)] // Used in streaming.rs match arms
    Certificate,
    /// JPEG image
    Jpeg,
    /// PNG image
    Png,
    /// File type could not be determined
    Unknown,
}

impl FileType {
    /// Returns true if this file type represents executable code (binaries, scripts, etc.)
    /// as opposed to data files (images, documents, etc.)
    #[must_use]
    pub(crate) fn is_program(&self) -> bool {
        match self {
            FileType::MachO
            | FileType::Elf
            | FileType::Pe
            | FileType::Shell
            | FileType::Batch
            | FileType::Python
            | FileType::JavaScript
            | FileType::TypeScript
            | FileType::Go
            | FileType::Rust
            | FileType::Java
            | FileType::JavaClass
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
            | FileType::Lnk
            | FileType::Png => true, // PNG included for steganography detection
            FileType::Archive
            | FileType::Unknown
            | FileType::Jpeg
            | FileType::Certificate => false, // Skip other images and unknown files by default in dir scans
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
    pub(crate) fn yara_filetypes(&self) -> Vec<&'static str> {
        match self {
            FileType::MachO => vec!["macho", "elf", "so"],
            FileType::Elf => vec!["elf", "so", "ko"],
            FileType::Pe => vec!["pe", "exe", "dll", "bat", "ps1"],
            FileType::Shell => {
                vec!["sh", "bash", "zsh", "application/x-sh", "application/x-zsh"]
            }
            FileType::Batch => vec!["bat", "cmd", "batch"],
            FileType::Python => vec!["py", "pyc"],
            FileType::JavaScript => vec!["js", "mjs", "cjs", "jsx", "ts"],
            FileType::TypeScript => vec!["ts", "tsx", "mts", "cts", "js"],
            FileType::Go => vec!["go"],
            FileType::Rust => vec!["rs"],
            FileType::Java => vec!["java"],
            FileType::JavaClass => vec!["class", "java"],
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
            FileType::Lnk => vec!["lnk", "shortcut"],
            FileType::Jpeg => vec!["jpeg", "jpg"],
            FileType::Png => vec!["png"],
            FileType::Unknown | FileType::Certificate => vec![], // No filtering for unknown types
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
}
