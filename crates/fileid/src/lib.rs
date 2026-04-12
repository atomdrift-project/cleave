//! Fast file format identification by magic bytes, shebangs, and extensions.
//!
//! `fileid` identifies file formats using a three-stage pipeline:
//!
//! 1. **Content** — magic bytes and shebangs (first 256 bytes)
//! 2. **Filename/Extension** — well-known names and extension mapping
//! 3. **Heuristics** — lightweight pattern matching (first 2 KB, no tree-sitter)
//!
//! Content is trusted first. Extension is a fallback. If neither yields a result,
//! the file is unidentifiable and `detect` returns `None`.
//!
//! # Example
//!
//! ```
//! use std::path::Path;
//! use fileid::{detect, FileType};
//!
//! let data = b"\x7fELF\x02\x01\x01\x00";
//! let det = detect(Path::new("mystery"), data).unwrap();
//! assert_eq!(det.file_type, FileType::Elf);
//! assert!(!det.extension_mismatch());
//! ```

mod ext;
mod heuristics;
mod magic;

use std::path::Path;

/// File format identified by fileid.
///
/// Variants cover binary formats, source languages, package manifests, archives,
/// and document types. Manifest types (e.g. `PackageJson`, `CargoToml`) are included
/// because they require format-specific analysis despite being syntactically JSON/TOML.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum FileType {
    /// Mach-O binary (macOS/iOS executable or library)
    MachO,
    /// ELF binary (Linux/Unix executable or shared library)
    Elf,
    /// PE binary (Windows executable, DLL)
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
    /// systemd service unit file (.service, .service.d/*.conf)
    SystemdService,
    /// Python package metadata (PKG-INFO, METADATA)
    PkgInfo,
    /// ZIP archive (zip, apk, ipa, nupkg, etc.)
    Zip,
    /// TAR archive (plain, no compression)
    Tar,
    /// Gzip-compressed TAR (.tar.gz, .tgz, .crate)
    TarGz,
    /// Bzip2-compressed TAR (.tar.bz2, .tbz2)
    TarBz2,
    /// XZ-compressed TAR (.tar.xz, .txz)
    TarXz,
    /// Zstandard-compressed TAR (.tar.zst, .xbps)
    TarZst,
    /// Gzip-compressed single file (.gz, not a tar)
    Gz,
    /// Bzip2-compressed single file (.bz2, not a tar)
    Bz2,
    /// XZ-compressed single file (.xz, not a tar)
    Xz,
    /// Zstandard-compressed single file (.zst, not a tar)
    Zst,
    /// 7-Zip archive (.7z)
    SevenZ,
    /// RAR archive (.rar)
    Rar,
    /// Debian package (.deb)
    Deb,
    /// RPM package (.rpm)
    Rpm,
    /// macOS installer package (.pkg, XAR format)
    Pkg,
    /// Cabinet archive (.cab)
    Cab,
    /// Chrome extension (.crx)
    Crx,
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
    /// OpenDocument Format (.odt, .ods, .odp, .odg) — ZIP-based office documents
    Odf,
    /// File type could not be determined
    Unknown,
}

impl FileType {
    /// Returns true if this file type represents executable code (binaries, scripts,
    /// manifests, archives, or document formats that can carry exploits).
    #[must_use]
    pub fn is_program(&self) -> bool {
        !matches!(
            self,
            Self::Unknown | Self::Html | Self::Markdown | Self::Odf
        )
    }

    /// Returns true if this file type is an archive or compressed container.
    #[must_use]
    pub fn is_archive(&self) -> bool {
        matches!(
            self,
            Self::Zip
                | Self::Tar
                | Self::TarGz
                | Self::TarBz2
                | Self::TarXz
                | Self::TarZst
                | Self::Gz
                | Self::Bz2
                | Self::Xz
                | Self::Zst
                | Self::SevenZ
                | Self::Rar
                | Self::Deb
                | Self::Rpm
                | Self::Pkg
                | Self::Cab
                | Self::Crx
                | Self::Jar
        )
    }

    /// Returns true if this file type is a compiled native binary.
    #[must_use]
    pub fn is_binary(&self) -> bool {
        matches!(
            self,
            Self::Elf | Self::Pe | Self::MachO | Self::JavaClass | Self::PythonBytecode
        )
    }

    /// Returns true if cleave supports analysis of this file type.
    /// All currently identified types are supported; this is future-proofing.
    #[must_use]
    pub fn is_supported(&self) -> bool {
        self.is_program()
    }

    /// Returns true if this file type represents source code with AST support.
    #[must_use]
    pub fn is_source_code(&self) -> bool {
        matches!(
            self,
            Self::Python
                | Self::Ruby
                | Self::JavaScript
                | Self::TypeScript
                | Self::Php
                | Self::Perl
                | Self::Lua
                | Self::CSharp
                | Self::C
                | Self::Rust
                | Self::Shell
                | Self::PowerShell
        )
    }
}

/// How the file type was identified.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub enum DetectionSource {
    /// Magic bytes at the start of the file.
    Magic,
    /// Shebang line (`#!...`).
    Shebang,
    /// Well-known filename (e.g. `package.json`, `action.yml`).
    Filename,
    /// File extension mapping.
    Extension,
    /// Lightweight content heuristics (pattern matching).
    Heuristic,
}

/// What the file extension implies about the content.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExtensionMatch {
    /// Extension maps to the same type as content detection, or no extension present.
    Consistent,
    /// Extension maps to a different known type.
    Different(FileType),
    /// Extension is present but not recognized by fileid.
    Unknown,
}

/// Result of file format identification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Detection {
    /// The identified file type.
    pub file_type: FileType,
    /// How we identified it.
    pub source: DetectionSource,
    /// Relationship between detected type and file extension.
    ext_match: ExtensionMatch,
}

impl Detection {
    /// True when content-based detection identified a different type than
    /// the file's extension implies.
    ///
    /// This covers two cases:
    /// - Extension maps to a *different* known type than content detected
    /// - Extension is present but *unknown* to fileid (e.g. `.woff2` containing PE)
    ///
    /// Returns false when:
    /// - Detection was extension/filename-based (no conflict possible)
    /// - The file has no extension
    /// - The extension maps to the same type as content detection
    #[must_use]
    pub fn extension_mismatch(&self) -> bool {
        matches!(
            self.source,
            DetectionSource::Magic | DetectionSource::Shebang | DetectionSource::Heuristic
        ) && !matches!(self.ext_match, ExtensionMatch::Consistent)
    }

    /// The file type implied by the extension, if any.
    /// `None` when the extension is absent, unrecognized, or matches the detected type.
    #[must_use]
    pub fn extension_type(&self) -> Option<FileType> {
        match self.ext_match {
            ExtensionMatch::Different(ft) => Some(ft),
            _ => None,
        }
    }
}

/// Detect file type from content + path. Content is trusted first, extension as fallback.
///
/// Returns `None` if the file format cannot be identified.
#[must_use]
pub fn detect(path: &Path, data: &[u8]) -> Option<Detection> {
    // Stage 1: Content-based detection (magic bytes, shebangs)
    if let Some((file_type, source)) = magic::detect_from_content(path, data) {
        let ext_ft = ext::detect_from_path(path);
        let ext_match = match ext_ft {
            Some(e) if e != file_type => ExtensionMatch::Different(e),
            None if path.extension().is_some() => ExtensionMatch::Unknown,
            Some(_) | None => ExtensionMatch::Consistent,
        };
        return Some(Detection {
            file_type,
            source,
            ext_match,
        });
    }

    // Stage 2: Filename / extension
    if let Some(file_type) = ext::detect_from_path(path) {
        // HTML extension requires content validation
        if file_type == FileType::Html && !heuristics::looks_like_html(data) {
            return None;
        }
        return Some(Detection {
            file_type,
            source: if ext::is_filename_match(path) {
                DetectionSource::Filename
            } else {
                DetectionSource::Extension
            },
            ext_match: ExtensionMatch::Consistent,
        });
    }

    // Skip data/config formats — don't let heuristics misclassify them
    if ext::is_data_format(path) {
        return None;
    }

    // Stage 3: Lightweight content heuristics
    if let Some(file_type) = heuristics::detect_from_content(data) {
        return Some(Detection {
            file_type,
            source: DetectionSource::Heuristic,
            ext_match: ExtensionMatch::Consistent,
        });
    }

    None
}

/// Detect file type from content alone (magic bytes + shebangs only).
///
/// Does not consider file extensions or heuristics.
#[must_use]
pub fn detect_content(data: &[u8]) -> Option<Detection> {
    let path = Path::new("");
    magic::detect_from_content(path, data).map(|(file_type, source)| Detection {
        file_type,
        source,
        ext_match: ExtensionMatch::Consistent,
    })
}

/// Detect file type from path/extension alone.
///
/// Does not examine file content.
#[must_use]
pub fn detect_path(path: &Path) -> Option<Detection> {
    ext::detect_from_path(path).map(|file_type| Detection {
        file_type,
        source: if ext::is_filename_match(path) {
            DetectionSource::Filename
        } else {
            DetectionSource::Extension
        },
        ext_match: ExtensionMatch::Consistent,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    // Helper: assert detection result
    fn assert_detect(path: &str, data: &[u8], expected: FileType) {
        let Some(det) = detect(Path::new(path), data) else {
            panic!("expected {expected:?} for {path}, got None");
        };
        assert_eq!(det.file_type, expected, "wrong type for {path}");
    }

    fn assert_ext(path: &str, expected: FileType) {
        assert_detect(path, b"x = 1\n", expected);
    }

    // ── Binary formats (magic bytes) ─────────────────────────────────

    #[test]
    fn macho_magic() {
        assert_detect(
            "binary",
            &[0xFE, 0xED, 0xFA, 0xCE, 0, 0, 0, 0],
            FileType::MachO,
        );
        assert_detect(
            "binary",
            &[0xCF, 0xFA, 0xED, 0xFE, 0, 0, 0, 0],
            FileType::MachO,
        );
        // Fat binary (nfat_arch=2, not Java class range)
        assert_detect(
            "binary",
            &[0xCA, 0xFE, 0xBA, 0xBE, 0, 0, 0, 2],
            FileType::MachO,
        );
    }

    #[test]
    fn elf_magic() {
        assert_detect(
            "a.out",
            b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00",
            FileType::Elf,
        );
    }

    #[test]
    fn elf_mismatch() {
        let data = b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00";
        let det = detect(Path::new("malware.jpg"), data).unwrap();
        assert_eq!(det.file_type, FileType::Elf);
        assert!(det.extension_mismatch());
        assert_eq!(det.extension_type(), Some(FileType::Jpeg));
    }

    #[test]
    fn pe_magic() {
        assert_detect("app.exe", b"MZ\x90\x00\x03\x00\x00\x00", FileType::Pe);
    }

    #[test]
    fn pe_mismatch() {
        let det = detect(Path::new("font.woff2"), b"MZ\x90\x00\x03\x00\x00\x00").unwrap();
        assert_eq!(det.file_type, FileType::Pe);
        assert!(det.extension_mismatch());
    }

    // ── Java ─────────────────────────────────────────────────────────

    #[test]
    fn java_class_magic() {
        assert_detect(
            "Main.class",
            &[0xCA, 0xFE, 0xBA, 0xBE, 0, 0, 0, 52],
            FileType::JavaClass,
        );
    }

    #[test]
    fn java_class_by_ext() {
        assert_ext("Foo.class", FileType::JavaClass);
    }

    #[test]
    fn java_source_by_ext() {
        assert_ext("Foo.java", FileType::Java);
    }

    #[test]
    fn jar_pk_magic() {
        assert_detect("lib.jar", b"PK\x03\x04jar content", FileType::Jar);
    }

    #[test]
    fn jar_by_ext() {
        assert_detect("lib.war", b"PK\x03\x04war content", FileType::Jar);
    }

    // ── Python ───────────────────────────────────────────────────────

    #[test]
    fn python_by_ext() {
        assert_ext("script.py", FileType::Python);
    }

    #[test]
    fn python_by_shebang() {
        assert_detect(
            "mystery",
            b"#!/usr/bin/env python3\nimport sys\n",
            FileType::Python,
        );
    }

    #[test]
    fn python_bytecode_magic() {
        assert_detect(
            "mod.pyc",
            &[0x42, 0x0D, 0x0D, 0x0A, 0, 0, 0, 0],
            FileType::PythonBytecode,
        );
    }

    #[test]
    fn python_bytecode_by_ext() {
        assert_ext("mod.pyc", FileType::PythonBytecode);
    }

    // ── JavaScript / TypeScript ──────────────────────────────────────

    #[test]
    fn javascript_by_ext() {
        assert_ext("app.js", FileType::JavaScript);
        assert_ext("app.mjs", FileType::JavaScript);
        assert_ext("app.cjs", FileType::JavaScript);
        assert_ext("app.jsx", FileType::JavaScript);
    }

    #[test]
    fn javascript_by_shebang() {
        assert_detect(
            "tool",
            b"#!/usr/bin/env node\nconsole.log('hi');\n",
            FileType::JavaScript,
        );
    }

    #[test]
    fn typescript_by_ext() {
        assert_ext("app.ts", FileType::TypeScript);
        assert_ext("app.tsx", FileType::TypeScript);
    }

    // ── Shell ────────────────────────────────────────────────────────

    #[test]
    fn shell_by_ext() {
        assert_ext("run.sh", FileType::Shell);
        assert_ext("run.bash", FileType::Shell);
        assert_ext("run.zsh", FileType::Shell);
    }

    #[test]
    fn shell_by_shebang() {
        assert_detect("mystery", b"#!/bin/bash\necho hello\n", FileType::Shell);
        assert_detect("mystery", b"#!/bin/sh\necho hello\n", FileType::Shell);
        assert_detect(
            "mystery",
            b"#!/usr/bin/env zsh\necho hello\n",
            FileType::Shell,
        );
    }

    #[test]
    fn shell_shebang_overrides_ext() {
        let det = detect(Path::new("script.py"), b"#!/bin/bash\necho hello\n").unwrap();
        assert_eq!(det.file_type, FileType::Shell);
        assert!(det.extension_mismatch());
        assert_eq!(det.extension_type(), Some(FileType::Python));
    }

    #[test]
    fn shell_empty_falls_back_to_ext() {
        let det = detect(Path::new("run.sh"), b"").unwrap();
        assert_eq!(det.file_type, FileType::Shell);
        assert_eq!(det.source, DetectionSource::Extension);
    }

    // ── Batch ────────────────────────────────────────────────────────

    #[test]
    fn batch_by_ext() {
        assert_ext("run.bat", FileType::Batch);
        assert_ext("run.cmd", FileType::Batch);
    }

    // ── VBScript ─────────────────────────────────────────────────────

    #[test]
    fn vbs_by_ext() {
        assert_ext("script.vbs", FileType::Vbs);
        assert_ext("script.vbe", FileType::Vbs);
        assert_ext("script.wsf", FileType::Vbs);
    }

    // ── Go / Rust / Swift / Objective-C / Zig / Elixir ──────────────

    #[test]
    fn go_by_ext() {
        assert_ext("main.go", FileType::Go);
    }

    #[test]
    fn rust_by_ext() {
        assert_ext("lib.rs", FileType::Rust);
    }

    #[test]
    fn swift_by_ext() {
        assert_ext("app.swift", FileType::Swift);
    }

    #[test]
    fn objc_by_ext() {
        assert_ext("view.m", FileType::ObjectiveC);
        assert_ext("view.mm", FileType::ObjectiveC);
    }

    #[test]
    fn zig_by_ext() {
        assert_ext("main.zig", FileType::Zig);
    }

    #[test]
    fn elixir_by_ext() {
        assert_ext("app.ex", FileType::Elixir);
        assert_ext("test.exs", FileType::Elixir);
    }

    // ── Ruby ─────────────────────────────────────────────────────────

    #[test]
    fn ruby_by_ext() {
        assert_ext("app.rb", FileType::Ruby);
    }

    #[test]
    fn ruby_by_shebang() {
        assert_detect("tool", b"#!/usr/bin/env ruby\nputs 'hi'\n", FileType::Ruby);
    }

    // ── PHP ──────────────────────────────────────────────────────────

    #[test]
    fn php_by_ext() {
        assert_ext("page.php", FileType::Php);
    }

    #[test]
    fn php_by_opening_tag() {
        assert_detect("page", b"<?php\necho 'hello';\n", FileType::Php);
    }

    #[test]
    fn php_by_shebang() {
        assert_detect(
            "tool",
            b"#!/usr/bin/env php\n<?php echo 1;\n",
            FileType::Php,
        );
    }

    // ── Perl ─────────────────────────────────────────────────────────

    #[test]
    fn perl_by_ext() {
        assert_ext("script.pl", FileType::Perl);
        assert_ext("module.pm", FileType::Perl);
    }

    #[test]
    fn perl_by_shebang() {
        assert_detect("tool", b"#!/usr/bin/perl\nuse strict;\n", FileType::Perl);
    }

    // ── Lua ──────────────────────────────────────────────────────────

    #[test]
    fn lua_by_ext() {
        assert_ext("script.lua", FileType::Lua);
    }

    #[test]
    fn lua_by_shebang() {
        assert_detect("tool", b"#!/usr/bin/env lua\nprint('hi')\n", FileType::Lua);
    }

    // ── C# ───────────────────────────────────────────────────────────

    #[test]
    fn csharp_by_ext() {
        assert_ext("App.cs", FileType::CSharp);
    }

    // ── PowerShell ───────────────────────────────────────────────────

    #[test]
    fn powershell_by_ext() {
        assert_ext("script.ps1", FileType::PowerShell);
        assert_ext("module.psm1", FileType::PowerShell);
    }

    // ── Groovy / Scala ───────────────────────────────────────────────

    #[test]
    fn groovy_by_ext() {
        assert_ext("build.groovy", FileType::Groovy);
        assert_ext("build.gradle", FileType::Groovy);
    }

    #[test]
    fn scala_by_ext() {
        assert_ext("App.scala", FileType::Scala);
    }

    // ── C/C++ ────────────────────────────────────────────────────────

    #[test]
    fn c_by_ext() {
        assert_ext("main.c", FileType::C);
        assert_ext("main.h", FileType::C);
        assert_ext("main.cpp", FileType::C);
        assert_ext("main.hpp", FileType::C);
    }

    // ── Manifests ────────────────────────────────────────────────────

    #[test]
    fn package_json() {
        let det = detect(Path::new("package.json"), b"{}").unwrap();
        assert_eq!(det.file_type, FileType::PackageJson);
        assert_eq!(det.source, DetectionSource::Filename);
    }

    #[test]
    fn composer_json() {
        assert_ext("composer.json", FileType::ComposerJson);
    }

    #[test]
    fn cargo_toml() {
        assert_ext("Cargo.toml", FileType::CargoToml);
    }

    #[test]
    fn pyproject_toml() {
        assert_ext("pyproject.toml", FileType::PyProjectToml);
    }

    #[test]
    fn vsix_manifest() {
        assert_detect("extension.vsixmanifest", b"<xml/>", FileType::VsixManifest);
    }

    #[test]
    fn chrome_manifest() {
        let data = br#"{"manifest_version": 3, "permissions": ["storage"]}"#;
        assert_detect("manifest.json", data, FileType::ChromeManifest);
    }

    #[test]
    fn github_actions_workflow() {
        let det = detect(Path::new(".github/workflows/ci.yml"), b"name: CI\n").unwrap();
        assert_eq!(det.file_type, FileType::GithubActions);
        assert_eq!(det.source, DetectionSource::Filename);
    }

    #[test]
    fn github_actions_composite() {
        assert_detect("action.yml", b"name: My Action\n", FileType::GithubActions);
    }

    #[test]
    fn systemd_service() {
        assert_detect(
            "evil.service",
            b"[Unit]\nDescription=Evil\n[Service]\nExecStart=/bin/true\n",
            FileType::SystemdService,
        );
    }

    #[test]
    fn systemd_service_drop_in() {
        assert_ext(
            "/etc/systemd/system/ssh.service.d/override.conf",
            FileType::SystemdService,
        );
    }

    #[test]
    fn pkg_info() {
        assert_detect("PKG-INFO", b"Metadata-Version: 2.1\n", FileType::PkgInfo);
        assert_detect("METADATA", b"Metadata-Version: 2.1\n", FileType::PkgInfo);
    }

    // ── Archives ─────────────────────────────────────────────────────

    #[test]
    fn zip_archive() {
        assert_detect("data.zip", b"PK\x03\x04content", FileType::Zip);
    }

    #[test]
    fn rar_archive() {
        assert_detect("data.rar", b"Rar!\x1a\x07\x01\x00", FileType::Rar);
    }

    #[test]
    fn gzip_archive() {
        assert_detect("data.gz", &[0x1f, 0x8b, 0x08, 0x00], FileType::Gz);
    }

    #[test]
    fn xz_archive() {
        assert_detect("data.xz", b"\xfd7zXZ\x00", FileType::Xz);
    }

    #[test]
    fn bzip2_archive() {
        assert_detect("data.bz2", b"BZh91AY&SY", FileType::Bz2);
    }

    #[test]
    fn sevenz_archive() {
        assert_detect("data.7z", b"7z\xBC\xAF\x27\x1C\x00", FileType::SevenZ);
    }

    #[test]
    fn zstd_archive() {
        assert_detect("data.zst", &[0x28, 0xB5, 0x2F, 0xFD, 0, 0], FileType::Zst);
    }

    #[test]
    fn tar_gz_by_ext() {
        assert_ext("data.tar.gz", FileType::TarGz);
        assert_ext("data.tgz", FileType::TarGz);
    }

    #[test]
    fn deb_by_ext() {
        assert_ext("package.deb", FileType::Deb);
    }

    #[test]
    fn rpm_by_ext() {
        assert_ext("package.rpm", FileType::Rpm);
    }

    #[test]
    fn is_archive_returns_true_for_archives() {
        assert!(FileType::Zip.is_archive());
        assert!(FileType::TarGz.is_archive());
        assert!(FileType::Rar.is_archive());
        assert!(FileType::SevenZ.is_archive());
        assert!(FileType::Deb.is_archive());
        assert!(FileType::Jar.is_archive());
        assert!(!FileType::Elf.is_archive());
        assert!(!FileType::Python.is_archive());
    }

    #[test]
    fn is_binary_returns_true_for_binaries() {
        assert!(FileType::Elf.is_binary());
        assert!(FileType::Pe.is_binary());
        assert!(FileType::MachO.is_binary());
        assert!(FileType::JavaClass.is_binary());
        assert!(!FileType::Zip.is_binary());
        assert!(!FileType::Python.is_binary());
    }

    // ── Documents ────────────────────────────────────────────────────

    #[test]
    fn pdf_magic() {
        assert_detect("doc.pdf", b"%PDF-1.4 content", FileType::Pdf);
    }

    #[test]
    fn pdf_by_ext() {
        assert_ext("doc.pdf", FileType::Pdf);
    }

    #[test]
    fn rtf_magic() {
        assert_detect("doc.rtf", b"{\\rtf1\\ansi content", FileType::Rtf);
    }

    #[test]
    fn ole_doc_magic() {
        let mut data = vec![0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1];
        data.extend_from_slice(&[0; 100]);
        assert_detect("doc.doc", &data, FileType::OleDoc);
    }

    #[test]
    fn ole_by_ext() {
        assert_ext("file.doc", FileType::OleDoc);
        assert_ext("file.xls", FileType::OleDoc);
        assert_ext("file.ppt", FileType::OleDoc);
        assert_ext("file.msg", FileType::OleDoc);
    }

    #[test]
    fn ooxml_by_ext_magic() {
        assert_detect("report.docx", b"PK\x03\x04office", FileType::Ooxml);
        assert_detect("sheet.xlsx", b"PK\x03\x04office", FileType::Ooxml);
        assert_detect("slides.pptx", b"PK\x03\x04office", FileType::Ooxml);
    }

    #[test]
    fn ooxml_by_ext_only() {
        assert_ext("report.docx", FileType::Ooxml);
        assert_ext("report.docm", FileType::Ooxml);
    }

    // ── Apple formats ────────────────────────────────────────────────

    #[test]
    fn applescript_magic() {
        assert_detect("script.scpt", b"Fasd\x00\x00", FileType::AppleScript);
    }

    #[test]
    fn applescript_by_ext() {
        assert_ext("script.scpt", FileType::AppleScript);
        assert_ext("script.applescript", FileType::AppleScript);
    }

    #[test]
    fn plist_binary() {
        assert_detect("prefs", b"bplist00\x00\x00\x00", FileType::Plist);
    }

    #[test]
    fn plist_xml() {
        assert_detect(
            "Info.plist",
            b"<?xml version=\"1.0\"?>\n<!DOCTYPE plist>",
            FileType::Plist,
        );
    }

    #[test]
    fn plist_by_ext() {
        assert_ext("prefs.plist", FileType::Plist);
    }

    // ── Images ───────────────────────────────────────────────────────

    #[test]
    fn jpeg_magic() {
        assert_detect(
            "photo.jpg",
            &[0xFF, 0xD8, 0xFF, 0xE0, 0, 0x10],
            FileType::Jpeg,
        );
    }

    #[test]
    fn jpeg_by_ext() {
        assert_ext("photo.jpg", FileType::Jpeg);
        assert_ext("photo.jpeg", FileType::Jpeg);
    }

    #[test]
    fn png_magic() {
        assert_detect(
            "image.png",
            b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR",
            FileType::Png,
        );
    }

    #[test]
    fn png_by_ext() {
        assert_ext("image.png", FileType::Png);
    }

    // ── Other formats ────────────────────────────────────────────────

    #[test]
    fn lnk_magic() {
        let mut data = vec![
            0x4C, 0x00, 0x00, 0x00, 0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x46,
        ];
        data.extend_from_slice(&[0; 100]);
        assert_detect("shortcut.lnk", &data, FileType::Lnk);
    }

    #[test]
    fn lnk_by_ext() {
        assert_ext("shortcut.lnk", FileType::Lnk);
    }

    #[test]
    fn pickle_magic() {
        assert_detect("model.pkl", &[0x80, 0x04, 0x95, 0x00], FileType::Pickle);
    }

    #[test]
    fn pickle_by_ext() {
        assert_ext("model.pkl", FileType::Pickle);
        assert_ext("data.pickle", FileType::Pickle);
    }

    #[test]
    fn html_with_content() {
        assert_detect(
            "page.html",
            b"<!DOCTYPE html><html><body>hi</body></html>",
            FileType::Html,
        );
    }

    #[test]
    fn html_without_content_skipped() {
        // .html extension but no HTML tags → skip
        assert!(detect(Path::new("page.html"), b"just plain text").is_none());
    }

    #[test]
    fn markdown_by_ext() {
        assert_ext("readme.md", FileType::Markdown);
        assert_ext("notes.markdown", FileType::Markdown);
    }

    // ── Skip / non-match ─────────────────────────────────────────────

    #[test]
    fn unknown_binary_returns_none() {
        assert!(detect(Path::new("data.bin"), b"\x00\x00\x00\x00").is_none());
    }

    #[test]
    fn yaml_not_misclassified() {
        assert!(detect(Path::new("config.yaml"), b"name: test\non: push\n").is_none());
    }

    #[test]
    fn json_data_not_misclassified() {
        assert!(detect(Path::new("data.json"), b"{\"key\": \"value\"}").is_none());
    }

    #[test]
    fn txt_not_misclassified() {
        assert!(detect(Path::new("notes.txt"), b"some text here").is_none());
    }

    // ── API: detect_content / detect_path ────────────────────────────

    #[test]
    fn detect_content_only() {
        let det = detect_content(b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR").unwrap();
        assert_eq!(det.file_type, FileType::Png);
    }

    #[test]
    fn detect_path_only() {
        let det = detect_path(Path::new("app.js")).unwrap();
        assert_eq!(det.file_type, FileType::JavaScript);
    }

    // ── Filename-detected types inside temp directories ──────────────

    /// Filename-detected types (package.json, Cargo.toml, etc.) must be
    /// recognized when the file sits inside a temp directory, which is how
    /// the HTTP upload handlers preserve the original name.
    #[test]
    fn package_json_in_temp_dir() {
        let det = detect(Path::new("/tmp/cleave-abc123/package.json"), b"{}").unwrap();
        assert_eq!(det.file_type, FileType::PackageJson);
    }

    #[test]
    fn cargo_toml_in_temp_dir() {
        let det = detect(Path::new("/tmp/cleave-abc123/Cargo.toml"), b"[package]").unwrap();
        assert_eq!(det.file_type, FileType::CargoToml);
    }

    #[test]
    fn composer_json_in_temp_dir() {
        let det = detect(Path::new("/tmp/cleave-abc123/composer.json"), b"{}").unwrap();
        assert_eq!(det.file_type, FileType::ComposerJson);
    }

    /// A temp file with a mangled name (old behavior: suffix-based) must NOT
    /// match filename detection — this documents why the temp-directory
    /// approach is necessary.
    #[test]
    fn mangled_temp_name_does_not_detect_package_json() {
        // Old behavior: TempBuilder::new().suffix("_package.json") produces
        // a filename like ".tmpXXXXXX_package.json" which doesn't match.
        assert!(detect(Path::new("/tmp/.tmpABC_package.json"), b"{}").is_none());
    }
}
