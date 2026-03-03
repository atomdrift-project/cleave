//! Core types for composite rules: Platform and FileType enums.

use serde::{Deserialize, Serialize};

/// Platform specifier for trait targeting
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "lowercase")]
pub(crate) enum Platform {
    /// Applies to all platforms
    All,
    /// Linux operating system
    Linux,
    /// macOS operating system
    MacOS,
    /// Windows operating system
    Windows,
    /// Any Unix-like operating system
    Unix,
    /// Android mobile OS
    Android,
    /// iOS mobile OS
    Ios,
}

/// File type specifier for rule targeting
#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub(crate) enum FileType {
    /// Applies to all file types
    All,
    /// ELF binary (Linux/Unix executable or shared library)
    Elf,
    /// Mach-O binary (macOS/iOS executable or library)
    Macho,
    /// PE binary (Windows executable)
    Pe,
    /// macOS dynamic library (.dylib)
    Dylib,
    /// Linux shared object (.so)
    So,
    /// Windows dynamic-link library (.dll)
    Dll,
    /// Java bytecode class file
    Class,
    /// Unix shell script (bash, sh, zsh, etc.)
    Shell,
    /// Windows batch script (.bat, .cmd)
    Batch,
    /// Python source file
    Python,
    /// JavaScript source file
    JavaScript,
    /// TypeScript source file
    TypeScript,
    /// Rust source file
    Rust,
    /// Java source file
    Java,
    /// Ruby source file
    Ruby,
    /// C/C++ source file (cpp aliases to this)
    C,
    /// C++ source file (aliased to C, kept for backwards compatibility)
    #[allow(dead_code)]
    Cpp,
    /// Go source file
    Go,
    /// PHP source file
    Php,
    /// C# source file
    CSharp,
    /// Lua source file
    Lua,
    /// Perl source file
    Perl,
    /// PowerShell script
    PowerShell,
    /// Swift source file
    Swift,
    /// Objective-C source file
    ObjectiveC,
    /// Groovy source file
    Groovy,
    /// Scala source file
    Scala,
    /// Zig source file
    Zig,
    /// Elixir source file
    Elixir,
    /// AppleScript source file
    AppleScript,
    /// VBScript source file
    Vbs,
    /// HTML file
    Html,
    /// npm package.json manifest
    PackageJson,
    /// Chrome extension manifest.json
    ChromeManifest,
    /// Rust Cargo.toml manifest
    CargoToml,
    /// Python pyproject.toml manifest
    PyProjectToml,
    /// GitHub Actions workflow YAML
    GithubActions,
    /// PHP composer.json manifest
    ComposerJson,
    /// Python package metadata (PKG-INFO, METADATA)
    PkgInfo,
    /// Apple Property List (.plist)
    Plist,
    /// Rich Text Format (.rtf)
    Rtf,
    /// Windows Shell Link (.lnk)
    Lnk,
    /// iOS App Package (.ipa) - not extractable by cleave
    Ipa,
    /// Plain text file
    Text,
    /// JPEG image
    Jpeg,
    /// PNG image
    Png,
}

impl FileType {
    /// Returns true if this file type is source code (not a compiled binary)
    #[must_use]
    pub(crate) fn is_source_code(&self) -> bool {
        matches!(
            self,
            FileType::Shell
                | FileType::Batch
                | FileType::Python
                | FileType::JavaScript
                | FileType::TypeScript
                | FileType::Rust
                | FileType::Java
                | FileType::Ruby
                | FileType::C
                | FileType::Cpp
                | FileType::Go
                | FileType::CSharp
                | FileType::Php
                | FileType::Lua
                | FileType::Perl
                | FileType::PowerShell
                | FileType::Swift
                | FileType::ObjectiveC
                | FileType::Groovy
                | FileType::Scala
                | FileType::Zig
                | FileType::Elixir
                | FileType::AppleScript
                | FileType::Vbs
                | FileType::Html
        )
    }

    /// Returns a list of all concrete file types (excluding All)
    #[must_use]
    pub(crate) fn all_concrete_variants() -> Vec<FileType> {
        vec![
            // Binary formats
            FileType::Elf,
            FileType::Macho,
            FileType::Pe,
            FileType::Dylib,
            FileType::So,
            FileType::Dll,
            FileType::Class,
            // Source code formats
            FileType::Shell,
            FileType::Batch,
            FileType::Python,
            FileType::JavaScript,
            FileType::TypeScript,
            FileType::Rust,
            FileType::Java,
            FileType::Ruby,
            FileType::C,
            FileType::Cpp,
            FileType::Go,
            FileType::Php,
            FileType::CSharp,
            FileType::Lua,
            FileType::Perl,
            FileType::PowerShell,
            FileType::Swift,
            FileType::ObjectiveC,
            FileType::Groovy,
            FileType::Scala,
            FileType::Zig,
            FileType::Elixir,
            FileType::AppleScript,
            FileType::Vbs,
            FileType::Html,
            // Manifest/config formats
            FileType::PackageJson,
            FileType::ChromeManifest,
            FileType::CargoToml,
            FileType::PyProjectToml,
            FileType::GithubActions,
            FileType::ComposerJson,
            FileType::PkgInfo,
            FileType::Plist,
            FileType::Rtf,
            FileType::Lnk,
            // Archive/installer formats
            FileType::Ipa,
            // Generic formats
            FileType::Text,
            // Image formats
            FileType::Jpeg,
            FileType::Png,
        ]
    }

    /// Parse a file type string into a FileType enum variant.
    /// This is the canonical mapping used by both production scanning and test-rules.
    #[must_use]
    pub(crate) fn from_str(file_type: &str) -> FileType {
        match file_type.to_lowercase().as_str() {
            "elf" => FileType::Elf,
            "macho" => FileType::Macho,
            "pe" | "exe" => FileType::Pe,
            "dylib" => FileType::Dylib,
            "so" => FileType::So,
            "dll" => FileType::Dll,
            "shell" | "shellscript" | "shell_script" => FileType::Shell,
            "batch" | "bat" | "cmd" => FileType::Batch,
            "python" | "python_script" => FileType::Python,
            "javascript" | "js" => FileType::JavaScript,
            "typescript" | "ts" => FileType::TypeScript,
            "c" | "h" | "cpp" | "cxx" | "cc" | "hpp" | "hxx" => FileType::C,
            "rust" | "rs" => FileType::Rust,
            "go" => FileType::Go,
            "java" => FileType::Java,
            "class" => FileType::Class,
            "ruby" | "rb" => FileType::Ruby,
            "php" => FileType::Php,
            "csharp" | "cs" => FileType::CSharp,
            "lua" => FileType::Lua,
            "perl" | "pl" => FileType::Perl,
            "powershell" | "ps1" => FileType::PowerShell,
            "swift" => FileType::Swift,
            "objectivec" | "objc" | "m" => FileType::ObjectiveC,
            "groovy" | "gradle" => FileType::Groovy,
            "scala" | "sc" => FileType::Scala,
            "zig" => FileType::Zig,
            "elixir" | "ex" | "exs" => FileType::Elixir,
            "applescript" | "scpt" => FileType::AppleScript,
            "vbs" | "vbscript" => FileType::Vbs,
            "html" | "htm" => FileType::Html,
            // cpp aliases to c (handled above)
            // Manifest/config formats
            "package.json" | "packagejson" => FileType::PackageJson,
            "chrome-manifest" | "chromemanifest" => FileType::ChromeManifest,
            "cargo-toml" | "cargotoml" | "cargo.toml" => FileType::CargoToml,
            "pyproject-toml" | "pyprojecttoml" | "pyproject.toml" => FileType::PyProjectToml,
            "github-actions" | "githubactions" => FileType::GithubActions,
            "composer-json" | "composerjson" | "composer.json" => FileType::ComposerJson,
            "jpeg" | "jpg" => FileType::Jpeg,
            "png" => FileType::Png,
            // Additional formats
            "plist" => FileType::Plist,
            "pkginfo" | "pkg-info" | "pkg_info" => FileType::PkgInfo,
            "rtf" => FileType::Rtf,
            "lnk" => FileType::Lnk,
            "ipa" => FileType::Ipa,
            "text" | "txt" => FileType::Text,
            _ => FileType::All,
        }
    }
}

/// Default platforms for rules (all platforms)
#[must_use]
pub(crate) fn default_platforms() -> Vec<Platform> {
    vec![Platform::All]
}

/// Default file types for rules (all file types)
#[must_use]
pub(crate) fn default_file_types() -> Vec<FileType> {
    vec![FileType::All]
}

#[cfg(test)]
mod tests {
    use super::*;

    // ==================== FileType::is_source_code Tests ====================

    #[test]
    fn test_is_source_code_true_for_shell() {
        assert!(FileType::Shell.is_source_code());
    }

    #[test]
    fn test_is_source_code_true_for_python() {
        assert!(FileType::Python.is_source_code());
    }

    #[test]
    fn test_is_source_code_true_for_javascript() {
        assert!(FileType::JavaScript.is_source_code());
    }

    #[test]
    fn test_is_source_code_true_for_rust() {
        assert!(FileType::Rust.is_source_code());
    }

    #[test]
    fn test_is_source_code_true_for_go() {
        assert!(FileType::Go.is_source_code());
    }

    #[test]
    fn test_is_source_code_true_for_applescript() {
        assert!(FileType::AppleScript.is_source_code());
    }

    #[test]
    fn test_is_source_code_false_for_elf() {
        assert!(!FileType::Elf.is_source_code());
    }

    #[test]
    fn test_is_source_code_false_for_macho() {
        assert!(!FileType::Macho.is_source_code());
    }

    #[test]
    fn test_is_source_code_false_for_pe() {
        assert!(!FileType::Pe.is_source_code());
    }

    #[test]
    fn test_is_source_code_false_for_all() {
        assert!(!FileType::All.is_source_code());
    }

    #[test]
    fn test_is_source_code_false_for_package_json() {
        assert!(!FileType::PackageJson.is_source_code());
    }

    #[test]
    fn test_is_source_code_false_for_plist() {
        assert!(!FileType::Plist.is_source_code());
    }

    #[test]
    fn test_is_source_code_false_for_jpeg() {
        assert!(!FileType::Jpeg.is_source_code());
    }

    // ==================== FileType::all_concrete_variants Tests ====================

    #[test]
    fn test_all_concrete_variants_excludes_all() {
        let variants = FileType::all_concrete_variants();
        assert!(!variants.contains(&FileType::All));
    }

    #[test]
    fn test_all_concrete_variants_includes_elf() {
        let variants = FileType::all_concrete_variants();
        assert!(variants.contains(&FileType::Elf));
    }

    #[test]
    fn test_all_concrete_variants_includes_python() {
        let variants = FileType::all_concrete_variants();
        assert!(variants.contains(&FileType::Python));
    }

    #[test]
    fn test_all_concrete_variants_includes_package_json() {
        let variants = FileType::all_concrete_variants();
        assert!(variants.contains(&FileType::PackageJson));
    }

    #[test]
    fn test_all_concrete_variants_includes_jpeg() {
        let variants = FileType::all_concrete_variants();
        assert!(variants.contains(&FileType::Jpeg));
    }

    #[test]
    fn test_all_concrete_variants_count() {
        let variants = FileType::all_concrete_variants();
        // Should have all variants except All
        assert!(variants.len() > 30); // At least 30+ variants
    }

    // ==================== default_platforms Tests ====================

    #[test]
    fn test_default_platforms_returns_all() {
        let platforms = default_platforms();
        assert_eq!(platforms.len(), 1);
        assert_eq!(platforms[0], Platform::All);
    }

    // ==================== default_file_types Tests ====================

    #[test]
    fn test_default_file_types_returns_all() {
        let file_types = default_file_types();
        assert_eq!(file_types.len(), 1);
        assert_eq!(file_types[0], FileType::All);
    }

    // ==================== Platform Equality Tests ====================

    #[test]
    fn test_platform_equality() {
        assert_eq!(Platform::Linux, Platform::Linux);
        assert_ne!(Platform::Linux, Platform::Windows);
    }

    // ==================== FileType Comparison Tests ====================

    #[test]
    fn test_file_type_equality() {
        assert_eq!(FileType::Elf, FileType::Elf);
        assert_ne!(FileType::Elf, FileType::Macho);
    }

    #[test]
    fn test_file_type_hash() {
        use std::collections::HashSet;
        let mut set = HashSet::new();
        set.insert(FileType::Elf);
        set.insert(FileType::Macho);
        set.insert(FileType::Elf); // Duplicate
        assert_eq!(set.len(), 2);
    }

    #[test]
    fn test_file_type_ord() {
        // FileType derives Ord, so we can compare
        // Just verify it doesn't panic
        let _ = FileType::Elf < FileType::Macho;
    }
}
