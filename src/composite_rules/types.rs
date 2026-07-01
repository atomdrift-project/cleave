//! Core types for composite rules: Platform and FileType enums.

use serde::{Deserialize, Serialize};

/// CPU architecture filter for trait rules.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "lowercase")]
pub(crate) enum Arch {
    All,
    X86,
    #[serde(rename = "x86-64")]
    X86_64,
    Aarch64,
    Arm,
    Riscv,
    Mips,
    Powerpc,
    Powerpc64,
    Sparc,
    M68k,
    Superh,
}

/// Default architectures for rules (all architectures)
#[must_use]
pub(crate) fn default_architectures() -> Vec<Arch> {
    vec![Arch::All]
}

impl Arch {
    /// Parse an architecture string from YAML trait definitions (kebab-case).
    #[must_use]
    pub(crate) fn from_str(arch: &str) -> Arch {
        match arch.to_lowercase().as_str() {
            "x86" | "i386" | "i686" => Arch::X86,
            "x86-64" | "x86_64" | "amd64" => Arch::X86_64,
            "aarch64" | "arm64" => Arch::Aarch64,
            "arm" | "arm32" => Arch::Arm,
            "riscv" | "riscv64" => Arch::Riscv,
            "mips" | "mipsel" => Arch::Mips,
            "powerpc" | "ppc" => Arch::Powerpc,
            "powerpc64" | "ppc64" | "ppc64le" => Arch::Powerpc64,
            "sparc" | "sparc64" => Arch::Sparc,
            "m68k" => Arch::M68k,
            "superh" | "sh" => Arch::Superh,
            _ => Arch::All,
        }
    }

    /// Parse an architecture string from analyzer report output.
    /// Report strings use the canonical forms set by each analyzer.
    #[must_use]
    pub(crate) fn from_report_str(arch: &str) -> Arch {
        match arch.to_lowercase().as_str() {
            "x86_64" | "x86-64" | "amd64" => Arch::X86_64,
            "x86" | "i386" | "i686" => Arch::X86,
            "aarch64" | "arm64" | "arm64e" => Arch::Aarch64,
            "arm" => Arch::Arm,
            "riscv" | "riscv64" => Arch::Riscv,
            "mips" | "mipsel" => Arch::Mips,
            "powerpc" | "ppc" => Arch::Powerpc,
            "powerpc64" | "ppc64" | "ppc64le" => Arch::Powerpc64,
            "sparc" | "sparc64" => Arch::Sparc,
            "m68k" => Arch::M68k,
            "superh" | "sh" | "sh4" => Arch::Superh,
            _ => Arch::All,
        }
    }
}

impl std::fmt::Display for Arch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Arch::All => write!(f, "all"),
            Arch::X86 => write!(f, "x86"),
            Arch::X86_64 => write!(f, "x86-64"),
            Arch::Aarch64 => write!(f, "aarch64"),
            Arch::Arm => write!(f, "arm"),
            Arch::Riscv => write!(f, "riscv"),
            Arch::Mips => write!(f, "mips"),
            Arch::Powerpc => write!(f, "powerpc"),
            Arch::Powerpc64 => write!(f, "powerpc64"),
            Arch::Sparc => write!(f, "sparc"),
            Arch::M68k => write!(f, "m68k"),
            Arch::Superh => write!(f, "superh"),
        }
    }
}

impl Arch {
    /// Infer architecture from a YARA rule name by looking for common arch
    /// indicators like `_X64_`, `_X86_`, `_ARM64_` etc. Returns `None` when
    /// no arch can be inferred (rule applies to any architecture).
    #[allow(dead_code)] // Used by lib.rs pipeline
    #[must_use]
    pub(crate) fn from_yara_rule_name(rule: &str) -> Option<Arch> {
        // Uppercase the rule name so matching is case-insensitive
        let upper = rule.to_uppercase();

        // Check for x86-64 indicators (must come before x86 to avoid false match)
        if contains_word(&upper, "X64")
            || contains_word(&upper, "X86_64")
            || contains_word(&upper, "AMD64")
        {
            return Some(Arch::X86_64);
        }

        // Check for x86 (32-bit) indicators
        if contains_word(&upper, "X86")
            || contains_word(&upper, "X32")
            || contains_word(&upper, "I386")
        {
            return Some(Arch::X86);
        }

        // Check for ARM64/AArch64 indicators
        if contains_word(&upper, "ARM64") || contains_word(&upper, "AARCH64") {
            return Some(Arch::Aarch64);
        }

        // PE/Win32 rules with hex patterns are overwhelmingly x86-64 targeted.
        // Assume x86-64 unless an explicit arch indicator above said otherwise.
        if contains_word(&upper, "WIN32") || contains_word(&upper, "WIN64") {
            return Some(Arch::X86_64);
        }

        None
    }
}

/// Check if `haystack` contains `word` as a delimited segment (bounded by `_`, start, or end).
#[allow(dead_code)] // Used by lib.rs pipeline via from_yara_rule_name
fn contains_word(haystack: &str, word: &str) -> bool {
    for (i, _) in haystack.match_indices(word) {
        let before_ok = i == 0 || haystack.as_bytes()[i - 1] == b'_';
        let end = i + word.len();
        let after_ok = end == haystack.len() || haystack.as_bytes()[end] == b'_';
        if before_ok && after_ok {
            return true;
        }
    }
    false
}

/// Platform specifier for trait targeting
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "lowercase")]
pub enum Platform {
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
    /// AIX Unix platform
    Aix,
    /// Solaris Unix platform
    Solaris,
    /// FreeBSD Unix platform
    FreeBsd,
    /// OpenBSD Unix platform
    OpenBsd,
    /// NetBSD Unix platform
    NetBsd,
    /// DragonFly BSD Unix platform
    DragonFlyBsd,
    /// OpenWrt Linux appliance platform
    OpenWrt,
    /// QNX Unix platform
    Qnx,
    /// VMware ESXi platform
    Esxi,
    /// z/OS platform
    Zos,
    /// Generic network/security appliance platform
    #[serde(rename = "appliance", alias = "network-appliance")]
    Appliance,
    /// MikroTik RouterOS appliance platform
    RouterOs,
    /// Fortinet FortiOS appliance platform
    FortiOs,
    /// Palo Alto PAN-OS appliance platform
    PanOs,
    /// Cisco IOS-XE appliance platform
    IosXe,
    /// Juniper Junos appliance platform
    Junos,
    /// Citrix NetScaler appliance platform
    Netscaler,
    /// Ivanti appliance platform
    Ivanti,
    /// VxWorks RTOS/appliance platform
    VxWorks,
}

impl Platform {
    /// Stable lowercase label used by CLI output and YARA metadata.
    #[must_use]
    pub fn label(&self) -> &'static str {
        match self {
            Self::All => "all",
            Self::Linux => "linux",
            Self::MacOS => "macos",
            Self::Windows => "windows",
            Self::Unix => "unix",
            Self::Android => "android",
            Self::Ios => "ios",
            Self::Aix => "aix",
            Self::Solaris => "solaris",
            Self::FreeBsd => "freebsd",
            Self::OpenBsd => "openbsd",
            Self::NetBsd => "netbsd",
            Self::DragonFlyBsd => "dragonflybsd",
            Self::OpenWrt => "openwrt",
            Self::Qnx => "qnx",
            Self::Esxi => "esxi",
            Self::Zos => "zos",
            Self::Appliance => "appliance",
            Self::RouterOs => "routeros",
            Self::FortiOs => "fortios",
            Self::PanOs => "panos",
            Self::IosXe => "iosxe",
            Self::Junos => "junos",
            Self::Netscaler => "netscaler",
            Self::Ivanti => "ivanti",
            Self::VxWorks => "vxworks",
        }
    }

    /// Whether this platform is covered by the Unix umbrella.
    #[must_use]
    pub fn is_unix_family(&self) -> bool {
        matches!(
            self,
            Self::Unix
                | Self::Linux
                | Self::MacOS
                | Self::Aix
                | Self::Solaris
                | Self::FreeBsd
                | Self::OpenBsd
                | Self::NetBsd
                | Self::DragonFlyBsd
                | Self::OpenWrt
                | Self::Qnx
                | Self::Esxi
                | Self::Zos
        )
    }

    /// Whether this platform is covered by the appliance umbrella.
    #[must_use]
    pub fn is_appliance_family(&self) -> bool {
        matches!(
            self,
            Self::Appliance
                | Self::RouterOs
                | Self::FortiOs
                | Self::PanOs
                | Self::IosXe
                | Self::Junos
                | Self::Netscaler
                | Self::Ivanti
                | Self::VxWorks
        )
    }

    /// True when a rule platform should be evaluated for a requested platform filter.
    #[must_use]
    pub fn matches_filter(&self, filter: &Self) -> bool {
        self == &Self::All
            || filter == &Self::All
            || self == filter
            || (self == &Self::Unix && filter.is_unix_family())
            || (filter == &Self::Unix && self.is_unix_family())
            || (self == &Self::Appliance && filter.is_appliance_family())
            || (filter == &Self::Appliance && self.is_appliance_family())
    }
}

/// True when rule platforms and active scan platform filters overlap, including umbrellas.
#[must_use]
pub fn platforms_intersect(rule: &[Platform], filters: &[Platform]) -> bool {
    if rule.is_empty() || filters.is_empty() {
        return true;
    }
    rule.iter().any(|rule_platform| {
        filters
            .iter()
            .any(|filter| rule_platform.matches_filter(filter))
    })
}

/// File type specifier for rule targeting
#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub(crate) enum FileType {
    /// Applies to all file types
    All,
    /// Generic archive/container when the analyzer does not filefacts a subtype
    Archive,
    /// Analyzer could not classify the file beyond opaque/unknown content
    Unknown,
    /// ELF binary (Linux/Unix executable or shared library)
    Elf,
    /// Mach-O binary (macOS/iOS executable or library)
    Macho,
    /// PE binary (Windows executable)
    Pe,
    /// Java bytecode class file
    Class,
    /// Python compiled bytecode (.pyc)
    Pyc,
    /// Erlang/Elixir compiled BEAM bytecode (.beam) — binary, string-extracted
    Beam,
    /// WebAssembly binary module (.wasm) — portable bytecode payload,
    /// string-extracted (Go/TinyGo/Rust/Emscripten compile target).
    Wasm,
    /// Unix shell script (bash, sh, zsh, etc.)
    Shell,
    /// Windows batch script (.bat, .cmd)
    Batch,
    /// IBM z/OS Job Control Language batch script (.jcl)
    Jcl,
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
    /// Kotlin source file
    Kotlin,
    /// Scala source file
    Scala,
    /// Zig source file
    Zig,
    /// Elixir source file
    Elixir,
    /// Clojure / ClojureScript / EDN source (.clj, .cljs, .cljc, .edn, .bb)
    Clojure,
    /// AppleScript source file
    AppleScript,
    /// VBScript source file
    Vbs,
    /// HTML file
    Html,
    /// Markdown file
    Markdown,
    /// Makefile / GNU Make build file
    Makefile,
    /// Dockerfile — container image build definition
    Dockerfile,
    /// Plain text data
    Text,
    /// Opaque binary data (.dat, .bin, .payload, .raw)
    Data,
    /// Generic JSON document
    Json,
    /// node-gyp build manifest (binding.gyp, .gyp, .gypi)
    Gyp,
    /// npm package.json manifest
    PackageJson,
    /// npm package-lock.json lockfile
    PackageLockJson,
    /// Go module dependency manifest (go.mod)
    GoMod,
    /// Chrome extension manifest.json
    ChromeManifest,
    /// VS Code extension manifest (extension.vsixmanifest)
    VsixManifest,
    /// Rust Cargo.toml manifest
    CargoToml,
    /// Python pyproject.toml manifest
    PyProjectToml,
    /// GitHub Actions workflow YAML
    GithubActions,
    /// systemd service unit file (.service, .service.d/*.conf)
    SystemdService,
    /// freedesktop.org Desktop Entry (.desktop) - XDG application launcher / autostart
    DesktopEntry,
    /// Generic XML document (MSBuild project, SVG, XML config, etc.)
    Xml,
    /// PHP composer.json manifest
    ComposerJson,
    /// Python package metadata (PKG-INFO, METADATA)
    PkgInfo,
    /// Apple Property List (.plist)
    Plist,
    /// Rich Text Format (.rtf)
    Rtf,
    /// Legacy Microsoft Office document (OLE2/CFBF: .doc, .xls, .ppt, .msg)
    OleDoc,
    /// Modern Microsoft Office document (OOXML: .docx, .xlsx, .pptx)
    Ooxml,
    /// Windows Shell Link (.lnk)
    Lnk,
    /// iOS App Package (.ipa) - not extractable by cleave
    Ipa,
    /// JPEG image
    Jpeg,
    /// PNG image
    Png,
    /// Python pickle serialized data
    Pickle,
    /// PDF document
    Pdf,
    /// Generic ZIP archive
    Zip,
    /// Android application package (.apk)
    #[serde(alias = "apk_android", alias = "apk_alpine")]
    Apk,
    /// Java archive (.jar, .war, .ear)
    Jar,
    /// Tar archive (.tar, .tar.gz, .tgz, etc.)
    Tar,
    /// Zstandard-compressed single file (.zst, not a tar)
    Zst,
    /// npm package (.tgz)
    Npm,
    /// NuGet package (.nupkg)
    Nupkg,
    /// Rust crate (.crate)
    Crate,
    /// conda package (.conda)
    Conda,
    /// Python egg (.egg)
    Egg,
    /// OS installer package (.pkg) — macOS (xar), FreeBSD/Arch (compressed tar)
    Pkg,
    /// Ruby gem (.gem)
    Gem,
    /// Python wheel (.whl)
    Whl,
    /// Python source distribution (.tar.gz / .zip sdist)
    PythonSdist,
    /// Debian package (.deb)
    Deb,
    /// RPM package (.rpm)
    Rpm,
    /// Chrome extension (.crx)
    Crx,
    /// Compiled HTML Help (.chm)
    Chm,
    /// Microsoft Cabinet archive (.cab)
    Cab,
    /// VS Code extension (.vsix archive)
    VsixArchive,
    /// Firefox extension (.xpi)
    Xpi,
}

impl From<filefacts::FileType> for FileType {
    /// Map a filefacts identification type onto cleave's trait-routing bucket.
    ///
    /// filefacts is the single source of truth for *what a file is*; this enum
    /// is the coarser vocabulary for *which traits' `for:` applies*. The two
    /// differ for two reasons, both encoded explicitly here:
    ///
    /// 1. Deliberate folding — identities that share one trait surface collapse
    ///    to one bucket (the three `pkg_*` ecosystems → [`Pkg`], the two `apk_*`
    ///    → [`Apk`], `typescript` → [`JavaScript`] mirroring `parse_file_types`,
    ///    `svg` → [`Xml`] since SVG is scanned as XML). The fine-grained label
    ///    still rides along in the report string for litmus/collimator.
    /// 2. Lag — identification types cleave has not yet grown a trait bucket for
    ///    (lockfiles, `src_info`, `registry`, single-file compression, niche
    ///    archives/documents) route to [`Unknown`], which honours every rule's
    ///    `for:` without claiming a capability surface.
    ///
    /// Every current filefacts variant is mapped explicitly so the routing
    /// decision is reviewable in one place. filefacts marks its enum
    /// `#[non_exhaustive]`, so a wildcard is required; a future type cleave has
    /// not classified routes to `Unknown` rather than dropping out — the same
    /// safe fallback that the broken hand-rolled string table lacked.
    fn from(ft: filefacts::FileType) -> Self {
        use filefacts::FileType as Ff;
        match ft {
            // Binaries
            Ff::MachO => Self::Macho,
            Ff::Elf => Self::Elf,
            Ff::Pe => Self::Pe,
            Ff::JavaClass => Self::Class,
            Ff::PythonBytecode => Self::Pyc,
            Ff::Beam => Self::Beam,
            Ff::Wasm => Self::Wasm,
            // Scripts / source
            Ff::Shell => Self::Shell,
            Ff::Batch => Self::Batch,
            Ff::Jcl => Self::Jcl,
            Ff::Vbs => Self::Vbs,
            Ff::Python => Self::Python,
            // TypeScript folds to JavaScript: `parse_file_types` routes both to
            // the same bucket, so analyzed `.ts` files must too or `for:
            // [javascript]` traits would miss them.
            Ff::JavaScript | Ff::TypeScript => Self::JavaScript,
            Ff::Go => Self::Go,
            Ff::Rust => Self::Rust,
            Ff::Java => Self::Java,
            Ff::Ruby => Self::Ruby,
            Ff::Php => Self::Php,
            Ff::Perl => Self::Perl,
            Ff::Lua => Self::Lua,
            Ff::CSharp => Self::CSharp,
            Ff::PowerShell => Self::PowerShell,
            Ff::Swift => Self::Swift,
            Ff::ObjectiveC => Self::ObjectiveC,
            Ff::Groovy => Self::Groovy,
            Ff::Scala => Self::Scala,
            Ff::Kotlin => Self::Kotlin,
            Ff::Zig => Self::Zig,
            Ff::Elixir => Self::Elixir,
            Ff::Clojure => Self::Clojure,
            Ff::C => Self::C,
            Ff::AppleScript => Self::AppleScript,
            Ff::Makefile => Self::Makefile,
            Ff::Dockerfile => Self::Dockerfile,
            // Manifests / config / structured text
            Ff::PackageJson => Self::PackageJson,
            Ff::PackageLockJson => Self::PackageLockJson,
            Ff::VsixManifest => Self::VsixManifest,
            Ff::ChromeManifest => Self::ChromeManifest,
            Ff::CargoToml => Self::CargoToml,
            Ff::PyProjectToml => Self::PyProjectToml,
            Ff::ComposerJson => Self::ComposerJson,
            Ff::Json => Self::Json,
            Ff::Gyp => Self::Gyp,
            Ff::GithubActions => Self::GithubActions,
            Ff::SystemdService => Self::SystemdService,
            Ff::DesktopEntry => Self::DesktopEntry,
            Ff::Xml | Ff::Svg => Self::Xml,
            Ff::PkgInfo => Self::PkgInfo,
            Ff::GoMod => Self::GoMod,
            // Documents / media
            Ff::Plist => Self::Plist,
            Ff::Rtf => Self::Rtf,
            Ff::OleDoc => Self::OleDoc,
            Ff::Ooxml => Self::Ooxml,
            Ff::Lnk => Self::Lnk,
            Ff::Jpeg => Self::Jpeg,
            Ff::Png => Self::Png,
            Ff::Pickle => Self::Pickle,
            Ff::Pdf => Self::Pdf,
            Ff::Html => Self::Html,
            Ff::Markdown => Self::Markdown,
            Ff::Text => Self::Text,
            Ff::Data => Self::Data,
            // Archives / packages
            Ff::Zip => Self::Zip,
            Ff::Tar | Ff::TarGz | Ff::TarBz2 | Ff::TarXz | Ff::TarZst => Self::Tar,
            Ff::Zst => Self::Zst,
            Ff::SevenZ | Ff::Rar => Self::Archive,
            Ff::Deb => Self::Deb,
            Ff::Rpm => Self::Rpm,
            Ff::PkgMacos | Ff::PkgFreebsd | Ff::PkgArch => Self::Pkg,
            Ff::Chm => Self::Chm,
            Ff::Cab => Self::Cab,
            Ff::Crx => Self::Crx,
            Ff::Xpi => Self::Xpi,
            Ff::Whl => Self::Whl,
            Ff::PythonSdist => Self::PythonSdist,
            Ff::Gem => Self::Gem,
            Ff::ApkAndroid | Ff::ApkAlpine | Ff::AndroidDex => Self::Apk,
            Ff::Npm => Self::Npm,
            Ff::Crate => Self::Crate,
            Ff::Conda => Self::Conda,
            Ff::Egg => Self::Egg,
            Ff::Nupkg => Self::Nupkg,
            Ff::Ipa => Self::Ipa,
            Ff::Vsix => Self::VsixArchive,
            Ff::Jar => Self::Jar,
            // Everything else routes to Unknown — it still honours every
            // rule's `for:`, it just claims no capability surface until a
            // dedicated bucket is chosen. This covers types not yet modelled
            // for trait routing (which resolved to Unknown before this bridge
            // too, so no regression): lockfiles + dependency text (CargoLock,
            // GoSum, RequirementsTxt, PoetryLock, PipfileLock, GemfileLock,
            // ComposerLock, YarnLock, PnpmLock), package metadata (SrcInfo,
            // Registry), single-file compression (Gz, Bz2, Xz), archives
            // without a dedicated bucket (Dmg, Asar, OciImage, Xbps,
            // GentooBinpkg), and documents (Odf). The wildcard
            // is also mandatory because filefacts::FileType is
            // `#[non_exhaustive]`.
            _ => Self::Unknown,
        }
    }
}

impl FileType {
    /// Returns true if this file type is source code (not a compiled binary)
    #[must_use]
    pub(crate) fn is_source_code(&self) -> bool {
        matches!(
            self,
            FileType::Shell
                | FileType::Batch
                | FileType::Jcl
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
                | FileType::Kotlin
                | FileType::Scala
                | FileType::Zig
                | FileType::Elixir
                | FileType::Clojure
                | FileType::AppleScript
                | FileType::Vbs
                | FileType::Html
                | FileType::Markdown
                | FileType::Makefile
                | FileType::Dockerfile
                | FileType::Text
        )
    }

    /// Returns true if this file type supports tree-sitter-backed AST queries.
    #[must_use]
    pub(crate) fn supports_ast_queries(&self) -> bool {
        matches!(
            self,
            FileType::C
                | FileType::Python
                | FileType::JavaScript
                | FileType::TypeScript
                | FileType::Rust
                | FileType::Go
                | FileType::Java
                | FileType::Ruby
                | FileType::Shell
                | FileType::Php
                | FileType::CSharp
                | FileType::Lua
                | FileType::Perl
                | FileType::PowerShell
                | FileType::Swift
                | FileType::ObjectiveC
                | FileType::Groovy
                | FileType::Scala
                | FileType::Zig
                | FileType::Elixir
                | FileType::Makefile
        )
    }

    /// Returns true when `type: text` should search raw file content for this file type.
    ///
    /// Text-mode uses raw content for source and other ASCII/UTF-8 structured formats,
    /// and uses extracted strings for binary-like formats.
    #[must_use]
    pub(crate) fn uses_raw_text_search(&self) -> bool {
        self.is_source_code()
            || matches!(
                self,
                FileType::PackageJson
                    | FileType::PackageLockJson
                    | FileType::GoMod
                    | FileType::Json
                    | FileType::ChromeManifest
                    | FileType::VsixManifest
                    | FileType::CargoToml
                    | FileType::PyProjectToml
                    | FileType::GithubActions
                    | FileType::SystemdService
                    | FileType::DesktopEntry
                    | FileType::Xml
                    | FileType::ComposerJson
                    | FileType::PkgInfo
                    | FileType::Plist
                    | FileType::Text
            )
    }

    /// Returns true if this file type is an archive or compressed container.
    #[must_use]
    pub(crate) fn is_archive(&self) -> bool {
        matches!(
            self,
            FileType::Archive
                | FileType::Zip
                | FileType::Apk
                | FileType::Jar
                | FileType::Tar
                | FileType::Npm
                | FileType::Nupkg
                | FileType::Crate
                | FileType::Conda
                | FileType::Egg
                | FileType::Pkg
                | FileType::Gem
                | FileType::Whl
                | FileType::PythonSdist
                | FileType::Deb
                | FileType::Rpm
                | FileType::Crx
                | FileType::Chm
                | FileType::Cab
                | FileType::VsixArchive
                | FileType::Xpi
                | FileType::Ipa
        )
    }

    /// Returns true if this file type typically has a section structure (ELF, Mach-O, PE)
    #[must_use]
    pub(crate) fn has_sections(&self) -> bool {
        matches!(self, FileType::Elf | FileType::Macho | FileType::Pe)
    }

    /// Returns a list of all concrete file types (excluding All)
    #[must_use]
    pub(crate) fn all_concrete_variants() -> Vec<FileType> {
        vec![
            // Binary formats
            FileType::Elf,
            FileType::Macho,
            FileType::Pe,
            FileType::Class,
            FileType::Pyc,
            FileType::Wasm,
            // Source code formats
            FileType::Shell,
            FileType::Batch,
            FileType::Jcl,
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
            FileType::Kotlin,
            FileType::Scala,
            FileType::Zig,
            FileType::Elixir,
            FileType::AppleScript,
            FileType::Vbs,
            FileType::Html,
            FileType::Markdown,
            FileType::Makefile,
            FileType::Dockerfile,
            FileType::Text,
            FileType::Data,
            FileType::Json,
            // Manifest/config formats
            FileType::PackageJson,
            FileType::PackageLockJson,
            FileType::GoMod,
            FileType::ChromeManifest,
            FileType::VsixManifest,
            FileType::CargoToml,
            FileType::PyProjectToml,
            FileType::GithubActions,
            FileType::SystemdService,
            FileType::DesktopEntry,
            FileType::Xml,
            FileType::ComposerJson,
            FileType::PkgInfo,
            FileType::Plist,
            FileType::Rtf,
            FileType::OleDoc,
            FileType::Ooxml,
            FileType::Lnk,
            // Archive/installer formats
            FileType::Ipa,
            // Image formats
            FileType::Jpeg,
            FileType::Png,
            // Serialized data
            FileType::Pickle,
            // Document formats
            FileType::Pdf,
            FileType::Unknown,
            // Archive/container formats
            FileType::Archive,
            FileType::Zip,
            FileType::Apk,
            FileType::Jar,
            FileType::Tar,
            FileType::Zst,
            FileType::Npm,
            FileType::Nupkg,
            FileType::Crate,
            FileType::Conda,
            FileType::Egg,
            FileType::Pkg,
            FileType::Gem,
            FileType::Whl,
            FileType::PythonSdist,
            FileType::Deb,
            FileType::Rpm,
            FileType::Crx,
            FileType::Chm,
            FileType::Cab,
            FileType::VsixArchive,
            FileType::Xpi,
        ]
    }

    /// Parse a file type string into a FileType enum variant.
    /// This is the canonical mapping used by both production scanning and test-rules.
    #[must_use]
    pub(crate) fn from_str(file_type: &str) -> FileType {
        // A report's `type` string is filefacts's canonical `FileType::label()`.
        // Resolve it through filefacts first so trait routing can never drift
        // from identification (the cause of the `objective_c`/`github_actions`
        // detection regression). Author-facing aliases that are not canonical
        // labels (`objc`, `cpp`, `gomod`, group tokens) fall through to the
        // explicit table below.
        if let Some(ft) = filefacts::FileType::from_label(file_type) {
            return FileType::from(ft);
        }
        match file_type.to_lowercase().as_str() {
            "elf" | "so" => FileType::Elf,
            "macho" | "dylib" => FileType::Macho,
            "pe" | "exe" | "dll" => FileType::Pe,
            "shell" | "shellscript" | "shell_script" => FileType::Shell,
            "batch" | "bat" | "cmd" => FileType::Batch,
            "jcl" => FileType::Jcl,
            "python" | "python_script" => FileType::Python,
            "javascript" | "js" | "typescript" | "ts" => FileType::JavaScript,
            "c" | "h" | "cpp" | "cxx" | "cc" | "hpp" | "hxx" => FileType::C,
            "rust" | "rs" => FileType::Rust,
            "go" => FileType::Go,
            "java" => FileType::Java,
            "class" | "java_class" | "javaclass" => FileType::Class,
            "pyc" | "python-bytecode" | "pythonbytecode" => FileType::Pyc,
            "wasm" | "webassembly" => FileType::Wasm,
            "ruby" | "rb" => FileType::Ruby,
            "php" => FileType::Php,
            "csharp" | "cs" => FileType::CSharp,
            "lua" => FileType::Lua,
            "perl" | "pl" => FileType::Perl,
            "powershell" | "ps1" => FileType::PowerShell,
            "swift" => FileType::Swift,
            "objectivec" | "objc" | "m" => FileType::ObjectiveC,
            "groovy" | "gradle" => FileType::Groovy,
            "kotlin" | "kt" | "kts" => FileType::Kotlin,
            "scala" | "sc" => FileType::Scala,
            "zig" => FileType::Zig,
            "elixir" | "ex" | "exs" => FileType::Elixir,
            "applescript" | "scpt" => FileType::AppleScript,
            "vbs" | "vbscript" => FileType::Vbs,
            "html" | "htm" => FileType::Html,
            "markdown" | "md" => FileType::Markdown,
            "makefile" | "make" | "mk" | "mak" => FileType::Makefile,
            "dockerfile" | "docker" | "containerfile" => FileType::Dockerfile,
            "text" | "txt" | "b64" | "base64" => FileType::Text,
            "data" | "dat" | "bin" | "payload" | "raw" => FileType::Data,
            "json" => FileType::Json,
            "gyp" | "gypi" | "binding.gyp" => FileType::Gyp,
            // cpp aliases to c (handled above)
            // Manifest/config formats
            "package.json" | "packagejson" => FileType::PackageJson,
            "package-lock.json" | "packagelockjson" => FileType::PackageLockJson,
            "go.mod" | "gomod" | "go-mod" | "gomodfile" => FileType::GoMod,
            "chrome-manifest" | "chromemanifest" => FileType::ChromeManifest,
            "vsixmanifest" | "vsix-manifest" | "extension.vsixmanifest" => FileType::VsixManifest,
            "cargo-toml" | "cargotoml" | "cargo.toml" => FileType::CargoToml,
            "pyproject-toml" | "pyprojecttoml" | "pyproject.toml" => FileType::PyProjectToml,
            "github-actions" | "githubactions" => FileType::GithubActions,
            "systemd-service" | "systemd_service" | "systemd" | "service" | ".service" => {
                FileType::SystemdService
            }
            "desktop-entry" | "desktop_entry" | "desktop" | ".desktop" | "xdg-desktop" => {
                FileType::DesktopEntry
            }
            "xml" | "csproj" | "msbuild" | "xaml" | "svg" | "xml-document" => FileType::Xml,
            "composer-json" | "composerjson" | "composer.json" => FileType::ComposerJson,
            "jpeg" | "jpg" => FileType::Jpeg,
            "png" => FileType::Png,
            "pickle" | "pkl" => FileType::Pickle,
            // Additional formats
            "plist" => FileType::Plist,
            "pkginfo" | "pkg-info" | "pkg_info" => FileType::PkgInfo,
            "rtf" => FileType::Rtf,
            "ole" | "doc" | "xls" | "ppt" | "msg" | "oledoc" => FileType::OleDoc,
            "ooxml" | "docx" | "xlsx" | "pptx" | "docm" | "xlsm" | "pptm" => FileType::Ooxml,
            "lnk" => FileType::Lnk,
            "ipa" => FileType::Ipa,
            "pdf" => FileType::Pdf,
            "archive" | "rar" | "7z" => FileType::Archive,
            // "unknown" falls through to the `_` wildcard arm below.
            "zip" => FileType::Zip,
            // Both `.apk` ecosystems match generic `apk`-scoped traits; the
            // fine-grained distinction lives in the report string for litmus /
            // collimator, not in trait-capability routing.
            "apk" | "apk_android" | "apk_alpine" => FileType::Apk,
            "jar" | "war" | "ear" => FileType::Jar,
            "tar" | "tgz" | "tar.gz" | "tar.bz2" | "tar.xz" => FileType::Tar,
            "zst" => FileType::Zst,
            "npm" => FileType::Npm,
            "nupkg" => FileType::Nupkg,
            "crate" => FileType::Crate,
            "conda" => FileType::Conda,
            "egg" => FileType::Egg,
            // The `.pkg` ecosystems share one trait-targeting bucket (like the
            // two apk ecosystems share `Apk`); the fine-grained distinction
            // lives in the report string for litmus / collimator.
            "pkg_macos" | "pkg_freebsd" | "pkg_arch" => FileType::Pkg,
            "gem" => FileType::Gem,
            "whl" => FileType::Whl,
            "python_sdist" | "python-sdist" | "sdist" => FileType::PythonSdist,
            "deb" => FileType::Deb,
            "rpm" => FileType::Rpm,
            "crx" => FileType::Crx,
            "chm" => FileType::Chm,
            "cab" => FileType::Cab,
            "vsix" => FileType::VsixArchive,
            "xpi" => FileType::Xpi,
            "beam" => FileType::Beam,
            "clojure" | "clj" | "cljs" | "cljc" | "cljr" | "edn" | "bb" => FileType::Clojure,
            // An UNRECOGNISED type string must NOT collapse to All: All is a
            // wildcard that, via the archive-family clause in trait evaluation,
            // lets archive-scoped rules (e.g. for: [apk]) fire on it. Unknown
            // keeps universal rules working while honouring every rule's `for:`.
            _ => FileType::Unknown,
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
    fn test_go_mod_is_raw_text_manifest() {
        assert!(!FileType::GoMod.is_source_code());
        assert!(FileType::GoMod.uses_raw_text_search());
        assert_eq!(FileType::from_str("go.mod"), FileType::GoMod);
        assert_eq!(FileType::from_str("gomod"), FileType::GoMod);
    }

    #[test]
    fn test_is_source_code_false_for_plist() {
        assert!(!FileType::Plist.is_source_code());
    }

    #[test]
    fn test_is_source_code_false_for_systemd_service() {
        assert!(!FileType::SystemdService.is_source_code());
        assert!(FileType::SystemdService.uses_raw_text_search());
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
    fn test_all_concrete_variants_includes_package_lock_json() {
        let variants = FileType::all_concrete_variants();
        assert!(variants.contains(&FileType::PackageLockJson));
    }

    #[test]
    fn test_all_concrete_variants_includes_go_mod() {
        let variants = FileType::all_concrete_variants();
        assert!(variants.contains(&FileType::GoMod));
    }

    #[test]
    fn test_all_concrete_variants_includes_systemd_service() {
        let variants = FileType::all_concrete_variants();
        assert!(variants.contains(&FileType::SystemdService));
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

    #[test]
    fn test_from_str_systemd_service_aliases() {
        assert_eq!(
            FileType::from_str("systemd-service"),
            FileType::SystemdService
        );
        assert_eq!(FileType::from_str("systemd"), FileType::SystemdService);
        assert_eq!(FileType::from_str("service"), FileType::SystemdService);
    }

    #[test]
    fn test_from_str_java_class_aliases() {
        assert_eq!(FileType::from_str("class"), FileType::Class);
        assert_eq!(FileType::from_str("java_class"), FileType::Class);
        assert_eq!(FileType::from_str("javaclass"), FileType::Class);
    }

    /// A report's `type` is filefacts's canonical `FileType::label()`. The
    /// trait engine resolves that exact string via `from_str` to gate `for:`,
    /// so every canonical label MUST route to its bucket — never `Unknown`.
    /// Regression guard for the `objective_c`/`github_actions` detection break
    /// where labels diverged from cleave's hand-rolled string table.
    #[test]
    fn from_str_resolves_canonical_filefacts_labels() {
        use filefacts::FileType as Ff;
        // The labels that actually regressed (snake_case diverged from the old
        // alias spellings the table knew).
        assert_eq!(
            FileType::from_str(Ff::ObjectiveC.label()),
            FileType::ObjectiveC
        );
        assert_eq!(
            FileType::from_str(Ff::GithubActions.label()),
            FileType::GithubActions
        );
        assert_eq!(
            FileType::from_str(Ff::PythonBytecode.label()),
            FileType::Pyc
        );
        assert_eq!(
            FileType::from_str(Ff::VsixManifest.label()),
            FileType::VsixManifest
        );
        assert_eq!(
            FileType::from_str(Ff::ChromeManifest.label()),
            FileType::ChromeManifest
        );
        assert_eq!(FileType::from_str(Ff::OleDoc.label()), FileType::OleDoc);
        // Deliberate foldings: the report keeps the precise label, routing uses
        // the coarse bucket.
        assert_eq!(
            FileType::from_str(Ff::TypeScript.label()),
            FileType::JavaScript
        );
        assert_eq!(FileType::from_str(Ff::Svg.label()), FileType::Xml);
        assert_eq!(FileType::from_str(Ff::ApkAndroid.label()), FileType::Apk);
        assert_eq!(FileType::from_str(Ff::AndroidDex.label()), FileType::Apk);
        assert_eq!(FileType::from_str(Ff::Cab.label()), FileType::Cab);
        assert_eq!(FileType::from_str(Ff::PkgArch.label()), FileType::Pkg);
        assert_eq!(FileType::from_str(Ff::TarZst.label()), FileType::Tar);
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn yaml_deserializes_filefacts_archive_labels() {
        #[derive(Deserialize)]
        struct RuleTarget {
            #[serde(rename = "for")]
            file_types: Vec<FileType>,
        }

        let parsed: RuleTarget = serde_yaml::from_str("for: [apk_android, apk_alpine, cab]")
            .expect("valid YAML rule target");

        assert_eq!(
            parsed.file_types,
            vec![FileType::Apk, FileType::Apk, FileType::Cab]
        );
    }

    /// Author-facing aliases that are NOT canonical labels must still resolve
    /// through the explicit table (the filefacts pre-pass returns `None` for
    /// them and falls through).
    #[test]
    fn from_str_keeps_author_aliases() {
        assert_eq!(FileType::from_str("objc"), FileType::ObjectiveC);
        assert_eq!(
            FileType::from_str("github-actions"),
            FileType::GithubActions
        );
        assert_eq!(FileType::from_str("cpp"), FileType::C);
        assert_eq!(FileType::from_str("gomod"), FileType::GoMod);
        assert_eq!(FileType::from_str("ts"), FileType::JavaScript);
    }

    // ==================== Platform Equality Tests ====================

    #[test]
    fn test_platform_equality() {
        assert_eq!(Platform::Linux, Platform::Linux);
        assert_ne!(Platform::Linux, Platform::Windows);
    }

    #[test]
    fn test_platform_rollup_intersection() {
        assert!(platforms_intersect(&[Platform::FreeBsd], &[Platform::Unix]));
        assert!(platforms_intersect(&[Platform::Unix], &[Platform::OpenWrt]));
        assert!(platforms_intersect(
            &[Platform::RouterOs],
            &[Platform::Appliance]
        ));
        assert!(platforms_intersect(
            &[Platform::Appliance],
            &[Platform::FortiOs]
        ));
        assert!(!platforms_intersect(
            &[Platform::MacOS],
            &[Platform::OpenWrt]
        ));
        assert!(!platforms_intersect(
            &[Platform::RouterOs],
            &[Platform::FortiOs]
        ));
        assert!(!platforms_intersect(
            &[Platform::RouterOs],
            &[Platform::Unix]
        ));
        assert!(!platforms_intersect(
            &[Platform::FreeBsd],
            &[Platform::Windows]
        ));
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

    // ==================== Arch::from_yara_rule_name Tests ====================

    #[test]
    fn test_yara_arch_x64_middle() {
        assert_eq!(
            Arch::from_yara_rule_name("GCTI_Cobaltstrike_Resources_Beacon_X64_V3_2"),
            Some(Arch::X86_64)
        );
    }

    #[test]
    fn test_yara_arch_x64_end() {
        assert_eq!(
            Arch::from_yara_rule_name("SomeRule_X64"),
            Some(Arch::X86_64)
        );
    }

    #[test]
    fn test_yara_arch_x86_middle() {
        assert_eq!(
            Arch::from_yara_rule_name("GCTI_Cobaltstrike_Sleeve_Beaconloader_X86_O_V4_3"),
            Some(Arch::X86)
        );
    }

    #[test]
    fn test_yara_arch_x86_end() {
        assert_eq!(
            Arch::from_yara_rule_name("Casper_Backdoor_X86"),
            Some(Arch::X86)
        );
    }

    #[test]
    fn test_yara_arch_lowercase_x64() {
        assert_eq!(
            Arch::from_yara_rule_name("beacon_loader_x64_v4"),
            Some(Arch::X86_64)
        );
    }

    #[test]
    fn test_yara_arch_amd64() {
        assert_eq!(
            Arch::from_yara_rule_name("Loader_AMD64_Variant"),
            Some(Arch::X86_64)
        );
    }

    #[test]
    fn test_yara_arch_arm64() {
        assert_eq!(
            Arch::from_yara_rule_name("Malware_ARM64_Loader"),
            Some(Arch::Aarch64)
        );
    }

    #[test]
    fn test_yara_arch_aarch64() {
        assert_eq!(
            Arch::from_yara_rule_name("Linux_Trojan_AArch64_Backdoor"),
            Some(Arch::Aarch64)
        );
    }

    #[test]
    fn test_yara_arch_i386() {
        assert_eq!(
            Arch::from_yara_rule_name("Exploit_I386_Shellcode"),
            Some(Arch::X86)
        );
    }

    #[test]
    fn test_yara_arch_x32() {
        assert_eq!(
            Arch::from_yara_rule_name("Template_X32_Payload"),
            Some(Arch::X86)
        );
    }

    #[test]
    fn test_yara_arch_none_generic_rule() {
        // No arch indicator — rule applies to any architecture
        assert_eq!(
            Arch::from_yara_rule_name("Linux_Trojan_Chinaz_a2140ca1"),
            None
        );
    }

    #[test]
    fn test_yara_arch_none_cobalt_generic() {
        assert_eq!(
            Arch::from_yara_rule_name("GCTI_Cobaltstrike_Resources_Artifact_Dll_V1_49_To_V3_14"),
            None
        );
    }

    #[test]
    fn test_yara_arch_no_false_positive_hex_suffix() {
        // "64" alone inside a hash suffix should NOT be parsed as arch
        assert_eq!(
            Arch::from_yara_rule_name("Linux_Exploit_CVE_2016_5195_364f3b7b"),
            None
        );
    }

    #[test]
    fn test_yara_arch_no_false_positive_version() {
        // "V3_14" should not match X86 due to partial overlap
        assert_eq!(Arch::from_yara_rule_name("Beacon_V3_14"), None);
    }

    #[test]
    fn test_yara_arch_x86_64_explicit() {
        assert_eq!(
            Arch::from_yara_rule_name("Shellcode_X86_64_Reverse"),
            Some(Arch::X86_64)
        );
    }

    #[test]
    fn test_yara_arch_win32_implies_x86_64() {
        assert_eq!(
            Arch::from_yara_rule_name("Win32_Trojan_Emotet_abc123"),
            Some(Arch::X86_64)
        );
    }

    #[test]
    fn test_yara_arch_win64_implies_x86_64() {
        assert_eq!(
            Arch::from_yara_rule_name("Win64_Ransomware_LockBit"),
            Some(Arch::X86_64)
        );
    }

    #[test]
    fn test_yara_arch_win32_arm64_override() {
        // Explicit ARM64 takes precedence over Win32 default
        assert_eq!(
            Arch::from_yara_rule_name("Win32_Trojan_ARM64_Loader"),
            Some(Arch::Aarch64)
        );
    }

    #[test]
    fn test_yara_arch_win32_case_insensitive() {
        assert_eq!(
            Arch::from_yara_rule_name("win32_backdoor_cobalt"),
            Some(Arch::X86_64)
        );
    }

    #[test]
    fn test_contains_word_boundaries() {
        // At start
        assert!(contains_word("X64_LOADER", "X64"));
        // At end
        assert!(contains_word("LOADER_X64", "X64"));
        // Middle
        assert!(contains_word("A_X64_B", "X64"));
        // Exact match
        assert!(contains_word("X64", "X64"));
        // Not a word boundary (embedded in larger token)
        assert!(!contains_word("FOX64BAR", "X64"));
        // Prefix match but not suffix
        assert!(!contains_word("X64BAR", "X64"));
        // Suffix match but not prefix
        assert!(!contains_word("FOX64", "X64"));
    }
}
