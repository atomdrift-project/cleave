//! Core types for composite rules: Platform and FileType enums.

use cleave_macros::EnumVariants;
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

/// A set of [`FileType`]s as a fixed-width bitset: one bit per variant, in
/// declaration order.
///
/// Carried per finding id at container level (the OR of every origin file's
/// [`FileType::type_bit`]) and cached per composite from its `for:` list, so
/// deciding whether a finding may satisfy a leg is one `intersects` instead
/// of a list scan per (leg x member x finding).
///
/// Wider than the enum needs today on purpose: the mask was a bare `u128`
/// until the 129th variant made `1 << 128` panic on every archive scanned.
/// The `const` assertion below turns the next overrun into a build error.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub(crate) struct TypeMask([u64; TypeMask::WORDS]);

impl TypeMask {
    const WORDS: usize = 4;
    /// Capacity in bits; [`FileType::VARIANT_COUNT`] must not exceed it.
    pub(crate) const BITS: usize = Self::WORDS * u64::BITS as usize;
    /// No types.
    pub(crate) const EMPTY: Self = Self([0; Self::WORDS]);
    /// Every type, including ones not yet declared: what `for: [all]` means.
    pub(crate) const ALL: Self = Self([u64::MAX; Self::WORDS]);

    /// The mask holding only the bit at `index`.
    ///
    /// `index` is a variant position, so it is always below `BITS` for a
    /// real `FileType`; anything wider is a programming error caught by the
    /// compile-time assertion rather than a runtime branch.
    #[must_use]
    pub(crate) const fn bit(index: usize) -> Self {
        let mut words = [0u64; Self::WORDS];
        words[index / u64::BITS as usize] = 1u64 << (index % u64::BITS as usize);
        Self(words)
    }

    /// Whether the two sets share at least one type.
    #[must_use]
    pub(crate) fn intersects(self, other: Self) -> bool {
        self.0.iter().zip(other.0).any(|(a, b)| a & b != 0)
    }
}

impl std::ops::BitOr for TypeMask {
    type Output = Self;
    fn bitor(mut self, rhs: Self) -> Self {
        self |= rhs;
        self
    }
}

impl std::ops::BitOrAssign for TypeMask {
    fn bitor_assign(&mut self, rhs: Self) {
        for (word, other) in self.0.iter_mut().zip(rhs.0) {
            *word |= other;
        }
    }
}

const _: () = assert!(
    FileType::VARIANT_COUNT <= TypeMask::BITS,
    "FileType has more variants than TypeMask has bits; widen TypeMask::WORDS"
);

/// File type specifier for rule targeting
#[derive(
    Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq, Hash, PartialOrd, Ord, EnumVariants,
)]
#[serde(rename_all = "lowercase")]
pub(crate) enum FileType {
    /// Applies to all file types
    All,
    /// RAR archive
    #[archive]
    Rar,
    /// 7-Zip archive
    #[archive]
    #[serde(rename = "7z")]
    SevenZ,
    /// cpio archive
    #[archive]
    Cpio,
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
    /// Dalvik/ART executable bytecode (.dex). A standalone program, not an APK.
    Dex,
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
    /// JavaServer Pages
    Jsp,
    /// Classic ASP and ASP.NET
    Asp,
    /// ColdFusion Markup Language
    Cfml,
    /// TeX or LaTeX source
    Tex,
    /// YARA rule source
    Yara,
    /// PostScript or EPS
    PostScript,
    /// DOS COM executable
    #[serde(rename = "dos_com")]
    DosCom,
    /// mIRC script
    Mirc,
    /// ircII or EPIC script
    IrcII,
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
    /// Cargo dependency lockfile (Cargo.lock)
    CargoLock,
    /// Python pip requirements file (requirements.txt)
    RequirementsTxt,
    /// Python Poetry lockfile (poetry.lock)
    PoetryLock,
    /// Python Pipenv lockfile (Pipfile.lock)
    PipfileLock,
    /// Ruby Bundler lockfile (Gemfile.lock)
    GemfileLock,
    /// PHP Composer lockfile (composer.lock)
    ComposerLock,
    /// Yarn dependency lockfile (yarn.lock)
    YarnLock,
    /// pnpm dependency lockfile (pnpm-lock.yaml)
    PnpmLock,
    /// Go module dependency manifest (go.mod)
    GoMod,
    /// Go module checksum database (go.sum)
    GoSum,
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
    /// Arch/AUR package metadata (.SRCINFO)
    SrcInfo,
    /// Normalized package-registry metadata
    Registry,
    /// Apple Property List (.plist)
    Plist,
    /// Compiled Interface Builder archive (.nib) in Xcode's `NIBArchive`
    /// format. The older keyed-archive form is a binary plist on disk and
    /// types as `Plist`; this variant is the distinct binary layout, whose
    /// object graph filefacts publishes as `nib.*` facts and strings.
    Nib,
    /// Xcode project file (project.pbxproj)
    Pbxproj,
    /// CMake build script (CMakeLists.txt, *.cmake)
    Cmake,
    /// Rich Text Format (.rtf)
    Rtf,
    /// Legacy Microsoft Office document (OLE2/CFBF: .doc, .xls, .ppt, .msg)
    OleDoc,
    /// Windows Installer package / patch (OLE2/CFBF: .msi, .msp). Same compound
    /// container as [`OleDoc`], but a distinct installer surface — not a document.
    Msi,
    /// Modern Microsoft Office document (OOXML: .docx, .xlsx, .pptx)
    Ooxml,
    /// OpenDocument Format document (.odt, .ods, .odp, .odg)
    Odf,
    /// Windows Shell Link (.lnk)
    Lnk,
    /// iOS App Package (.ipa) - not extractable by cleave
    #[archive]
    #[package]
    Ipa,
    /// JPEG image
    Jpeg,
    /// PNG image
    Png,
    /// SVG image (`.svg`) — XML-based vector graphic. A distinct rule type
    /// rather than an alias for `Xml`: it is a media carrier (a payload can
    /// ride after `</svg>`), and folding it into `Xml` meant every `for: [svg]`
    /// rule silently targeted Android manifests and MSBuild projects too.
    Svg,
    /// RIFF audio (`.wav`).
    Wav,
    /// IFF audio (`.aiff`, `.aifc`).
    Aiff,
    /// MPEG audio with ID3 tags (`.mp3`).
    Mp3,
    /// ISO base media (`.mp4`, `.m4a`, `.mov`).
    Mp4,
    /// Windows icon or cursor (`.ico`, `.cur`).
    Ico,
    /// GIF image (`.gif`).
    Gif,
    /// Windows bitmap (`.bmp`).
    Bmp,
    /// RIFF image (`.webp`).
    Webp,
    /// Font container: sfnt (`.ttf`/`.otf`/`.ttc`), WOFF, WOFF2, EOT.
    /// filefacts validates the table directory and reports `font.*` facts, so
    /// rules can separate a real font from a payload wearing a font name and
    /// from a valid font carrying a stowaway in its unclaimed bytes.
    Font,
    /// Python pickle serialized data
    Pickle,
    /// PDF document
    Pdf,
    /// Generic ZIP archive
    #[archive]
    Zip,
    /// Android application package (.apk) -- a ZIP container. `apk` is kept
    /// as an alias since every existing trait's `for:` says `apk` meaning
    /// this; new rules should prefer the explicit `android_apk` spelling.
    /// Distinct from `AlpineApk` below: same file extension, unrelated
    /// ecosystems and threat models (Dalvik bytecode/app sideloading vs. a
    /// musl-libc Linux package manager format), previously conflated into
    /// one `Apk` bucket that could never tell them apart.
    #[archive]
    #[package]
    #[serde(rename = "android_apk", alias = "apk", alias = "apk_android")]
    AndroidApk,
    /// Alpine Linux package (.apk) -- a tar.gz container, unrelated to the
    /// Android APK format above despite the shared extension.
    #[archive]
    #[package]
    #[serde(rename = "alpine_apk", alias = "apk_alpine")]
    AlpineApk,
    /// Java archive (.jar, .war, .ear)
    #[archive]
    Jar,
    /// Tar archive (.tar, .tar.gz, .tgz, etc.)
    #[archive]
    Tar,
    /// Zstandard-compressed single file (.zst, not a tar)
    Zst,
    /// Gzip-compressed single file (.gz, not a tar)
    Gz,
    /// Bzip2-compressed single file (.bz2, not a tar)
    Bz2,
    /// XZ-compressed single file (.xz, not a tar)
    Xz,
    /// LZMA-alone compressed single file (.lzma)
    Lzma,
    /// npm package (.tgz)
    #[archive]
    #[package]
    Npm,
    /// NuGet package (.nupkg)
    #[archive]
    #[package]
    Nupkg,
    /// Rust crate (.crate)
    #[archive]
    #[package]
    Crate,
    /// conda package (.conda)
    #[archive]
    #[package]
    Conda,
    /// Python egg (.egg)
    #[archive]
    #[package]
    Egg,
    /// OS installer package (.pkg) — macOS (xar), FreeBSD/Arch (compressed tar)
    #[archive]
    #[package]
    Pkg,
    /// Apple disk image (.dmg, UDIF container)
    #[archive]
    Dmg,
    /// Ruby gem (.gem)
    #[archive]
    #[package]
    Gem,
    /// Python wheel (.whl)
    #[archive]
    #[package]
    Whl,
    /// Python source distribution (.tar.gz / .zip sdist)
    #[archive]
    #[package]
    PythonSdist,
    /// Debian package (.deb)
    #[archive]
    #[package]
    Deb,
    /// Unix static library (.a). Native object code, so it routes with the
    /// `binaries` family — NOT the archive family (which would apply zip/jar
    /// content rules to its uncompressed `ar` member bytes).
    StaticLib,
    /// RPM package (.rpm)
    #[archive]
    #[package]
    Rpm,
    /// Chrome extension (.crx)
    #[archive]
    #[package]
    Crx,
    /// Compiled HTML Help (.chm)
    #[archive]
    Chm,
    /// Microsoft Cabinet archive (.cab)
    #[archive]
    Cab,
    /// Optical-disc image (.iso) — ISO 9660 and/or UDF. Its own bucket
    /// rather than folded into the generic archive family because the
    /// `iso.*` facts its rules read exist on no other container, and
    /// because an image is
    /// a filesystem: members are addressable sector runs, not compressed
    /// entries, so the archive-family content rules do not apply to it.
    #[archive]
    Iso,
    /// OCI / Docker container image archive
    #[archive]
    #[package]
    OciImage,
    /// Void Linux package (.xbps)
    #[archive]
    #[package]
    Xbps,
    /// Gentoo binary package (.gpkg.tar)
    #[archive]
    #[package]
    GentooBinpkg,
    /// Electron ASAR application archive (.asar)
    #[archive]
    Asar,
    /// VS Code extension (.vsix archive)
    #[archive]
    #[package]
    VsixArchive,
    /// Firefox extension (.xpi)
    #[archive]
    #[package]
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
    /// 2. Deliberate fallback — only filefacts types without a corresponding
    ///    routing bucket (including future non-exhaustive variants) route to
    ///    [`Unknown`], which honours every rule's `for:` without claiming a
    ///    capability surface.
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
            Ff::Dex => Self::Dex,
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
            Ff::CargoLock => Self::CargoLock,
            Ff::RequirementsTxt => Self::RequirementsTxt,
            Ff::PoetryLock => Self::PoetryLock,
            Ff::PipfileLock => Self::PipfileLock,
            Ff::GemfileLock => Self::GemfileLock,
            Ff::ComposerLock => Self::ComposerLock,
            Ff::YarnLock => Self::YarnLock,
            Ff::PnpmLock => Self::PnpmLock,
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
            Ff::Xml => Self::Xml,
            Ff::PkgInfo => Self::PkgInfo,
            Ff::SrcInfo => Self::SrcInfo,
            Ff::Registry => Self::Registry,
            Ff::GoMod => Self::GoMod,
            Ff::GoSum => Self::GoSum,
            // Documents / media
            Ff::Plist => Self::Plist,
            Ff::Nib => Self::Nib,
            Ff::Pbxproj => Self::Pbxproj,
            Ff::Cmake => Self::Cmake,
            Ff::Rtf => Self::Rtf,
            Ff::OleDoc => Self::OleDoc,
            Ff::Msi => Self::Msi,
            Ff::Ooxml => Self::Ooxml,
            Ff::Odf => Self::Odf,
            Ff::Lnk => Self::Lnk,
            Ff::Jpeg => Self::Jpeg,
            Ff::Png => Self::Png,
            Ff::Font => Self::Font,
            Ff::Svg => Self::Svg,
            Ff::Wav => Self::Wav,
            Ff::Aiff => Self::Aiff,
            Ff::Mp3 => Self::Mp3,
            Ff::Mp4 => Self::Mp4,
            Ff::Ico => Self::Ico,
            Ff::Gif => Self::Gif,
            Ff::Bmp => Self::Bmp,
            Ff::Webp => Self::Webp,
            Ff::Pickle => Self::Pickle,
            Ff::Pdf => Self::Pdf,
            Ff::Html => Self::Html,
            Ff::Jsp => Self::Jsp,
            Ff::Asp => Self::Asp,
            Ff::Cfml => Self::Cfml,
            Ff::Tex => Self::Tex,
            Ff::Yara => Self::Yara,
            Ff::PostScript => Self::PostScript,
            Ff::DosCom => Self::DosCom,
            Ff::Mirc => Self::Mirc,
            Ff::IrcII => Self::IrcII,
            Ff::Markdown => Self::Markdown,
            Ff::Text => Self::Text,
            Ff::Data => Self::Data,
            // Archives / packages
            Ff::Zip => Self::Zip,
            Ff::Tar | Ff::TarGz | Ff::TarBz2 | Ff::TarXz | Ff::TarZst => Self::Tar,
            Ff::Gz => Self::Gz,
            Ff::Bz2 => Self::Bz2,
            Ff::Xz => Self::Xz,
            Ff::Lzma => Self::Lzma,
            Ff::Zst => Self::Zst,
            Ff::SevenZ => Self::SevenZ,
            Ff::Rar => Self::Rar,
            Ff::Cpio => Self::Cpio,
            Ff::Iso => Self::Iso,
            Ff::Deb => Self::Deb,
            Ff::StaticLib => Self::StaticLib,
            Ff::Rpm => Self::Rpm,
            Ff::PkgMacos | Ff::PkgFreebsd | Ff::PkgArch => Self::Pkg,
            Ff::Dmg => Self::Dmg,
            Ff::Chm => Self::Chm,
            Ff::Cab => Self::Cab,
            Ff::OciImage => Self::OciImage,
            Ff::Xbps => Self::Xbps,
            Ff::GentooBinpkg => Self::GentooBinpkg,
            Ff::Asar => Self::Asar,
            Ff::Crx => Self::Crx,
            Ff::Xpi => Self::Xpi,
            Ff::Whl => Self::Whl,
            Ff::PythonSdist => Self::PythonSdist,
            Ff::Gem => Self::Gem,
            Ff::ApkAndroid => Self::AndroidApk,
            Ff::ApkAlpine => Self::AlpineApk,
            Ff::Npm => Self::Npm,
            Ff::Crate => Self::Crate,
            Ff::Conda => Self::Conda,
            Ff::Egg => Self::Egg,
            Ff::Nupkg => Self::Nupkg,
            Ff::Ipa => Self::Ipa,
            Ff::Vsix => Self::VsixArchive,
            Ff::Jar => Self::Jar,
            // The wildcard is mandatory because filefacts::FileType is
            // `#[non_exhaustive]`; unknown future types safely route to
            // Unknown until they are assigned a deliberate bucket.
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
                | FileType::Jsp
                | FileType::Asp
                | FileType::Cfml
                | FileType::Tex
                | FileType::Yara
                | FileType::PostScript
                | FileType::Mirc
                | FileType::IrcII
                | FileType::Markdown
                | FileType::Makefile
                | FileType::Dockerfile
                | FileType::Text
        )
    }

    /// Grammar name for this file type, as [`filefacts::validate_source_query`]
    /// spells it. `None` means no tree-sitter grammar is wired up, so `type:
    /// tree-sitter` conditions can never match this type.
    ///
    /// This is the single source of truth for AST support: it names the
    /// grammar a `query:` is compiled against during `cleave validate`, and
    /// [`Self::supports_ast_queries`] is derived from it, so the validation
    /// gate and the evaluation gate can never drift apart.
    #[must_use]
    pub(crate) fn tree_sitter_language_name(&self) -> Option<&'static str> {
        Some(match self {
            FileType::C => "c",
            FileType::Python => "python",
            FileType::JavaScript => "javascript",
            FileType::TypeScript => "typescript",
            FileType::Rust => "rust",
            FileType::Go => "go",
            FileType::Java => "java",
            FileType::Ruby => "ruby",
            FileType::Shell => "shell",
            FileType::Php => "php",
            FileType::CSharp => "csharp",
            FileType::Lua => "lua",
            FileType::Perl => "perl",
            FileType::PowerShell => "powershell",
            FileType::Swift => "swift",
            FileType::ObjectiveC => "objc",
            FileType::Groovy => "groovy",
            FileType::Scala => "scala",
            FileType::Zig => "zig",
            FileType::Elixir => "elixir",
            FileType::Makefile => "makefile",
            _ => return None,
        })
    }

    /// Returns true if this file type supports tree-sitter-backed AST queries.
    #[must_use]
    pub(crate) fn supports_ast_queries(&self) -> bool {
        self.tree_sitter_language_name().is_some()
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
                    | FileType::CargoLock
                    | FileType::RequirementsTxt
                    | FileType::PoetryLock
                    | FileType::PipfileLock
                    | FileType::GemfileLock
                    | FileType::ComposerLock
                    | FileType::YarnLock
                    | FileType::PnpmLock
                    | FileType::GoMod
                    | FileType::GoSum
                    | FileType::Json
                    | FileType::ChromeManifest
                    | FileType::VsixManifest
                    | FileType::CargoToml
                    | FileType::PyProjectToml
                    | FileType::GithubActions
                    | FileType::SystemdService
                    | FileType::DesktopEntry
                    | FileType::Xml
                    // SVG is markup. A smuggled script often sits on one long
                    // line after a comment pad; string extraction keeps a
                    // prefix of that line and the loader never reaches a
                    // `type: text` rule.
                    | FileType::Svg
                    | FileType::ComposerJson
                    | FileType::PkgInfo
                    | FileType::SrcInfo
                    | FileType::Registry
                    | FileType::Plist
                    | FileType::Nib
                    | FileType::Text
            )
    }

    /// Select the text haystack for this file's content.
    #[must_use]
    pub(crate) fn uses_raw_text_search_for(&self, bytes: &[u8]) -> bool {
        self.uses_raw_text_search() && !(*self == FileType::AppleScript && scpt::is_scpt(bytes))
    }

    /// Returns true if this file type typically has a section structure (ELF, Mach-O, PE)
    #[must_use]
    pub(crate) fn has_sections(&self) -> bool {
        matches!(self, FileType::Elf | FileType::Macho | FileType::Pe)
    }

    /// Returns a list of all concrete file types (excluding All)
    #[must_use]
    pub(crate) fn all_concrete_variants() -> Vec<FileType> {
        Self::all_variants()
            .into_iter()
            .filter(|file_type| *file_type != FileType::All)
            .collect()
    }

    /// The generic container format(s) this specialised archive type is built
    /// on -- a JAR, APK or wheel *is* a ZIP; an npm tarball or crate *is* a
    /// tar. A rule declaring `for: [zip]` is about ZIP-format containers, so it
    /// also applies to every ZIP-based package; the reverse does not hold.
    ///
    /// Mirrors `filefacts::FileType::archive_format` for the `#[archive]`
    /// variants, with two widenings where one routing bucket spans both
    /// containers: `PythonSdist` (legacy `.zip` sdists) and `Conda` (`.conda`
    /// is a zip, the legacy package a `.tar.bz2`). `Pkg` folds macOS `xar`
    /// packages in with the tar-based Arch/FreeBSD ones and keeps tar.
    ///
    /// Deb (`ar`), RPM (its own header over a cpio payload), CHM, CAB, ISO,
    /// DMG and ASAR have no base among the rule types; the bases themselves
    /// (`zip`, `tar`, `rar`, `7z`, `cpio`) have none either.
    #[must_use]
    pub(crate) const fn container_bases(self) -> &'static [FileType] {
        match self {
            FileType::AndroidApk
            | FileType::Jar
            | FileType::Whl
            | FileType::Nupkg
            | FileType::Crx
            | FileType::Xpi
            | FileType::VsixArchive
            | FileType::Egg
            | FileType::Ipa => &[FileType::Zip],
            FileType::AlpineApk
            | FileType::Npm
            | FileType::Crate
            | FileType::Gem
            | FileType::Pkg
            | FileType::OciImage
            | FileType::Xbps
            | FileType::GentooBinpkg => &[FileType::Tar],
            FileType::PythonSdist | FileType::Conda => &[FileType::Zip, FileType::Tar],
            _ => &[],
        }
    }

    /// The `for:` types -- besides the node's own type and `all` -- whose
    /// rules apply to a node of this type. Drives both the gate
    /// ([`Self::rule_applies_to`]) and the per-type trait indexes, which must
    /// agree on it.
    ///
    /// For a concrete archive this is only its [`Self::container_bases`]: a
    /// JAR admits `for: [zip]` rules, not `for: [android_apk]` or
    /// `for: [deb]` ones. A container that collapsed to [`FileType::All`] (no
    /// type of its own) admits every archive-typed rule, since which archive
    /// it is cannot be known.
    #[must_use]
    pub(crate) const fn admitted_rule_types(self) -> &'static [FileType] {
        match self {
            FileType::All => Self::archive_family_types(),
            _ => self.container_bases(),
        }
    }

    /// Whether an atomic trait declaring `rule_for` applies to a node of type
    /// `node`: the single statement of that `for:` gate.
    ///
    /// It used to admit any archive-typed rule on any archive node (the
    /// "archive family"), so `for: [android_apk]` fired on JARs and zips,
    /// `for: [deb]` on wheels, and `for: [jar]` on bare zips.
    #[must_use]
    pub(crate) fn rule_applies_to(rule_for: &[FileType], node: FileType) -> bool {
        rule_for.contains(&FileType::All)
            || rule_for.contains(&node)
            || node
                .admitted_rule_types()
                .iter()
                .any(|admitted| rule_for.contains(admitted))
    }

    /// This type's bit in a [`TypeMask`].
    #[must_use]
    pub(crate) const fn type_bit(self) -> TypeMask {
        TypeMask::bit(self.variant_index())
    }

    /// The canonical spelling an author writes in a rule's `for:` list.
    ///
    /// The inverse of [`Self::from_str`], and the only correct way to name a
    /// file type in a message a rule author will act on. `format!("{:?}")`
    /// is not: its lowercased Debug gives `packagejson`, `sevenz` and
    /// `cargolock`, none of which parse back, so an author who pastes one
    /// into `for:` silently gets `Unknown`.
    ///
    /// `label_round_trips_through_from_str` pins every arm, and the match is
    /// exhaustive, so a new variant cannot be added without naming it here.
    #[must_use]
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::All => "all",
            Self::Rar => "rar",
            Self::SevenZ => "7z",
            Self::Cpio => "cpio",
            Self::Unknown => "unknown",
            Self::Elf => "elf",
            Self::Macho => "macho",
            Self::Pe => "pe",
            Self::Class => "class",
            Self::Pyc => "pyc",
            Self::Beam => "beam",
            Self::Wasm => "wasm",
            Self::Dex => "dex",
            Self::Shell => "shell",
            Self::Batch => "batch",
            Self::Jcl => "jcl",
            Self::Python => "python",
            Self::JavaScript => "javascript",
            Self::TypeScript => "typescript",
            Self::Rust => "rust",
            Self::Java => "java",
            Self::Ruby => "ruby",
            Self::C => "c",
            Self::Cpp => "cpp",
            Self::Go => "go",
            Self::Php => "php",
            Self::CSharp => "csharp",
            Self::Lua => "lua",
            Self::Perl => "perl",
            Self::PowerShell => "powershell",
            Self::Swift => "swift",
            Self::ObjectiveC => "objectivec",
            Self::Groovy => "groovy",
            Self::Kotlin => "kotlin",
            Self::Scala => "scala",
            Self::Zig => "zig",
            Self::Elixir => "elixir",
            Self::Clojure => "clojure",
            Self::AppleScript => "applescript",
            Self::Vbs => "vbs",
            Self::Html => "html",
            Self::Jsp => "jsp",
            Self::Asp => "asp",
            Self::Cfml => "cfml",
            Self::Tex => "tex",
            Self::Yara => "yara",
            Self::PostScript => "postscript",
            Self::DosCom => "dos_com",
            Self::Mirc => "mirc",
            Self::IrcII => "ircii",
            Self::Markdown => "markdown",
            Self::Makefile => "makefile",
            Self::Dockerfile => "dockerfile",
            Self::Text => "text",
            Self::Data => "data",
            Self::Json => "json",
            Self::Gyp => "gyp",
            Self::PackageJson => "package.json",
            Self::PackageLockJson => "package-lock.json",
            Self::CargoLock => "cargo.lock",
            Self::RequirementsTxt => "requirements.txt",
            Self::PoetryLock => "poetry.lock",
            Self::PipfileLock => "pipfile.lock",
            Self::GemfileLock => "gemfile.lock",
            Self::ComposerLock => "composer.lock",
            Self::YarnLock => "yarn.lock",
            Self::PnpmLock => "pnpm-lock.yaml",
            Self::GoMod => "go.mod",
            Self::GoSum => "go.sum",
            Self::ChromeManifest => "chrome-manifest",
            Self::VsixManifest => "vsixmanifest",
            Self::CargoToml => "cargo-toml",
            Self::PyProjectToml => "pyproject-toml",
            Self::GithubActions => "github-actions",
            Self::SystemdService => "systemd_service",
            Self::DesktopEntry => "desktop_entry",
            Self::Xml => "xml",
            Self::ComposerJson => "composer-json",
            Self::PkgInfo => "pkginfo",
            Self::SrcInfo => "src_info",
            Self::Registry => "registry",
            Self::Plist => "plist",
            Self::Nib => "nib",
            Self::Pbxproj => "pbxproj",
            Self::Cmake => "cmake",
            Self::Rtf => "rtf",
            Self::OleDoc => "ole",
            Self::Msi => "msi",
            Self::Ooxml => "ooxml",
            Self::Odf => "odf",
            Self::Lnk => "lnk",
            Self::Ipa => "ipa",
            Self::Jpeg => "jpeg",
            Self::Png => "png",
            Self::Svg => "svg",
            Self::Wav => "wav",
            Self::Aiff => "aiff",
            Self::Mp3 => "mp3",
            Self::Mp4 => "mp4",
            Self::Ico => "ico",
            Self::Gif => "gif",
            Self::Bmp => "bmp",
            Self::Webp => "webp",
            Self::Font => "font",
            Self::Pickle => "pickle",
            Self::Pdf => "pdf",
            Self::Zip => "zip",
            Self::AndroidApk => "apk",
            Self::AlpineApk => "apk_alpine",
            Self::Jar => "jar",
            Self::Tar => "tar",
            Self::Zst => "zst",
            Self::Gz => "gz",
            Self::Bz2 => "bz2",
            Self::Xz => "xz",
            Self::Lzma => "lzma",
            Self::Npm => "npm",
            Self::Nupkg => "nupkg",
            Self::Crate => "crate",
            Self::Conda => "conda",
            Self::Egg => "egg",
            Self::Pkg => "pkg_macos",
            Self::Dmg => "dmg",
            Self::Gem => "gem",
            Self::Whl => "whl",
            Self::PythonSdist => "python_sdist",
            Self::Deb => "deb",
            Self::StaticLib => "static-lib",
            Self::Rpm => "rpm",
            Self::Crx => "crx",
            Self::Chm => "chm",
            Self::Cab => "cab",
            Self::Iso => "iso",
            Self::OciImage => "oci_image",
            Self::Xbps => "xbps",
            Self::GentooBinpkg => "gentoo_binpkg",
            Self::Asar => "asar",
            Self::VsixArchive => "vsix",
            Self::Xpi => "xpi",
        }
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
            "static-lib" | "staticlib" | "a" => FileType::StaticLib,
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
            "dex" | "dalvik" => FileType::Dex,
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
            "jsp" | "jspx" => FileType::Jsp,
            "asp" | "aspx" => FileType::Asp,
            "cfml" | "cfm" | "cfc" => FileType::Cfml,
            "tex" => FileType::Tex,
            "yara" | "yar" => FileType::Yara,
            "postscript" | "ps" | "eps" => FileType::PostScript,
            "dos_com" | "dos-com" | "doscom" => FileType::DosCom,
            "mirc" | "mrc" => FileType::Mirc,
            "ircii" => FileType::IrcII,
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
            "xml" | "csproj" | "msbuild" | "xaml" | "xml-document" => FileType::Xml,
            "svg" => FileType::Svg,
            "composer-json" | "composerjson" | "composer.json" => FileType::ComposerJson,
            "jpeg" | "jpg" => FileType::Jpeg,
            "png" => FileType::Png,
            "font" | "ttf" | "otf" | "ttc" | "woff" | "woff2" | "eot" => FileType::Font,
            "wav" | "wave" => FileType::Wav,
            "aiff" | "aif" | "aifc" => FileType::Aiff,
            "mp3" => FileType::Mp3,
            "mp4" | "m4a" | "m4v" | "mov" => FileType::Mp4,
            "ico" | "cur" | "favicon" => FileType::Ico,
            "gif" => FileType::Gif,
            "bmp" | "dib" => FileType::Bmp,
            "webp" => FileType::Webp,
            "pickle" | "pkl" => FileType::Pickle,
            // Additional formats
            "plist" => FileType::Plist,
            "nib" => FileType::Nib,
            "pbxproj" | "xcodeproj" => FileType::Pbxproj,
            "cmake" | "cmakelists" => FileType::Cmake,
            "pkginfo" | "pkg-info" | "pkg_info" => FileType::PkgInfo,
            "rtf" => FileType::Rtf,
            // Every legacy Office extension filefacts recognises. The
            // template and add-in variants were missing, so a `.xla` or a
            // `.dot` fell through to Unknown and no OleDoc rule reached it.
            "ole" | "doc" | "xls" | "ppt" | "msg" | "oledoc" | "dot" | "pps" | "pot" | "ppa"
            | "xlt" | "xla" => FileType::OleDoc,
            "msi" | "msp" | "mst" | "msm" => FileType::Msi,
            // Likewise for OOXML. `.ppam` and `.xlam` are add-ins and
            // `.dotm` / `.potm` / `.ppsm` macro-enabled templates -- the
            // formats macro delivery reaches for precisely because they get
            // looked at less, and until now they got no rules at all.
            "ooxml" | "docx" | "xlsx" | "pptx" | "docm" | "xlsm" | "pptm" | "dotx" | "dotm"
            | "xltx" | "xltm" | "xlam" | "ppam" | "potx" | "potm" | "ppsx" | "ppsm" | "sldx"
            | "sldm" => FileType::Ooxml,
            "lnk" => FileType::Lnk,
            "ipa" => FileType::Ipa,
            "pdf" => FileType::Pdf,
            "rar" => FileType::Rar,
            "7z" => FileType::SevenZ,
            "cpio" => FileType::Cpio,
            // "unknown" falls through to the `_` wildcard arm below.
            "zip" => FileType::Zip,
            // `apk` bare (and its old alias `apk_android`) means the Android
            // ecosystem, matching the existing trait corpus's assumption; the
            // Alpine Linux package format is a distinct, unrelated ecosystem
            // (see `AndroidApk`/`AlpineApk` doc comments above).
            "apk" | "apk_android" | "android_apk" => FileType::AndroidApk,
            "apk_alpine" | "alpine_apk" => FileType::AlpineApk,
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

    /// Every filefacts type a rule can name must convert to its rule-engine
    /// counterpart. A missing arm here falls through to `Unknown`, and the
    /// engine then skips every trait whose `for:` names that type -- silently,
    /// with the file still reported under its correct detected type, so the
    /// rules simply never fire and nothing says why.
    ///
    /// `pbxproj` and `cmake` were added to the enum, to `from_str`, and to the
    /// `build` group without this arm, which cost an afternoon: `cleave
    /// test-rules` reported "Detected file type: Pbxproj" on the line above
    /// "file is Unknown".
    #[test]
    fn build_file_types_convert_from_filefacts() {
        use filefacts::FileType as Ff;
        for (ff, expected) in [
            (Ff::Pbxproj, FileType::Pbxproj),
            (Ff::Cmake, FileType::Cmake),
            (Ff::Makefile, FileType::Makefile),
            (Ff::Dockerfile, FileType::Dockerfile),
            (Ff::Plist, FileType::Plist),
            (Ff::Nib, FileType::Nib),
        ] {
            assert_eq!(
                FileType::from(ff),
                expected,
                "{ff:?} must not fall through to Unknown"
            );
        }
    }

    /// Every Office extension filefacts recognises has to route to a rule
    /// file type, or the rules written for that format never reach the file.
    ///
    /// The macro-enabled add-in and template variants were the ones missing,
    /// which is the wrong half to lose: `.ppam` and `.xlam` are what macro
    /// delivery uses to get looked at less.
    #[test]
    fn office_variants_route_to_their_document_type() {
        for ext in [
            "docx", "xlsx", "pptx", "docm", "xlsm", "pptm", "dotx", "dotm", "xltx", "xltm", "xlam",
            "ppam", "potx", "potm", "ppsx", "ppsm", "sldx", "sldm", "ooxml",
        ] {
            assert_eq!(
                FileType::from_str(ext),
                FileType::Ooxml,
                "{ext} did not route to Ooxml"
            );
        }
        for ext in [
            "doc", "xls", "ppt", "msg", "dot", "pps", "pot", "ppa", "xlt", "xla", "oledoc",
        ] {
            assert_eq!(
                FileType::from_str(ext),
                FileType::OleDoc,
                "{ext} did not route to OleDoc"
            );
        }
    }

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
    fn test_svg_is_raw_text() {
        assert!(!FileType::Svg.is_source_code());
        assert!(FileType::Svg.uses_raw_text_search());
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
        // MSI is its own routing bucket: the office analyzer reports subtype
        // "msi", and filefacts labels .msi/.msp as `msi` (not ole_doc).
        assert_eq!(FileType::from_str("msi"), FileType::Msi);
        assert_eq!(FileType::from_str("msp"), FileType::Msi);
        assert_eq!(FileType::from_str("mst"), FileType::Msi);
        assert_eq!(FileType::from_str("msm"), FileType::Msi);
        assert_eq!(FileType::from_str(Ff::Msi.label()), FileType::Msi);
        // Deliberate foldings: the report keeps the precise label, routing uses
        // the coarse bucket.
        assert_eq!(
            FileType::from_str(Ff::TypeScript.label()),
            FileType::JavaScript
        );
        // SVG is its own rule type, not an alias for XML: it is a media
        // carrier, and while it was folded into `Xml` every `for: [svg]` rule
        // silently targeted Android manifests and MSBuild projects as well.
        assert_eq!(FileType::from_str(Ff::Svg.label()), FileType::Svg);
        assert_eq!(
            FileType::from_str(Ff::ApkAndroid.label()),
            FileType::AndroidApk
        );
        assert_eq!(
            FileType::from_str(Ff::ApkAlpine.label()),
            FileType::AlpineApk
        );
        assert_eq!(FileType::from_str(Ff::Dex.label()), FileType::Dex);
        assert_eq!(FileType::from_str("dex"), FileType::Dex);
        assert_eq!(FileType::from_str(Ff::Cab.label()), FileType::Cab);
        assert_eq!(FileType::from_str(Ff::PkgArch.label()), FileType::Pkg);
        assert_eq!(FileType::from_str(Ff::TarZst.label()), FileType::Tar);
        assert_eq!(FileType::from_str(Ff::Dmg.label()), FileType::Dmg);
        assert_eq!(FileType::from_str(Ff::Asar.label()), FileType::Asar);
        assert_eq!(FileType::from_str(Ff::OciImage.label()), FileType::OciImage);
        assert_eq!(FileType::from_str(Ff::Xbps.label()), FileType::Xbps);
        assert_eq!(
            FileType::from_str(Ff::GentooBinpkg.label()),
            FileType::GentooBinpkg
        );
        assert_eq!(FileType::from_str(Ff::Odf.label()), FileType::Odf);
        // A `.a` static library routes to its own StaticLib bucket (a native
        // binary), NOT to Deb (the `ar`-magic sibling) or Unknown.
        assert_eq!(
            FileType::from_str(Ff::StaticLib.label()),
            FileType::StaticLib
        );
    }

    #[test]
    fn static_lib_is_a_binary_not_an_archive() {
        // A static library is native object code: it must not carry the
        // archive-family `for:` bypass (which applied zip/jar content rules to
        // its uncompressed `ar` member bytes), and it must be reachable via the
        // `static-lib`/`a` tokens.
        assert!(!FileType::StaticLib.is_archive());
        assert_eq!(FileType::from_str("static-lib"), FileType::StaticLib);
        assert_eq!(FileType::from_str("a"), FileType::StaticLib);
    }

    #[test]
    fn every_variant_has_a_distinct_type_bit() {
        // The mask was a bare `u128` until the 129th variant made
        // `1 << 128` panic on every archive scanned. Each variant must land
        // on its own bit, no bit may be shared, and a mask built from the
        // whole inventory must intersect every single type -- across the
        // word boundary that a one-word mask never crossed.
        let variants = FileType::all_variants();
        assert_eq!(variants.len(), FileType::VARIANT_COUNT);
        let mut union = TypeMask::EMPTY;
        for (i, ft) in variants.iter().enumerate() {
            let bit = ft.type_bit();
            assert_ne!(bit, TypeMask::EMPTY, "{ft:?} has no bit");
            assert!(!union.intersects(bit), "{ft:?} shares a bit");
            assert_eq!(ft.variant_index(), i);
            union |= bit;
        }
        for ft in &variants {
            assert!(union.intersects(ft.type_bit()));
            assert!(TypeMask::ALL.intersects(ft.type_bit()));
        }
        assert!(!TypeMask::EMPTY.intersects(TypeMask::ALL));
        // Two types on different words of the mask do not intersect.
        let first = variants[0].type_bit();
        let last = variants[variants.len() - 1].type_bit();
        assert!(!first.intersects(last));
        assert!((first | last).intersects(last));
    }

    #[test]
    fn label_round_trips_through_from_str() {
        // Every type name an author is shown must be one they can type back.
        // Three deliberate exceptions, none of which `from_str` owns:
        // `All` is a group keyword resolved in `capabilities::parsing`, and
        // `TypeScript`/`Cpp` fold onto `JavaScript`/`C` (one grammar, one
        // rule surface), so neither has a spelling of its own.
        for ft in FileType::all_variants() {
            if matches!(ft, FileType::TypeScript | FileType::Cpp | FileType::All) {
                continue;
            }
            assert_eq!(
                FileType::from_str(ft.label()),
                ft,
                "label() for {ft:?} is {:?}, which from_str does not map back",
                ft.label()
            );
        }
    }

    #[test]
    fn rar_7z_cpio_are_their_own_archive_family_members() {
        // The old generic `archive` bucket collapsed rar/7z/cpio into one
        // undifferentiated type; each now has its own concrete FileType so
        // `for:` can target them individually, and the bare literal
        // "archive" is retired -- it must not resolve to anything.
        assert_eq!(FileType::from_str("rar"), FileType::Rar);
        assert_eq!(FileType::from_str("7z"), FileType::SevenZ);
        assert_eq!(FileType::from_str("cpio"), FileType::Cpio);
        assert!(FileType::Rar.is_archive());
        assert!(FileType::SevenZ.is_archive());
        assert!(FileType::Cpio.is_archive());
        assert_ne!(FileType::from_str("archive"), FileType::Rar);
        assert_ne!(FileType::from_str("archive"), FileType::SevenZ);
        assert_ne!(FileType::from_str("archive"), FileType::Cpio);
        assert_eq!(FileType::from_str("archive"), FileType::Unknown);
    }

    #[test]
    fn archive_family_is_generated_from_enum_markers() {
        let family = FileType::archive_family_types();
        assert!(family.contains(&FileType::Rar));
        assert!(family.contains(&FileType::SevenZ));
        assert!(family.contains(&FileType::Cpio));
        assert!(family.contains(&FileType::Dmg));
        assert!(family.contains(&FileType::Asar));
        assert!(family.contains(&FileType::OciImage));
        assert!(family.contains(&FileType::Xbps));
        assert!(family.contains(&FileType::GentooBinpkg));
        assert!(FileType::Dmg.is_archive());
        assert!(!FileType::Gz.is_archive());
        assert!(!FileType::StaticLib.is_archive());
    }

    #[test]
    #[allow(clippy::panic)]
    fn container_bases_mirror_filefacts_archive_format() {
        use filefacts::{ArchiveFormat, FileType as Ff};
        // Every base is itself a base-less archive type, and every type that
        // has one is an archive: the relation is one level deep.
        for ft in FileType::all_variants() {
            for base in ft.container_bases() {
                assert!(ft.is_archive(), "{ft:?} has a base but is no archive");
                assert!(base.is_archive() && base.container_bases().is_empty());
            }
        }
        // filefacts owns the container decomposition; the rule buckets that
        // map 1:1 onto a filefacts type must agree with it.
        for ff in [
            Ff::ApkAndroid,
            Ff::Jar,
            Ff::Whl,
            Ff::Nupkg,
            Ff::Crx,
            Ff::Xpi,
            Ff::Vsix,
            Ff::Egg,
            Ff::Ipa,
            Ff::Conda,
            Ff::ApkAlpine,
            Ff::Npm,
            Ff::Crate,
            Ff::Gem,
            Ff::PythonSdist,
            Ff::OciImage,
            Ff::Xbps,
            Ff::GentooBinpkg,
            Ff::PkgArch,
        ] {
            let base = match ff.archive_format() {
                Some(ArchiveFormat::Zip) => FileType::Zip,
                Some(ArchiveFormat::Tar) => FileType::Tar,
                other => panic!("{ff:?} decomposes to {other:?}"),
            };
            let bucket = FileType::from(ff);
            assert!(
                bucket.container_bases().contains(&base),
                "{bucket:?} ({ff:?}) is a {base:?} per filefacts"
            );
        }
        // Not subtypes of anything a rule can name.
        for ft in [FileType::Deb, FileType::Rpm, FileType::Zip, FileType::Tar] {
            assert!(ft.container_bases().is_empty(), "{ft:?}");
        }
    }

    #[test]
    fn rule_applies_to_is_not_an_archive_family_union() {
        use FileType as T;
        assert!(!T::rule_applies_to(&[T::AndroidApk], T::Jar));
        assert!(!T::rule_applies_to(&[T::AndroidApk], T::Zip));
        assert!(!T::rule_applies_to(&[T::Jar], T::Zip));
        assert!(!T::rule_applies_to(&[T::Deb], T::Whl));
        assert!(T::rule_applies_to(&[T::Zip], T::Jar));
        assert!(T::rule_applies_to(&[T::Zip, T::AndroidApk], T::AndroidApk));
        assert!(T::rule_applies_to(&[T::Tar], T::Npm));
        assert!(T::rule_applies_to(&[T::All], T::Elf));
        assert!(T::rule_applies_to(&[T::Deb], T::All));
        assert!(!T::rule_applies_to(&[T::Python], T::All));
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

        // apk_android and apk_alpine are unrelated ecosystems (Android app
        // sideloading vs. a musl-libc Linux package manager) and must not
        // collapse onto the same FileType.
        assert_eq!(
            parsed.file_types,
            vec![FileType::AndroidApk, FileType::AlpineApk, FileType::Cab]
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

#[cfg(test)]
mod package_family_tests {
    use super::FileType;

    /// Every `#[package]` variant must also be `#[archive]`. A package is a
    /// container by definition, and `parent_package` only ever inspects
    /// ancestors that the archive walk produced -- a package-but-not-archive
    /// type would be unreachable there, silently.
    #[test]
    fn every_package_is_an_archive() {
        let strays: Vec<_> = FileType::package_family_types()
            .iter()
            .filter(|ft| !FileType::is_archive(ft))
            .collect();
        assert!(
            strays.is_empty(),
            "package types missing #[archive]: {strays:?}"
        );
    }

    /// The split is "unit of distribution" vs "generic container". Spelled out
    /// so a new variant has to make a deliberate choice rather than inherit one.
    #[test]
    fn the_split_is_distribution_versus_container() {
        for ft in [
            FileType::Npm,
            FileType::Gem,
            FileType::Whl,
            FileType::Deb,
            FileType::Rpm,
            FileType::AlpineApk,
            FileType::AndroidApk,
            FileType::Ipa,
            FileType::VsixArchive,
            FileType::Crx,
            FileType::Xpi,
            FileType::OciImage,
        ] {
            assert!(ft.is_package(), "{ft:?} is a unit of distribution");
        }
        for ft in [
            FileType::Zip,
            FileType::Tar,
            FileType::Iso,
            FileType::Asar,
            FileType::Cab,
            FileType::Dmg,
            // A container format reused everywhere (jar-in-war, jar-in-ear),
            // not a boundary an author means by "this package".
            FileType::Jar,
        ] {
            assert!(!ft.is_package(), "{ft:?} is a generic container");
        }
    }

    /// Both halves of the old hand-written pair are gone; `from_str` has to
    /// route every label filefacts emits for a package onto a `#[package]`
    /// variant, or the ancestor walk stops recognising it.
    #[test]
    fn package_labels_round_trip_through_from_str() {
        for label in [
            "npm",
            "nupkg",
            "gem",
            "whl",
            "python_sdist",
            "crate",
            "conda",
            "egg",
            "deb",
            "rpm",
            "apk_alpine",
            "apk_android",
            "xbps",
            "oci_image",
        ] {
            assert!(
                FileType::from_str(label).is_package(),
                "label {label} must route to a #[package] type"
            );
        }
        for label in ["zip", "tar", "iso", "jar", "elf", "javascript"] {
            assert!(
                !FileType::from_str(label).is_package(),
                "label {label} must not be a package"
            );
        }
    }
}
