//! YARA rule engine integration.
//!
//! This module provides YARA pattern matching for malware detection.
//! It loads and compiles YARA rules from:
//! - Built-in rules (traits/yara/)
//! - Third-party rules (if enabled)
//!
//! Rules are compiled once at startup for performance.

use crate::capabilities::CapabilityMapper;
use crate::types::{
    deduplicate_evidence, Evidence, MatchedString, YaraMatch, MAX_EVIDENCE_PER_TRAIT,
};
use anyhow::{Context, Result};
use rayon::prelude::*;
use std::cell::RefCell;
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use walkdir::WalkDir;

/// Compiled regex for YARA rule header matching — shared across all preprocessing steps.
fn rule_start_re() -> Option<&'static regex::Regex> {
    static RE: OnceLock<Option<regex::Regex>> = OnceLock::new();
    RE.get_or_init(|| regex::Regex::new(r"(?m)^(\s*)((?:private\s+|global\s+)*)rule\s+(\w+)").ok())
        .as_ref()
}

/// Maximum pattern match ranges to collect per pattern.
/// Patterns matching more than this are truncated to prevent memory exhaustion.
const MAX_PATTERN_MATCHES: usize = 100_000;

/// Maximum scanners to cache per thread in the engine tier cache.
/// Typically only 2 tiers scanned per file (generic + file-type), so 4 is generous.
const ENGINE_SCANNER_CACHE_SIZE: usize = 4;

// Thread-local LRU cache for YARA scanners keyed by `Rules` pointer address.
// Avoids expensive `Scanner::new()` on every file (wasmtime VM instantiation).
// Each rayon worker thread caches its own scanners (typically 2: generic + file-type).
// Bounded to prevent memory explosion across many threads.
thread_local! {
    static ENGINE_SCANNER_CACHE: RefCell<lru::LruCache<usize, yara_x::Scanner<'static>>> = {
        use std::num::NonZeroUsize;
        let cache_size =
            NonZeroUsize::new(ENGINE_SCANNER_CACHE_SIZE).unwrap_or(NonZeroUsize::MIN);
        RefCell::new(lru::LruCache::new(cache_size))
    };
}

/// Clear the thread-local engine scanner cache for this thread.
/// Called during periodic cache cleanup and on hot-reload.
pub(crate) fn clear_engine_scanner_cache() {
    ENGINE_SCANNER_CACHE.with(|cache| {
        let mut cache = cache.borrow_mut();
        let cleared = cache.len();
        cache.clear();
        if cleared > 0 {
            tracing::debug!(
                cleared_entries = cleared,
                "Cleared YARA engine scanner cache"
            );
        }
    });
}

/// Raw match data collected from a YARA scan before processing into `YaraMatch`.
struct RawRule {
    name: String,
    namespace: String,
    tags: Vec<String>,
    metadata: Vec<(String, String)>,
    patterns: Vec<(String, Vec<(usize, usize)>)>,
}

/// File-type tier for pre-classified YARA rule sets.
///
/// Rules are compiled into separate `yara_x::Rules` per tier so each scan
/// only processes the subset relevant to the target file type. Every scan
/// runs two passes: the tier-specific set + the `Generic` set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum YaraTier {
    /// Rules with no filetype constraint, plus all built-in and inline trait YARA.
    Generic,
    /// PE / DLL / EXE rules (~7K from third-party).
    Pe,
    /// ELF / SO / KO rules (~1.5K).
    Elf,
    /// MachO / dylib / kext rules (~300).
    MachO,
    /// Scripting language rules: PS1, PHP, Python, JS, shell, etc. (~1.5K).
    Script,
    /// Document format rules: PDF, RTF, OLE, LNK, ZIP (~200).
    Doc,
}

impl YaraTier {
    /// All tier variants in a fixed order for iteration.
    const ALL: &[Self] = &[
        Self::Generic,
        Self::Pe,
        Self::Elf,
        Self::MachO,
        Self::Script,
        Self::Doc,
    ];

    /// Classify a set of filetype strings (from metadata/inference) into a tier.
    fn from_filetypes(filetypes: &[&str]) -> Self {
        for ft in filetypes {
            match *ft {
                "pe" | "exe" | "dll" | "sys" => return Self::Pe,
                "elf" | "so" | "ko" => return Self::Elf,
                "macho" | "dylib" | "kext" => return Self::MachO,
                "sh" | "bash" | "zsh" | "py" | "pyc" | "js" | "mjs" | "cjs" | "ts" | "php"
                | "rb" | "pl" | "pm" | "lua" | "ps1" | "psm1" | "psd1" | "bat" | "cmd" | "vbs"
                | "vba" | "java" | "jar" | "class" | "jsp" | "aspx" | "asp" => return Self::Script,
                "pdf" | "rtf" | "ole" | "doc" | "docx" | "xls" | "xlsx" | "ppt" | "pptx"
                | "msg" | "lnk" | "zip" | "iso" | "img" | "one" | "onepkg" => return Self::Doc,
                _ => {}
            }
        }
        Self::Generic
    }

    /// Map the `file_type_filter` strings passed by callers to a tier.
    fn from_filter(filter: Option<&[&str]>) -> Self {
        match filter {
            None => Self::Generic,
            Some(types) => Self::from_filetypes(types),
        }
    }

    /// Short label for cache filenames and logging.
    fn label(self) -> &'static str {
        match self {
            Self::Generic => "generic",
            Self::Pe => "pe",
            Self::Elf => "elf",
            Self::MachO => "macho",
            Self::Script => "script",
            Self::Doc => "doc",
        }
    }
}

/// YARA-X engine for pattern-based detection.
///
/// Rules are compiled into tiered sets by file type. Each scan runs two passes:
/// 1. The tier matching the target file type (e.g. PE rules for a PE file)
/// 2. The Generic tier (applies to all files)
///
/// Scanners are cached per-thread to avoid expensive re-creation.
#[derive(Debug)]
pub(crate) struct YaraEngine {
    /// Per-tier compiled rule sets. `Generic` always present when loaded.
    tiers: HashMap<YaraTier, yara_x::Rules>,
    /// Namespaces compiled into the combined engine from inline trait YARA conditions.
    /// Used to split scan results: inline matches (keyed here) go to trait evaluation;
    /// all other matches are returned as regular YARA findings.
    compiled_inline_namespaces: Vec<String>,
}

/// Content-based scoring indicators for classifying YARA rules by target platform.
///
/// Each array contains lowercase strings to match against the lowercased rule body.
/// A match contributes 1 point toward the corresponding tier. The tier with the
/// highest score (above a minimum threshold) wins. Ties or ambiguity → Generic.
mod indicators {
    // ── PE / Windows ──────────────────────────────────────────────
    /// Windows DLLs — very high signal.
    pub(super) const PE_DLLS: &[&str] = &[
        "kernel32",
        "ntdll",
        "advapi32",
        "ws2_32",
        "wininet",
        "winhttp",
        "user32",
        "shell32",
        "ole32",
        "oleaut32",
        "msvcrt",
        "mscoree",
        "crypt32",
        "urlmon",
        "comctl32",
        "gdi32",
        "shlwapi",
        "amsi.dll",
        "clr.dll",
        "netapi32",
        "psapi",
        "dbghelp",
        "cabinet.dll",
        "version.dll",
        "secur32",
        "winspool",
        "mpr.dll",
        "iphlpapi",
        "dnsapi",
        "rasapi32",
        "mswsock",
    ];

    /// Windows API function names — very high signal.
    pub(super) const PE_APIS: &[&str] = &[
        "virtualalloc",
        "virtualprotect",
        "virtualfree",
        "createprocess",
        "createremotethread",
        "createthread",
        "writeprocessmemory",
        "readprocessmemory",
        "ntcreatethreadex",
        "ntmapviewofsection",
        "ntwritevirtualmemory",
        "loadlibrary",
        "getprocaddress",
        "getmodulehandle",
        "winexec",
        "shellexecute",
        "regopenkeyex",
        "regsetvalueex",
        "regcreatekeyex",
        "internetopen",
        "internetconnect",
        "httpopenrequest",
        "urldownloadtofile",
        "cocreateinstance",
        "isdebuggerpresent",
        "checkremotedebuggerpresent",
        "openprocess",
        "terminateprocess",
        "setwindowshookex",
        "callnexthookex",
        "cryptencrypt",
        "cryptdecrypt",
        "cryptacquirecontext",
        "adjusttokenprivileges",
        "openprocesstoken",
        "ntqueryinformationprocess",
        "ntsetinformationthread",
        "rtlinitunicodestring",
        "zwquerysysteminformation",
        "ldrloaddll",
        "rtldecompressbuffer",
        "getasynckeystate",
        "gettemppath",
        "getwindowtext",
        "createservice",
        "startservice",
    ];

    /// Windows-specific paths and registry keys.
    pub(super) const PE_PATHS: &[&str] = &[
        "\\windows\\",
        "\\system32\\",
        "\\syswow64\\",
        "\\appdata\\",
        "\\programdata\\",
        "hkey_local_machine",
        "hkey_current_user",
        "software\\microsoft",
        "currentversion\\run",
        "\\temp\\",
        "\\users\\",
    ];

    /// Windows executables and LOLBins.
    pub(super) const PE_EXES: &[&str] = &[
        "cmd.exe",
        "powershell.exe",
        "wscript.exe",
        "cscript.exe",
        "rundll32",
        "regsvr32",
        "msiexec",
        "certutil",
        "bitsadmin",
        "schtasks",
        "mshta",
    ];

    /// .NET / CLR indicators.
    pub(super) const PE_DOTNET: &[&str] = &[
        "system.reflection",
        "system.runtime",
        "system.diagnostics",
        "_corexemain",
        "_cordllmain",
        "mscorlib",
        "assembly.load",
        "system.convert",
        "system.net.webclient",
        "system.net.sockets",
    ];

    /// PE structure artifacts.
    pub(super) const PE_STRUCTURE: &[&str] = &[
        "this program cannot be run in dos mode",
        "image_dos_header",
        "image_nt_headers",
        "rich_header",
        // PDB paths (strong Windows signal)
        ".pdb",
        "\\release\\",
        "\\debug\\",
        // Windows services / registry
        "wsuscomserverimpl",
        "currentcontrolset",
        "software\\classes",
        "software\\policies",
        "software\\wow6432node",
        // Windows service/event patterns
        "sc.exe",
        "net.exe",
        "wevtutil",
        // Common PE metadata strings
        "companyname",
        "fileversion",
        "legalcopyright",
    ];

    /// Windows COM / WMI / scripting hosts.
    pub(super) const PE_COM: &[&str] = &[
        "win32_process",
        "wscript.shell",
        "scripting.filesystemobject",
        "wmi",
        "iwbemservices",
    ];

    /// PE rule-name keywords (matched against lowercased rule name).
    pub(super) const PE_NAME: &[&str] = &[
        // Binary format hints
        "shellcode",
        "dll",
        "dotnet",
        "msil",
        "_exe_",
        "_pe_",
        "_pdb",
        "wsus",
        "_driver_",
        "loldrivers",
        "_sys_",
        // Windows tool/LOLBin names in rule names
        "msiexec",
        "certutil",
        "rundll",
        "regsvr",
        "schtask",
        "bitsadmin",
        "mshta",
        // Windows vendor/platform signals
        "microsoft",
        "wintapix",
        // Vendor prefixes overwhelmingly targeting Windows PE
        "cape_",
        // Common Windows malware families
        "bazar",
        "cobalt",
        "mimikatz",
        "metasploit",
        "meterpreter",
        "emotet",
        "trickbot",
        "dridex",
        "qakbot",
        "qbot",
        "icedid",
        "bazarloader",
        "formbook",
        "lokibot",
        "njrat",
        "asyncrat",
        "remcos",
        "nanocore",
        "darkcomet",
        "agenttesla",
        "redline",
        "raccoon",
        "vidar",
        "smokeloader",
        "amadey",
        "rhadamanthys",
        "stealc",
        "lumma",
        "risepro",
        "privateloader",
        "pikabot",
        "darkgate",
        "netreactor",
        "confuserex",
        "danabot",
        "ursnif",
        "gozi",
        "zloader",
        "bancteian",
        "ramnit",
        "neshta",
        "sality",
        "pswstealer",
        "infostealer",
        // Windows ransomware families
        "ransomware",
        "ransom_",
        "cryptolocker",
        "wannacry",
        "ryuk",
        "revil",
        "sodinokibi",
        "lockbit",
        "conti",
        "babuk",
        "darkside",
        "blackmatter",
        "hive_ransom",
        "maze_ransom",
        "clop",
        "netwalker",
        "mountlocker",
        "wastedlocker",
        "bitpaymer",
        "nefilim",
        // Windows APT / backdoor families
        "hikit",
        "enfal",
        "turla",
        "gazer",
        "carbon",
        "hermeticwiper",
        "industroyer",
        "notpetya",
        // IIS (Windows web server)
        "_iis_",
        // Known Windows-centric APT groups/campaigns
        "opcleaver",
        "empire",
        "sunburst",
        "ccleaner",
        "plugx",
        // Windows credential tools
        "createmini",
        "lsass",
    ];

    // ── ELF / Linux ───────────────────────────────────────────────
    pub(super) const ELF_PATHS: &[&str] = &[
        "/bin/sh",
        "/bin/bash",
        "/bin/dash",
        "/etc/passwd",
        "/etc/shadow",
        "/etc/crontab",
        "/proc/self",
        "/proc/net",
        "/dev/shm",
        "/dev/null",
        "/var/tmp/",
        "/var/run/",
    ];

    pub(super) const ELF_LIBS: &[&str] = &[
        "ld-linux",
        "libc.so",
        "libpthread",
        "libdl.so",
        "ld_preload",
        "ld_library_path",
    ];

    pub(super) const ELF_NAME: &[&str] = &[
        "_elf_", "_lnx_", "mirai", "tsunami", "xorddos", "bpfdoor", "kaiji", "gafgyt", "bashlite",
        "dofloo", "kobalos", "perfctl",
    ];

    // ── MachO / macOS ─────────────────────────────────────────────
    pub(super) const MACHO_BODY: &[&str] = &[
        "/library/launchagents",
        "/library/launchdaemons",
        "com.apple.",
        "nsapplescript",
        "nsappleeventdescriptor",
        "osascript",
        "launchctl",
        "lc_load_dylib",
        "lc_segment_64",
        "cfsocketref",
        "ioservicematching",
        "security.framework",
        "corefoundation",
        "xprotect",
    ];

    pub(super) const MACHO_NAME: &[&str] = &[
        "_macho_",
        "_osx_",
        "amos",
        "atomic_stealer",
        "bundlore",
        "shlayer",
        "pirrit",
        "adload",
        "xcsset",
        "rustbucket",
        "jokerspy",
    ];

    // ── Script ────────────────────────────────────────────────────
    pub(super) const SCRIPT_BODY: &[&str] = &[
        // PHP
        "<?php",
        "<?=",
        "base64_decode(",
        "gzinflate(",
        "str_rot13(",
        "preg_replace(",
        "function_exists(",
        // PowerShell
        "-encodedcommand",
        "invoke-expression",
        "new-object system.net",
        "invoke-webrequest",
        "downloadstring(",
        "iex(",
        // JavaScript / VBS
        "activexobject",
        "document.createelement",
        // Python
        "import subprocess",
        "import socket",
        // Loose description/metadata matches — language name anywhere in rule body.
        // Note: "powershell" is intentionally omitted here because "powershell.exe"
        // in PE_EXES would cause PE vs Script ties. It's in SCRIPT_NAME for name matching.
        "php ",
        "python ",
        "ruby ",
        "perl ",
        "autoit",
        "vbscript",
        "javascript",
    ];

    /// Script name indicators. Note: "shell" is intentionally omitted —
    /// many binary malware rules reference shell commands, and "shellcode" is PE.
    pub(super) const SCRIPT_NAME: &[&str] = &[
        "webshell",
        "php",
        "python",
        "powershell",
        "_asp",
        "ruby",
        "perl",
        "lua",
        "autoit",
        "vbs",
        "vba",
        "hta",
        "jse",
        "wsf",
        "javascript",
        "jscript",
    ];

    // ── Document ──────────────────────────────────────────────────
    pub(super) const DOC_BODY: &[&str] = &[
        "%pdf",
        "/javascript",
        "/openaction",
        "/aa ",
        "endobj",
        "endstream",
        "{\\rtf",
        "\\objdata",
        "\\objupd",
        "\\objemb",
        "vbaproject",
        "auto_open",
        "document_open",
        "autoopen",
        "workbook_open",
        "activedocument",
        "thisdocument",
        // Metadata/tag signals
        "maldoc",
        ": maldoc",
    ];

    pub(super) const DOC_NAME: &[&str] = &[
        "_doc_",
        "_pdf_",
        "_rtf_",
        "_ole_",
        "_lnk_",
        "maldoc",
        "excelmacro",
        "_xls",
        "_ppam",
        "_docm",
        "_docx_",
        "_xlsm",
        "_msi_",
        "onenote",
        "_msg_",
        "_cab_",
        "_iso_",
        "_img_",
        "_zip_",
        "_zpaq",
    ];
}

impl YaraTier {
    /// Classify a single YARA rule into a tier based on its metadata, condition,
    /// module references, magic bytes, content indicators, and rule name.
    pub(crate) fn classify_rule(rule_name: &str, rule_body: &str, namespace: &str) -> Self {
        let lower = rule_body.to_lowercase();

        // 1. Explicit filetype/os metadata
        let mut os_meta: Option<String> = None;
        for line in lower.lines() {
            let trimmed = line.trim();
            if (trimmed.starts_with("filetype") || trimmed.starts_with("filetypes"))
                && trimmed.contains('=')
            {
                if let Some(val) = trimmed.split('=').nth(1) {
                    let val = val.trim().trim_matches('"').trim_matches('\'');
                    let types: Vec<&str> = val.split(',').map(str::trim).collect();
                    let tier = Self::from_filetypes(&types);
                    if tier != Self::Generic {
                        return tier;
                    }
                }
            }
            // Extract os metadata (e.g. os = "windows") for later use
            if trimmed.starts_with("os") && trimmed.contains('=') {
                // Guard against matching "os_" prefixed keys
                let after_os = &trimmed[2..];
                if after_os.starts_with(' ') || after_os.starts_with('=') {
                    if let Some(val) = trimmed.split('=').nth(1) {
                        let val = val.trim().trim_matches('"').trim_matches('\'');
                        if val != "multi" && val != "all" {
                            os_meta = Some(val.to_string());
                        }
                    }
                }
            }
        }

        // 1b. If os metadata found, use it for classification — but only if all
        // inferred filetypes map to the same tier (skip cross-platform os like "win,linux")
        if let Some(ref os) = os_meta {
            let inferred = crate::third_party_yara::infer_filetypes(rule_name, Some(os));
            if !inferred.is_empty() {
                let first_tier = Self::from_filetypes(&inferred);
                // Check that all filetypes resolve to the same non-Generic tier
                let mixed = inferred.iter().any(|ft| {
                    let t = Self::from_filetypes(&[ft]);
                    t != Self::Generic && t != first_tier
                });
                if !mixed && first_tier != Self::Generic {
                    return first_tier;
                }
            }
        }

        // 2. Module references in condition
        if crate::third_party_yara::has_module_reference(&lower, "pe.")
            || crate::third_party_yara::has_module_reference(&lower, "dotnet.")
        {
            return Self::Pe;
        }
        if crate::third_party_yara::has_module_reference(&lower, "elf.") {
            return Self::Elf;
        }
        if crate::third_party_yara::has_module_reference(&lower, "macho.") {
            return Self::MachO;
        }

        // 3. Magic byte patterns
        if let Some(ft) = crate::third_party_yara::filetype_from_magic(&lower) {
            let tier = Self::from_filetypes(&[ft]);
            if tier != Self::Generic {
                return tier;
            }
        }

        // 4. Content-based scoring — analyze rule body strings and hex patterns
        if let Some(tier) = Self::classify_by_content(rule_name, &lower, namespace) {
            return tier;
        }

        // 5. Infer from rule name (with os metadata if available)
        let inferred = crate::third_party_yara::infer_filetypes(rule_name, os_meta.as_deref());
        if !inferred.is_empty() {
            return Self::from_filetypes(&inferred);
        }

        // 6. Infer from namespace
        let ns_inferred =
            crate::third_party_yara::infer_filetypes_from_namespace(namespace, os_meta.as_deref());
        if !ns_inferred.is_empty() {
            return Self::from_filetypes(&ns_inferred);
        }

        Self::Generic
    }

    /// Score rule body content and rule name against platform-specific indicator lists.
    ///
    /// Returns the best-matching tier if there is a clear winner (score ≥ 2 and at
    /// least double the runner-up), or `None` to fall through to weaker heuristics.
    fn classify_by_content(rule_name: &str, body_lower: &str, _namespace: &str) -> Option<Self> {
        let name_lower = rule_name.to_ascii_lowercase();
        // Scores: [PE, ELF, MachO, Script, Doc]
        let mut s = [0u32; 5];

        // Extract description metadata for additional platform hints
        let description = body_lower
            .lines()
            .find_map(|line| {
                let t = line.trim();
                if t.starts_with("description") && t.contains('=') {
                    t.split('=')
                        .nth(1)
                        .map(|v| v.trim().trim_matches('"').to_string())
                } else {
                    None
                }
            })
            .unwrap_or_default();

        // Description-based platform hints (weak signal, +1 each)
        if description.contains("windows")
            || description.contains(" exe ")
            || description.contains(" dll ")
        {
            s[0] += 1;
        }
        if description.contains("linux") {
            s[1] += 1;
        }
        if description.contains("macos") || description.contains("osx") {
            s[2] += 1;
        }

        // PE body indicators
        for &ind in indicators::PE_DLLS {
            if body_lower.contains(ind) {
                s[0] += 1;
            }
        }
        for &ind in indicators::PE_APIS {
            if body_lower.contains(ind) {
                s[0] += 1;
            }
        }
        for &ind in indicators::PE_PATHS {
            if body_lower.contains(ind) {
                s[0] += 1;
            }
        }
        for &ind in indicators::PE_EXES {
            if body_lower.contains(ind) {
                s[0] += 1;
            }
        }
        for &ind in indicators::PE_DOTNET {
            if body_lower.contains(ind) {
                s[0] += 1;
            }
        }
        for &ind in indicators::PE_STRUCTURE {
            if body_lower.contains(ind) {
                s[0] += 1;
            }
        }
        for &ind in indicators::PE_COM {
            if body_lower.contains(ind) {
                s[0] += 1;
            }
        }

        // ELF body indicators
        for &ind in indicators::ELF_PATHS {
            if body_lower.contains(ind) {
                s[1] += 1;
            }
        }
        for &ind in indicators::ELF_LIBS {
            if body_lower.contains(ind) {
                s[1] += 1;
            }
        }

        // MachO body indicators
        for &ind in indicators::MACHO_BODY {
            if body_lower.contains(ind) {
                s[2] += 1;
            }
        }

        // Script body indicators
        for &ind in indicators::SCRIPT_BODY {
            if body_lower.contains(ind) {
                s[3] += 1;
            }
        }

        // Doc body indicators
        for &ind in indicators::DOC_BODY {
            if body_lower.contains(ind) {
                s[4] += 1;
            }
        }

        // Name indicators
        for &ind in indicators::PE_NAME {
            if name_lower.contains(ind) {
                s[0] += 1;
            }
        }
        for &ind in indicators::ELF_NAME {
            if name_lower.contains(ind) {
                s[1] += 1;
            }
        }
        for &ind in indicators::MACHO_NAME {
            if name_lower.contains(ind) {
                s[2] += 1;
            }
        }
        for &ind in indicators::SCRIPT_NAME {
            if name_lower.contains(ind) {
                s[3] += 1;
            }
        }
        for &ind in indicators::DOC_NAME {
            if name_lower.contains(ind) {
                s[4] += 1;
            }
        }

        let tiers = [Self::Pe, Self::Elf, Self::MachO, Self::Script, Self::Doc];

        // Find max and second-highest scores
        let (max_idx, &max_score) = s.iter().enumerate().max_by_key(|(_, &v)| v)?;
        if max_score == 0 {
            return None;
        }

        let second = s
            .iter()
            .enumerate()
            .filter(|(i, _)| *i != max_idx)
            .map(|(_, &v)| v)
            .max()
            .unwrap_or(0);

        // Single indicator with no competing platform → classify (aggressive).
        // Multiple indicators → classify if clear winner (at least 2x runner-up).
        // The body indicators (DLLs, APIs, paths) are strong enough signals individually.
        if second == 0 || max_score > second * 2 {
            Some(tiers[max_idx])
        } else {
            None // Ambiguous — stay Generic
        }
    }
}

impl YaraEngine {
    /// Total number of compiled YARA rules across all tiers.
    #[must_use]
    pub(crate) fn total_rules(&self) -> usize {
        self.tiers.values().map(|r| r.iter().count()).sum()
    }

    /// Create a new YARA engine without rules loaded
    #[must_use]
    pub(crate) fn new() -> Self {
        Self {
            tiers: HashMap::new(),
            compiled_inline_namespaces: Vec::new(),
        }
    }

    /// Create a new YARA engine with a pre-existing capability mapper (avoids duplicate loading)
    #[must_use]
    #[allow(dead_code)] // Used by binary target (commands/analyze.rs) and tests
    pub(crate) fn new_with_mapper(_capability_mapper: CapabilityMapper) -> Self {
        Self {
            tiers: HashMap::new(),
            compiled_inline_namespaces: Vec::new(),
        }
    }

    /// Create a new YARA engine for testing (without validation)
    #[cfg(test)]
    #[must_use]
    pub(crate) fn new_for_test() -> Self {
        Self {
            tiers: HashMap::new(),
            compiled_inline_namespaces: Vec::new(),
        }
    }

    /// Load all YARA rules (built-in from traits/ + optionally third-party from third_party/)
    /// Uses cache if available and valid.
    ///
    /// Rules are compiled into separate per-tier `yara_x::Rules` sets:
    /// - **Generic**: built-in rules + inline trait YARA + uncategorized third-party
    /// - **Pe/Elf/MachO/Script/Doc**: third-party rules classified by file type
    ///
    /// Each scan runs two passes: the tier matching the target + Generic.
    ///
    /// Environment variables:
    /// - `CLEAVE_SKIP_YARA=1`: Skip YARA entirely (for fast unit tests)
    /// - `CLEAVE_BUILTIN_YARA_ONLY=1`: Load only built-in rules, skip third-party (~500 vs 14k)
    /// - `CLEAVE_MINIMAL_RULES=1`: Load only essential rules (~100 instead of 14k)
    pub(crate) fn load_all_rules(&mut self, enable_third_party: bool) -> (usize, usize) {
        let _span = tracing::info_span!("load_yara_rules").entered();

        // Fast path: skip YARA entirely for tests that don't need it
        if std::env::var("CLEAVE_SKIP_YARA").is_ok() || std::env::var("cleave_SKIP_YARA").is_ok() {
            tracing::info!("YARA skipped (CLEAVE_SKIP_YARA set)");
            return (0, 0);
        }

        // Override third-party setting via environment (for tests that need YARA but not 14k rules)
        let enable_third_party =
            enable_third_party && std::env::var("CLEAVE_BUILTIN_YARA_ONLY").is_err();

        tracing::info!("Loading YARA rules");

        // Try to load from cache
        if let Ok(cache_path) = crate::cache::yara_cache_path(enable_third_party) {
            if cache_path.exists() {
                tracing::debug!("Attempting to load from cache");
                match self.load_from_cache(&cache_path) {
                    Ok((builtin, third_party)) => {
                        tracing::info!("Loaded YARA rules from cache");
                        return (builtin, third_party);
                    }
                    Err(e) => {
                        tracing::warn!("Cache load failed ({e}), recompiling");
                        eprintln!("⚠️  Cache invalid, recompiling...");
                    }
                }
            } else {
                tracing::info!(
                    expected = %cache_path.display(),
                    "YARA cache miss — expected file not found"
                );
                match crate::cache::most_recent_yar_file() {
                    Ok((mtime, path)) => {
                        let age = mtime.elapsed().map(|d| d.as_secs()).unwrap_or(0);
                        tracing::info!(
                            newest_rule = %path.display(),
                            modified_ago = %crate::cache::format_age(age),
                            "Cache key derived from newest .yar/.yara file"
                        );
                    }
                    Err(_) => tracing::info!("No .yar/.yara files found in traits directory"),
                }
            }
        }

        // Cache miss or invalid - compile from source into per-tier rule sets
        tracing::info!("Compiling YARA rules from source (tiered)");

        let traits_dir = crate::cache::traits_path();
        let third_party_dir = crate::cache::third_party_path();

        // Phase 1: collect (namespace, source) pairs per tier — all pure transforms, no compilers yet.

        // 0. Inline YARA from trait YAML files → Generic
        let inline_sources = if traits_dir.exists() {
            Self::collect_inline_trait_sources(&traits_dir)
        } else {
            vec![]
        };
        self.compiled_inline_namespaces = inline_sources.iter().map(|(ns, _)| ns.clone()).collect();
        let inline_count = self.compiled_inline_namespaces.len();

        // 1. Built-in YARA rule files → Generic
        let builtin_sources = if traits_dir.exists() {
            Self::collect_builtin_sources(&traits_dir)
        } else {
            vec![]
        };
        let builtin_count = builtin_sources.len();

        // 2. Third-party rules → classified into per-tier source lists
        let (mut tier_sources, third_party_count, vt_skipped, disabled_count) =
            if enable_third_party && third_party_dir.exists() {
                Self::collect_third_party_sources_tiered(&third_party_dir)
            } else {
                (HashMap::new(), 0, 0, 0)
            };

        let total_count = builtin_count + third_party_count + inline_count;
        if total_count == 0 {
            eprintln!("\n⚠️  No YARA rules loaded");
            return (0, 0);
        }

        // Merge all Generic-tier sources: inline + built-in + generic third-party
        let generic_sources: Vec<(String, String)> = inline_sources
            .into_iter()
            .chain(builtin_sources)
            .chain(tier_sources.remove(&YaraTier::Generic).unwrap_or_default())
            .collect();
        tier_sources.insert(YaraTier::Generic, generic_sources);

        // Phase 2: build all tiers in parallel.
        //
        // yara_x::Compiler uses Rc internally and is not Send, so we cannot share one across
        // threads. Instead we create a fresh Compiler inside each rayon task (no Send required),
        // load its assigned sources, call build(), and return the resulting Rules (which is Send).
        // All 6 tiers compile concurrently; total wall-clock time ≈ slowest tier rather than sum.
        let non_empty_tiers = tier_sources.values().filter(|v| !v.is_empty()).count();
        let total_sources: usize = tier_sources.values().map(Vec::len).sum();
        tracing::info!(
            sources = total_sources,
            tiers = non_empty_tiers,
            "Compiling YARA rules (this may take 30-60s on first run)"
        );
        let compile_start = std::time::Instant::now();

        let tier_rules: Vec<(YaraTier, yara_x::Rules)> = tier_sources
            .into_iter()
            .collect::<Vec<_>>()
            .into_par_iter()
            .filter_map(|(tier, sources)| {
                if sources.is_empty() {
                    return None;
                }
                let mut compiler = yara_x::Compiler::new();
                for (ns, src) in &sources {
                    compiler.new_namespace(ns);
                    if let Err(e) = compiler.add_source(src.as_bytes()) {
                        tracing::warn!("Tier {:?}: failed to add source: {:?}", tier, e);
                    }
                }
                Some((tier, compiler.build()))
            })
            .collect();

        let compile_elapsed_ms = compile_start.elapsed().as_millis();
        let mut total_rules = 0usize;
        for (tier, rules) in tier_rules {
            let count = rules.iter().count();
            if count > 0 {
                tracing::info!("Tier {}: {} rules", tier.label(), count);
                total_rules += count;
                self.tiers.insert(tier, rules);
            }
        }
        tracing::info!(
            elapsed_ms = compile_elapsed_ms,
            rules = total_rules,
            "YARA compilation complete"
        );

        if disabled_count > 0 {
            tracing::info!("{} third-party rule(s) disabled via config", disabled_count);
        }
        if vt_skipped > 0 {
            tracing::info!(
                "{} third-party rule(s) skipped (require VirusTotal context)",
                vt_skipped
            );
        }

        // Save to cache for next time
        if let Ok(cache_path) = crate::cache::yara_cache_path(enable_third_party) {
            if let Err(e) = self.save_to_cache(&cache_path, builtin_count, third_party_count) {
                eprintln!("⚠️  Failed to save cache: {}", e);
            } else {
                let _ = crate::cache::cleanup_old_caches(&cache_path);
            }
        }

        (builtin_count, third_party_count)
    }

    /// Parse trait YAML files and collect all `type: yara` conditions as (namespace, source) pairs.
    ///
    /// Each rule is tagged with namespace `inline.{trait_id}` so that scan results
    /// can be mapped back to the originating trait during evaluation.
    fn collect_inline_trait_sources(traits_dir: &Path) -> Vec<(String, String)> {
        let yaml_files: Vec<PathBuf> = WalkDir::new(traits_dir)
            .follow_links(false)
            .into_iter()
            .filter_map(std::result::Result::ok)
            .filter(|e| {
                let p = e.path();
                p.is_file()
                    && p.extension()
                        .map(|ext| ext == "yaml" || ext == "yml")
                        .unwrap_or(false)
            })
            .map(|e| e.path().to_path_buf())
            .collect();

        // Read and parse YAML files in parallel, then collect inline YARA sources.
        yaml_files
            .par_iter()
            .flat_map(|path| {
                let Ok(content) = fs::read_to_string(path) else {
                    return vec![];
                };
                let Ok(doc) = serde_yaml::from_str::<serde_yaml::Value>(&content) else {
                    return vec![];
                };

                let items = match &doc {
                    serde_yaml::Value::Mapping(m) => m
                        .get("traits")
                        .and_then(|v| v.as_sequence())
                        .map(|s| s.to_vec()),
                    serde_yaml::Value::Sequence(s) => Some(s.clone()),
                    _ => None,
                };

                let Some(items) = items else { return vec![] };

                let mut result = Vec::new();
                for item in &items {
                    let Some(id) = item.get("id").and_then(|v| v.as_str()) else {
                        continue;
                    };
                    let Some(if_cond) = item.get("if") else {
                        continue;
                    };
                    if if_cond.get("type").and_then(|v| v.as_str()) != Some("yara") {
                        continue;
                    }
                    let Some(source) = if_cond.get("source").and_then(|v| v.as_str()) else {
                        continue;
                    };
                    tracing::trace!("Collected inline YARA rule for trait {}", id);
                    result.push((format!("inline.{}", id), source.to_string()));
                }
                result
            })
            .collect()
    }

    /// Scan binary data and split results into regular YARA matches and inline trait results.
    ///
    /// Performs a two-pass scan:
    /// 1. **Generic tier** — always runs (built-in rules, inline trait YARA, uncategorized third-party)
    /// 2. **File-type tier** — runs only the rules matching the target file type (PE, ELF, etc.)
    ///
    /// Scanners are cached per-thread to avoid expensive re-creation.
    ///
    /// Regular matches (non-`inline.*` namespaces) are returned as `Vec<YaraMatch>` for
    /// inclusion in the analysis report. Inline matches are returned as a
    /// `HashMap<String, Vec<Evidence>>` keyed by namespace (`"inline.{trait_id}"`), for use
    /// by trait evaluation via `EvaluationContext::inline_yara_results`.
    pub(crate) fn scan_bytes_with_inline(
        &self,
        data: &[u8],
        file_type_filter: Option<&[&str]>,
    ) -> Result<(Vec<YaraMatch>, HashMap<String, Vec<Evidence>>)> {
        let scan_start = std::time::Instant::now();
        if self.tiers.is_empty() {
            anyhow::bail!("No YARA rules loaded");
        }

        // Determine which tiers to scan
        let target_tier = YaraTier::from_filter(file_type_filter);
        let tiers_to_scan: Vec<YaraTier> = if target_tier == YaraTier::Generic {
            // Only generic needed
            vec![YaraTier::Generic]
        } else {
            // Two-pass: specific tier + generic
            let mut v = vec![target_tier];
            if self.tiers.contains_key(&YaraTier::Generic) {
                v.push(YaraTier::Generic);
            }
            v
        };

        let inline_ns_set: std::collections::HashSet<&str> = self
            .compiled_inline_namespaces
            .iter()
            .map(String::as_str)
            .collect();

        // Report rule counts per tier (visible with --verbose)
        let mut total_rules: usize = 0;
        for tier in &tiers_to_scan {
            if let Some(rules) = self.tiers.get(tier) {
                let count = rules.iter().count();
                total_rules += count;
                tracing::info!(tier = tier.label(), count, "YARA tier rule count");
            }
        }
        tracing::info!(
            total = total_rules,
            tiers = tiers_to_scan.len(),
            "YARA scan starting"
        );

        // Scan tiers in parallel when there are two (specific + generic).
        // Each tier has its own compiled Rules, and Scanner only borrows &Rules + &[u8],
        // so two scanners can run concurrently on the same data without contention.
        let all_raw: Vec<(YaraTier, Result<Vec<RawRule>>)> = if tiers_to_scan.len() == 2 {
            let tier_a = tiers_to_scan[0];
            let tier_b = tiers_to_scan[1];
            let rules_a = self.tiers.get(&tier_a);
            let rules_b = self.tiers.get(&tier_b);
            match (rules_a, rules_b) {
                (Some(ra), Some(rb)) => {
                    let (res_a, res_b) = rayon::join(
                        || Self::run_scanner(ra, data),
                        || Self::run_scanner(rb, data),
                    );
                    vec![(tier_a, res_a), (tier_b, res_b)]
                }
                (Some(ra), None) => vec![(tier_a, Self::run_scanner(ra, data))],
                (None, Some(rb)) => vec![(tier_b, Self::run_scanner(rb, data))],
                (None, None) => vec![],
            }
        } else {
            tiers_to_scan
                .iter()
                .filter_map(|tier| {
                    self.tiers
                        .get(tier)
                        .map(|rules| (*tier, Self::run_scanner(rules, data)))
                })
                .collect()
        };

        let mut yara_matches = Vec::new();
        let mut inline_results: HashMap<String, Vec<Evidence>> = HashMap::new();

        for (_tier, result) in all_raw {
            let raw_rules = result?;
            for raw in raw_rules {
                if inline_ns_set.contains(raw.namespace.as_str()) {
                    Self::collect_inline_evidence(&raw, data, &mut inline_results);
                    continue;
                }

                let yara_match = self.build_yara_match(
                    raw.name,
                    raw.namespace,
                    &raw.tags,
                    &raw.metadata,
                    &raw.patterns,
                    data,
                    file_type_filter,
                );
                if let Some(m) = yara_match {
                    yara_matches.push(m);
                }
            }
        }

        // Deduplicate evidence in inline results
        let inline_results: HashMap<String, Vec<Evidence>> = inline_results
            .into_iter()
            .map(|(k, v)| (k, deduplicate_evidence(v)))
            .collect();

        // Log tier-level scan summary (rule count per tier, not individual rules)
        if tracing::enabled!(tracing::Level::DEBUG) {
            for tier in &tiers_to_scan {
                if let Some(rules) = self.tiers.get(tier) {
                    tracing::debug!(
                        tier = tier.label(),
                        rules = rules.iter().count(),
                        "YARA scan set",
                    );
                }
            }
        }
        tracing::info!(
            elapsed_ms = scan_start.elapsed().as_millis() as u64,
            tiers = tiers_to_scan.len(),
            matches = yara_matches.len(),
            inline_traits = inline_results.len(),
            "YARA scan complete",
        );

        Ok((yara_matches, inline_results))
    }

    /// Run a YARA scanner against data and collect raw match results.
    ///
    /// Scanners are cached per-thread to avoid expensive `Scanner::new()` calls.
    /// The cache is keyed by the `Rules` pointer address. This is safe because
    /// `Rules` live in `Arc<YaraEngine>` behind `OnceLock` statics for the
    /// program's duration.
    fn run_scanner(rules: &yara_x::Rules, data: &[u8]) -> Result<Vec<RawRule>> {
        use std::time::Duration;

        let key = rules as *const yara_x::Rules as usize;

        // Scan and collect results inside the thread-local borrow so ScanResults
        // (which borrows the Scanner) is consumed before the RefCell is released.
        ENGINE_SCANNER_CACHE.with(|cache| {
            let mut cache = cache.borrow_mut();
            if cache.get(&key).is_none() {
                // SAFETY: Rules are stored in Arc<YaraEngine> behind OnceLock statics
                // and live for the program's duration. Extending the borrow to 'static
                // is sound under this invariant.
                let rules_static: &'static yara_x::Rules =
                    unsafe { &*(rules as *const yara_x::Rules) };
                let mut s = yara_x::Scanner::new(rules_static);
                s.set_timeout(Duration::from_secs(30));
                tracing::debug!("Created new YARA scanner for tier (ptr={:#x})", key);
                cache.put(key, s);
            }
            let Some(scanner) = cache.get_mut(&key) else {
                anyhow::bail!("scanner cache entry missing after insertion");
            };

            let scan_results = scanner
                .scan(data)
                .map_err(|e| anyhow::anyhow!("YARA scan failed: {:?}", e))?;

            let raw_rules: Vec<RawRule> = scan_results
                .matching_rules()
                .map(|rule| {
                    let patterns: Vec<_> = rule
                        .patterns()
                        .map(|pat| {
                            let total_matches = pat.matches().count();
                            if total_matches > MAX_PATTERN_MATCHES {
                                let inline_trait_id = rule.namespace().strip_prefix("inline.");
                                tracing::info!(
                                    rule = %rule.identifier(),
                                    namespace = %rule.namespace(),
                                    pattern = %pat.identifier(),
                                    matches = total_matches,
                                    limit = MAX_PATTERN_MATCHES,
                                    inline_trait_id,
                                    "Hit YARA-pattern match limit; stopping early"
                                );
                            }
                            let ranges: Vec<_> = pat
                                .matches()
                                .take(MAX_PATTERN_MATCHES)
                                .map(|m| (m.range().start, m.range().end))
                                .collect();
                            (pat.identifier().to_string(), ranges)
                        })
                        .collect();
                    RawRule {
                        name: rule.identifier().to_string(),
                        namespace: rule.namespace().to_string(),
                        tags: rule.tags().map(|t| t.identifier().to_string()).collect(),
                        metadata: rule
                            .metadata()
                            .map(|(k, v)| (k.to_string(), format!("{:?}", v)))
                            .collect(),
                        patterns,
                    }
                })
                .collect();

            Ok(raw_rules)
        })
    }

    /// Collect inline evidence from a raw rule match into the results map.
    fn collect_inline_evidence(
        raw: &RawRule,
        data: &[u8],
        inline_results: &mut HashMap<String, Vec<Evidence>>,
    ) {
        let evidence: Vec<Evidence> = raw
            .patterns
            .iter()
            .flat_map(|(_pattern_id, ranges)| {
                ranges.iter().map(|(start, end)| {
                    let match_len = end - start;
                    let value = if match_len <= 100 {
                        String::from_utf8_lossy(&data[*start..*end]).to_string()
                    } else {
                        format!("<{} bytes>", match_len)
                    };
                    Evidence {
                        method: "yara".to_string(),
                        source: "yara-x".to_string(),
                        value,
                        location: Some(format!("offset:0x{:x}", start)),
                        ..Default::default()
                    }
                })
            })
            .take(MAX_EVIDENCE_PER_TRAIT)
            .collect();
        let entry = inline_results.entry(raw.namespace.clone()).or_default();
        let remaining = MAX_EVIDENCE_PER_TRAIT.saturating_sub(entry.len());
        entry.extend(evidence.into_iter().take(remaining));
    }

    /// Collect built-in YARA rule sources from the traits directory as (namespace, source) pairs.
    ///
    /// All built-in rules share the `"traits"` namespace. The third-party subdirectory is
    /// skipped here — it is loaded separately with per-file namespaces.
    fn collect_builtin_sources(dir: &Path) -> Vec<(String, String)> {
        let third_party_dir = crate::cache::third_party_path();
        let rule_files: Vec<PathBuf> = WalkDir::new(dir)
            .follow_links(false)
            .into_iter()
            .filter_map(std::result::Result::ok)
            .filter(|entry| {
                let path = entry.path();
                if path.starts_with(&third_party_dir) {
                    return false;
                }
                path.is_file()
                    && path
                        .extension()
                        .map(|ext| ext == "yar" || ext == "yara")
                        .unwrap_or(false)
            })
            .map(|entry| entry.path().to_path_buf())
            .collect();

        tracing::debug!("Found {} built-in YARA rule files", rule_files.len());

        rule_files
            .par_iter()
            .filter_map(|path| {
                let bytes = fs::read(path).ok()?;
                let source = String::from_utf8_lossy(&bytes).into_owned();
                tracing::trace!("Collected built-in {}", path.display());
                Some(("traits".to_string(), source))
            })
            .collect()
    }

    /// Collect third-party YARA rule sources, classifying each rule into a tier.
    ///
    /// Small files (single-rule or few rules from one vendor) are classified as a whole.
    /// Large monolithic files (like YARAForge's single .yar with ~11K rules) are split
    /// per-rule so each rule goes to the correct tier.
    ///
    /// Returns `(tier_sources, total_source_count, vt_skipped, disabled_count)`.
    /// `tier_sources` maps each `YaraTier` to its list of `(namespace, source)` pairs.
    fn collect_third_party_sources_tiered(
        dir: &Path,
    ) -> (
        HashMap<YaraTier, Vec<(String, String)>>,
        usize,
        usize,
        usize,
    ) {
        let disabled_rules = crate::third_party_config::disabled_rule_ids();

        let rule_files: Vec<PathBuf> = WalkDir::new(dir)
            .follow_links(false)
            .into_iter()
            .filter_map(std::result::Result::ok)
            .filter(|entry| {
                let path = entry.path();
                path.is_file()
                    && path
                        .extension()
                        .map(|e| e == "yar" || e == "yara")
                        .unwrap_or(false)
            })
            .map(|entry| entry.path().to_path_buf())
            .collect();

        tracing::debug!("Found {} third-party YARA files", rule_files.len());

        let Some(re) = rule_start_re() else {
            tracing::warn!(
                "failed to compile YARA rule-start regex; skipping third-party YARA preprocessing"
            );
            return (HashMap::new(), 0, 0, 0);
        };

        struct Processed {
            path: PathBuf,
            namespace: String,
            split: HashMap<YaraTier, String>,
            vt_stripped: usize,
            disabled_stripped: usize,
        }

        // Read and preprocess all files in parallel — namespace derivation, VT filtering,
        // filetype hint injection, disabled-rule filtering, and tier splitting are all
        // pure transforms with no shared mutable state.
        let processed: Vec<Processed> = rule_files
            .par_iter()
            .filter_map(|path| {
                let bytes = fs::read(path).ok()?;

                let namespace = path
                    .strip_prefix(dir)
                    .ok()
                    .and_then(|rel| rel.to_str())
                    .map(|s| {
                        let parts: Vec<&str> = s
                            .split(std::path::MAIN_SEPARATOR)
                            .filter(|p| !p.is_empty())
                            .collect();
                        let mut ns_parts = parts.to_vec();
                        if let Some(last) = ns_parts.last_mut() {
                            *last = last.trim_end_matches(".yar").trim_end_matches(".yara");
                        }
                        format!("3p.{}", ns_parts.join("."))
                    })
                    .unwrap_or_else(|| "3p".to_string());

                let raw_source = String::from_utf8_lossy(&bytes);

                let (raw_source, vt_stripped) = if raw_source.contains("vt.") {
                    let (filtered, count) = Self::filter_vt_rules(&raw_source, re);
                    (std::borrow::Cow::Owned(filtered), count)
                } else {
                    (raw_source, 0)
                };

                if raw_source.trim().is_empty() {
                    return None;
                }

                let source = crate::third_party_yara::inject_condition_filetype_hints(&raw_source);

                let (filtered_source, disabled_stripped) =
                    Self::filter_disabled_rules(&source, &namespace, &disabled_rules, re);

                if filtered_source.trim().is_empty() {
                    return None;
                }

                let split = Self::split_monolithic_by_tier(&filtered_source, &namespace, re);
                Some(Processed {
                    path: path.clone(),
                    namespace,
                    split,
                    vt_stripped,
                    disabled_stripped,
                })
            })
            .collect();

        let mut tier_sources: HashMap<YaraTier, Vec<(String, String)>> = HashMap::new();
        let mut total = 0;
        let mut vt_skipped = 0;
        let mut disabled_count = 0;
        let mut tier_counts: HashMap<YaraTier, usize> = HashMap::new();

        for p in processed {
            if p.vt_stripped > 0 {
                tracing::debug!(
                    "{}: stripped {} rule(s) requiring VirusTotal context",
                    p.path.display(),
                    p.vt_stripped,
                );
            }
            vt_skipped += p.vt_stripped;
            disabled_count += p.disabled_stripped;

            for (tier, tier_source) in p.split {
                tier_sources
                    .entry(tier)
                    .or_default()
                    .push((p.namespace.clone(), tier_source));
                total += 1;
                *tier_counts.entry(tier).or_insert(0) += 1;
            }
        }

        for (tier, count) in &tier_counts {
            tracing::info!("Third-party tier {:?}: {} source(s)", tier, count);
        }
        tracing::debug!(
            "Successfully added {} third-party YARA source(s) across {} tier(s)",
            total,
            tier_counts.len().max(1),
        );

        (tier_sources, total, vt_skipped, disabled_count)
    }

    /// Split a large monolithic YARA source into per-tier chunks.
    ///
    /// Extracts import statements and private rules, then classifies each public rule.
    /// Private rules are duplicated into every tier that has dependents (simplest approach
    /// since there are typically <30 private rules).
    fn split_monolithic_by_tier(
        source: &str,
        namespace: &str,
        rule_re: &regex::Regex,
    ) -> HashMap<YaraTier, String> {
        // Extract imports from top of file
        let mut imports = String::new();
        for line in source.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with("import ") {
                imports.push_str(line);
                imports.push('\n');
            }
            // Stop scanning for imports once we hit a rule
            if trimmed.starts_with("rule ") || trimmed.starts_with("private rule") {
                break;
            }
        }

        // Parse rule boundaries
        struct RuleInfo<'a> {
            start: usize,
            end: usize,
            name: &'a str,
            is_private: bool,
        }

        let mut rules: Vec<RuleInfo<'_>> = Vec::new();
        for cap in rule_re.captures_iter(source) {
            let (Some(name_match), Some(start_match)) = (cap.get(3), cap.get(0)) else {
                continue;
            };
            let name = name_match.as_str();
            let start = start_match.start();
            let is_private = cap
                .get(2)
                .map(|m| m.as_str().contains("private"))
                .unwrap_or(false);
            rules.push(RuleInfo {
                start,
                end: 0,
                name,
                is_private,
            });
        }

        // Fill end positions: each rule ends where the next begins
        let starts: Vec<usize> = rules.iter().map(|r| r.start).collect();
        for (i, rule) in rules.iter_mut().enumerate() {
            rule.end = starts.get(i + 1).copied().unwrap_or(source.len());
        }

        // Collect private rules (included in every tier)
        let private_chunk: String = rules
            .iter()
            .filter(|r| r.is_private)
            .map(|r| &source[r.start..r.end])
            .collect::<Vec<_>>()
            .join("\n");

        // Classify each public rule
        let mut tier_rules: HashMap<YaraTier, Vec<&str>> = HashMap::new();
        for r in &rules {
            if r.is_private {
                continue;
            }
            let rule_text = &source[r.start..r.end];
            let tier = YaraTier::classify_rule(r.name, rule_text, namespace);
            tier_rules.entry(tier).or_default().push(rule_text);
        }

        // Build per-tier source strings
        let mut result: HashMap<YaraTier, String> = HashMap::new();
        for (tier, rule_texts) in tier_rules {
            let mut s = String::with_capacity(imports.len() + private_chunk.len() + 4096);
            s.push_str(&imports);
            s.push('\n');
            if !private_chunk.is_empty() {
                s.push_str(&private_chunk);
                s.push('\n');
            }
            for text in rule_texts {
                s.push_str(text);
            }
            result.insert(tier, s);
        }

        result
    }

    /// Filter out disabled rules from YARA source.
    /// Returns the filtered source and the count of removed rules.
    fn filter_disabled_rules(
        source: &str,
        namespace: &str,
        disabled_rules: &std::collections::HashSet<String>,
        re: &regex::Regex,
    ) -> (String, usize) {
        // Quick check: if no disabled rules, return as-is
        if disabled_rules.is_empty() {
            return (source.to_string(), 0);
        }

        let mut result = String::with_capacity(source.len());
        let mut last_end = 0;
        let mut removed = 0;

        // Find all rule starts and their positions
        let mut rule_ranges: Vec<(usize, usize, &str)> = Vec::new();
        for cap in re.captures_iter(source) {
            let (Some(rule_name_match), Some(rule_start_match)) = (cap.get(3), cap.get(0)) else {
                continue;
            };
            let rule_name = rule_name_match.as_str();
            let rule_start = rule_start_match.start();
            rule_ranges.push((rule_start, 0, rule_name)); // end will be filled later
        }

        // Fill in rule end positions (start of next rule or end of source)
        let range_starts: Vec<usize> = rule_ranges.iter().map(|r| r.0).collect();
        for (i, range) in rule_ranges.iter_mut().enumerate() {
            range.1 = range_starts.get(i + 1).copied().unwrap_or(source.len());
        }

        // Build filtered source
        for (start, end, rule_name) in rule_ranges {
            // Use trait_id format (third_party/vendor/...) for consistency with config
            let trait_id = crate::third_party_yara::derive_trait_id(namespace, rule_name, None);
            if disabled_rules.contains(&trait_id) {
                // Skip this rule - add any content before it that hasn't been added yet
                if start > last_end {
                    result.push_str(&source[last_end..start]);
                }
                last_end = end;
                removed += 1;
                tracing::debug!("Filtered disabled rule: {}", trait_id);
            }
        }

        // Add remaining content
        if last_end < source.len() {
            result.push_str(&source[last_end..]);
        }

        // If nothing was removed, return original to avoid allocation
        if removed == 0 {
            return (source.to_string(), 0);
        }

        (result, removed)
    }

    /// Strip individual rules that reference the VirusTotal module (`vt.`) from source.
    ///
    /// Returns the filtered source and the count of removed rules. Rules that don't
    /// reference `vt.` are preserved. This replaces the old whole-file skip which
    /// incorrectly dropped the entire YARAForge monolithic collection.
    fn filter_vt_rules(source: &str, re: &regex::Regex) -> (String, usize) {
        let mut rule_ranges: Vec<(usize, usize)> = Vec::new();
        for cap in re.captures_iter(source) {
            let Some(rule_start_match) = cap.get(0) else {
                continue;
            };
            let rule_start = rule_start_match.start();
            rule_ranges.push((rule_start, 0));
        }

        if rule_ranges.is_empty() {
            return (source.to_string(), 0);
        }

        // Fill end positions: each rule ends where the next begins
        let vt_starts: Vec<usize> = rule_ranges.iter().map(|r| r.0).collect();
        for (i, range) in rule_ranges.iter_mut().enumerate() {
            range.1 = vt_starts.get(i + 1).copied().unwrap_or(source.len());
        }

        let mut result = String::with_capacity(source.len());
        let mut last_end = 0;
        let mut removed = 0;

        for (start, end) in &rule_ranges {
            let rule_text = &source[*start..*end];
            if rule_text.contains("vt.") {
                // Skip this rule, keep content before it
                if *start > last_end {
                    result.push_str(&source[last_end..*start]);
                }
                last_end = *end;
                removed += 1;
            }
        }

        if removed == 0 {
            return (source.to_string(), 0);
        }

        if last_end < source.len() {
            result.push_str(&source[last_end..]);
        }

        (result, removed)
    }

    /// Extract namespace from file path with prefix
    #[allow(dead_code)] // Used by tests
    fn extract_namespace_with_prefix(&self, path: &Path, prefix: &str) -> String {
        let path_str = path.to_string_lossy();

        // Find the base directory (traits/ or third-party/)
        let search_str = if prefix == "third_party" {
            "third-party/"
        } else {
            "traits/"
        };

        if let Some(idx) = path_str.find(search_str) {
            let relative = &path_str[idx + search_str.len()..];

            // Remove filename and extension
            if let Some(parent) = Path::new(relative).parent() {
                let namespace_path = parent.to_string_lossy().replace('/', ".");
                return if namespace_path.is_empty() {
                    prefix.to_string()
                } else {
                    format!("{}.{}", prefix, namespace_path)
                };
            }
        }

        prefix.to_string()
    }

    /// Normalize a filetype string for use as a cache suffix
    /// Simplifies types like "application/x-sh" to "sh"
    #[allow(dead_code)] // Used by tests
    fn normalize_filetype_for_cache(filetype: &str) -> &str {
        // Remove MIME type prefixes
        if let Some(suffix) = filetype.strip_prefix("application/x-") {
            return suffix;
        }
        if let Some(suffix) = filetype.strip_prefix("text/x-") {
            return suffix;
        }
        // Return as-is for simple types
        filetype
    }

    /// Check if a YARA rule matches the given file types
    /// Parses the metadata section for "filetype" or "filetypes" fields
    #[allow(dead_code)] // Used by tests
    fn rule_matches_filetypes(source: &str, filter_types: &[&str]) -> bool {
        // If no metadata section, include the rule (no type restriction)
        if !source.contains("meta:") {
            return true;
        }

        // Simple text-based parsing for filetype metadata
        // Look for: filetype = "value" or filetypes = "value1,value2"
        for line in source.lines() {
            let trimmed = line.trim();

            // Single filetype
            if trimmed.starts_with("filetype") && trimmed.contains('=') {
                if let Some(value_part) = trimmed.split('=').nth(1) {
                    let value = value_part
                        .trim()
                        .trim_matches('"')
                        .trim_matches('\'')
                        .to_lowercase();

                    // Check if any filter type matches
                    for filter_type in filter_types {
                        if value == filter_type.to_lowercase() {
                            return true;
                        }
                    }
                }
            }

            // Multiple filetypes (comma-separated)
            if trimmed.starts_with("filetypes") && trimmed.contains('=') {
                if let Some(value_part) = trimmed.split('=').nth(1) {
                    let value = value_part.trim().trim_matches('"').trim_matches('\'');

                    // Split by comma and check each type
                    for rule_type in value.split(',') {
                        let rule_type = rule_type.trim().to_lowercase();
                        for filter_type in filter_types {
                            if rule_type == filter_type.to_lowercase() {
                                return true;
                            }
                        }
                    }
                }
            }
        }

        // No matching filetype found, exclude the rule
        false
    }

    /// Scan a file with loaded YARA rules
    pub(crate) fn scan_file(&self, file_path: &Path) -> Result<Vec<YaraMatch>> {
        if self.tiers.is_empty() {
            anyhow::bail!("No YARA rules loaded");
        }

        let data =
            fs::read(file_path).context(format!("Failed to read file: {}", file_path.display()))?;

        self.scan_bytes(&data)
    }

    /// Scan byte data with loaded YARA rules
    /// Optionally filter results by file type
    pub(crate) fn scan_bytes(&self, data: &[u8]) -> Result<Vec<YaraMatch>> {
        self.scan_bytes_filtered(data, None)
    }

    /// Scan byte data with optional file type filtering.
    /// Inline YARA results (namespace `inline.*`) are silently discarded; use
    /// `scan_bytes_with_inline` when you need them for trait evaluation.
    pub(crate) fn scan_bytes_filtered(
        &self,
        data: &[u8],
        file_type_filter: Option<&[&str]>,
    ) -> Result<Vec<YaraMatch>> {
        let (matches, _inline) = self.scan_bytes_with_inline(data, file_type_filter)?;
        Ok(matches)
    }

    /// Build a `YaraMatch` from raw match data collected during scanning.
    /// Returns `None` if the rule is an inline trait rule (those go into `inline_results`).
    fn build_yara_match(
        &self,
        rule_name: String,
        namespace: String,
        tags: &[String],
        metadata: &[(String, String)],
        patterns: &[(String, Vec<(usize, usize)>)],
        data: &[u8],
        file_type_filter: Option<&[&str]>,
    ) -> Option<YaraMatch> {
        let mut description = String::new();
        let mut crit = "baseline".to_string();
        let mut capability_flag = false;
        let mut mbc_code: Option<String> = None;
        let mut attack_code: Option<String> = None;
        let mut rule_filetypes: Vec<String> = Vec::new();
        let mut filetype_source = "none"; // tracks where the filetype came from
        let mut os_meta: Option<String> = None;
        let mut arch_context_meta: Option<String> = None;

        for tag_name in tags {
            if matches!(
                tag_name.as_str(),
                "baseline" | "notable" | "suspicious" | "hostile"
            ) {
                crit = tag_name.clone();
                break;
            }
        }

        let is_third_party = namespace.starts_with("3p.");
        if is_third_party {
            crit = "suspicious".to_string();
        }

        for (key, value_str) in metadata {
            let value_str = if value_str.starts_with("String(\"") && value_str.ends_with("\")") {
                value_str[8..value_str.len() - 2].to_string()
            } else {
                value_str.trim_matches('"').to_string()
            };

            match key.as_str() {
                "description" => description = value_str,
                "risk" => {
                    if !is_third_party {
                        crit = value_str;
                    }
                }
                "capability" => {
                    capability_flag = value_str.to_lowercase() == "true" || value_str == "1";
                }
                "mbc" => mbc_code = Some(value_str),
                "attack" => attack_code = Some(value_str),
                "filetype" | "filetypes" => {
                    rule_filetypes = value_str
                        .split(',')
                        .map(|s| s.trim().to_lowercase())
                        .collect();
                    filetype_source = "metadata";
                }
                "os" => os_meta = Some(value_str.to_lowercase()),
                "arch_context" => arch_context_meta = Some(value_str.to_lowercase()),
                _ => {}
            }
        }

        // Infer filetypes from tags (e.g., `: PE`, `: ELF`, `: MACHO`)
        if rule_filetypes.is_empty() {
            for tag_name in tags {
                match tag_name.to_uppercase().as_str() {
                    "PE" | "EXE" | "DLL" => {
                        rule_filetypes = vec!["pe".to_string(), "dll".to_string()];
                        filetype_source = "tag";
                        break;
                    }
                    "ELF" => {
                        rule_filetypes = vec!["elf".to_string(), "so".to_string()];
                        filetype_source = "tag";
                        break;
                    }
                    "MACHO" | "MACH_O" | "MACH-O" => {
                        rule_filetypes = vec!["macho".to_string(), "dylib".to_string()];
                        filetype_source = "tag";
                        break;
                    }
                    _ => {}
                }
            }
        }

        if rule_filetypes.is_empty() {
            let inferred = crate::third_party_yara::infer_filetypes(&rule_name, os_meta.as_deref());
            if !inferred.is_empty() {
                rule_filetypes = inferred
                    .iter()
                    .map(std::string::ToString::to_string)
                    .collect();
                filetype_source = "rule-name";
            }
        }

        // For third-party rules: if still no filetype, try the namespace filename component.
        // e.g. namespace "3p.RussianPanda95.VanillaTempest.win_mal_TextShell" → "win_mal_TextShell"
        // → "win" token → Windows → ["pe", "dll"]
        if rule_filetypes.is_empty() && is_third_party {
            let inferred = crate::third_party_yara::infer_filetypes_from_namespace(
                &namespace,
                os_meta.as_deref(),
            );
            if !inferred.is_empty() {
                rule_filetypes = inferred
                    .iter()
                    .map(std::string::ToString::to_string)
                    .collect();
                filetype_source = "namespace";
            }
        }

        // Log filetype association for verbose output
        crate::third_party_yara::log_filetype_association(
            &rule_name,
            &namespace,
            &rule_filetypes,
            filetype_source,
        );

        if let Some(filter_types) = file_type_filter {
            if !rule_filetypes.is_empty() {
                let matches_filter = rule_filetypes.iter().any(|rule_type| {
                    filter_types
                        .iter()
                        .any(|ft| rule_type == &ft.to_lowercase())
                });
                if !matches_filter {
                    tracing::warn!(
                        rule = %rule_name,
                        rule_targets = ?rule_filetypes,
                        scanning = ?filter_types,
                        "YARA rule filtered: targets {:?}, not applicable to {:?}",
                        rule_filetypes,
                        filter_types,
                    );
                    return None;
                }
            }
        }

        let mut matched_strings = Vec::new();
        'outer: for (pattern_id, ranges) in patterns {
            for (start, end) in ranges {
                if matched_strings.len() >= MAX_EVIDENCE_PER_TRAIT {
                    break 'outer;
                }
                let match_len = end - start;
                let value = if match_len <= 100 {
                    String::from_utf8_lossy(&data[*start..*end]).to_string()
                } else {
                    format!("<{} bytes>", match_len)
                };
                matched_strings.push(MatchedString {
                    identifier: pattern_id.clone(),
                    offset: *start as u64,
                    value,
                });
            }
        }

        let is_capability = capability_flag || mbc_code.is_some() || attack_code.is_some();
        let trait_id = if is_third_party {
            Some(crate::third_party_yara::derive_trait_id(
                &namespace,
                &rule_name,
                os_meta.as_deref(),
            ))
        } else {
            None
        };

        // Apply config-based criticality for third-party rules
        // Returns None if the rule is disabled via config
        if is_third_party {
            match crate::third_party_config::third_party_criticality(
                &namespace,
                trait_id.as_deref(),
            ) {
                Some(config_crit) => crit = config_crit,
                None => return None, // Rule disabled
            }
        }

        Some(YaraMatch {
            rule: rule_name,
            namespace,
            crit,
            desc: description,
            matched_strings,
            is_capability,
            mbc: mbc_code,
            attack: attack_code,
            trait_id,
            arch_context: arch_context_meta,
        })
    }

    /// Check if rules are loaded
    #[must_use]
    pub(crate) fn is_loaded(&self) -> bool {
        !self.tiers.is_empty()
    }

    /// Map YARA match to capability evidence
    #[must_use]
    pub(crate) fn yara_match_to_evidence(&self, yara_match: &YaraMatch) -> Vec<Evidence> {
        let mut evidence = Vec::new();

        for matched_str in &yara_match.matched_strings {
            // Use actual matched value if printable, otherwise use identifier
            let is_printable = matched_str
                .value
                .bytes()
                .all(|b| (0x20..0x7f).contains(&b) || b == b'\n' || b == b'\t');
            let evidence_value = if is_printable && !matched_str.value.is_empty() {
                matched_str.value.clone()
            } else {
                matched_str.identifier.clone()
            };

            evidence.push(Evidence {
                method: "yara".to_string(),
                source: "yara-x".to_string(),
                value: evidence_value,
                location: Some(format!("offset:0x{:x}", matched_str.offset)),
                ..Default::default()
            });
        }

        // If no specific strings matched, add general evidence
        if evidence.is_empty() {
            evidence.push(Evidence {
                method: "yara".to_string(),
                source: "yara-x".to_string(),
                value: yara_match.rule.clone(),
                location: Some(yara_match.namespace.clone()),
                ..Default::default()
            });
        }

        evidence
    }

    /// Map YARA namespace to capability ID
    /// Returns the capability ID if the namespace maps to a known capability
    #[must_use]
    #[allow(dead_code)]
    pub(crate) fn namespace_to_capability(&self, namespace: &str) -> Option<String> {
        // YARA namespace format: exec.cmd, anti-static.obfuscation, etc.
        // Convert to capability ID: execution/command, anti-analysis/obfuscation
        let parts: Vec<&str> = namespace.split('.').collect();

        match parts.as_slice() {
            ["exec", "cmd"] | ["exec", "shell"] => Some("execution/command/shell".to_string()),
            ["exec", "program"] => Some("execution/command/direct".to_string()),
            ["net", sub] => Some(format!("net/{}", sub)),
            ["crypto", sub] => Some(format!("crypto/{}", sub)),
            ["fs", sub] => Some(format!("fs/{}", sub)),
            ["anti-static", "obfuscation"] => Some("anti-analysis/obfuscation".to_string()),
            ["process", sub] => Some(format!("process/{}", sub)),
            ["credential", sub] => Some(format!("credential/{}", sub)),
            // For third-party rules, use the namespace directly as the capability
            _ if !namespace.is_empty() => Some(namespace.replace('.', "/")),
            _ => None,
        }
    }

    /// Scan a file and return both YARA matches and derived findings
    /// This is the main entry point for universal YARA scanning
    #[allow(dead_code)]
    pub(crate) fn scan_bytes_to_findings(
        &self,
        data: &[u8],
        file_type_filter: Option<&[&str]>,
    ) -> Result<(Vec<YaraMatch>, Vec<crate::types::Finding>)> {
        use crate::types::{Criticality, Finding, FindingKind};

        let matches = self.scan_bytes_filtered(data, file_type_filter)?;
        let mut findings = Vec::new();

        for yara_match in &matches {
            // Skip filtered matches
            if yara_match.crit == "filtered" {
                continue;
            }

            // Use derived trait_id for third-party rules, otherwise map namespace to capability
            let finding_id = yara_match
                .trait_id
                .clone()
                .or_else(|| self.namespace_to_capability(&yara_match.namespace));

            if let Some(cap_id) = finding_id {
                let evidence = self.yara_match_to_evidence(yara_match);

                let criticality = match yara_match.crit.as_str() {
                    "hostile" => Criticality::Hostile,
                    "suspicious" => Criticality::Suspicious,
                    "notable" => Criticality::Notable,
                    _ => Criticality::Baseline,
                };

                findings.push(Finding {
                    kind: FindingKind::Capability,
                    trait_refs: vec![],
                    id: cap_id,
                    desc: yara_match.desc.clone(),
                    conf: 0.9,
                    crit: criticality,
                    mbc: yara_match.mbc.clone(),
                    attack: yara_match.attack.clone(),
                    evidence,
                    match_count: 0,
                    source_file: None,
                });
            }
        }

        Ok((matches, findings))
    }

    /// Save compiled YARA rules to cache using per-tier serialization.
    ///
    /// Cache format v6: header + JSON manifest + per-tier serialized rules.
    /// The manifest maps tier labels to (offset, length) pairs within the file.
    fn save_to_cache(
        &self,
        cache_path: &Path,
        builtin_count: usize,
        third_party_count: usize,
    ) -> Result<()> {
        use std::io::Write;

        if self.tiers.is_empty() {
            anyhow::bail!("No rules to cache");
        }

        // Serialize each tier's rules
        let mut tier_data: Vec<(String, Vec<u8>)> = Vec::new();
        for tier in YaraTier::ALL {
            if let Some(rules) = self.tiers.get(tier) {
                let data = rules
                    .serialize()
                    .context(format!("Failed to serialize tier {:?}", tier))?;
                tier_data.push((tier.label().to_string(), data));
            }
        }

        // Build manifest: tier_label → (offset, length) — offsets filled after layout
        #[derive(serde::Serialize)]
        struct CacheManifest {
            builtin_count: usize,
            third_party_count: usize,
            inline_namespaces: Vec<String>,
            tiers: Vec<CacheTierEntry>,
        }
        #[derive(serde::Serialize)]
        struct CacheTierEntry {
            label: String,
            offset: usize,
            length: usize,
        }

        // Calculate layout: header + manifest_json + padding + tier1_data + tier2_data + ...
        let manifest_placeholder = CacheManifest {
            builtin_count,
            third_party_count,
            inline_namespaces: self.compiled_inline_namespaces.clone(),
            tiers: Vec::new(),
        };
        // Estimate manifest size (will recalculate after filling offsets)
        let manifest_estimate = serde_json::to_vec(&manifest_placeholder)
            .unwrap_or_default()
            .len()
            + 512;
        let data_start = CACHE_HEADER_SIZE + manifest_estimate;
        let data_start_aligned = (data_start + 7) & !7;

        let mut current_offset = data_start_aligned;
        let mut tier_entries = Vec::new();
        for (label, data) in &tier_data {
            tier_entries.push(CacheTierEntry {
                label: label.clone(),
                offset: current_offset,
                length: data.len(),
            });
            current_offset += data.len();
            // Align each tier to 8 bytes
            current_offset = (current_offset + 7) & !7;
        }

        let manifest = CacheManifest {
            builtin_count,
            third_party_count,
            inline_namespaces: self.compiled_inline_namespaces.clone(),
            tiers: tier_entries,
        };
        let manifest_json =
            serde_json::to_vec(&manifest).context("Failed to serialize manifest")?;

        // Recalculate with actual manifest size
        let actual_data_start = CACHE_HEADER_SIZE + manifest_json.len();
        let actual_data_start_aligned = (actual_data_start + 7) & !7;

        // If data start shifted, rebuild manifest with corrected offsets
        let (manifest_json, _data_start_aligned) =
            if actual_data_start_aligned != data_start_aligned {
                let mut entries = Vec::new();
                let mut off = actual_data_start_aligned;
                for (label, data) in &tier_data {
                    entries.push(CacheTierEntry {
                        label: label.clone(),
                        offset: off,
                        length: data.len(),
                    });
                    off += data.len();
                    off = (off + 7) & !7;
                }
                let m = CacheManifest {
                    builtin_count,
                    third_party_count,
                    inline_namespaces: self.compiled_inline_namespaces.clone(),
                    tiers: entries,
                };
                let j = serde_json::to_vec(&m).context("Failed to serialize manifest")?;
                let final_start = (CACHE_HEADER_SIZE + j.len() + 7) & !7;
                (j, final_start)
            } else {
                (manifest_json, actual_data_start_aligned)
            };

        // Write cache file
        let mut file = fs::File::create(cache_path).context("Failed to create cache file")?;

        // Header
        file.write_all(CACHE_MAGIC)?;
        file.write_all(&CACHE_VERSION.to_le_bytes())?;
        file.write_all(&(manifest_json.len() as u64).to_le_bytes())?;

        // Manifest
        file.write_all(&manifest_json)?;

        // Pad to alignment
        let pos = CACHE_HEADER_SIZE + manifest_json.len();
        let pad = ((_data_start_aligned).saturating_sub(pos)).min(7);
        if pad > 0 {
            file.write_all(&vec![0u8; pad])?;
        }

        // Tier data
        for (i, (_label, data)) in tier_data.iter().enumerate() {
            file.write_all(data)?;
            // Align between tiers
            if i + 1 < tier_data.len() {
                let cur = file.metadata()?.len() as usize;
                let aligned = (cur + 7) & !7;
                let gap = aligned - cur;
                if gap > 0 {
                    file.write_all(&vec![0u8; gap])?;
                }
            }
        }

        tracing::info!(
            "Saved YARA cache: {} tier(s), {:.1}MB",
            tier_data.len(),
            file.metadata()?.len() as f64 / 1_048_576.0,
        );

        Ok(())
    }

    /// Load compiled YARA rules from cache using memory-mapped I/O.
    ///
    /// Reads the v6 per-tier cache format: header + JSON manifest + per-tier rule data.
    #[allow(clippy::unwrap_used)] // Slice-to-array conversions safe after size checks
    fn load_from_cache(&mut self, cache_path: &Path) -> Result<(usize, usize)> {
        let t0 = std::time::Instant::now();

        let file = fs::File::open(cache_path).context("Failed to open cache file")?;
        let mmap = unsafe { memmap2::Mmap::map(&file) }.context("Failed to mmap cache file")?;

        if mmap.len() < CACHE_HEADER_SIZE {
            anyhow::bail!("Cache file too small");
        }
        if &mmap[0..4] != CACHE_MAGIC {
            anyhow::bail!("Invalid cache magic");
        }

        let version = u32::from_le_bytes(
            mmap[4..8]
                .try_into()
                .map_err(|_| anyhow::anyhow!("cache header version truncated"))?,
        );
        if version != CACHE_VERSION {
            anyhow::bail!(
                "Cache version mismatch: expected {}, got {}",
                CACHE_VERSION,
                version
            );
        }

        let manifest_len = u64::from_le_bytes(
            mmap[8..16]
                .try_into()
                .map_err(|_| anyhow::anyhow!("cache header manifest length truncated"))?,
        ) as usize;
        let manifest_end = CACHE_HEADER_SIZE + manifest_len;
        if manifest_end > mmap.len() {
            anyhow::bail!("Cache manifest truncated");
        }

        #[derive(serde::Deserialize)]
        struct CacheManifest {
            builtin_count: usize,
            third_party_count: usize,
            inline_namespaces: Vec<String>,
            tiers: Vec<CacheTierEntry>,
        }
        #[derive(serde::Deserialize)]
        struct CacheTierEntry {
            label: String,
            offset: usize,
            length: usize,
        }

        let manifest: CacheManifest =
            serde_json::from_slice(&mmap[CACHE_HEADER_SIZE..manifest_end])
                .context("Failed to parse cache manifest")?;

        let t1 = std::time::Instant::now();

        // Deserialize each tier
        for entry in &manifest.tiers {
            let end = entry.offset + entry.length;
            if end > mmap.len() {
                anyhow::bail!("Cache tier '{}' data truncated", entry.label);
            }
            let rules = yara_x::Rules::deserialize(&mmap[entry.offset..end])
                .context(format!("Failed to deserialize tier '{}'", entry.label))?;

            let tier = YaraTier::ALL
                .iter()
                .find(|t| t.label() == entry.label)
                .copied()
                .unwrap_or(YaraTier::Generic);

            tracing::debug!(
                "Loaded tier '{}': {} rules",
                entry.label,
                rules.iter().count()
            );
            self.tiers.insert(tier, rules);
        }

        let t2 = std::time::Instant::now();

        self.compiled_inline_namespaces = manifest.inline_namespaces;

        tracing::debug!(
            "YARA cache load: manifest={:?}, tiers={:?} ({} tier(s))",
            t1.duration_since(t0),
            t2.duration_since(t1),
            self.tiers.len(),
        );

        Ok((manifest.builtin_count, manifest.third_party_count))
    }
}

/// Per-tier cache format v6.
/// Layout: MAGIC(4) + VERSION(4) + manifest_len(8) + manifest_json + padding + tier_data...
const CACHE_MAGIC: &[u8; 4] = b"YARC";
const CACHE_VERSION: u32 = 8;
const CACHE_HEADER_SIZE: usize = 4 + 4 + 8; // 16 bytes

impl Default for YaraEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
impl YaraEngine {
    /// Compile YARA rules from source text into the Generic tier. For tests only.
    fn load_rule_source(&mut self, source: &str) -> Result<()> {
        let mut compiler = yara_x::Compiler::new();
        compiler
            .add_source(source.as_bytes())
            .map_err(|e| anyhow::anyhow!("{:?}", e))?;
        self.tiers.insert(YaraTier::Generic, compiler.build());
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)] // Tests use direct assertions and helpers for brevity
mod tests {
    use super::*;

    #[test]
    fn test_simple_rule() {
        let rule = r#"
rule test_rule {
    meta:
        description = "Test rule"
        risk = "notable"
    strings:
        $test = "TESTPATTERN"
    condition:
        $test
}
"#;

        let mut engine = YaraEngine::new_for_test();
        engine.load_rule_source(rule).unwrap();

        let test_data = b"This contains TESTPATTERN in the data";
        let matches = engine.scan_bytes(test_data).unwrap();

        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].rule, "test_rule");
        assert!(!matches[0].matched_strings.is_empty());
    }

    #[test]
    fn test_no_match() {
        let rule = r#"
rule test_rule {
    strings:
        $test = "NOTFOUND"
    condition:
        $test
}
"#;

        let mut engine = YaraEngine::new_for_test();
        engine.load_rule_source(rule).unwrap();

        let test_data = b"This does not contain the pattern";
        let matches = engine.scan_bytes(test_data).unwrap();

        assert_eq!(matches.len(), 0);
    }

    #[test]
    fn test_new() {
        let engine = YaraEngine::new_for_test();
        assert!(!engine.is_loaded());
    }

    #[test]
    fn test_default() {
        let engine = YaraEngine::new_for_test();
        assert!(!engine.is_loaded());
    }

    #[test]
    fn test_is_loaded() {
        let mut engine = YaraEngine::new_for_test();
        assert!(!engine.is_loaded());

        engine
            .load_rule_source(r#"rule test { strings: $a = "test" condition: $a }"#)
            .unwrap();

        assert!(engine.is_loaded());
    }

    #[test]
    fn test_scan_without_rules() {
        let engine = YaraEngine::new_for_test();
        let result = engine.scan_bytes(b"test data");
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("No YARA rules loaded"));
    }

    #[test]
    fn test_extract_namespace_with_prefix() {
        let engine = YaraEngine::new_with_mapper(CapabilityMapper::empty());
        let path = Path::new("/path/to/traits/execution/shell/test.yar");
        let namespace = engine.extract_namespace_with_prefix(path, "traits");
        assert_eq!(namespace, "traits.execution.shell");
    }

    #[test]
    fn test_extract_namespace_with_prefix_third_party() {
        let engine = YaraEngine::new_with_mapper(CapabilityMapper::empty());
        let path = Path::new("/path/to/third-party/malware/test.yar");
        let namespace = engine.extract_namespace_with_prefix(path, "third_party");
        assert_eq!(namespace, "third_party.malware");
    }

    #[test]
    fn test_extract_namespace_with_prefix_no_subdirs() {
        let engine = YaraEngine::new_with_mapper(CapabilityMapper::empty());
        let path = Path::new("/path/to/traits/test.yar");
        let namespace = engine.extract_namespace_with_prefix(path, "traits");
        assert_eq!(namespace, "traits");
    }

    #[test]
    fn test_rule_with_metadata() {
        let rule = r#"
rule test_rule {
    meta:
        description = "Test description"
        risk = "hostile"
        capability = "true"
        mbc = "B0001"
        attack = "T1059"
    strings:
        $test = "PATTERN"
    condition:
        $test
}
"#;

        let mut engine = YaraEngine::new_for_test();
        engine.load_rule_source(rule).unwrap();

        let test_data = b"This contains PATTERN in the data";
        let matches = engine.scan_bytes(test_data).unwrap();

        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].desc, "Test description");
        assert_eq!(matches[0].crit, "hostile");
        assert!(matches[0].is_capability);
        assert_eq!(matches[0].mbc, Some("B0001".to_string()));
        assert_eq!(matches[0].attack, Some("T1059".to_string()));
    }

    #[test]
    fn test_rule_with_tags() {
        let rule = r#"
rule test_rule : suspicious {
    strings:
        $test = "TAGGED"
    condition:
        $test
}
"#;

        let mut engine = YaraEngine::new_for_test();
        engine.load_rule_source(rule).unwrap();

        let test_data = b"TAGGED data";
        let matches = engine.scan_bytes(test_data).unwrap();

        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].crit, "suspicious");
    }

    #[test]
    fn test_yara_match_to_evidence() {
        let engine = YaraEngine::new_for_test();

        let yara_match = YaraMatch {
            rule: "test_rule".to_string(),
            namespace: "test.namespace".to_string(),
            crit: "hostile".to_string(),
            desc: "Test".to_string(),
            matched_strings: vec![MatchedString {
                identifier: "$pattern".to_string(),
                offset: 0x1000,
                value: "test".to_string(),
            }],
            is_capability: false,
            mbc: None,
            attack: None,
            trait_id: None,
            arch_context: None,
        };

        let evidence = engine.yara_match_to_evidence(&yara_match);

        assert_eq!(evidence.len(), 1);
        assert_eq!(evidence[0].method, "yara");
        assert_eq!(evidence[0].source, "yara-x");
        assert_eq!(evidence[0].value, "test"); // Uses actual matched value
        assert_eq!(evidence[0].location, Some("offset:0x1000".to_string()));
    }

    #[test]
    fn test_yara_match_to_evidence_no_strings() {
        let engine = YaraEngine::new_for_test();

        let yara_match = YaraMatch {
            rule: "test_rule".to_string(),
            namespace: "test.namespace".to_string(),
            crit: "hostile".to_string(),
            desc: "Test".to_string(),
            matched_strings: vec![],
            is_capability: false,
            mbc: None,
            attack: None,
            trait_id: None,
            arch_context: None,
        };

        let evidence = engine.yara_match_to_evidence(&yara_match);

        assert_eq!(evidence.len(), 1);
        assert_eq!(evidence[0].value, "test_rule");
        assert_eq!(evidence[0].location, Some("test.namespace".to_string()));
    }

    #[test]
    fn test_multiple_patterns() {
        let rule = r#"
rule test_rule {
    strings:
        $a = "FIRST"
        $b = "SECOND"
    condition:
        any of them
}
"#;

        let mut engine = YaraEngine::new_for_test();
        engine.load_rule_source(rule).unwrap();

        let test_data = b"FIRST and SECOND patterns";
        let matches = engine.scan_bytes(test_data).unwrap();

        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].matched_strings.len(), 2);
    }

    #[test]
    fn test_long_match_truncation() {
        let rule = r#"
rule test_rule {
    strings:
        $long = /A{200}/
    condition:
        $long
}
"#;

        let mut engine = YaraEngine::new_for_test();
        engine.load_rule_source(rule).unwrap();

        let test_data = vec![b'A'; 200];
        let matches = engine.scan_bytes(&test_data).unwrap();

        assert_eq!(matches.len(), 1);
        assert!(matches[0].matched_strings[0].value.contains("200 bytes"));
    }

    #[test]
    fn test_capability_inference_from_mbc() {
        let rule = r#"
rule test_rule {
    meta:
        mbc = "B0015.001"
    strings:
        $test = "TEST"
    condition:
        $test
}
"#;

        let mut engine = YaraEngine::new_for_test();
        engine.load_rule_source(rule).unwrap();

        let test_data = b"TEST";
        let matches = engine.scan_bytes(test_data).unwrap();

        assert_eq!(matches.len(), 1);
        assert!(matches[0].is_capability); // Inferred from MBC presence
    }

    #[test]
    fn test_capability_inference_from_attack() {
        let rule = r#"
rule test_rule {
    meta:
        attack = "T1059.004"
    strings:
        $test = "TEST"
    condition:
        $test
}
"#;

        let mut engine = YaraEngine::new_for_test();
        engine.load_rule_source(rule).unwrap();

        let test_data = b"TEST";
        let matches = engine.scan_bytes(test_data).unwrap();

        assert_eq!(matches.len(), 1);
        assert!(matches[0].is_capability); // Inferred from ATT&CK presence
    }

    #[test]
    fn test_filter_disabled_rules() {
        let source = r#"
rule KeepMe {
    strings:
        $a = "keep"
    condition:
        $a
}

rule DisableMe {
    strings:
        $b = "disable"
    condition:
        $b
}

rule AlsoKeep {
    strings:
        $c = "also"
    condition:
        $c
}
"#;

        let mut disabled = std::collections::HashSet::new();
        // derive_trait_id("3p.test.file", "DisableMe", None) -> "third_party/test/file/disableme"
        disabled.insert("third_party/test/file/disableme".to_string());

        let (filtered, count) = YaraEngine::filter_disabled_rules(
            source,
            "3p.test.file",
            &disabled,
            rule_start_re().expect("valid test regex"),
        );

        assert_eq!(count, 1);
        assert!(filtered.contains("rule KeepMe"));
        assert!(!filtered.contains("rule DisableMe"));
        assert!(filtered.contains("rule AlsoKeep"));

        // Verify filtered source is valid YARA
        let mut compiler = yara_x::Compiler::new();
        assert!(compiler.add_source(filtered.as_bytes()).is_ok());
    }

    #[test]
    fn test_filter_disabled_rules_no_match() {
        let source = r#"
rule KeepMe {
    strings:
        $a = "keep"
    condition:
        $a
}
"#;

        let mut disabled = std::collections::HashSet::new();
        // Different namespace - won't match rules in test.file
        disabled.insert("third_party/other/file/somerule".to_string());

        let (filtered, count) = YaraEngine::filter_disabled_rules(
            source,
            "3p.test.file",
            &disabled,
            rule_start_re().expect("valid test regex"),
        );

        assert_eq!(count, 0);
        assert_eq!(filtered, source);
    }

    #[test]
    fn test_filter_disabled_rules_with_tags() {
        let source = r#"
rule KeepMe : tag1 tag2 {
    strings:
        $a = "keep"
    condition:
        $a
}

rule DisableMe : hostile malware {
    strings:
        $b = "disable"
    condition:
        $b
}
"#;

        let mut disabled = std::collections::HashSet::new();
        disabled.insert("third_party/test/file/disableme".to_string());

        let (filtered, count) = YaraEngine::filter_disabled_rules(
            source,
            "3p.test.file",
            &disabled,
            rule_start_re().expect("valid test regex"),
        );

        assert_eq!(count, 1);
        assert!(filtered.contains("rule KeepMe : tag1 tag2"));
        assert!(!filtered.contains("rule DisableMe"));

        // Verify filtered source is valid YARA
        let mut compiler = yara_x::Compiler::new();
        assert!(compiler.add_source(filtered.as_bytes()).is_ok());
    }

    #[test]
    fn test_filter_disabled_rules_private_global() {
        let source = r#"
private rule PrivateKeep {
    strings:
        $a = "keep"
    condition:
        $a
}

global rule GlobalDisable {
    strings:
        $b = "disable"
    condition:
        $b
}

private global rule PrivateGlobalKeep {
    strings:
        $c = "keep2"
    condition:
        $c
}
"#;

        let mut disabled = std::collections::HashSet::new();
        disabled.insert("third_party/test/file/globaldisable".to_string());

        let (filtered, count) = YaraEngine::filter_disabled_rules(
            source,
            "3p.test.file",
            &disabled,
            rule_start_re().expect("valid test regex"),
        );

        assert_eq!(count, 1);
        assert!(filtered.contains("private rule PrivateKeep"));
        assert!(!filtered.contains("global rule GlobalDisable"));
        assert!(filtered.contains("private global rule PrivateGlobalKeep"));

        // Verify filtered source is valid YARA
        let mut compiler = yara_x::Compiler::new();
        assert!(compiler.add_source(filtered.as_bytes()).is_ok());
    }

    #[test]
    fn test_filter_disabled_rules_first_rule() {
        let source = r#"rule FirstDisabled {
    strings:
        $a = "first"
    condition:
        $a
}

rule Second {
    strings:
        $b = "second"
    condition:
        $b
}
"#;

        let mut disabled = std::collections::HashSet::new();
        disabled.insert("third_party/test/file/firstdisabled".to_string());

        let (filtered, count) = YaraEngine::filter_disabled_rules(
            source,
            "3p.test.file",
            &disabled,
            rule_start_re().expect("valid test regex"),
        );

        assert_eq!(count, 1);
        assert!(!filtered.contains("rule FirstDisabled"));
        assert!(filtered.contains("rule Second"));

        // Verify filtered source is valid YARA
        let mut compiler = yara_x::Compiler::new();
        assert!(compiler.add_source(filtered.as_bytes()).is_ok());
    }

    #[test]
    fn test_filter_disabled_rules_last_rule() {
        let source = r#"
rule First {
    strings:
        $a = "first"
    condition:
        $a
}

rule LastDisabled {
    strings:
        $b = "last"
    condition:
        $b
}
"#;

        let mut disabled = std::collections::HashSet::new();
        disabled.insert("third_party/test/file/lastdisabled".to_string());

        let (filtered, count) = YaraEngine::filter_disabled_rules(
            source,
            "3p.test.file",
            &disabled,
            rule_start_re().expect("valid test regex"),
        );

        assert_eq!(count, 1);
        assert!(filtered.contains("rule First"));
        assert!(!filtered.contains("rule LastDisabled"));

        // Verify filtered source is valid YARA
        let mut compiler = yara_x::Compiler::new();
        assert!(compiler.add_source(filtered.as_bytes()).is_ok());
    }

    #[test]
    fn test_filter_disabled_rules_multiple() {
        let source = r#"
rule Keep1 {
    strings:
        $a = "keep1"
    condition:
        $a
}

rule Disable1 {
    strings:
        $b = "disable1"
    condition:
        $b
}

rule Keep2 {
    strings:
        $c = "keep2"
    condition:
        $c
}

rule Disable2 {
    strings:
        $d = "disable2"
    condition:
        $d
}

rule Keep3 {
    strings:
        $e = "keep3"
    condition:
        $e
}
"#;

        let mut disabled = std::collections::HashSet::new();
        disabled.insert("third_party/test/file/disable1".to_string());
        disabled.insert("third_party/test/file/disable2".to_string());

        let (filtered, count) = YaraEngine::filter_disabled_rules(
            source,
            "3p.test.file",
            &disabled,
            rule_start_re().expect("valid test regex"),
        );

        assert_eq!(count, 2);
        assert!(filtered.contains("rule Keep1"));
        assert!(!filtered.contains("rule Disable1"));
        assert!(filtered.contains("rule Keep2"));
        assert!(!filtered.contains("rule Disable2"));
        assert!(filtered.contains("rule Keep3"));

        // Verify filtered source is valid YARA
        let mut compiler = yara_x::Compiler::new();
        assert!(compiler.add_source(filtered.as_bytes()).is_ok());
    }

    #[test]
    fn test_filter_disabled_rules_with_imports() {
        let source = r#"import "pe"
import "math"

rule KeepMe {
    strings:
        $a = "keep"
    condition:
        $a
}

rule DisableMe {
    strings:
        $b = "disable"
    condition:
        $b
}
"#;

        let mut disabled = std::collections::HashSet::new();
        disabled.insert("third_party/test/file/disableme".to_string());

        let (filtered, count) = YaraEngine::filter_disabled_rules(
            source,
            "3p.test.file",
            &disabled,
            rule_start_re().expect("valid test regex"),
        );

        assert_eq!(count, 1);
        assert!(filtered.contains("import \"pe\""));
        assert!(filtered.contains("import \"math\""));
        assert!(filtered.contains("rule KeepMe"));
        assert!(!filtered.contains("rule DisableMe"));
    }

    #[test]
    fn test_filter_disabled_rules_complex_condition() {
        let source = r#"
rule KeepComplex {
    meta:
        description = "Complex rule"
    strings:
        $a = "pattern1"
        $b = "pattern2"
        $c = /regex[0-9]+/
    condition:
        ($a and $b) or
        ($c and filesize < 1MB) or
        (
            for any i in (0..10) : (
                uint32(i) == 0x12345678
            )
        )
}

rule DisableMe {
    strings:
        $x = "disable"
    condition:
        $x
}
"#;

        let mut disabled = std::collections::HashSet::new();
        disabled.insert("third_party/test/file/disableme".to_string());

        let (filtered, count) = YaraEngine::filter_disabled_rules(
            source,
            "3p.test.file",
            &disabled,
            rule_start_re().expect("valid test regex"),
        );

        assert_eq!(count, 1);
        assert!(filtered.contains("rule KeepComplex"));
        assert!(filtered.contains("for any i in"));
        assert!(!filtered.contains("rule DisableMe"));

        // Verify filtered source is valid YARA
        let mut compiler = yara_x::Compiler::new();
        assert!(compiler.add_source(filtered.as_bytes()).is_ok());
    }

    #[test]
    fn test_filter_disabled_rules_all_disabled() {
        let source = r#"
rule Disable1 {
    strings:
        $a = "d1"
    condition:
        $a
}

rule Disable2 {
    strings:
        $b = "d2"
    condition:
        $b
}
"#;

        let mut disabled = std::collections::HashSet::new();
        disabled.insert("third_party/test/file/disable1".to_string());
        disabled.insert("third_party/test/file/disable2".to_string());

        let (filtered, count) = YaraEngine::filter_disabled_rules(
            source,
            "3p.test.file",
            &disabled,
            rule_start_re().expect("valid test regex"),
        );

        assert_eq!(count, 2);
        assert!(!filtered.contains("rule Disable1"));
        assert!(!filtered.contains("rule Disable2"));
        // Should be essentially empty (just whitespace)
        assert!(filtered.trim().is_empty());
    }

    #[test]
    fn test_filter_disabled_rules_preserves_comments() {
        let source = r#"
// This is a file-level comment
/* Multi-line
   comment */

rule KeepMe {
    // Rule comment
    strings:
        $a = "keep"
    condition:
        $a
}

rule DisableMe {
    strings:
        $b = "disable"
    condition:
        $b
}
"#;

        let mut disabled = std::collections::HashSet::new();
        disabled.insert("third_party/test/file/disableme".to_string());

        let (filtered, count) = YaraEngine::filter_disabled_rules(
            source,
            "3p.test.file",
            &disabled,
            rule_start_re().expect("valid test regex"),
        );

        assert_eq!(count, 1);
        assert!(filtered.contains("// This is a file-level comment"));
        assert!(filtered.contains("/* Multi-line"));
        assert!(filtered.contains("rule KeepMe"));
        assert!(!filtered.contains("rule DisableMe"));
    }

    /// Test YARA rule tier classification against fixture files.
    ///
    /// Fixtures live in `tests/yara_tier_fixtures/{platforms}/{filetypes}/rule.yar`.
    /// The `{filetypes}` directory name determines the expected `YaraTier`.
    /// Platforms are sorted alphabetically, comma-separated (e.g. `linux,windows`).
    /// Filetypes are sorted alphabetically, comma-separated (e.g. `elf,pe`).
    ///
    /// To add a regression test for a misclassified rule, just drop the `.yar` file
    /// into the appropriate directory.
    #[test]
    fn test_tier_classification_fixtures() {
        let fixtures_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("yara_tier_fixtures");

        if !fixtures_dir.exists() {
            // Skip if fixtures not present (e.g., CI without test data)
            return;
        }

        let mut tested = 0;
        let mut failures: Vec<String> = Vec::new();

        // Walk: {fixtures_dir}/{platform_dir}/{filetype_dir}/*.yar
        for platform_entry in std::fs::read_dir(&fixtures_dir).unwrap() {
            let platform_entry = platform_entry.unwrap();
            if !platform_entry.file_type().unwrap().is_dir() {
                continue;
            }
            let platform_dir = platform_entry.file_name().to_string_lossy().to_string();

            for filetype_entry in std::fs::read_dir(platform_entry.path()).unwrap() {
                let filetype_entry = filetype_entry.unwrap();
                if !filetype_entry.file_type().unwrap().is_dir() {
                    continue;
                }
                let filetype_dir = filetype_entry.file_name().to_string_lossy().to_string();

                // Map the filetype directory to the expected YaraTier.
                // The first filetype token determines the tier.
                let expected_tier = match filetype_dir.split(',').next().unwrap_or("") {
                    "pe" | "dll" | "exe" => YaraTier::Pe,
                    "elf" | "so" => YaraTier::Elf,
                    "macho" | "dylib" => YaraTier::MachO,
                    "script" => YaraTier::Script,
                    "doc" => YaraTier::Doc,
                    "generic" => YaraTier::Generic,
                    other => {
                        failures.push(format!(
                            "Unknown filetype directory: {}/{}",
                            platform_dir, other
                        ));
                        continue;
                    }
                };

                for rule_file in std::fs::read_dir(filetype_entry.path()).unwrap() {
                    let rule_file = rule_file.unwrap();
                    let path = rule_file.path();
                    if path.extension().and_then(|e| e.to_str()) != Some("yar") {
                        continue;
                    }

                    let source = std::fs::read_to_string(&path).unwrap();
                    let rule_name = extract_rule_name(&source)
                        .unwrap_or_else(|| path.file_stem().unwrap().to_string_lossy().to_string());

                    // Use a plausible namespace for third-party rules
                    let ns = format!("3p.test.{}", platform_dir);
                    let actual_tier = YaraTier::classify_rule(&rule_name, &source, &ns);

                    if actual_tier != expected_tier {
                        failures.push(format!(
                            "FAIL: {}/{}/{} — rule '{}': expected {:?}, got {:?}",
                            platform_dir,
                            filetype_dir,
                            path.file_name().unwrap().to_string_lossy(),
                            rule_name,
                            expected_tier,
                            actual_tier,
                        ));
                    }
                    tested += 1;
                }
            }
        }

        eprintln!(
            "Tier classification: {tested} rules tested, {} failures",
            failures.len()
        );
        if !failures.is_empty() {
            for f in &failures {
                eprintln!("  {f}");
            }
            panic!(
                "{} of {} tier classification tests failed:\n{}",
                failures.len(),
                tested,
                failures.join("\n"),
            );
        }
        assert!(tested > 0, "No fixture files found");
    }

    /// Extract the rule name from YARA source text.
    fn extract_rule_name(source: &str) -> Option<String> {
        for line in source.lines() {
            let trimmed = line.trim();
            if let Some(rest) = trimmed.strip_prefix("rule ") {
                // "rule NAME {" or "rule NAME : TAG {"
                let name = rest.split_whitespace().next()?.trim_end_matches('{');
                return Some(name.to_string());
            }
        }
        None
    }

    /// Diagnostic test: classify all third-party YARA rules and print distribution.
    /// Run with: cargo test --lib test_classify_all_third_party -- --nocapture --ignored
    #[test]
    #[ignore]
    fn test_classify_all_third_party() {
        use std::collections::HashMap;

        let rule_re = regex::Regex::new(r"(?m)^((private\s+)?rule\s+)(\w+)").unwrap();

        let traits_dir = dirs::data_dir()
            .unwrap_or_default()
            .join("cleave")
            .join("traits")
            .join("third-party");

        let mut tier_counts: HashMap<YaraTier, usize> = HashMap::new();
        let mut generic_names: Vec<String> = Vec::new();

        // Walk all .yar files
        for entry in walkdir::WalkDir::new(&traits_dir)
            .into_iter()
            .filter_map(Result::ok)
            .filter(|e| {
                e.path()
                    .extension()
                    .map(|ext| ext == "yar" || ext == "yara")
                    .unwrap_or(false)
            })
        {
            let path = entry.path();
            let Ok(source) = std::fs::read_to_string(path) else {
                continue;
            };

            // Derive namespace from path
            let rel = path.strip_prefix(&traits_dir).unwrap_or(path);
            let ns = format!(
                "3p.{}",
                rel.with_extension("").to_string_lossy().replace('/', ".")
            );

            for cap in rule_re.captures_iter(&source) {
                let name = cap.get(3).unwrap().as_str();
                let is_private = cap
                    .get(2)
                    .map(|m| m.as_str().contains("private"))
                    .unwrap_or(false);
                if is_private {
                    continue;
                }

                let start = cap.get(0).unwrap().start();
                // Find rule body end (next rule start or EOF)
                let body_end = rule_re
                    .find_at(&source, start + 1)
                    .map(|m| m.start())
                    .unwrap_or(source.len());
                let rule_text = &source[start..body_end];

                let tier = YaraTier::classify_rule(name, rule_text, &ns);
                *tier_counts.entry(tier).or_default() += 1;
                if tier == YaraTier::Generic {
                    generic_names.push(format!("{} (ns={})", name, ns));
                }
            }
        }

        eprintln!("\n=== YARA Tier Distribution ===");
        let mut total = 0;
        for tier in YaraTier::ALL {
            let count = tier_counts.get(tier).copied().unwrap_or(0);
            total += count;
            eprintln!("  {:8}: {}", tier.label(), count);
        }
        eprintln!("  {:8}: {}", "TOTAL", total);

        // Sort and print Generic rules
        generic_names.sort();
        eprintln!("\n=== Generic Rules ({}) ===", generic_names.len());
        for name in &generic_names {
            eprintln!("  {name}");
        }
    }
}
