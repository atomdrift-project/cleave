//! Pure helpers for classifying YARA rules by target filetype and scan tier.
//!
//! This crate intentionally contains no engine integration, I/O, or `cleave`
//! runtime dependencies so it can be tested and iterated on independently.

/// File-type tier for pre-classified YARA rule sets.
///
/// Rules are compiled into separate tiered sets so each scan only processes the
/// subset relevant to the target file type. Every scan typically runs the
/// tier-specific set(s) plus the `CrossFormat` set. Residual unclassified
/// third-party rules land in `Unknown`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum YaraTier {
    /// Rules intentionally broad across multiple formats or curated broad rules.
    CrossFormat,
    /// PE / DLL / EXE rules.
    Pe,
    /// ELF / SO / KO rules.
    Elf,
    /// Mach-O / dylib / kext rules.
    MachO,
    /// JavaScript / TypeScript / Node / Electron rules.
    ScriptJs,
    /// Non-JS scripting rules plus script-generic fallbacks.
    Script,
    /// Document and container format rules.
    Doc,
    /// Residual unclassified third-party rules that still need audit.
    Unknown,
}

impl YaraTier {
    /// All tier variants in a fixed order for iteration and reporting.
    pub const ALL: &'static [Self] = &[
        Self::CrossFormat,
        Self::Pe,
        Self::Elf,
        Self::MachO,
        Self::ScriptJs,
        Self::Script,
        Self::Doc,
        Self::Unknown,
    ];

    /// Classify a set of filetype strings into a YARA tier.
    #[must_use]
    pub fn from_filetypes(filetypes: &[&str]) -> Self {
        for ft in filetypes {
            match *ft {
                "pe" | "exe" | "dll" | "sys" => return Self::Pe,
                "elf" | "so" | "ko" => return Self::Elf,
                "macho" | "mach" | "mach-o" | "dylib" | "kext" => return Self::MachO,
                "js" | "mjs" | "cjs" | "jsx" | "ts" | "tsx" | "mts" | "cts" => {
                    return Self::ScriptJs;
                }
                "sh" | "bash" | "zsh" | "py" | "pyc" | "php" | "rb" | "pl" | "pm" | "lua"
                | "ps1" | "psm1" | "psd1" | "bat" | "cmd" | "vbs" | "vba" | "java" | "jar"
                | "class" | "jsp" | "aspx" | "asp" | "apk" | "dex" => return Self::Script,
                "pdf" | "rtf" | "ole" | "doc" | "docx" | "xls" | "xlsx" | "ppt" | "pptx"
                | "msg" | "lnk" | "zip" | "iso" | "img" | "one" | "onepkg" | "msi" | "cab"
                | "gzip" | "gz" | "bzip2" | "bz2" | "xz" | "rar" | "7z" | "tar" | "vhd"
                | "vmdk" => return Self::Doc,
                _ => {}
            }
        }
        Self::Unknown
    }

    /// Map the `file_type_filter` strings passed by callers to a tier.
    #[must_use]
    pub fn from_filter(filter: Option<&[&str]>) -> Self {
        match filter {
            None => Self::Unknown,
            Some(types) => Self::from_filetypes(types),
        }
    }

    /// Determine the ordered tier scan set for a target filter.
    ///
    /// Most files scan their specific tier(s) plus `CrossFormat`. Residual
    /// `Unknown` rules are scanned only when the target file type is itself
    /// unknown, so they can be audited without penalizing every typed scan.
    #[must_use]
    pub fn scan_order(filter: Option<&[&str]>) -> Vec<Self> {
        match filter {
            None => vec![Self::CrossFormat, Self::Unknown],
            Some(types) => {
                let mut tiers: Vec<Self> = types
                    .iter()
                    .map(|ft| Self::from_filetypes(&[*ft]))
                    .filter(|tier| *tier != Self::Unknown)
                    .collect();
                tiers.sort_by_key(|tier| Self::ALL.iter().position(|candidate| candidate == tier));
                tiers.dedup();
                if tiers.is_empty() {
                    vec![Self::CrossFormat, Self::Unknown]
                } else {
                    tiers.push(Self::CrossFormat);
                    tiers
                }
            }
        }
    }

    /// Short label for cache filenames and logging.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::CrossFormat => "cross-format",
            Self::Pe => "pe",
            Self::Elf => "elf",
            Self::MachO => "macho",
            Self::ScriptJs => "script-js",
            Self::Script => "script",
            Self::Doc => "doc",
            Self::Unknown => "unknown",
        }
    }

    /// Classify a single YARA rule into a tier based on its metadata, condition,
    /// module references, magic bytes, content indicators, and rule name.
    #[must_use]
    pub fn classify_rule(rule_name: &str, rule_body: &str, namespace: &str) -> Self {
        let lower = rule_body.to_lowercase();
        let header_tags = extract_header_tags(rule_body);

        // 1. Explicit filetype/os metadata
        let mut os_meta: Option<String> = None;
        let mut metadata_hint_text = String::new();
        for line in lower.lines() {
            let trimmed = line.trim();
            if (trimmed.starts_with("filetype") || trimmed.starts_with("filetypes"))
                && trimmed.contains('=')
            {
                if let Some(val) = trimmed.split('=').nth(1) {
                    let val = val.trim().trim_matches('"').trim_matches('\'');
                    let types: Vec<&str> = val.split(',').map(str::trim).collect();
                    if let Some(tier) = classify_rule_filetypes(&types) {
                        return tier;
                    }
                }
            }
            if trimmed.starts_with("os") && trimmed.contains('=') {
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
            if let Some((key, val)) = trimmed.split_once('=') {
                let key = key.trim();
                if matches!(
                    key,
                    "description"
                        | "source_url"
                        | "reference"
                        | "category"
                        | "classification"
                        | "threat_name"
                        | "scan_context"
                        | "tags"
                ) {
                    if !metadata_hint_text.is_empty() {
                        metadata_hint_text.push(' ');
                    }
                    metadata_hint_text.push_str(val.trim().trim_matches('"').trim_matches('\''));
                }
            }
        }

        // 1a. Explicit header tags in the rule declaration
        let tagged = infer_filetypes_from_tags(&header_tags);
        if !tagged.is_empty() {
            if let Some(tier) = classify_rule_filetypes(&tagged) {
                return tier;
            }
        }

        // 1b. Metadata prose/URLs often carry specific filetype hints.
        let metadata_inferred = infer_filetypes_from_metadata_text(&metadata_hint_text);
        if !metadata_inferred.is_empty() {
            if let Some(tier) = classify_rule_filetypes(&metadata_inferred) {
                if matches!(tier, Self::Script | Self::ScriptJs | Self::Doc) {
                    if let Some(binary_tier) =
                        preferred_binary_tier(rule_name, namespace, os_meta.as_deref())
                    {
                        return binary_tier;
                    }
                }
                return tier;
            }
        }

        // 1c. Use os metadata only when all inferred filetypes land in one tier.
        if let Some(ref os) = os_meta {
            let inferred = infer_filetypes(rule_name, Some(os));
            if let Some(tier) = classify_rule_filetypes(&inferred) {
                if tier != Self::CrossFormat {
                    return tier;
                }
            }
        }

        // 2. Module references in condition
        if has_module_reference(&lower, "pe.") || has_module_reference(&lower, "dotnet.") {
            return Self::Pe;
        }
        if has_module_reference(&lower, "elf.") {
            return Self::Elf;
        }
        if has_module_reference(&lower, "macho.") {
            return Self::MachO;
        }

        // 3. Magic byte patterns
        if let Some(ft) = filetype_from_magic(&lower) {
            let tier = Self::from_filetypes(&[ft]);
            if tier != Self::Unknown {
                return tier;
            }
        }

        // 4. Content-based scoring
        if let Some(tier) = classify_by_content(rule_name, &lower) {
            return tier;
        }

        // 5. Infer from rule name
        let inferred = infer_filetypes(rule_name, os_meta.as_deref());
        if let Some(tier) = classify_rule_filetypes(&inferred) {
            return tier;
        }

        // 6. Infer from namespace
        let ns_inferred = infer_filetypes_from_namespace(namespace, os_meta.as_deref());
        if let Some(tier) = classify_rule_filetypes(&ns_inferred) {
            return tier;
        }

        let namespace_lower = namespace.to_ascii_lowercase();
        let rule_name_lower = rule_name.to_ascii_lowercase();
        if namespace_lower
            .split('.')
            .any(|part| matches!(part, "multi" | "any" | "all"))
            || rule_name_lower.starts_with("multi_")
        {
            return Self::CrossFormat;
        }

        if looks_intentionally_broad(
            &rule_name_lower,
            &namespace_lower,
            &metadata_hint_text,
            os_meta.as_deref(),
        ) {
            return Self::CrossFormat;
        }

        Self::Unknown
    }
}

fn split_text_tokens(lower: &str) -> impl Iterator<Item = &str> {
    lower
        .split(|c: char| !c.is_ascii_alphanumeric())
        .filter(|token| !token.is_empty())
}

fn has_exact_token(lower: &str, needle: &str) -> bool {
    split_text_tokens(lower).any(|token| token == needle)
}

fn looks_intentionally_broad(
    rule_name_lower: &str,
    namespace_lower: &str,
    metadata_hint_text: &str,
    os_meta: Option<&str>,
) -> bool {
    let broad_os = os_meta.is_some_and(|os| {
        split_text_tokens(&os.to_ascii_lowercase())
            .any(|token| matches!(token, "all" | "any" | "multi"))
    });
    let broad_name = split_text_tokens(rule_name_lower)
        .any(|token| matches!(token, "any" | "multi" | "all"));
    let broad_ns = namespace_lower
        .split('.')
        .any(|part| matches!(part, "any" | "multi" | "all"));
    let metadata_lower = metadata_hint_text.to_ascii_lowercase();
    let broad_text = metadata_lower.contains("any file")
        || metadata_lower.contains("any files")
        || metadata_lower.contains("any format")
        || metadata_lower.contains("cross-platform")
        || metadata_lower.contains("cross platform")
        || metadata_lower.contains("multi-platform")
        || metadata_lower.contains("multi platform")
        || metadata_lower.contains("multiple file types");

    broad_os && (broad_name || broad_ns || broad_text)
}

fn extract_header_tags(rule_text: &str) -> Vec<String> {
    let header = rule_text.split('{').next().unwrap_or(rule_text);
    let Some((_, tags)) = header.split_once(':') else {
        return Vec::new();
    };
    tags.split_whitespace()
        .map(str::trim)
        .filter(|tag| !tag.is_empty())
        .map(std::string::ToString::to_string)
        .collect()
}

mod indicators {
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

    pub(super) const PE_STRUCTURE: &[&str] = &[
        "this program cannot be run in dos mode",
        "image_dos_header",
        "image_nt_headers",
        "rich_header",
        ".pdb",
        "\\release\\",
        "\\debug\\",
        "wsuscomserverimpl",
        "currentcontrolset",
        "software\\classes",
        "software\\policies",
        "software\\wow6432node",
        "sc.exe",
        "net.exe",
        "wevtutil",
        "companyname",
        "fileversion",
        "legalcopyright",
    ];

    pub(super) const PE_COM: &[&str] = &[
        "win32_process",
        "wscript.shell",
        "scripting.filesystemobject",
        "wmi",
        "iwbemservices",
    ];

    pub(super) const PE_NAME: &[&str] = &[
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
        "msiexec",
        "certutil",
        "rundll",
        "regsvr",
        "schtask",
        "bitsadmin",
        "mshta",
        "microsoft",
        "wintapix",
        "cape_",
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
        "hikit",
        "enfal",
        "turla",
        "gazer",
        "carbon",
        "hermeticwiper",
        "industroyer",
        "notpetya",
        "_iis_",
        "opcleaver",
        "empire",
        "sunburst",
        "ccleaner",
        "plugx",
        "createmini",
        "lsass",
    ];

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

    pub(super) const SCRIPT_BODY: &[&str] = &[
        "<?php",
        "<?=",
        "base64_decode(",
        "gzinflate(",
        "str_rot13(",
        "preg_replace(",
        "function_exists(",
        "-encodedcommand",
        "invoke-expression",
        "new-object system.net",
        "invoke-webrequest",
        "downloadstring(",
        "iex(",
        "activexobject",
        "document.createelement",
        "import subprocess",
        "import socket",
        "php ",
        "python ",
        "ruby ",
        "perl ",
        "autoit",
        "vbscript",
        "javascript",
    ];

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

fn classify_by_content(rule_name: &str, body_lower: &str) -> Option<YaraTier> {
    let name_lower = rule_name.to_ascii_lowercase();
    let mut s = [0u32; 5];

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

    for &ind in indicators::MACHO_BODY {
        if body_lower.contains(ind) {
            s[2] += 1;
        }
    }

    for &ind in indicators::SCRIPT_BODY {
        if body_lower.contains(ind) {
            s[3] += 1;
        }
    }

    for &ind in indicators::DOC_BODY {
        if body_lower.contains(ind) {
            s[4] += 1;
        }
    }

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

    let tiers = [
        YaraTier::Pe,
        YaraTier::Elf,
        YaraTier::MachO,
        YaraTier::Script,
        YaraTier::Doc,
    ];

    let (max_idx, &max_score) = s.iter().enumerate().max_by_key(|(_, v)| *v)?;
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

    if second == 0 || max_score > second * 2 {
        Some(tiers[max_idx])
    } else {
        None
    }
}

fn infer_binary_filetypes_from_name_and_os(
    rule_name: &str,
    os_meta: Option<&str>,
) -> Vec<&'static str> {
    let lower = rule_name.to_ascii_lowercase();
    let tokens: Vec<&str> = split_text_tokens(&lower).collect();
    if tokens
        .iter()
        .any(|token| matches!(*token, "pe" | "exe" | "dll" | "sys" | "driver"))
        || lower.contains("portable executable")
        || lower.contains(".net executable")
        || lower.contains("dotnet executable")
        || lower.contains("ps2exe")
    {
        return vec!["pe", "dll"];
    }

    if tokens
        .iter()
        .any(|token| matches!(*token, "elf" | "elf32" | "elf64" | "so" | "ko"))
        || lower.contains("shared object")
    {
        return vec!["elf", "so"];
    }

    if tokens
        .iter()
        .any(|token| matches!(*token, "macho" | "mach" | "dylib" | "kext"))
        || lower.contains("mach-o")
        || lower.contains("macho")
    {
        return vec!["macho", "dylib"];
    }

    if let Some(os) = os_meta {
        let mut types: Vec<&'static str> = Vec::new();
        for token in os.to_lowercase().split(',').map(str::trim) {
            match token {
                "linux" => push_unique_types(&mut types, &["elf", "so"]),
                "windows" | "win32" | "win64" | "win" => {
                    push_unique_types(&mut types, &["pe", "dll"])
                }
                "macos" | "osx" | "darwin" | "mac" => {
                    push_unique_types(&mut types, &["macho", "dylib"])
                }
                "all" => return vec![],
                _ => {}
            }
        }
        if !types.is_empty() {
            return types;
        }
    }

    for part in rule_name.split('_') {
        match part {
            "Win" | "win" | "Win32" | "Win64" | "Windows" => return vec!["pe", "dll"],
            "Linux" | "linux" => return vec!["elf", "so"],
            "MacOS" | "Macos" | "MACOS" | "macos" | "OSX" | "osx" => {
                return vec!["macho", "dylib"];
            }
            _ => {}
        }
    }

    vec![]
}

fn classify_rule_filetypes(filetypes: &[&str]) -> Option<YaraTier> {
    let mut tiers: Vec<YaraTier> = filetypes
        .iter()
        .map(|ft| YaraTier::from_filetypes(&[*ft]))
        .filter(|tier| *tier != YaraTier::Unknown)
        .collect();

    tiers.sort_by_key(|tier| YaraTier::ALL.iter().position(|candidate| candidate == tier));
    tiers.dedup();

    match tiers.as_slice() {
        [] => None,
        [tier] => Some(*tier),
        _ => Some(YaraTier::CrossFormat),
    }
}

fn preferred_binary_tier(
    rule_name: &str,
    namespace: &str,
    os_meta: Option<&str>,
) -> Option<YaraTier> {
    if let Some(name_tier) = classify_rule_filetypes(&infer_filetypes(rule_name, os_meta)) {
        if matches!(name_tier, YaraTier::Pe | YaraTier::Elf | YaraTier::MachO) {
            return Some(name_tier);
        }
    }

    if let Some(namespace_tier) =
        classify_rule_filetypes(&infer_filetypes_from_namespace(namespace, None))
    {
        if matches!(
            namespace_tier,
            YaraTier::Pe | YaraTier::Elf | YaraTier::MachO
        ) {
            return Some(namespace_tier);
        }
    }

    None
}

fn push_unique_types(dest: &mut Vec<&'static str>, src: &[&'static str]) {
    for item in src {
        if !dest.contains(item) {
            dest.push(item);
        }
    }
}

/// Infer filetype constraint strings for a YARA rule.
///
/// Priority:
/// 1. Document format signals (`PDF`, `RTF`, `LNK`, `OneNote`, ...)
/// 2. Script/language signals (`ps1`, `php`, `jsp`, `bash`, ...)
/// 3. Platform signals (`Win32_`, `Linux_`, `MacOS_`, `os = "windows"`, ...)
#[must_use]
pub fn infer_filetypes(rule_name: &str, os_meta: Option<&str>) -> Vec<&'static str> {
    let specific_types = infer_filetypes_from_metadata_text(rule_name);
    if !specific_types.is_empty() {
        return specific_types;
    }

    let binary_types = infer_binary_filetypes_from_name_and_os(rule_name, os_meta);
    if !binary_types.is_empty() {
        return binary_types;
    }

    vec![]
}

/// Infer specific doc/script filetypes from free-form metadata text.
#[must_use]
pub fn infer_filetypes_from_metadata_text(text: &str) -> Vec<&'static str> {
    let doc_types = doc_filetypes_from_text(text);
    if !doc_types.is_empty() {
        return doc_types;
    }
    let script_types = script_filetypes_from_text(text);
    if !script_types.is_empty() {
        return script_types;
    }
    infer_binary_filetypes_from_name_and_os(text, None)
}

/// Infer filetypes from explicit YARA rule header tags.
#[must_use]
pub fn infer_filetypes_from_tags(tags: &[String]) -> Vec<&'static str> {
    for tag in tags {
        let upper = tag.to_ascii_uppercase();
        match upper.as_str() {
            "PE" | "EXE" | "DLL" | "SYS" => return vec!["pe", "dll"],
            "ELF" | "SO" | "KO" => return vec!["elf", "so"],
            "MACHO" | "MACH_O" | "MACH-O" | "DYLIB" | "KEXT" => {
                return vec!["macho", "dylib"];
            }
            "PDF" => return vec!["pdf"],
            "RTF" => return vec!["rtf", "doc"],
            "LNK" | "LNKR" => return vec!["lnk"],
            "ONENOTE" | "ONE" | "ONEPKG" => return vec!["one", "onepkg"],
            "ISO" | "IMG" => return vec!["iso", "img"],
            "ZIP" => return vec!["zip"],
            "PHP" => return vec!["php"],
            "JSP" => return vec!["jsp"],
            "ASPX" => return vec!["aspx"],
            "ASP" => return vec!["asp"],
            "POWERSHELL" | "PS1" | "PSM1" | "PSD1" => return vec!["ps1", "psm1", "psd1"],
            "PYTHON" | "PY" | "PYC" => return vec!["py", "pyc"],
            "JAVASCRIPT" | "JS" | "JSCRIPT" => return vec!["js", "mjs", "cjs"],
            "VBS" | "VBSCRIPT" | "VBA" => return vec!["vbs", "vba"],
            "BAT" | "CMD" => return vec!["bat", "cmd"],
            "JAVA" | "JAR" | "CLASS" => return vec!["jar", "class", "java"],
            _ => {
                let inferred = infer_filetypes_from_metadata_text(tag);
                if !inferred.is_empty() {
                    return inferred;
                }
            }
        }
    }
    vec![]
}

/// Infer filetypes from the filename component of a third-party YARA namespace.
#[must_use]
pub fn infer_filetypes_from_namespace(namespace: &str, os_meta: Option<&str>) -> Vec<&'static str> {
    let filename_stem = match namespace.rsplit('.').next() {
        Some(s) if !s.is_empty() && s != "3p" => s,
        _ => return vec![],
    };
    infer_filetypes(filename_stem, os_meta)
}

/// Inject `filetype` metadata into YARA rule source when file magic conditions are detected.
#[must_use]
pub fn inject_condition_filetype_hints(source: &str) -> String {
    if !source_has_magic_condition(source) {
        return source.to_string();
    }

    let mut result = String::with_capacity(source.len() + 128);
    let mut pos = 0;
    let bytes = source.as_bytes();

    while pos < source.len() {
        match find_rule_start(source, pos) {
            None => {
                result.push_str(&source[pos..]);
                break;
            }
            Some(rule_kw) => {
                result.push_str(&source[pos..rule_kw]);

                let brace_start = match source[rule_kw..].find('{') {
                    Some(off) => rule_kw + off,
                    None => {
                        result.push_str(&source[rule_kw..]);
                        break;
                    }
                };

                let body_start = brace_start + 1;
                let Some(body_end) = find_matching_brace(bytes, brace_start) else {
                    result.push_str(&source[rule_kw..]);
                    break;
                };

                let header = &source[rule_kw..=brace_start];
                let body = &source[body_start..body_end];
                let close = &source[body_end..body_end + 1];

                result.push_str(header);
                result.push_str(&maybe_inject_filetype(body));
                result.push_str(close);

                pos = body_end + 1;
            }
        }
    }

    result
}

fn source_has_magic_condition(source: &str) -> bool {
    let lower = source.to_lowercase();
    lower.contains("0x5a4d")
        || lower.contains("0x4d5a")
        || lower.contains("0x464c457f")
        || lower.contains("0x7f454c46")
        || lower.contains("0x457f")
        || lower.contains("0x7f45")
        || lower.contains("0xfeedface")
        || lower.contains("0xcefaedfe")
        || lower.contains("0xfeedfacf")
        || lower.contains("0xcffaedfe")
        || lower.contains("0xfacf")
        || lower.contains("0xface")
        || lower.contains("0xd0cf11e0")
        || lower.contains("0xcfd0")
        || lower.contains("0x25504446")
        || lower.contains("0x7b5c7274")
        || lower.contains("0x504b")
        || lower.contains("0x04034b50")
        || lower.contains("0x0000004c")
        || has_module_reference(&lower, "pe.")
        || has_module_reference(&lower, "elf.")
        || has_module_reference(&lower, "macho.")
}

/// Check if `source` contains a YARA module reference like `pe.` at a word boundary.
#[must_use]
pub fn has_module_reference(lower_source: &str, module_prefix: &str) -> bool {
    let mut pos = 0;
    while let Some(idx) = lower_source[pos..].find(module_prefix) {
        let abs = pos + idx;
        let at_boundary = abs == 0 || !lower_source.as_bytes()[abs - 1].is_ascii_alphanumeric();
        if at_boundary {
            return true;
        }
        pos = abs + 1;
    }
    false
}

/// Infer the filetype from magic patterns and YARA module references in a rule's body.
#[must_use]
pub fn filetype_from_magic(body: &str) -> Option<&'static str> {
    let lower = body.to_lowercase();
    let condensed: String = lower.chars().filter(|c| !c.is_ascii_whitespace()).collect();

    if condensed.contains("uint16(0)==0x5a4d")
        || condensed.contains("uint16be(0)==0x4d5a")
        || has_module_reference(&lower, "pe.")
    {
        return Some("pe");
    }

    if condensed.contains("uint32(0)==0x464c457f")
        || condensed.contains("uint32be(0)==0x7f454c46")
        || condensed.contains("uint16(0)==0x457f")
        || condensed.contains("uint16be(0)==0x7f45")
        || has_module_reference(&lower, "elf.")
    {
        return Some("elf");
    }

    if condensed.contains("uint32(0)==0xfeedface")
        || condensed.contains("uint32(0)==0xcefaedfe")
        || condensed.contains("uint32(0)==0xfeedfacf")
        || condensed.contains("uint32(0)==0xcffaedfe")
        || condensed.contains("uint16(0)==0xfacf")
        || condensed.contains("uint16(0)==0xface")
        || has_module_reference(&lower, "macho.")
    {
        return Some("macho");
    }

    if condensed.contains("uint32(0)==0xd0cf11e0")
        || condensed.contains("uint16(0)==0xcfd0")
        || condensed.contains("uint16(0)==0xd0cf")
    {
        return Some("ole");
    }

    if condensed.contains("uint32(0)==0x25504446") {
        return Some("pdf");
    }

    if condensed.contains("uint32(0)==0x7b5c7274") {
        return Some("rtf");
    }

    if condensed.contains("uint16(0)==0x504b") || condensed.contains("uint32(0)==0x04034b50") {
        return Some("zip");
    }

    if condensed.contains("uint32(0)==0x0000004c") {
        return Some("lnk");
    }

    None
}

fn maybe_inject_filetype(body: &str) -> String {
    let has_filetype_meta = body.lines().any(|line| {
        let trimmed = line.trim();
        trimmed.starts_with("filetype") && trimmed.contains('=')
    });
    if has_filetype_meta {
        return body.to_string();
    }
    let Some(ft) = filetype_from_magic(body) else {
        return body.to_string();
    };

    let inject_line = format!("\n        filetype = \"{}\"", ft);
    for marker in &["meta:", "strings:", "condition:"] {
        if let Some(off) = body.find(marker) {
            let insert_pos = off + marker.len();
            let mut out = body.to_string();
            out.insert_str(insert_pos, &inject_line);
            return out;
        }
    }
    body.to_string()
}

fn find_rule_start(src: &str, from: usize) -> Option<usize> {
    let mut pos = from;
    while pos < src.len() {
        if src[pos..].starts_with("//") {
            if let Some(nl) = src[pos..].find('\n') {
                pos += nl + 1;
                continue;
            }
            return None;
        }
        if src[pos..].starts_with("rule ")
            && (pos == 0 || matches!(src.as_bytes()[pos - 1], b'\n' | b'\r' | b' ' | b'\t'))
        {
            return Some(pos);
        }
        pos += 1;
    }
    None
}

fn find_matching_brace(bytes: &[u8], open_pos: usize) -> Option<usize> {
    let mut depth = 0usize;
    for (i, &b) in bytes.iter().enumerate().skip(open_pos) {
        match b {
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    return Some(i);
                }
            }
            _ => {}
        }
    }
    None
}

/// Infer filetype constraints from document-format signals in free-form text.
#[must_use]
pub fn doc_filetypes_from_text(text: &str) -> Vec<&'static str> {
    let lower = text.to_ascii_lowercase();
    for token in lower.split(|c: char| !c.is_ascii_alphanumeric()) {
        match token {
            "pdf" => return vec!["pdf"],
            "rtf" => return vec!["rtf", "doc"],
            "office" | "word" | "excel" | "olefile" | "ole" | "macro" | "maldoc" => {
                return vec!["doc", "docx", "xls", "xlsx", "ole"];
            }
            "onenote" | "one" | "onepkg" => return vec!["one", "onepkg"],
            "lnk" | "lnkr" => return vec!["lnk"],
            "iso" | "img" => return vec!["iso", "img"],
            "zip" | "zipcrypto" => return vec!["zip"],
            "gzip" | "gz" | "bzip2" | "bz2" | "xz" | "rar" | "7z" | "tar" => {
                return vec!["gzip"];
            }
            "cab" | "msi" => return vec!["cab"],
            "vhd" | "vmdk" => return vec!["vhd"],
            "msg" => return vec!["msg"],
            _ => {}
        }
    }
    if lower.contains("embeddedpdf") || lower.contains("adobepdf") {
        return vec!["pdf"];
    }
    vec![]
}

/// Infer filetype constraints from scripting language signals in free-form text.
#[must_use]
pub fn script_filetypes_from_text(text: &str) -> Vec<&'static str> {
    let lower = text.to_ascii_lowercase();
    for token in lower.split(|c: char| !c.is_ascii_alphanumeric()) {
        match token {
            "powershell" | "ps1" | "psm1" | "psd1" | "psh" | "ps" => {
                return vec!["ps1", "psm1", "psd1"];
            }
            "python" | "py" | "pyc" => return vec!["py", "pyc"],
            "javascript" | "jscript" | "js" | "mjs" | "cjs" => return vec!["js", "mjs", "cjs"],
            "php" => return vec!["php"],
            "jsp" => return vec!["jsp"],
            "aspx" => return vec!["aspx"],
            "asp" => return vec!["asp"],
            "vbs" | "vbscript" | "vba" => return vec!["vbs", "vba"],
            "bat" | "cmd" | "batch" => return vec!["bat", "cmd"],
            "shell" | "bash" | "sh" | "zsh" => return vec!["sh", "bash", "zsh"],
            "java" | "jar" | "class" => return vec!["jar", "class", "java"],
            "apk" | "dex" => return vec!["apk", "dex"],
            "ruby" | "rb" => return vec!["rb"],
            "perl" | "pl" | "pm" => return vec!["pl", "pm"],
            "lua" => return vec!["lua"],
            token if token.starts_with("webshell") => return vec!["php", "jsp", "aspx", "asp"],
            token if token.contains("powershell") => return vec!["ps1", "psm1", "psd1"],
            _ => {}
        }
    }
    if lower.contains("webshell") {
        return vec!["php", "jsp", "aspx", "asp"];
    }
    if lower.contains("powershell") {
        return vec!["ps1", "psm1", "psd1"];
    }
    vec![]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_infer_doc_and_script_override_platform_hints() {
        assert_eq!(
            infer_filetypes("PDF_Something", Some("windows")),
            vec!["pdf"]
        );
        assert_eq!(
            infer_filetypes("RTF_Bad_Doc", Some("linux")),
            vec!["rtf", "doc"]
        );
        assert_eq!(
            infer_filetypes("Linux_Backdoor_Bash_e427876d", None),
            vec!["sh", "bash", "zsh"]
        );
        assert_eq!(
            infer_filetypes("Win_PS1_Malware", None),
            vec!["ps1", "psm1", "psd1"]
        );
    }

    #[test]
    fn test_infer_metadata_text_and_tags() {
        assert_eq!(
            infer_filetypes_from_metadata_text(
                "Presence of Windows Script Encoding Header in a OneNote file with embedded files",
            ),
            vec!["one", "onepkg"]
        );
        assert_eq!(
            infer_filetypes_from_tags(&["PowerShell".to_string()]),
            vec!["ps1", "psm1", "psd1"]
        );
    }

    #[test]
    fn test_namespace_filename_inference() {
        assert_eq!(
            infer_filetypes_from_namespace(
                "3p.RussianPanda95.VanillaTempest.win_mal_TextShell",
                None
            ),
            vec!["pe", "dll"]
        );
        assert!(infer_filetypes_from_namespace("3p.huntress.ScreenConnect", None).is_empty());
    }

    #[test]
    fn test_magic_and_module_detection() {
        assert_eq!(filetype_from_magic("uint16(0) == 0x5A4D"), Some("pe"));
        assert_eq!(filetype_from_magic("uint32(0) == 0x464c457f"), Some("elf"));
        assert_eq!(filetype_from_magic("uint16(0) == 0x457f"), Some("elf"));
        assert!(has_module_reference("pe.number_of_sections > 3", "pe."));
        assert!(!has_module_reference("recipe.format", "pe."));
    }

    #[test]
    fn test_inject_condition_filetype_hints() {
        let source = r#"rule Demo {
    meta:
        description = "PE rule"
    condition:
        uint16(0) == 0x5A4D
}"#;
        let output = inject_condition_filetype_hints(source);
        assert!(output.contains("filetype = \"pe\""));
    }

    #[test]
    fn test_classify_rule_metadata_hints() {
        let source = r#"
rule DELIVRTO_SUSP_Onenote_Win_Script_Encoding_Feb23 : FILE
{
    meta:
        description = "Presence of Windows Script Encoding Header in a OneNote file with embedded files"
        source_url = "https://github.com/delivr-to/detections/blob/main/yara-rules/onenote_windows_script_encoding_file.yar"
    condition:
        true
}
"#;
        assert_eq!(
            YaraTier::classify_rule(
                "DELIVRTO_SUSP_Onenote_Win_Script_Encoding_Feb23",
                source,
                "3p.YARAForge.delivrto"
            ),
            YaraTier::Doc
        );

        let js_source = r#"
rule suspicious_node_implant : FILE
{
    meta:
        description = "JavaScript credential stealer for Electron and Node.js applications"
    condition:
        true
}
"#;
        assert_eq!(
            YaraTier::classify_rule("suspicious_node_implant", js_source, "3p.test.javascript"),
            YaraTier::ScriptJs
        );
    }

    #[test]
    fn test_binary_rule_name_overrides_misleading_script_metadata() {
        let source = r#"
rule ARKBIRD_SOLG_MAL_OSX_Wizardupdate_Oct_2021_2 : FILE
{
    meta:
        description = "Detect a structure like the bash of WizardUpdate installer on OSX system"
        source_url = "https://example.invalid/MAL_OSX_WizardUpdate_Oct_2021_2.yara"
    condition:
        true
}
"#;

        assert_eq!(
            YaraTier::classify_rule(
                "ARKBIRD_SOLG_MAL_OSX_Wizardupdate_Oct_2021_2",
                source,
                "3p.test.macos"
            ),
            YaraTier::MachO
        );
    }

    #[test]
    fn test_binary_namespace_overrides_misleading_doc_metadata() {
        let source = r#"
rule TRELLIX_ARC_Pwnlnx_Backdoor_Variant_1 : BACKDOOR FILE
{
    meta:
        description = "Rule to detect the backdoor pwnlnx variant 1"
        reference = "https://example.invalid/report.pdf"
    condition:
        true
}
"#;

        assert_eq!(
            YaraTier::classify_rule(
                "TRELLIX_ARC_Pwnlnx_Backdoor_Variant_1",
                source,
                "3p.test.linux"
            ),
            YaraTier::Elf
        );
    }

    #[test]
    fn test_os_metadata_does_not_force_binary_tier_when_namespace_has_no_signal() {
        let source = r#"
rule VOLEXITY_Susp_Php_Fileinput_Eval : FILE
{
    meta:
        description = "Rule designed to detect PHP files which use file_get_contents() and then shortly afterwards use an eval statement."
        os = "win,linux"
    condition:
        true
}
"#;

        assert_eq!(
            YaraTier::classify_rule("VOLEXITY_Susp_Php_Fileinput_Eval", source, "3p.test.any"),
            YaraTier::Script
        );
    }

    #[test]
    fn test_scan_order() {
        assert_eq!(
            YaraTier::scan_order(Some(&["ts", "tsx", "js"])),
            vec![YaraTier::ScriptJs, YaraTier::CrossFormat]
        );
        assert_eq!(
            YaraTier::scan_order(Some(&["ps1"])),
            vec![YaraTier::Script, YaraTier::CrossFormat]
        );
        assert_eq!(
            YaraTier::scan_order(Some(&["jar", "zip"])),
            vec![YaraTier::Script, YaraTier::Doc, YaraTier::CrossFormat]
        );
        assert_eq!(
            YaraTier::scan_order(None),
            vec![YaraTier::CrossFormat, YaraTier::Unknown]
        );
    }

    #[test]
    fn test_cross_format_and_unknown_classification() {
        let cross_format = r#"
rule mixed_windows_linux_payload {
    meta:
        filetypes = "pe,elf"
    condition:
        true
}
"#;
        assert_eq!(
            YaraTier::classify_rule("mixed_windows_linux_payload", cross_format, "3p.test.multi"),
            YaraTier::CrossFormat
        );

        let unknown = r#"
rule opaque_family_name {
    condition:
        true
}
"#;
        assert_eq!(
            YaraTier::classify_rule("opaque_family_name", unknown, "3p.test.unknown"),
            YaraTier::Unknown
        );
    }

    #[test]
    fn test_additional_filetype_aliases_and_name_heuristics() {
        assert_eq!(YaraTier::from_filetypes(&["apk"]), YaraTier::Script);
        assert_eq!(YaraTier::from_filetypes(&["vhd"]), YaraTier::Doc);
        assert_eq!(YaraTier::from_filetypes(&["mach"]), YaraTier::MachO);

        assert_eq!(
            infer_filetypes("kimsuky_downloader_pe", None),
            vec!["pe", "dll"]
        );
        assert_eq!(
            infer_filetypes("APT29_wellmess_elf", None),
            vec!["elf", "so"]
        );
        assert_eq!(
            infer_filetypes("malware_unknown_machOdownloader", None),
            vec!["macho", "dylib"]
        );
        assert_eq!(
            infer_filetypes("RUSSIANPANDA_Solarmarker_Loader_PS2EXE", None),
            vec!["pe", "dll"]
        );
    }

    #[test]
    fn test_metadata_text_handles_android_and_containers() {
        assert_eq!(
            infer_filetypes_from_metadata_text("Detects Dex files containing GuardZoo strings."),
            vec!["apk", "dex"]
        );
        assert_eq!(
            infer_filetypes_from_metadata_text("fake gzip provided by CC"),
            vec!["gzip"]
        );
        assert_eq!(
            infer_filetypes_from_metadata_text("Detect suspicious VHD file with APT28 artefacts inside"),
            vec!["vhd"]
        );
        assert_eq!(
            infer_filetypes_from_metadata_text("Detects Embedded PDFs which can start malicious content"),
            vec!["pdf"]
        );
    }

    #[test]
    fn test_classify_rule_additional_filetype_examples() {
        let apk_rule = r#"
rule SEKOIA_Apt_Yemen_Apk_Guardzoo : FILE
{
    meta:
        description = "Detects Dex files containing GuardZoo strings."
    condition:
        true
}
"#;
        assert_eq!(
            YaraTier::classify_rule(
                "SEKOIA_Apt_Yemen_Apk_Guardzoo",
                apk_rule,
                "3p.test.android"
            ),
            YaraTier::Script
        );

        let vhd_rule = r#"
rule ARKBIRD_SOLG_APT_APT28_VHD_Nov_2020_1 : FILE
{
    meta:
        description = "Detect suspicious VHD file with APT28 artefacts inside"
    condition:
        true
}
"#;
        assert_eq!(
            YaraTier::classify_rule(
                "ARKBIRD_SOLG_APT_APT28_VHD_Nov_2020_1",
                vhd_rule,
                "3p.test.container"
            ),
            YaraTier::Doc
        );

        let broad_rule = r#"
rule VOLEXITY_Susp_Any_Jarischf_User_Path : FILE MEMORY
{
    meta:
        description = "Detects paths embedded in released projects."
        os = "all"
    condition:
        true
}
"#;
        assert_eq!(
            YaraTier::classify_rule(
                "VOLEXITY_Susp_Any_Jarischf_User_Path",
                broad_rule,
                "3p.test.any"
            ),
            YaraTier::CrossFormat
        );
    }

    #[test]
    fn test_tier_classification_fixtures() {
        let fixtures_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("tests")
            .join("yara_tier_fixtures");

        if !fixtures_dir.exists() {
            return;
        }

        let mut tested = 0;
        let mut failures: Vec<String> = Vec::new();

        for platform_entry in std::fs::read_dir(&fixtures_dir).expect("fixtures directory readable")
        {
            let platform_entry = platform_entry.expect("platform entry readable");
            if !platform_entry
                .file_type()
                .expect("platform file type readable")
                .is_dir()
            {
                continue;
            }
            let platform_dir = platform_entry.file_name().to_string_lossy().to_string();

            for filetype_entry in
                std::fs::read_dir(platform_entry.path()).expect("filetype directory readable")
            {
                let filetype_entry = filetype_entry.expect("filetype entry readable");
                if !filetype_entry
                    .file_type()
                    .expect("filetype kind readable")
                    .is_dir()
                {
                    continue;
                }
                let filetype_dir = filetype_entry.file_name().to_string_lossy().to_string();

                let expected_tier = match filetype_dir.split(',').next().unwrap_or("") {
                    "pe" | "dll" | "exe" => YaraTier::Pe,
                    "elf" | "so" => YaraTier::Elf,
                    "macho" | "dylib" => YaraTier::MachO,
                    "js" | "ts" | "script-js" => YaraTier::ScriptJs,
                    "script" => YaraTier::Script,
                    "doc" => YaraTier::Doc,
                    "generic" => YaraTier::CrossFormat,
                    other => {
                        failures.push(format!(
                            "Unknown filetype directory: {}/{}",
                            platform_dir, other
                        ));
                        continue;
                    }
                };

                for rule_file in std::fs::read_dir(filetype_entry.path())
                    .expect("rule fixture directory readable")
                {
                    let rule_file = rule_file.expect("rule fixture readable");
                    let path = rule_file.path();
                    if path.extension().and_then(|e| e.to_str()) != Some("yar") {
                        continue;
                    }

                    let source =
                        std::fs::read_to_string(&path).expect("rule fixture source readable");
                    let rule_name = extract_rule_name(&source).unwrap_or_else(|| {
                        path.file_stem()
                            .expect("fixture stem")
                            .to_string_lossy()
                            .to_string()
                    });

                    let ns = format!("3p.test.{}", platform_dir);
                    let actual_tier = YaraTier::classify_rule(&rule_name, &source, &ns);

                    if actual_tier != expected_tier {
                        failures.push(format!(
                            "FAIL: {}/{}/{} — rule '{}': expected {:?}, got {:?}",
                            platform_dir,
                            filetype_dir,
                            path.file_name()
                                .expect("fixture filename")
                                .to_string_lossy(),
                            rule_name,
                            expected_tier,
                            actual_tier,
                        ));
                    }
                    tested += 1;
                }
            }
        }

        if !failures.is_empty() {
            panic!(
                "{} of {} tier classification tests failed:\n{}",
                failures.len(),
                tested,
                failures.join("\n"),
            );
        }
        assert!(tested > 0, "No fixture files found");
    }

    fn extract_rule_name(source: &str) -> Option<String> {
        for line in source.lines() {
            let trimmed = line.trim();
            if let Some(rest) = trimmed.strip_prefix("rule ") {
                let name = rest.split_whitespace().next()?.trim_end_matches('{');
                return Some(name.to_string());
            }
        }
        None
    }

    #[test]
    #[ignore]
    fn test_audit_third_party_residual_tiers() {
        fn collect_rule_files(dir: &std::path::Path, files: &mut Vec<std::path::PathBuf>) {
            let Ok(entries) = std::fs::read_dir(dir) else {
                return;
            };
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    collect_rule_files(&path, files);
                } else if path
                    .extension()
                    .and_then(|ext| ext.to_str())
                    .map(|ext| ext == "yar" || ext == "yara")
                    .unwrap_or(false)
                {
                    files.push(path);
                }
            }
        }

        fn split_rules(source: &str) -> Vec<(String, bool, &str)> {
            let mut starts: Vec<(usize, String, bool)> = Vec::new();
            for (offset, line) in source
                .match_indices('\n')
                .map(|(i, _)| (i + 1, &source[i + 1..]))
            {
                let trimmed = line.trim_start();
                let is_private = trimmed.starts_with("private rule ");
                let rest = if is_private {
                    trimmed.strip_prefix("private rule ")
                } else {
                    trimmed.strip_prefix("rule ")
                };
                if let Some(rest) = rest {
                    if let Some(name) = rest.split_whitespace().next() {
                        starts.push((offset, name.trim_end_matches('{').to_string(), is_private));
                    }
                }
            }
            if source.starts_with("rule ") || source.starts_with("private rule ") {
                let trimmed = source.trim_start();
                let is_private = trimmed.starts_with("private rule ");
                let rest = if is_private {
                    trimmed.strip_prefix("private rule ")
                } else {
                    trimmed.strip_prefix("rule ")
                };
                if let Some(rest) = rest {
                    if let Some(name) = rest.split_whitespace().next() {
                        starts.insert(0, (0, name.trim_end_matches('{').to_string(), is_private));
                    }
                }
            }

            let mut rules = Vec::new();
            for (idx, (start, name, is_private)) in starts.iter().enumerate() {
                let end = starts
                    .get(idx + 1)
                    .map(|next| next.0)
                    .unwrap_or(source.len());
                rules.push((name.clone(), *is_private, &source[*start..end]));
            }
            rules
        }

        let traits_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("..")
            .join("cleave-traits")
            .join("third-party");

        if !traits_dir.exists() {
            return;
        }

        let mut files = Vec::new();
        collect_rule_files(&traits_dir, &mut files);
        files.sort();

        let mut counts: std::collections::HashMap<YaraTier, usize> =
            std::collections::HashMap::new();
        let mut cross_format = Vec::new();
        let mut unknown = Vec::new();

        for path in files {
            let Ok(source) = std::fs::read_to_string(&path) else {
                continue;
            };
            let rel = path.strip_prefix(&traits_dir).unwrap_or(&path);
            let ns = format!(
                "3p.{}",
                rel.with_extension("").to_string_lossy().replace('/', ".")
            );
            for (name, is_private, rule_text) in split_rules(&source) {
                if is_private {
                    continue;
                }
                let tier = YaraTier::classify_rule(&name, rule_text, &ns);
                *counts.entry(tier).or_default() += 1;
                match tier {
                    YaraTier::CrossFormat => cross_format.push(format!("{} (ns={})", name, ns)),
                    YaraTier::Unknown => unknown.push(format!("{} (ns={})", name, ns)),
                    _ => {}
                }
            }
        }

        cross_format.sort();
        unknown.sort();

        eprintln!("\n=== Residual Tier Audit ===");
        for tier in YaraTier::ALL {
            let count = counts.get(tier).copied().unwrap_or(0);
            eprintln!("  {:12}: {}", tier.label(), count);
        }
        eprintln!("\n=== Cross-Format Rules ({}) ===", cross_format.len());
        for name in &cross_format {
            eprintln!("  {name}");
        }
        eprintln!("\n=== Unknown Rules ({}) ===", unknown.len());
        for name in &unknown {
            eprintln!("  {name}");
        }
    }
}
