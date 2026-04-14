//! Pure helpers for classifying YARA rules by target filetype and scan tier.
//!
//! This crate intentionally contains no engine integration, I/O, or `cleave`
//! runtime dependencies so it can be tested and iterated on independently.

/// File-type tier for pre-classified YARA rule sets.
///
/// Rules are compiled into separate tiered sets so each scan only processes the
/// subset relevant to the target file type. Every scan typically runs the
/// tier-specific set(s) plus the `CrossFormat` set. Explicit raw blob rules
/// land in `Raw`, and residual unclassified third-party rules land in
/// `Unknown`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum YaraTier {
    /// Rules intentionally broad across multiple formats or curated broad rules.
    CrossFormat,
    /// Explicit raw/shellcode/blob rules that exclude normal container magic.
    Raw,
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
    /// Archive and package format rules (zip, jar, apk, iso, tar, rar, etc.).
    Archive,
    /// Residual unclassified third-party rules that still need audit.
    Unknown,
}

impl YaraTier {
    /// All tier variants in a fixed order for iteration and reporting.
    pub const ALL: &'static [Self] = &[
        Self::CrossFormat,
        Self::Raw,
        Self::Pe,
        Self::Elf,
        Self::MachO,
        Self::ScriptJs,
        Self::Script,
        Self::Doc,
        Self::Archive,
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
                | "ps1" | "psm1" | "psd1" | "bat" | "cmd" | "vbs" | "vba" | "jsp" | "aspx"
                | "asp" | "hta" | "au3" | "sct" | "wsf" | "awk" | "tcl" => {
                    return Self::Script;
                }
                "jar" | "class" | "java" | "apk" | "dex" | "zip" | "iso" | "img" | "cab"
                | "msi" | "gzip" | "gz" | "bzip2" | "bz2" | "xz" | "rar" | "7z" | "tar" | "vhd"
                | "vmdk" => return Self::Archive,
                "pdf" | "rtf" | "ole" | "doc" | "docx" | "xls" | "xlsx" | "ppt" | "pptx"
                | "msg" | "lnk" | "rdp" | "one" | "onepkg" | "txt" | "text" | "log" | "xml"
                | "json" | "ini" | "cfg" | "conf" | "ovpn" | "html" | "htm" | "svg" | "eps"
                | "eml" => return Self::Doc,
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
    /// `Raw` rules are also reserved for untyped inputs.
    #[must_use]
    pub fn scan_order(filter: Option<&[&str]>) -> Vec<Self> {
        match filter {
            None => vec![Self::CrossFormat, Self::Raw, Self::Unknown],
            Some(types) => {
                let mut tiers: Vec<Self> = types
                    .iter()
                    .map(|ft| Self::from_filetypes(&[*ft]))
                    .filter(|tier| *tier != Self::Unknown)
                    .collect();
                tiers.sort_by_key(|tier| Self::ALL.iter().position(|candidate| candidate == tier));
                tiers.dedup();
                if tiers.is_empty() {
                    vec![Self::CrossFormat, Self::Raw, Self::Unknown]
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
            Self::Raw => "raw",
            Self::Pe => "pe",
            Self::Elf => "elf",
            Self::MachO => "macho",
            Self::ScriptJs => "script-js",
            Self::Script => "script",
            Self::Doc => "doc",
            Self::Archive => "archive",
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

        // 3. Infer from rule name — checked before magic so that an explicit name
        //    like "Java_ClassFile_Dropper" resolves to Archive rather than being
        //    overridden by the ambiguous 0xcafebabe magic (shared by Java class
        //    files and Mach-O fat binaries).
        let inferred = infer_filetypes(rule_name, os_meta.as_deref());
        if let Some(tier) = classify_rule_filetypes(&inferred) {
            return tier;
        }

        // 4. Magic byte patterns — fallback when the rule name gives no signal.
        if let Some(ft) = filetype_from_magic(&lower) {
            let tier = Self::from_filetypes(&[ft]);
            if tier != Self::Unknown {
                return tier;
            }
        }

        // Rules that gate on a shebang header are still targeting script files.
        if has_shebang_magic(&lower) {
            return Self::Script;
        }

        // 4a. Explicit raw/blob rules should not be forced into PE/ELF/Mach-O.
        if is_explicit_raw_blob_rule(rule_name, &lower) {
            return Self::Raw;
        }

        // 5. Content-based scoring
        if let Some(tier) = classify_by_content(rule_name, &lower) {
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
            || split_text_tokens(&rule_name_lower).any(|token| matches!(token, "multi" | "eicar"))
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
    let broad_name =
        split_text_tokens(rule_name_lower).any(|token| matches!(token, "any" | "multi" | "all"));
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

fn is_explicit_raw_blob_rule(rule_name: &str, lower_source: &str) -> bool {
    let condensed: String = lower_source
        .chars()
        .filter(|c| !c.is_ascii_whitespace())
        .collect();
    let excludes_known_binary_magic = condensed.contains("uint16(0)!=0x5a4d")
        || condensed.contains("uint16be(0)!=0x4d5a")
        || condensed.contains("uint32(0)!=0x464c457f")
        || condensed.contains("uint32be(0)!=0x7f454c46")
        || condensed.contains("uint32(0)!=0xfeedface")
        || condensed.contains("uint32(0)!=0xfeedfacf")
        || condensed.contains("uint32be(0)!=0xcafebabe");
    if !excludes_known_binary_magic {
        return false;
    }

    let name_lower = rule_name.to_ascii_lowercase();
    let rawish_name = split_text_tokens(&name_lower).any(|token| {
        matches!(
            token,
            "raw"
                | "raw32"
                | "raw64"
                | "shellcode"
                | "loader"
                | "stager"
                | "stub"
                | "payload"
                | "implant"
                | "injector"
                | "beacon"
                | "unpacker"
                | "dropper"
        )
    });
    let rawish_text = lower_source.contains("shellcode")
        || lower_source.contains("supporting file")
        || lower_source.contains("blob file")
        || lower_source.contains("raw32")
        || lower_source.contains("raw64");

    rawish_name || rawish_text
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
        "xworm",
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

    pub(super) const SCRIPT_JS_BODY: &[&str] = &[
        "activexobject",
        "document.createelement",
        "navigator.useragent",
        "navigator.language",
        "navigator.plugins",
        "window.window===window",
        "self.self===self",
        "window.location.replace(",
        "window.rtcpeerconnection",
        "document.getelementbyid(",
        "document.referrer",
        "module.exports",
        "btoa(",
        "xmlhttprequest",
        "eval(function(p,a,c,k,",
        ".split_data = function",
        "loadjs =",
        "screen.colordepth",
        "packetproc = function",
        "request.request.url",
        "plugin_timeout*1000",
        "canvas.getcontext('2d",
        "window.moveto",
        "window.resizeto",
        "window.moveto -",
        "window.resizeto 0",
        "var __addr__=",
        "var __hwid__=",
        "var __xkey__=",
        "javascript",
    ];

    pub(super) const SCRIPT_GENERIC_BODY: &[&str] = &[
        "<?php",
        "<?=",
        "base64_decode(",
        "gzinflate(",
        "str_rot13(",
        "preg_replace(",
        "function_exists(",
        "@echo off",
        "-encodedcommand",
        "invoke-expression",
        "new-object system.net",
        "invoke-webrequest",
        "downloadstring(",
        "iex(",
        "import subprocess",
        "import socket",
        "php ",
        "python ",
        "ironpython",
        "autoit",
        "au3!ea06",
        "<scriptlet>",
        "<registration progid=",
        "language=\"vbscript\"",
        "[io.file]::",
        "[system.net.webrequest]::",
        "[system.text.encoding]::",
        "system.io.file]::",
        "response.getwriter().write(",
        "response.binarywrite(",
        "request.headers.get(",
        "$_session",
        "@set_time_limit(",
        "extract_session_readbuf(",
        "headers.add('authorization'",
        "headers.add('cookie'",
        "getresponsestream()",
        "get-random -count",
        "application.getrealpath(",
        "[parameter(position",
        "[string]$",
        "for($",
        "[environment]::newline",
        "out-file -filepath",
        ".padright(",
        "ruby ",
        "perl ",
        "autoit",
        "vbscript",
    ];

    pub(super) const SCRIPT_JS_NAME: &[&str] =
        &["javascript", "jscript", "jslib", "electronapp", "nodejs"];

    pub(super) const SCRIPT_GENERIC_NAME: &[&str] = &[
        "webshell",
        "php",
        "python",
        "pydoor",
        "powershell",
        "_asp",
        "_script_",
        "_scripts",
        "userscript",
        "opscript",
        "malscript",
        "p0wned",
        "ruby",
        "perl",
        "lua",
        "autoit",
        "vbs",
        "vba",
        "hta",
        "jse",
        "wsf",
        "powershower",
        "tclsh",
        "awk",
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
        "full address:s:",
        "redirectprinters",
        "redirectclipboard",
        "<service name=\\\"catalina\\\">",
        "ajp/1.3",
        "begindata",
        "host1:",
        "port1:",
        "[defaultinstall]",
        "registerdlls=ourdll",
        "signature=\"$windows nt$\"",
    ];

    pub(super) const DOC_NAME: &[&str] = &[
        "_doc_",
        "_pdf_",
        "_rtf_",
        "_ole_",
        "_lnk_",
        "_rdp_",
        "maldoc",
        "excelmacro",
        "_xls",
        "_ppam",
        "_docm",
        "_docx_",
        "_xlsm",
        "onenote",
        "htmlsmuggling",
        "phishing_page",
        "webpage",
        "readme",
        "userconfig",
        "_log_",
        "_config_file",
        "forensic",
        "_xml_",
        "_json_",
        "_ini_",
        "_cfg_",
        "_conf_",
        "_output",
        "_outputs",
        "_msg_",
    ];

    pub(super) const ARCHIVE_NAME: &[&str] = &[
        "_zip_", "_zpaq", "_cab_", "_iso_", "_img_", "_msi_", "_jar_", "_apk_", "_dex_", "_rar_",
        "_7z_", "_tar_", "_gzip_", "_vhd_", "_vmdk_",
    ];
}

fn classify_by_content(rule_name: &str, body_lower: &str) -> Option<YaraTier> {
    let name_lower = rule_name.to_ascii_lowercase();
    let mut s = [0u32; 7];

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

    for &ind in indicators::SCRIPT_JS_BODY {
        if body_lower.contains(ind) {
            s[3] += 1;
        }
    }
    for &ind in indicators::SCRIPT_GENERIC_BODY {
        if body_lower.contains(ind) {
            s[4] += 1;
        }
    }

    for &ind in indicators::DOC_BODY {
        if body_lower.contains(ind) {
            s[5] += 1;
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
    for &ind in indicators::SCRIPT_JS_NAME {
        if name_lower.contains(ind) {
            s[3] += 1;
        }
    }
    for &ind in indicators::SCRIPT_GENERIC_NAME {
        if name_lower.contains(ind) {
            s[4] += 1;
        }
    }
    for &ind in indicators::DOC_NAME {
        if name_lower.contains(ind) {
            s[5] += 1;
        }
    }
    for &ind in indicators::ARCHIVE_NAME {
        if name_lower.contains(ind) {
            s[6] += 1;
        }
    }

    let tiers = [
        YaraTier::Pe,
        YaraTier::Elf,
        YaraTier::MachO,
        YaraTier::ScriptJs,
        YaraTier::Script,
        YaraTier::Doc,
        YaraTier::Archive,
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
    if lower.contains("details/win.")
        || lower.contains("/rules/win.")
        || lower.contains("native iis")
        || lower.contains("iis native module")
    {
        return vec!["pe", "dll"];
    }

    if lower.contains("details/elf.")
        || lower.contains("/rules/elf.")
        || lower.contains("details/linux.")
        || lower.contains("/rules/linux.")
    {
        return vec!["elf", "so"];
    }

    if lower.contains("details/osx.")
        || lower.contains("details/macos.")
        || lower.contains("details/mac.")
        || lower.contains("/rules/osx.")
        || lower.contains("/rules/macos.")
    {
        return vec!["macho", "dylib"];
    }

    if lower.contains("details/android.") || lower.contains("/rules/android.") {
        return vec!["apk", "dex"];
    }

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
        .any(|token| matches!(*token, "macho" | "mach" | "dylib" | "kext" | "mac"))
        || lower.contains("mach-o")
        || lower.contains("macho")
        || lower.contains("_mac_")
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
            "Mac" | "mac" | "MacOS" | "Macos" | "MACOS" | "macos" | "OSX" | "osx" => {
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
    let specific_types = doc_filetypes_from_text(rule_name);
    if !specific_types.is_empty() {
        return specific_types;
    }

    let specific_types = platform_filetypes_from_rule_name(rule_name);
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
    let script_types = platform_filetypes_from_text(text);
    if !script_types.is_empty() {
        return script_types;
    }
    infer_binary_filetypes_from_name_and_os(text, None)
}

fn platform_filetypes_from_text_inner(
    text: &str,
    shell_tokens_imply_script: bool,
) -> Vec<&'static str> {
    let lower = text.to_ascii_lowercase();
    for token in lower.split(|c: char| !c.is_ascii_alphanumeric()) {
        match token {
            "powershell" | "ps1" | "psm1" | "psd1" | "psh" | "ps" => {
                return vec!["ps1", "psm1", "psd1"];
            }
            "python" | "py" | "pyc" | "ironpython" => return vec!["py", "pyc"],
            "javascript" | "jscript" | "js" | "mjs" | "cjs" => return vec!["js", "mjs", "cjs"],
            "jslib" | "nodejs" | "electron" | "electronapp" => {
                return vec!["js", "mjs", "cjs"];
            }
            "php" => return vec!["php"],
            "autoit" | "au3" => return vec!["au3"],
            "jsp" => return vec!["jsp"],
            "aspx" => return vec!["aspx"],
            "asp" => return vec!["asp"],
            "hta" => return vec!["hta"],
            "sct" | "scriptlet" => return vec!["sct", "wsf"],
            "vbs" | "vbscript" | "vba" => return vec!["vbs", "vba"],
            "bat" | "cmd" | "batch" => return vec!["bat", "cmd"],
            "powershower" => return vec!["ps1", "psm1", "psd1"],
            "awk" => return vec!["awk"],
            "tcl" | "tclsh" => return vec!["tcl"],
            "shell" | "bash" | "sh" | "zsh" if shell_tokens_imply_script => {
                return vec!["sh", "bash", "zsh"];
            }
            "java" | "jar" | "class" => return vec!["jar", "class", "java"],
            "apk" | "dex" | "android" => return vec!["apk", "dex"],
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
    if !shell_tokens_imply_script && looks_like_shell_script_text(&lower) {
        return vec!["sh", "bash", "zsh"];
    }
    vec![]
}

fn looks_like_shell_script_text(lower: &str) -> bool {
    lower.contains("#!/bin/sh")
        || lower.contains("#!/bin/bash")
        || lower.contains("#!/usr/bin/python")
        || lower.contains("#!/usr/bin/env python")
        || lower.contains("#!/usr/bin/env bash")
        || lower.contains("#!/usr/bin/env sh")
        || lower.contains("shell script")
        || lower.contains("bash script")
        || lower.contains("zsh script")
        || lower.contains("sh script")
        || lower.contains("shell-script")
        || lower.contains("bash-script")
        || lower.contains("zsh-script")
}

fn has_shebang_magic(lower_source: &str) -> bool {
    let condensed: String = lower_source
        .chars()
        .filter(|c| !c.is_ascii_whitespace())
        .collect();
    condensed.contains("uint16(0)==0x2123") || condensed.contains("uint16be(0)==0x2321")
}

/// Infer filetypes from explicit YARA rule header tags.
#[must_use]
pub fn infer_filetypes_from_tags(tags: &[String]) -> Vec<&'static str> {
    for tag in tags {
        let upper = tag.to_ascii_uppercase();
        match upper.as_str() {
            "PE" | "EXE" | "DLL" | "SYS" | "WINMALWARE" | "WINDOWSMALWARE" => {
                return vec!["pe", "dll"];
            }
            "ELF" | "SO" | "KO" | "LINUXMALWARE" => return vec!["elf", "so"],
            "MACHO" | "MACH_O" | "MACH-O" | "DYLIB" | "KEXT" => {
                return vec!["macho", "dylib"];
            }
            "OSXMALWARE" | "MACOSMALWARE" => return vec!["macho", "dylib"],
            "PDF" => return vec!["pdf"],
            "RTF" => return vec!["rtf", "doc"],
            "LNK" | "LNKR" => return vec!["lnk"],
            "ONENOTE" | "ONE" | "ONEPKG" => return vec!["one", "onepkg"],
            "ISO" | "IMG" => return vec!["iso", "img"],
            "ZIP" => return vec!["zip"],
            "LOG" => return vec!["log"],
            "TXT" | "TEXT" => return vec!["txt"],
            "XML" => return vec!["xml"],
            "JSON" => return vec!["json"],
            "INI" => return vec!["ini"],
            "CFG" | "CONF" | "CONFIG" => return vec!["cfg", "conf", "ini"],
            "OVPN" => return vec!["ovpn"],
            "HTML" | "HTM" => return vec!["html"],
            "SVG" => return vec!["svg"],
            "EPS" => return vec!["eps"],
            "EML" => return vec!["eml"],
            "MSG" | "OUTLOOK" => return vec!["msg"],
            "PHP" => return vec!["php"],
            "JSP" => return vec!["jsp"],
            "ASPX" => return vec!["aspx"],
            "ASP" => return vec!["asp"],
            "HTA" => return vec!["hta"],
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
        || lower.contains("0xcafebabe")
        || lower.contains("0xbebafeca")
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
        || condensed.contains("int16(0)==0x5a4d")
        || condensed.contains("uint32be(0)==0x5a4d")
        || condensed.contains("int32be(0)==0x5a4d")
        || condensed.contains("uint16be(0)==0x4d5a")
        || has_module_reference(&lower, "pe.")
    {
        return Some("pe");
    }

    if condensed.contains("uint32(0)==0x464c457f")
        || condensed.contains("int32(0)==0x464c457f")
        || condensed.contains("uint32be(0)==0x7f454c46")
        || condensed.contains("int32be(0)==0x7f454c46")
        || condensed.contains("uint32(0x0)==0x464c457f")
        || condensed.contains("int32(0x0)==0x464c457f")
        || condensed.contains("uint32be(0x0)==0x7f454c46")
        || condensed.contains("int32be(0x0)==0x7f454c46")
        || condensed.contains("uint16(0)==0x457f")
        || condensed.contains("int16(0)==0x457f")
        || condensed.contains("uint16be(0)==0x7f45")
        || has_module_reference(&lower, "elf.")
    {
        return Some("elf");
    }

    if condensed.contains("uint32(0)==0xcafebabe")
        || condensed.contains("uint32be(0)==0xcafebabe")
        || condensed.contains("uint32(0)==0xbebafeca")
        || condensed.contains("uint32be(0)==0xbebafeca")
        || condensed.contains("uint32(0)==0xfeedface")
        || condensed.contains("uint32be(0)==0xfeedface")
        || condensed.contains("uint32(0)==0xcefaedfe")
        || condensed.contains("uint32be(0)==0xcefaedfe")
        || condensed.contains("uint32(0)==0xfeedfacf")
        || condensed.contains("uint32be(0)==0xfeedfacf")
        || condensed.contains("uint32(0)==0xcffaedfe")
        || condensed.contains("uint32be(0)==0xcffaedfe")
        || condensed.contains("uint16(0)==0xfacf")
        || condensed.contains("uint16(0)==0xface")
        || has_module_reference(&lower, "macho.")
    {
        return Some("macho");
    }

    if condensed.contains("uint32(0)==0xd0cf11e0")
        || condensed.contains("uint32be(0)==0xd0cf11e0")
        || condensed.contains("uint16(0)==0xcfd0")
        || condensed.contains("uint16(0)==0xd0cf")
    {
        return Some("ole");
    }

    if condensed.contains("uint32(0)==0x25504446") || condensed.contains("uint32be(0)==0x25504446")
    {
        return Some("pdf");
    }

    if condensed.contains("uint32(0)==0x7b5c7274") {
        return Some("rtf");
    }

    if condensed.contains("uint16(0)==0x504b")
        || condensed.contains("uint32(0)==0x04034b50")
        || condensed.contains("uint32be(0)==0x504b0304")
    {
        return Some("zip");
    }

    if condensed.contains("uint32be(0)==0x6465780a") {
        return Some("dex");
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
            "pdf" | "pdfs" => return vec!["pdf"],
            "rtf" => return vec!["rtf", "doc"],
            "office" | "word" | "excel" | "olefile" | "ole" | "macro" | "maldoc" => {
                return vec!["doc", "docx", "xls", "xlsx", "ole"];
            }
            "securepreferences" | "json" => return vec!["json"],
            "onenote" | "one" | "onepkg" => return vec!["one", "onepkg"],
            "lnk" | "lnkr" | "shortcut" => return vec!["lnk"],
            "rdp" => return vec!["rdp"],
            "readme" | "txt" | "text" => return vec!["txt"],
            "xml" => return vec!["xml"],
            "ini" => return vec!["ini"],
            "cfg" | "conf" => return vec!["cfg", "conf", "ini"],
            "openvpn" | "ovpn" => return vec!["ovpn"],
            "iso" | "img" => return vec!["iso", "img"],
            "zip" | "zipcrypto" => return vec!["zip"],
            "html" | "htm" | "htmlsmuggling" => return vec!["html"],
            "svg" => return vec!["svg"],
            "eps" => return vec!["eps"],
            "eml" => return vec!["eml"],
            "outlook" | "msg" => return vec!["msg"],
            "gzip" | "gz" | "bzip2" | "bz2" | "xz" | "rar" | "7z" | "tar" => {
                return vec!["gzip"];
            }
            "cab" | "msi" => return vec!["cab"],
            "vhd" | "vmdk" => return vec!["vhd"],
            _ => {}
        }
    }
    if lower.contains("embeddedpdf") || lower.contains("embedded pdf") || lower.contains("adobepdf")
    {
        return vec!["pdf"];
    }
    if lower.contains("config file")
        || lower.contains("configuration file")
        || lower.contains("userconfig")
    {
        return vec!["cfg", "conf", "ini"];
    }
    if lower.contains("log file")
        || lower.contains("log files")
        || lower.contains("logs generated")
        || lower.contains("found in logs")
        || lower.contains("indicators found in logs")
        || lower.contains("forensic artifact")
        || lower.contains("forensic artifacts")
        || lower.contains("forensic artefact")
        || lower.contains("forensic artefacts")
        || lower.contains("forensic artificats")
    {
        return vec!["log", "txt"];
    }
    if lower.contains("output file")
        || lower.contains("output files")
        || lower.contains("output of")
        || lower.contains("outputs of")
        || lower.contains("system info output")
        || lower.contains("dump output")
        || lower.contains("password dump file")
        || lower.contains("hash dump output file")
    {
        return vec!["txt", "log"];
    }
    if lower.contains("phishing page")
        || lower.contains("web page")
        || lower.contains("webpage")
        || lower.contains("html smuggling")
    {
        return vec!["html"];
    }
    vec![]
}

/// Infer filetype constraints from scripting language and JVM/Android platform
/// signals in free-form text.
#[must_use]
pub fn platform_filetypes_from_text(text: &str) -> Vec<&'static str> {
    platform_filetypes_from_text_inner(text, false)
}

/// Infer platform filetypes from rule names.
///
/// Rule names intentionally use stronger shorthand than metadata prose, so
/// tokens like `Bash` or `Shell` are treated as script-specific here.
#[must_use]
pub fn platform_filetypes_from_rule_name(text: &str) -> Vec<&'static str> {
    platform_filetypes_from_text_inner(text, true)
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::*;

    fn split_rules(source: &str) -> Vec<(String, bool, &str)> {
        let mut starts: Vec<(usize, String, bool)> = Vec::new();
        let mut offset = 0usize;

        for line in source.split_inclusive('\n') {
            let line_no_nl = line.strip_suffix('\n').unwrap_or(line);
            let trimmed = line_no_nl.trim_start();
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
            offset += line.len();
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
        assert_eq!(infer_filetypes_from_tags(&["LOG".to_string()]), vec!["log"]);
        assert_eq!(
            infer_filetypes_from_tags(&["LINUXMALWARE".to_string()]),
            vec!["elf", "so"]
        );
        assert_eq!(
            infer_filetypes_from_tags(&["WINMALWARE".to_string()]),
            vec!["pe", "dll"]
        );
        assert_eq!(
            infer_filetypes_from_metadata_text("Detects malicious RDP files"),
            vec!["rdp"]
        );
        assert_eq!(
            infer_filetypes_from_metadata_text("Detects some kind of HTMLSmuggling used by APT28"),
            vec!["html"]
        );
        assert_eq!(
            infer_filetypes_from_metadata_text("Detects APT28 Phishing page"),
            vec!["html"]
        );
        assert_eq!(
            infer_filetypes_from_metadata_text(
                "https://example.invalid/yara_rules/apt_lazarus_backdoored_jslib.yar"
            ),
            vec!["js", "mjs", "cjs"]
        );
        assert_eq!(
            infer_filetypes_from_metadata_text(
                "https://example.invalid/yara_rules/apt_luckymouse_compromised_electronapp.yar"
            ),
            vec!["js", "mjs", "cjs"]
        );
        assert_eq!(
            infer_filetypes_from_metadata_text("Detects clean version of PowerShower"),
            vec!["ps1", "psm1", "psd1"]
        );
        assert_eq!(
            infer_filetypes_from_metadata_text("Auto-generated rule - file README.cup.NOPEN"),
            vec!["txt"]
        );
        assert_eq!(
            infer_filetypes_from_metadata_text("OpenVPN configuration artifact"),
            vec!["ovpn"]
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
        assert_eq!(filetype_from_magic("uint32be(0) == 0x5A4D"), Some("pe"));
        assert_eq!(filetype_from_magic("uint32(0) == 0x464c457f"), Some("elf"));
        assert_eq!(filetype_from_magic("uint16(0) == 0x457f"), Some("elf"));
        assert_eq!(filetype_from_magic("int16(0) == 0x5A4D"), Some("pe"));
        assert_eq!(filetype_from_magic("int32be(0) == 0x7f454c46"), Some("elf"));
        assert_eq!(
            filetype_from_magic("uint32be(0x0) == 0x7F454C46"),
            Some("elf")
        );
        assert_eq!(
            filetype_from_magic("uint32be(0) == 0xcffaedfe"),
            Some("macho")
        );
        assert_eq!(
            filetype_from_magic("uint32be(0) == 0xcafebabe"),
            Some("macho")
        );
        assert_eq!(
            filetype_from_magic("uint32be(0) == 0x504B0304"),
            Some("zip")
        );
        assert_eq!(
            filetype_from_magic("uint32be(0) == 0xD0CF11E0"),
            Some("ole")
        );
        assert_eq!(
            filetype_from_magic("uint32be(0) == 0x6465780A"),
            Some("dex")
        );
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

        let rdp_source = r#"
rule SEKOIA_Apt_Apt29_Malicious_Rdp_File : FILE
{
    meta:
        description = "Detects malicious RDP files"
        source_url = "https://example.invalid/apt_apt29_malicious_rdp_file.yar"
    condition:
        true
}
"#;
        assert_eq!(
            YaraTier::classify_rule(
                "SEKOIA_Apt_Apt29_Malicious_Rdp_File",
                rdp_source,
                "3p.test.rdp"
            ),
            YaraTier::Doc
        );

        let html_smuggling_source = r#"
rule SEKOIA_Apt_Apt28_Htmlsmuggling : FILE
{
    meta:
        description = "Detects some kind of HTMLSmuggling used by APT28"
        source_url = "https://example.invalid/apt_apt28_htmlsmuggling.yar"
    condition:
        true
}
"#;
        assert_eq!(
            YaraTier::classify_rule(
                "SEKOIA_Apt_Apt28_Htmlsmuggling",
                html_smuggling_source,
                "3p.test.html"
            ),
            YaraTier::Doc
        );

        let jslib_source = r#"
rule SEKOIA_Apt_Lazarus_Backdoored_Jslib : FILE
{
    meta:
        description = "Detects InvisibleFerret based on common ressource."
        source_url = "https://example.invalid/apt_lazarus_backdoored_jslib.yar"
    condition:
        true
}
"#;
        assert_eq!(
            YaraTier::classify_rule(
                "SEKOIA_Apt_Lazarus_Backdoored_Jslib",
                jslib_source,
                "3p.test.jslib"
            ),
            YaraTier::ScriptJs
        );

        let electron_source = r#"
rule SEKOIA_Apt_Luckymouse_Compromised_Electronapp : FILE
{
    meta:
        description = "Detects compromised ElectronApp"
        source_url = "https://example.invalid/apt_luckymouse_compromised_electronapp.yar"
    condition:
        true
}
"#;
        assert_eq!(
            YaraTier::classify_rule(
                "SEKOIA_Apt_Luckymouse_Compromised_Electronapp",
                electron_source,
                "3p.test.electron"
            ),
            YaraTier::ScriptJs
        );

        let powershower_source = r#"
rule SEKOIA_Apt_Cloudatlas_Powershower_Clean : FILE
{
    meta:
        description = "Detects clean version of PowerShower"
        source_url = "https://example.invalid/apt_cloudatlas_powershower_clean.yar"
    condition:
        true
}
"#;
        assert_eq!(
            YaraTier::classify_rule(
                "SEKOIA_Apt_Cloudatlas_Powershower_Clean",
                powershower_source,
                "3p.test.ps1"
            ),
            YaraTier::Script
        );

        let readme_source = r#"
rule SIGNATURE_BASE_FVEY_Shadowbroker_README_Cup
{
    meta:
        description = "Auto-generated rule - file README.cup.NOPEN"
    condition:
        true
}
"#;
        assert_eq!(
            YaraTier::classify_rule(
                "SIGNATURE_BASE_FVEY_Shadowbroker_README_Cup",
                readme_source,
                "3p.test.readme"
            ),
            YaraTier::Doc
        );

        let log_source = r#"
rule SIGNATURE_BASE_LOG_F5_BIGIP_Exploitation_Artefacts_CVE_2021_22986_Mar21_1 : LOG
{
    meta:
        description = "Detects forensic artefacts indicating successful exploitation of F5 BIG IP appliances"
    condition:
        true
}
"#;
        assert_eq!(
            YaraTier::classify_rule(
                "SIGNATURE_BASE_LOG_F5_BIGIP_Exploitation_Artefacts_CVE_2021_22986_Mar21_1",
                log_source,
                "3p.test.log"
            ),
            YaraTier::Doc
        );
    }

    #[test]
    fn test_classify_rule_content_hints_for_scripts_and_configs() {
        let js_source = r#"
rule SEKOIA_Apt_Tortoiseshell_Wateringhole_Script : FILE
{
    strings:
        $ = "btoa(document.referrer)"
        $ = "navigator.language"
        $ = "window.RTCPeerConnection"
        $ = "sha256(canvas.toDataURL("
    condition:
        3 of them
}
"#;
        assert_eq!(
            YaraTier::classify_rule(
                "SEKOIA_Apt_Tortoiseshell_Wateringhole_Script",
                js_source,
                "3p.test.browserjs"
            ),
            YaraTier::ScriptJs
        );

        let ps_source = r#"
rule SEKOIA_Apt_Cloudatlas_Powershower_Clean : FILE
{
    strings:
        $ = "[io.file]::WriteAllBytes($zipfile"
        $ = "System.IO.File]::Exists($p_t"
    condition:
        all of them
}
"#;
        assert_eq!(
            YaraTier::classify_rule(
                "SEKOIA_Apt_Cloudatlas_Powershower_Clean",
                ps_source,
                "3p.test.ps-body"
            ),
            YaraTier::Script
        );

        let tomcat_source = r#"
rule SIGNATURE_BASE_VUL_Tomcat_Catalina_CVE_2020_1938 : FILE
{
    strings:
        $h1 = "<?xml "
        $a1 = "<Service name=\"Catalina\">"
        $v1 = "<Connector port=\"8009\" protocol=\"AJP/1.3\" redirectPort=\"8443\"/>"
    condition:
        all of them
}
"#;
        assert_eq!(
            YaraTier::classify_rule(
                "SIGNATURE_BASE_VUL_Tomcat_Catalina_CVE_2020_1938",
                tomcat_source,
                "3p.test.tomcat"
            ),
            YaraTier::Doc
        );
    }

    #[test]
    fn test_classify_rule_additional_magic_and_tag_variants() {
        let linux_tag_source = r#"
rule DEADBITS_Watchdog_Botnet : BOTNET LINUXMALWARE EXPLOITATION CVE_2019_11581
{
    condition:
        true
}
"#;
        assert_eq!(
            YaraTier::classify_rule(
                "DEADBITS_Watchdog_Botnet",
                linux_tag_source,
                "3p.test.deadbits"
            ),
            YaraTier::Elf
        );

        let signed_elf_source = r#"
rule SEKOIA_Apt_Apt31_Pakdoor : FILE
{
    condition:
        int32be ( 0 ) == 0x7f454c46 and true
}
"#;
        assert_eq!(
            YaraTier::classify_rule(
                "SEKOIA_Apt_Apt31_Pakdoor",
                signed_elf_source,
                "3p.test.pakdoor"
            ),
            YaraTier::Elf
        );

        let offset_elf_source = r#"
rule SECUINFRA_RANSOM_Esxiargs_Ransomware_Encryptor_Feb23
{
    condition:
        uint32be( 0x0 ) == 0x7F454C46 and true
}
"#;
        assert_eq!(
            YaraTier::classify_rule(
                "SECUINFRA_RANSOM_Esxiargs_Ransomware_Encryptor_Feb23",
                offset_elf_source,
                "3p.test.esxiargs"
            ),
            YaraTier::Elf
        );

        let fat_macho_source = r#"
rule SEKOIA_Apt_Cloudmensis_Spyagent_Strings : FILE
{
    condition:
        uint32be( 0 ) == 0xcafebabe and true
}
"#;
        assert_eq!(
            YaraTier::classify_rule(
                "SEKOIA_Apt_Cloudmensis_Spyagent_Strings",
                fat_macho_source,
                "3p.test.cloudmensis"
            ),
            YaraTier::MachO
        );

        let signed_pe_source = r#"
rule SIGNATURE_BASE_APT_NK_Lazarus_RC4_Loop : FILE
{
    condition:
        int16 ( 0 ) == 0x5a4d and true
}
"#;
        assert_eq!(
            YaraTier::classify_rule(
                "SIGNATURE_BASE_APT_NK_Lazarus_RC4_Loop",
                signed_pe_source,
                "3p.test.lazarus"
            ),
            YaraTier::Pe
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
            vec![YaraTier::Archive, YaraTier::CrossFormat]
        );
        assert_eq!(
            YaraTier::scan_order(None),
            vec![YaraTier::CrossFormat, YaraTier::Raw, YaraTier::Unknown]
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
        assert_eq!(YaraTier::from_filetypes(&["apk"]), YaraTier::Archive);
        assert_eq!(YaraTier::from_filetypes(&["vhd"]), YaraTier::Archive);
        assert_eq!(YaraTier::from_filetypes(&["mach"]), YaraTier::MachO);
        assert_eq!(YaraTier::from_filetypes(&["hta"]), YaraTier::Script);
        assert_eq!(YaraTier::from_filetypes(&["au3"]), YaraTier::Script);
        assert_eq!(YaraTier::from_filetypes(&["sct"]), YaraTier::Script);
        assert_eq!(YaraTier::from_filetypes(&["svg"]), YaraTier::Doc);

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
        assert_eq!(
            infer_filetypes("SEKOIA_Downloader_Mac_Smooth_Operator", None),
            vec!["macho", "dylib"]
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
            infer_filetypes_from_metadata_text(
                "Detect suspicious VHD file with APT28 artefacts inside"
            ),
            vec!["vhd"]
        );
        assert_eq!(
            infer_filetypes_from_metadata_text(
                "Detects Embedded PDFs which can start malicious content"
            ),
            vec!["pdf"]
        );
        assert_eq!(
            infer_filetypes_from_metadata_text("Detects DarkGate AutoIT script"),
            vec!["au3"]
        );
        assert_eq!(
            infer_filetypes_from_metadata_text("Detect IronPython script used by Turla group"),
            vec!["py", "pyc"]
        );
        assert_eq!(
            infer_filetypes_from_metadata_text("Cobalt Strike resources/template.sct signature"),
            vec!["sct", "wsf"]
        );
        assert_eq!(
            infer_filetypes_from_metadata_text(
                "Detect samples of the Android banking trojan BRATA"
            ),
            vec!["apk", "dex"]
        );
        assert_eq!(
            infer_filetypes_from_metadata_text("Suspicious SVG foreignObject smuggling document"),
            vec!["svg"]
        );
        assert_eq!(
            infer_filetypes_from_metadata_text("Outlook reminder exploit message"),
            vec!["msg"]
        );
        assert!(
            infer_filetypes_from_metadata_text(
                "Detects code found in report on exploits against CVE-2020-5902 F5 BIG-IP vulnerability by NCC group"
            )
            .is_empty()
        );
        assert_eq!(
            infer_filetypes_from_metadata_text("Suspicious bash script downloader"),
            vec!["sh", "bash", "zsh"]
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
            YaraTier::classify_rule("SEKOIA_Apt_Yemen_Apk_Guardzoo", apk_rule, "3p.test.android"),
            YaraTier::Archive
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
            YaraTier::Archive
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

        let multi_rule = r#"
rule BINARYALERT_Hacktool_Multi_Bloodhound_Owned : FILE
{
    condition:
        true
}
"#;
        assert_eq!(
            YaraTier::classify_rule(
                "BINARYALERT_Hacktool_Multi_Bloodhound_Owned",
                multi_rule,
                "3p.test.multi"
            ),
            YaraTier::CrossFormat
        );

        let autoit_rule = r#"
rule RUSSIANPANDA_Darkgate_Autoit
{
    meta:
        description = "Detects DarkGate AutoIT script"
    strings:
        $h = "AU3!EA06"
    condition:
        $h
}
"#;
        assert_eq!(
            YaraTier::classify_rule(
                "RUSSIANPANDA_Darkgate_Autoit",
                autoit_rule,
                "3p.test.autoit"
            ),
            YaraTier::Script
        );

        let powgoop_decoded_rule = r#"
rule SEKOIA_Apt_Muddywater_Powgoop_Decoded : FILE
{
    strings:
        $h1 = "[System.Net.WebRequest]::Create(" ascii wide
        $h2 = "Headers.Add('Authorization'" ascii wide
        $h3 = "Headers.Add('Cookie',('value=' + $ec + ';')" ascii wide
        $h4 = "GetResponseStream()" ascii wide
        $c1 = "return (65..90) + (97..122) | Get-Random -Count" ascii wide
    condition:
        3 of them
}
"#;
        assert_eq!(
            YaraTier::classify_rule(
                "SEKOIA_Apt_Muddywater_Powgoop_Decoded",
                powgoop_decoded_rule,
                "3p.test.powgoop"
            ),
            YaraTier::Script
        );

        let sysrvbot_tomcat_rule = r#"
rule backdoor_SysrvBot_tomcat {
    strings:
        $s1 = "&echo ----file ROOT good----" ascii
        $s2 = "application.getRealPath(\"tomcat.jsp\").split(\"\\\\tomcat.jsp\");" ascii
        $s3 = "ldr.sh?tomcat)|bash" ascii
    condition:
        all of them
}
"#;
        assert_eq!(
            YaraTier::classify_rule(
                "backdoor_SysrvBot_tomcat",
                sysrvbot_tomcat_rule,
                "3p.JPCERT.sysrvbot"
            ),
            YaraTier::Script
        );

        let mimipenguin_rule = r#"
rule SIGNATURE_BASE_Mimipenguin_1 : FILE
{
    strings:
        $x1 = "def _dump_target_processes(self):" fullword ascii
    condition:
        uint16( 0 ) == 0x2123 and $x1
}
"#;
        assert_eq!(
            YaraTier::classify_rule(
                "SIGNATURE_BASE_Mimipenguin_1",
                mimipenguin_rule,
                "3p.YARAForge.yara-rules-full"
            ),
            YaraTier::Script
        );

        let waterpamola_js_rule = r#"
rule WaterPamola_stealjs_str {
    strings:
        $str1 = "eval(function(p,a,c,k,"
        $str2 = "XMLHttpRequest"
        $str3 = "application/x-www-form-urlencoded"
    condition:
        all of them
}
"#;
        assert_eq!(
            YaraTier::classify_rule(
                "WaterPamola_stealjs_str",
                waterpamola_js_rule,
                "3p.JPCERT.waterpamola"
            ),
            YaraTier::ScriptJs
        );

        let batcopier_rule = r#"
rule SEKOIA_Apt_Unk_Batcopier_Strings : FILE
{
    strings:
        $ = "@echo off"
        $ = "echo F|xcopy"
        $ = "attrib +r +s +h"
    condition:
        all of them
}
"#;
        assert_eq!(
            YaraTier::classify_rule(
                "SEKOIA_Apt_Unk_Batcopier_Strings",
                batcopier_rule,
                "3p.YARAForge.yara-rules-full"
            ),
            YaraTier::Script
        );

        let bypassgodzilla_rule = r#"
rule SEKOIA_Tool_Bypassgodzilla : FILE
{
    strings:
        $jsp_1a = "response.getWriter().write(\""
        $asp_1 = "[\"payload\"]).CreateInstance(\"LY\");"
        $php_1 = "=(\"!\"^\"@\").'ss'.Chr(\"101\").'rs';"
        $php_3 = "*/isset($_SESSION/*"
        $php_4 = "@set_time_limit(Chr(\"48\"))"
    condition:
        all of them
}
"#;
        assert_eq!(
            YaraTier::classify_rule(
                "SEKOIA_Tool_Bypassgodzilla",
                bypassgodzilla_rule,
                "3p.YARAForge.yara-rules-full"
            ),
            YaraTier::Script
        );

        let pivotnacci_webshell_rule = r#"
rule SEKOIA_Tool_Pivotnacci_Webshell : FILE
{
    strings:
        $ = "Response.BinaryWrite(newBuff)"
        $ = "Request.Headers.Get(ID_HEADER)"
        $ = "extract_session_readbuf($conn_id"
    condition:
        all of them
}
"#;
        assert_eq!(
            YaraTier::classify_rule(
                "SEKOIA_Tool_Pivotnacci_Webshell",
                pivotnacci_webshell_rule,
                "3p.YARAForge.yara-rules-full"
            ),
            YaraTier::Script
        );

        let proxynotshell_log_rule = r#"
rule SIGNATURE_BASE_EXPL_Exchange_Proxynotshell_Patterns_CVE_2022_41040_Oct22_1 : SCRIPT
{
    meta:
        description = "Detects successful ProxyNotShell exploitation attempts in log files"
    condition:
        true
}
"#;
        assert_eq!(
            YaraTier::classify_rule(
                "SIGNATURE_BASE_EXPL_Exchange_Proxynotshell_Patterns_CVE_2022_41040_Oct22_1",
                proxynotshell_log_rule,
                "3p.YARAForge.yara-rules-full"
            ),
            YaraTier::Doc
        );

        let barracuda_forensics_rule = r#"
rule SIGNATURE_BASE_APT_UNC4841_ESG_Barracuda_CVE_2023_2868_Forensic_Artifacts_Jun23_1 : SCRIPT
{
    meta:
        description = "Detects forensic artifacts found in the exploitation of CVE-2023-2868 in Barracuda ESG devices by UNC4841"
    condition:
        true
}
"#;
        assert_eq!(
            YaraTier::classify_rule(
                "SIGNATURE_BASE_APT_UNC4841_ESG_Barracuda_CVE_2023_2868_Forensic_Artifacts_Jun23_1",
                barracuda_forensics_rule,
                "3p.YARAForge.yara-rules-full"
            ),
            YaraTier::Doc
        );

        let casper_output_rule = r#"
rule SIGNATURE_BASE_Casper_Systeminformation_Output
{
    meta:
        description = "Casper French Espionage Malware - System Info Output"
    condition:
        true
}
"#;
        assert_eq!(
            YaraTier::classify_rule(
                "SIGNATURE_BASE_Casper_Systeminformation_Output",
                casper_output_rule,
                "3p.YARAForge.yara-rules-full"
            ),
            YaraTier::Doc
        );

        let gsecdump_output_rule = r#"
rule SIGNATURE_BASE_Gsecdump_Password_Dump_File : FILE
{
    meta:
        description = "Detects a gsecdump output file"
    condition:
        true
}
"#;
        assert_eq!(
            YaraTier::classify_rule(
                "SIGNATURE_BASE_Gsecdump_Password_Dump_File",
                gsecdump_output_rule,
                "3p.YARAForge.yara-rules-full"
            ),
            YaraTier::Doc
        );

        let ntlm_output_rule = r#"
rule SIGNATURE_BASE_NTLM_Dump_Output
{
    meta:
        description = "NTML Hash Dump output file - John/LC format"
    condition:
        true
}
"#;
        assert_eq!(
            YaraTier::classify_rule(
                "SIGNATURE_BASE_NTLM_Dump_Output",
                ntlm_output_rule,
                "3p.YARAForge.yara-rules-full"
            ),
            YaraTier::Doc
        );

        let recon_outputs_rule = r#"
rule SIGNATURE_BASE_SUSP_Recon_Outputs_Jun20_1 : FILE
{
    meta:
        description = "Detects outputs of many different commands often used for reconnaissance purposes"
    condition:
        true
}
"#;
        assert_eq!(
            YaraTier::classify_rule(
                "SIGNATURE_BASE_SUSP_Recon_Outputs_Jun20_1",
                recon_outputs_rule,
                "3p.YARAForge.yara-rules-full"
            ),
            YaraTier::Doc
        );

        let scanbox_rule = r#"
rule SEKOIA_Apt_Scanbox_Framework_Not_Obfuscated : FILE
{
    strings:
        $ = ".fun.split_data = function"
        $ = "loadjs ="
        $ = "info.color = screen.colorDepth"
    condition:
        all of them
}
"#;
        assert_eq!(
            YaraTier::classify_rule(
                "SEKOIA_Apt_Scanbox_Framework_Not_Obfuscated",
                scanbox_rule,
                "3p.YARAForge.yara-rules-full"
            ),
            YaraTier::ScriptJs
        );

        let sharpext_rule = r#"
rule SEKOIA_Apt_Kimsuky_Sharpext_Devtoolmodule_Strings : FILE
{
    strings:
        $ = "packetProc = function"
        $ = "var url = request.request.url"
        $ = "https://mail"
    condition:
        all of them
}
"#;
        assert_eq!(
            YaraTier::classify_rule(
                "SEKOIA_Apt_Kimsuky_Sharpext_Devtoolmodule_Strings",
                sharpext_rule,
                "3p.YARAForge.yara-rules-full"
            ),
            YaraTier::ScriptJs
        );

        let powerexchange_rule = r#"
rule SEKOIA_Apt_Oilrig_Powerexchange : FILE
{
    strings:
        $ = "($h.value).PadRight((($h.value).Length+($h.value).Length%4),'=')"
        $ = "[Environment]::NewLine+$_.Exception.Message | Out-File -FilePath"
    condition:
        all of them
}
"#;
        assert_eq!(
            YaraTier::classify_rule(
                "SEKOIA_Apt_Oilrig_Powerexchange",
                powerexchange_rule,
                "3p.YARAForge.yara-rules-full"
            ),
            YaraTier::Script
        );

        let securepreferences_rule = r#"
rule SEKOIA_Apt_Kimsuky_Sharpext_Compromised_Securepreferences
{
    meta:
        description = "Detects compromised Chrome SecurePreferences file"
    condition:
        true
}
"#;
        assert_eq!(
            YaraTier::classify_rule(
                "SEKOIA_Apt_Kimsuky_Sharpext_Compromised_Securepreferences",
                securepreferences_rule,
                "3p.YARAForge.yara-rules-full"
            ),
            YaraTier::Doc
        );

        let guloader_unpacker_rule = r#"
rule SEKOIA_Guloader_Unpacker : FILE
{
    strings:
        $p1 = "([Parameter(Position = 0)] [Type[]] $" base64
        $p2 = "}else {" base64
    condition:
        all of them
}
"#;
        assert_eq!(
            YaraTier::classify_rule(
                "SEKOIA_Guloader_Unpacker",
                guloader_unpacker_rule,
                "3p.YARAForge.yara-rules-full"
            ),
            YaraTier::Script
        );

        let guloader_unpacker_decoded_rule = r#"
rule SEKOIA_Guloader_Unpacker_Decoded : FILE
{
    strings:
        $s1 = "([String]$"
        $s2 = "For($"
        $s3 = ",[Parameter(Position = 1)] [Type] $"
    condition:
        all of them
}
"#;
        assert_eq!(
            YaraTier::classify_rule(
                "SEKOIA_Guloader_Unpacker_Decoded",
                guloader_unpacker_decoded_rule,
                "3p.YARAForge.yara-rules-full"
            ),
            YaraTier::Script
        );

        let scriptlet_rule = r#"
rule GCTI_Cobaltstrike_Resources_Template_Sct_V3_3_To_V4_X
{
    meta:
        description = "Cobalt Strike's resources/template.sct signature"
    strings:
        $a = "<scriptlet>"
        $b = "<script language=\"vbscript\">"
    condition:
        all of them
}
"#;
        assert_eq!(
            YaraTier::classify_rule(
                "GCTI_Cobaltstrike_Resources_Template_Sct_V3_3_To_V4_X",
                scriptlet_rule,
                "3p.test.sct"
            ),
            YaraTier::Script
        );

        let native_iis_rule = r#"
rule ESET_IIS_Group14
{
    meta:
        description = "Detects Group 14 native IIS malware family"
    condition:
        true
}
"#;
        assert_eq!(
            YaraTier::classify_rule("ESET_IIS_Group14", native_iis_rule, "3p.test.iis"),
            YaraTier::Pe
        );

        let shortcut_rule = r#"
rule suspicious_shortcut
{
    meta:
        description = "Suspicious shortcut with remote URL"
    condition:
        true
}
"#;
        assert_eq!(
            YaraTier::classify_rule("suspicious_shortcut", shortcut_rule, "3p.test.shortcut"),
            YaraTier::Doc
        );

        let raw32_rule = r#"
rule FIREEYE_RT_APT_Loader_Raw32_REDFLARE_1 : FILE
{
    meta:
        description = "No description has been set in the source file - FireEye-RT"
    condition:
        ( uint16( 0 ) != 0x5A4D ) and true
}
"#;
        assert_eq!(
            YaraTier::classify_rule(
                "FIREEYE_RT_APT_Loader_Raw32_REDFLARE_1",
                raw32_rule,
                "3p.test.raw"
            ),
            YaraTier::Raw
        );

        let octowave_support_rule = r#"
rule SIGNATURE_BASE_Octowave_Loader_Supporting_File_03_2025 : FILE
{
    meta:
        description = "Detects supporting file used by Octowave loader containing hardcoded values"
    condition:
        uint16( 0 ) != 0x5a4d and true
}
"#;
        assert_eq!(
            YaraTier::classify_rule(
                "SIGNATURE_BASE_Octowave_Loader_Supporting_File_03_2025",
                octowave_support_rule,
                "3p.test.raw"
            ),
            YaraTier::Raw
        );

        let sliver_implant_rule = r#"
rule GCTI_Sliver_Implant_32Bit
{
    meta:
        description = "Sliver 32-bit implant (with and without --debug flag at compile)"
    condition:
        true
}
"#;
        assert_eq!(
            YaraTier::classify_rule(
                "GCTI_Sliver_Implant_32Bit",
                sliver_implant_rule,
                "3p.test.unknown"
            ),
            YaraTier::Unknown
        );

        let smooth_operator_rule = r#"
rule SEKOIA_Downloader_Mac_Smooth_Operator : FILE
{
    meta:
        description = "Detect the Smooth_Operator malware"
        source_url = "https://example.invalid/yara_rules/downloader_mac_smooth_operator.yar"
    condition:
        uint32be( 0 ) == 0xcafebabe and true
}
"#;
        assert_eq!(
            YaraTier::classify_rule(
                "SEKOIA_Downloader_Mac_Smooth_Operator",
                smooth_operator_rule,
                "3p.test.macos"
            ),
            YaraTier::MachO
        );

        let sharpnbtscan_rule = r#"
rule SEKOIA_Tool_Sharpnbtscan_Strings : FILE
{
    condition:
        uint32be( 0 ) == 0x5A4D and true
}
"#;
        assert_eq!(
            YaraTier::classify_rule(
                "SEKOIA_Tool_Sharpnbtscan_Strings",
                sharpnbtscan_rule,
                "3p.YARAForge.yara-rules-full"
            ),
            YaraTier::Pe
        );

        let malscript_rule = r#"
rule MalScript_Tricks
{
    strings:
        $s1 = "window.moveTo -"
        $s2 = "window.resizeTo 0"
    condition:
        all of them
}
"#;
        assert_eq!(
            YaraTier::classify_rule(
                "MalScript_Tricks",
                malscript_rule,
                "3p.bartblaze.generic.MalScript_Tricks"
            ),
            YaraTier::ScriptJs
        );

        let jupyter_rule = r#"
rule Jupyter
{
    strings:
        $ = "var __addr__="
        $ = "var __hwid__="
        $ = "var __xkey__="
    condition:
        all of them
}
"#;
        assert_eq!(
            YaraTier::classify_rule("Jupyter", jupyter_rule, "3p.bartblaze.crimeware.Jupyter"),
            YaraTier::ScriptJs
        );

        let systembc_config_rule = r#"
rule SystemBC_Config
{
    strings:
        $ = "BEGINDATA"
        $ = "HOST1:"
        $ = "PORT1:"
        $ = "TOR:"
    condition:
        3 of them
}
"#;
        assert_eq!(
            YaraTier::classify_rule(
                "SystemBC_Config",
                systembc_config_rule,
                "3p.bartblaze.crimeware.SystemBC"
            ),
            YaraTier::Doc
        );

        let ta18_scripts_rule = r#"
rule SIGNATURE_BASE_TA18_074A_Scripts : FILE
{
    condition:
        true
}
"#;
        assert_eq!(
            YaraTier::classify_rule(
                "SIGNATURE_BASE_TA18_074A_Scripts",
                ta18_scripts_rule,
                "3p.YARAForge.yara-rules-full"
            ),
            YaraTier::Script
        );

        let moveit_log_rule = r#"
rule SIGNATURE_BASE_LOG_EXPL_Moveit_Exploitation_Indicator_Jun23_1
{
    condition:
        true
}
"#;
        assert_eq!(
            YaraTier::classify_rule(
                "SIGNATURE_BASE_LOG_EXPL_Moveit_Exploitation_Indicator_Jun23_1",
                moveit_log_rule,
                "3p.YARAForge.yara-rules-full"
            ),
            YaraTier::Doc
        );

        let fourelementsword_config_rule = r#"
rule SIGNATURE_BASE_Fourelementsword_Config_File
{
    strings:
        $s1 = "RegisterDlls=OurDll"
        $s2 = "[DefaultInstall]"
        $s3 = "Signature=\"$Windows NT$\""
    condition:
        all of them
}
"#;
        assert_eq!(
            YaraTier::classify_rule(
                "SIGNATURE_BASE_Fourelementsword_Config_File",
                fourelementsword_config_rule,
                "3p.YARAForge.yara-rules-full"
            ),
            YaraTier::Doc
        );

        let ares_pydoor_rule = r#"
rule BlackTech_AresPYDoor_str
{
    condition:
        true
}
"#;
        assert_eq!(
            YaraTier::classify_rule(
                "BlackTech_AresPYDoor_str",
                ares_pydoor_rule,
                "3p.JPCERT.blacktech"
            ),
            YaraTier::Script
        );

        let p0wned_rule = r#"
rule SIGNATURE_BASE_Hacktool_Strings_P0Wnedshell : FILE
{
    condition:
        true
}
"#;
        assert_eq!(
            YaraTier::classify_rule(
                "SIGNATURE_BASE_Hacktool_Strings_P0Wnedshell",
                p0wned_rule,
                "3p.YARAForge.yara-rules-full"
            ),
            YaraTier::Script
        );

        let forensic_name_rule = r#"
rule SIGNATURE_BASE_Nautilus_Forensic_Artificats
{
    condition:
        true
}
"#;
        assert_eq!(
            YaraTier::classify_rule(
                "SIGNATURE_BASE_Nautilus_Forensic_Artificats",
                forensic_name_rule,
                "3p.YARAForge.yara-rules-full"
            ),
            YaraTier::Doc
        );
    }

    #[test]
    fn test_classify_rule_pe_magic_and_module_examples() {
        let cert_rule = r#"
rule REVERSINGLABS_Cert_Blocklist_0332D5C942869Bdcabf5A8266197Cd14 : INFO FILE
{
    meta:
        description = "Certificate used for digitally signing malware."
        tags = "INFO, FILE"
    condition:
        uint16( 0 ) == 0x5A4D and for any i in ( 0 .. pe.number_of_signatures ) : (
            pe.signatures [ i ] . subject contains "JAWRO SP Z O O"
        )
}
"#;
        assert_eq!(
            YaraTier::classify_rule(
                "REVERSINGLABS_Cert_Blocklist_0332D5C942869Bdcabf5A8266197Cd14",
                cert_rule,
                "3p.test.reversinglabs"
            ),
            YaraTier::Pe
        );

        let indicator_rule = r#"
rule DITEKSHEN_INDICATOR_KB_CERT_066276Af2F2C7E246D3B1Cab1B4Aa42E : FILE
{
    meta:
        description = "Detects executables signed with stolen, revoked or invalid certificates"
    condition:
        uint16( 0 ) == 0x5a4d and for any i in ( 0 .. pe.number_of_signatures ) : (
            pe.signatures [ i ] . subject contains "IQ Trade ApS"
        )
}
"#;
        assert_eq!(
            YaraTier::classify_rule(
                "DITEKSHEN_INDICATOR_KB_CERT_066276Af2F2C7E246D3B1Cab1B4Aa42E",
                indicator_rule,
                "3p.test.ditekshen"
            ),
            YaraTier::Pe
        );
    }

    #[test]
    fn test_exact_third_party_cert_examples_classify_as_pe() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("..")
            .join("cleave-traits")
            .join("third-party")
            .join("YARAForge")
            .join("yara-rules-full.yar");
        if !path.exists() {
            return;
        }

        let source = std::fs::read_to_string(&path).expect("read YARAForge rules");
        for target in [
            "REVERSINGLABS_Cert_Blocklist_0332D5C942869Bdcabf5A8266197Cd14",
            "DITEKSHEN_INDICATOR_KB_CERT_066276Af2F2C7E246D3B1Cab1B4Aa42E",
        ] {
            let (_, _, rule_text) = split_rules(&source)
                .into_iter()
                .find(|(name, is_private, _)| !*is_private && name == target)
                .expect("target rule present");
            let lower = rule_text.to_lowercase();
            assert!(
                filetype_from_magic(rule_text).is_some() || has_module_reference(&lower, "pe."),
                "missing PE signal for {target}: {rule_text}"
            );
            assert_eq!(
                YaraTier::classify_rule(target, rule_text, "3p.YARAForge.yara-rules-full"),
                YaraTier::Pe,
                "failed for {target}: filetype_from_magic={:?} has_pe_module={} source={rule_text}",
                filetype_from_magic(rule_text),
                has_module_reference(&lower, "pe.")
            );
        }
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
        let mut raw = Vec::new();
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
                    YaraTier::Raw => raw.push(format!("{} (ns={})", name, ns)),
                    YaraTier::Unknown => unknown.push(format!("{} (ns={})", name, ns)),
                    _ => {}
                }
            }
        }

        cross_format.sort();
        raw.sort();
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
        eprintln!("\n=== Raw Rules ({}) ===", raw.len());
        for name in &raw {
            eprintln!("  {name}");
        }
        eprintln!("\n=== Unknown Rules ({}) ===", unknown.len());
        for name in &unknown {
            eprintln!("  {name}");
        }
    }
}
