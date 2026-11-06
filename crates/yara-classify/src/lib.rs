//! Pure helpers for classifying YARA rules by target filetype and scan tier.
//!
//! This crate intentionally contains no engine integration, I/O, or `cleave`
//! runtime dependencies so it can be tested and iterated on independently.

mod overrides;
#[allow(clippy::wildcard_imports)]
use overrides::*;

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
                && let Some(val) = trimmed.split('=').nth(1)
            {
                let val = val.trim().trim_matches('"').trim_matches('\'');
                let types: Vec<&str> = val.split(',').map(str::trim).collect();
                if let Some(tier) = classify_rule_filetypes(&types) {
                    return tier;
                }
            }
            if trimmed.starts_with("os") && trimmed.contains('=') {
                let after_os = &trimmed[2..];
                if (after_os.starts_with(' ') || after_os.starts_with('='))
                    && let Some(val) = trimmed.split('=').nth(1)
                {
                    let val = val.trim().trim_matches('"').trim_matches('\'');
                    if val != "multi" && val != "all" {
                        os_meta = Some(val.to_string());
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
        if !tagged.is_empty()
            && let Some(tier) = classify_rule_filetypes(&tagged)
        {
            return tier;
        }

        // 1b. Metadata prose/URLs often carry specific filetype hints.
        let metadata_inferred = infer_filetypes_from_metadata_text(&metadata_hint_text);
        if !metadata_inferred.is_empty()
            && let Some(tier) = classify_rule_filetypes(&metadata_inferred)
        {
            if matches!(tier, Self::Script | Self::ScriptJs | Self::Doc)
                && let Some(binary_tier) =
                    preferred_binary_tier(rule_name, namespace, os_meta.as_deref())
            {
                return binary_tier;
            }
            return tier;
        }

        // 1c. Use os metadata only when all inferred filetypes land in one tier.
        if let Some(ref os) = os_meta {
            let inferred = infer_filetypes(rule_name, Some(os));
            if let Some(tier) = classify_rule_filetypes(&inferred)
                && tier != Self::CrossFormat
            {
                return tier;
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
        let condensed: String = lower.chars().filter(|c| !c.is_ascii_whitespace()).collect();
        if condensed.contains("uint16(0)==0x2123") || condensed.contains("uint16be(0)==0x2321") {
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

mod indicators;

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

    // Binary-format name tokens (strongest): an explicit format word pins the type.
    for token in &tokens {
        match *token {
            "pe" | "exe" | "dll" | "sys" | "driver" | "dotnet" | "win32" | "win64" => {
                return vec!["pe", "dll"];
            }
            "elf" | "ko" => return vec!["elf", "so"],
            "macho" | "dylib" | "kext" => return vec!["macho", "dylib"],
            _ => {}
        }
    }
    if lower.contains("portable executable")
        || lower.contains(".net executable")
        || lower.contains("dotnet executable")
        || lower.contains("ps2exe")
    {
        return vec!["pe", "dll"];
    }
    // OS name tokens (weaker — only after format tokens and the script/doc passes
    // that run earlier in `infer_filetypes`): map the OS to its native binary.
    for token in &tokens {
        match *token {
            "windows" => return vec!["pe", "dll"],
            "linux" => return vec!["elf", "so"],
            "osx" | "macos" | "macosx" => return vec!["macho", "dylib"],
            _ => {}
        }
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
                "linux" => push_unique_types(&mut types, &["elf"]),
                "windows" | "win32" | "win64" | "win" => push_unique_types(&mut types, &["pe"]),
                "macos" | "osx" | "darwin" | "mac" => push_unique_types(&mut types, &["macho"]),
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
    if let Some(name_tier) = classify_rule_filetypes(&infer_filetypes(rule_name, os_meta))
        && matches!(name_tier, YaraTier::Pe | YaraTier::Elf | YaraTier::MachO)
    {
        return Some(name_tier);
    }

    if let Some(namespace_tier) =
        classify_rule_filetypes(&infer_filetypes_from_namespace(namespace, None))
        && matches!(
            namespace_tier,
            YaraTier::Pe | YaraTier::Elf | YaraTier::MachO
        )
    {
        return Some(namespace_tier);
    }

    None
}

/// Collapse a binary-format alias to the primary file type it is detected as.
///
/// cleave detects a DLL/EXE as `analyzers::FileType::Pe`, a `.so`/`.ko` as
/// `Elf`, and a `.dylib`/`.kext` as `MachO`, and `yara_filetypes()` already lists
/// every alias for that type — so a scan loads `pe.yrc` and `dll.yrc` together.
/// Bucketing a rule under both is pure duplication; collapse to the primary so
/// each rule lives in exactly one of `pe`/`elf`/`macho`. Script-ish aliases that
/// are their own file type (`bat`, `ps1`, `java`) are intentionally left alone.
#[must_use]
pub fn canonical_binary_filetype(filetype: &str) -> &str {
    match filetype {
        "exe" | "dll" | "win32" | "win64" => "pe",
        "so" | "ko" => "elf",
        "dylib" | "kext" | "mach" => "macho",
        other => multiword_binary_filetype(other).unwrap_or(other),
    }
}

/// Resolve a `filetype` value that names a binary format in more than one word.
///
/// Upstream rule packs copy VirusTotal's free-text vocabulary straight into
/// `filetype = "Win32 EXE"` / `"Mach-O"`. Those never matched the single-token
/// aliases above, so each became a bucket of its own — and a scan asks for
/// `pe`, never `win32 exe`, so the rule compiled into a tier nothing ever
/// selects and silently never ran.
///
/// Only unambiguous values resolve: a string whose words point at two different
/// formats is left alone rather than guessed at.
fn multiword_binary_filetype(filetype: &str) -> Option<&'static str> {
    let mut resolved: Option<&'static str> = None;
    for word in filetype.split(|c: char| !c.is_ascii_alphanumeric()) {
        let canon = match word {
            "pe" | "exe" | "dll" | "win32" | "win64" => "pe",
            "elf" => "elf",
            "macho" | "mach" | "dylib" | "kext" => "macho",
            _ => continue,
        };
        match resolved {
            None => resolved = Some(canon),
            Some(prev) if prev == canon => {}
            Some(_) => return None,
        }
    }
    resolved
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

    if looks_like_python_name(rule_name) {
        return vec!["py", "pyc"];
    }

    let binary_types = infer_binary_filetypes_from_name_and_os(rule_name, os_meta);
    if !binary_types.is_empty() {
        return binary_types;
    }

    vec![]
}

/// A `py` signal in a rule name almost always means Python — either source
/// (`py`) or compiled bytecode (`pyc`). Matches explicit substrings, a delimited
/// `py` token, and a camelCase `Py`/`PY` segment (so `AresPYDoor` matches) while
/// avoiding false positives like `SPYWARE`, `copy`, or `happy` (no camelCase `P`
/// boundary, and `py` is never a standalone token there).
#[must_use]
fn looks_like_python_name(rule_name: &str) -> bool {
    let lower = rule_name.to_ascii_lowercase();
    if lower.contains("python")
        || lower.contains("ironpython")
        || lower.contains("pyinstaller")
        || lower.contains("py2exe")
        || lower.contains("pyarmor")
        || lower.contains("pyc")
    {
        return true;
    }
    // Delimited `py` token, e.g. `mal_py_loader`.
    if rule_name
        .split(|c: char| !c.is_ascii_alphanumeric())
        .any(|t| t.eq_ignore_ascii_case("py"))
    {
        return true;
    }
    // camelCase `Py`/`PY` segment: an uppercase `P` followed by `y`/`Y` that
    // starts a new word (preceded by start, a non-letter, or a lowercase letter).
    let b = rule_name.as_bytes();
    for i in 0..b.len() {
        if b[i] == b'P' && i + 1 < b.len() && (b[i + 1] == b'y' || b[i + 1] == b'Y') {
            let starts_word =
                i == 0 || !b[i - 1].is_ascii_alphabetic() || b[i - 1].is_ascii_lowercase();
            if starts_word {
                return true;
            }
        }
    }
    false
}

/// High-confidence filetype markers found in a rule's string literals / body.
///
/// Only near-definitive markers belong here — a single weak string (e.g. just
/// `kernel32.dll`, which countless cross-format rules mention) would mis-bucket.
/// Used as a fallback signal when a rule has no magic check, module reference,
/// or naming/metadata hint.
#[must_use]
pub fn infer_filetypes_from_string_markers(body: &str) -> Vec<&'static str> {
    let lower = body.to_ascii_lowercase();
    // .NET runtime markers — a .NET assembly is a PE.
    if lower.contains("_corexemain")
        || lower.contains("mscoree.dll")
        || lower.contains("mscorlib")
        || lower.contains("#~\x00")
    // .NET metadata stream
    {
        return vec!["pe", "dll"];
    }
    vec![]
}

/// Look up the curated `RULE_FILETYPE_OVERRIDES` table for `rule_name`.
#[must_use]
pub fn filetypes_from_override(rule_name: &str) -> Vec<&'static str> {
    let lower = rule_name.to_ascii_lowercase();
    for (needle, types) in RULE_FILETYPE_OVERRIDES {
        if lower.contains(needle) {
            return types.to_vec();
        }
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
    // Byte-oriented scan: `pos += 1` may land mid-codepoint (rule comments can
    // carry em-dashes and other multi-byte characters), so slicing `&src[pos..]`
    // would panic on a non-boundary. Every returned position is the start of an
    // ASCII `rule ` keyword, hence always a char boundary.
    let bytes = src.as_bytes();
    let mut pos = from;
    while pos < bytes.len() {
        if bytes[pos..].starts_with(b"//") {
            if let Some(nl) = bytes[pos..].iter().position(|&b| b == b'\n') {
                pos += nl + 1;
                continue;
            }
            return None;
        }
        if bytes[pos..].starts_with(b"rule ")
            && (pos == 0 || matches!(bytes[pos - 1], b'\n' | b'\r' | b' ' | b'\t'))
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
mod tests;
