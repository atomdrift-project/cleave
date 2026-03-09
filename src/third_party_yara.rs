//! Third-party YARA rule trait ID derivation.
//!
//! Pure functions for deriving trait IDs from YARA match data at match time.
//! Zero pre-parsing, zero I/O, zero registry/HashMap lookups.
//!
//! The namespace format used for third-party rules is `"3p.{vendor}[.{subdir}...]"`.

use crate::composite_rules::{Arch, Platform};

/// Derive the trait ID for a third-party YARA match.
///
/// The namespace format is `"3p.{vendor}[.{subdir}...]"`.
/// Returns a path like `"third_party/{vendor}/[{platform}/][{type}/]{family}"`.
pub(crate) fn derive_trait_id(namespace: &str, rule_name: &str, _os_meta: Option<&str>) -> String {
    // Parse "3p.vendor[.subdir...]" -> vendor, subdirs
    let without_prefix = namespace.strip_prefix("3p.").unwrap_or(namespace);
    let (vendor, rest) = match without_prefix.find('.') {
        Some(idx) => (&without_prefix[..idx], &without_prefix[idx + 1..]),
        None => (without_prefix, ""),
    };
    let subdirs: Vec<&str> = if rest.is_empty() {
        vec![]
    } else {
        rest.split('.').collect()
    };

    if vendor == "YARAForge" {
        derive_yaraforge_id(rule_name)
    } else {
        derive_vendor_id(vendor, &subdirs, rule_name)
    }
}

/// Infer platform(s) from rule name prefix and optional `os` metadata field.
///
/// Priority: `os` metadata first, then rule name prefix (e.g. `Win32_`, `Linux_`).
/// Returns empty vec if unknown — rule applies to all platforms.
pub(crate) fn platforms_from_name_and_os(rule_name: &str, os_meta: Option<&str>) -> Vec<Platform> {
    if let Some(os) = os_meta {
        let mut platforms = Vec::new();
        for token in os.to_lowercase().split(',').map(str::trim) {
            match token {
                "linux" => {
                    if !platforms.contains(&Platform::Linux) {
                        platforms.push(Platform::Linux);
                    }
                }
                "windows" | "win32" | "win64" | "win" => {
                    if !platforms.contains(&Platform::Windows) {
                        platforms.push(Platform::Windows);
                    }
                }
                "macos" | "osx" | "darwin" | "mac" => {
                    if !platforms.contains(&Platform::MacOS) {
                        platforms.push(Platform::MacOS);
                    }
                }
                "android" => {
                    if !platforms.contains(&Platform::Android) {
                        platforms.push(Platform::Android);
                    }
                }
                "ios" => {
                    if !platforms.contains(&Platform::Ios) {
                        platforms.push(Platform::Ios);
                    }
                }
                "all" => return vec![], // "all" means no constraint
                _ => {}
            }
        }
        if !platforms.is_empty() {
            return platforms;
        }
    }
    // Scan all underscore-delimited tokens, not just the first.
    // Handles rules like "JPCERT_Win32_Emotet", "win_mal_TextShell", or "linux_trojan_foo".
    for part in rule_name.split('_') {
        match part {
            "Win" | "win" | "Win32" | "Win64" | "Windows" => return vec![Platform::Windows],
            "Linux" | "linux" => return vec![Platform::Linux],
            "MacOS" | "Macos" | "MACOS" | "macos" | "OSX" | "osx" => {
                return vec![Platform::MacOS]
            }
            "Android" | "android" => return vec![Platform::Android],
            "iOS" | "ios" => return vec![Platform::Ios],
            _ => {}
        }
    }
    vec![]
}

/// Map platforms to the filetype strings expected by the YARA file-type filter.
///
/// Returns lowercase type strings compatible with `scan_bytes_filtered`'s filter:
/// Windows → ["pe", "dll"], Linux → ["elf", "so"], macOS → ["macho", "dylib"].
/// Returns empty slice for platforms with no binary constraint (All, Android, iOS).
pub(crate) fn filetypes_from_platforms(platforms: &[Platform]) -> Vec<&'static str> {
    let mut types: Vec<&'static str> = Vec::new();
    for platform in platforms {
        match platform {
            Platform::Windows => {
                if !types.contains(&"pe") {
                    types.push("pe");
                    types.push("dll");
                }
            }
            Platform::Linux | Platform::Unix => {
                if !types.contains(&"elf") {
                    types.push("elf");
                    types.push("so");
                }
            }
            Platform::MacOS => {
                if !types.contains(&"macho") {
                    types.push("macho");
                    types.push("dylib");
                }
            }
            Platform::All | Platform::Android | Platform::Ios => {}
        }
    }
    types
}

/// Infer filetype constraint strings for a third-party YARA rule.
///
/// Combines all heuristics in priority order:
/// 1. `os` metadata field → binary platform filetypes
/// 2. Rule name platform prefix (`Win32_`, `Linux_`, `MacOS_`) → binary filetypes
/// 3. Rule name document-format prefix (`PDF_`, `RTF_`, `Office_`, etc.) → doc filetypes
///
/// Returns empty vec if no constraint can be inferred — the rule applies to all files.
/// Returned strings are lowercase and match the values used by `scan_bytes_filtered`.
pub(crate) fn infer_filetypes(rule_name: &str, os_meta: Option<&str>) -> Vec<&'static str> {
    let platforms = platforms_from_name_and_os(rule_name, os_meta);
    if !platforms.is_empty() {
        let types = filetypes_from_platforms(&platforms);
        if !types.is_empty() {
            return types;
        }
    }
    doc_filetypes_from_rule_name(rule_name)
}

/// Infer filetypes from the filename component of a third-party YARA namespace.
///
/// Third-party namespaces have the form `"3p.{vendor}[.{subdirs}].{filename_stem}"`.
/// The filename stem (e.g. `"win_mal_TextShell"`) often carries platform/type signals
/// that aren't in the rule identifier itself (e.g. `"TextShell"`).
///
/// Returns empty vec if no constraint can be inferred.
pub(crate) fn infer_filetypes_from_namespace(namespace: &str, os_meta: Option<&str>) -> Vec<&'static str> {
    // Extract the last dot-separated component (the filename stem)
    let filename_stem = match namespace.rsplit('.').next() {
        Some(s) if !s.is_empty() && s != "3p" => s,
        _ => return vec![],
    };
    infer_filetypes(filename_stem, os_meta)
}

/// Inject `filetype` metadata into YARA rule source when file magic conditions are detected.
///
/// Handles the common pattern where rules check `uint16(0) == 0x5A4D` (PE/MZ magic),
/// `uint32(0) == 0x464c457f` (ELF magic), or MachO magic values in their condition
/// but carry no explicit `filetype` metadata key. Injects a `filetype = "pe"` (or
/// equivalent) line into each qualifying rule's `meta:` section.
///
/// This runs at rule-load time so the hint is baked into the compiled rules cache.
pub(crate) fn inject_condition_filetype_hints(source: &str) -> String {
    // Quick reject: skip files with no recognizable magic pattern
    if !source_has_magic_condition(source) {
        return source.to_string();
    }

    let mut result = String::with_capacity(source.len() + 128);
    let mut pos = 0;
    let bytes = source.as_bytes();

    while pos < source.len() {
        // Find the next `rule ` keyword (at word boundary — not inside a string/comment)
        match find_rule_start(source, pos) {
            None => {
                result.push_str(&source[pos..]);
                break;
            }
            Some(rule_kw) => {
                // Emit everything before this rule unchanged
                result.push_str(&source[pos..rule_kw]);

                // Find the opening brace of the rule body
                let brace_start = match source[rule_kw..].find('{') {
                    Some(off) => rule_kw + off,
                    None => {
                        result.push_str(&source[rule_kw..]);
                        break;
                    }
                };

                // Find the matching closing brace (brace-depth tracking)
                let body_start = brace_start + 1;
                let body_end = match find_matching_brace(bytes, brace_start) {
                    Some(e) => e,
                    None => {
                        result.push_str(&source[rule_kw..]);
                        break;
                    }
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

/// Returns `true` if the source contains any of the magic byte condition patterns
/// that indicate a specific file type.
fn source_has_magic_condition(source: &str) -> bool {
    // Use a lowercase copy for case-insensitive matching
    let lower = source.to_lowercase();
    lower.contains("uint16(0) == 0x5a4d")
        || lower.contains("uint32(0) == 0x464c457f")
        || lower.contains("uint32be(0) == 0x7f454c46")
        || lower.contains("uint32(0) == 0xfeedface")
        || lower.contains("uint32(0) == 0xcefaedfe")
        || lower.contains("uint32(0) == 0xfeedfacf")
        || lower.contains("uint32(0) == 0xcffaedfe")
}

/// Infer the filetype from magic patterns found in a rule's body text.
fn filetype_from_magic(body: &str) -> Option<&'static str> {
    let lower = body.to_lowercase();
    if lower.contains("uint16(0) == 0x5a4d") {
        return Some("pe");
    }
    if lower.contains("uint32(0) == 0x464c457f") || lower.contains("uint32be(0) == 0x7f454c46") {
        return Some("elf");
    }
    if lower.contains("uint32(0) == 0xfeedface")
        || lower.contains("uint32(0) == 0xcefaedfe")
        || lower.contains("uint32(0) == 0xfeedfacf")
        || lower.contains("uint32(0) == 0xcffaedfe")
    {
        return Some("macho");
    }
    None
}

/// Inject a `filetype` metadata line into a rule body if the condition implies one
/// and the body doesn't already declare a `filetype` key.
fn maybe_inject_filetype(body: &str) -> String {
    // Already has a filetype declaration → leave it alone
    if body.contains("filetype") {
        return body.to_string();
    }
    let Some(ft) = filetype_from_magic(body) else {
        return body.to_string();
    };

    // Inject after "meta:" if present, otherwise before "strings:" or "condition:"
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

/// Find the position of the next `rule ` keyword in `src` starting from `from`.
/// Skips occurrences inside line comments (`//`).
fn find_rule_start(src: &str, from: usize) -> Option<usize> {
    let mut pos = from;
    while pos < src.len() {
        // Skip line comments
        if src[pos..].starts_with("//") {
            if let Some(nl) = src[pos..].find('\n') {
                pos += nl + 1;
                continue;
            } else {
                return None;
            }
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

/// Find the position of the `}` that closes the brace opened at `open_pos` in `bytes`.
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

/// Parse `arch_context` metadata from Elastic-style third-party YARA rules.
///
/// Semantics follow Elastic's convention:
/// - `"x86"` → x86 family: both 32-bit x86 **and** x86-64 (rules target the ISA family)
/// - `"x64"` → x86-64 only
/// - `"arm64"` → AArch64 only
/// - Comma-separated values are unioned
///
/// Returns empty vec when the string is empty or no known arch token is found,
/// meaning the rule applies to all architectures.
#[allow(dead_code)] // Used by lib.rs pipeline (process_yara_result)
pub(crate) fn archs_from_arch_context(arch_context: &str) -> Vec<Arch> {
    let mut archs: Vec<Arch> = Vec::new();
    for token in arch_context.split(',').map(str::trim) {
        match token.to_lowercase().as_str() {
            "x86" => {
                // x86 in Elastic metadata means the x86 ISA family (32-bit and 64-bit)
                if !archs.contains(&Arch::X86) {
                    archs.push(Arch::X86);
                }
                if !archs.contains(&Arch::X86_64) {
                    archs.push(Arch::X86_64);
                }
            }
            "x64" | "amd64" | "x86_64" | "x86-64" => {
                if !archs.contains(&Arch::X86_64) {
                    archs.push(Arch::X86_64);
                }
            }
            "arm64" | "aarch64" => {
                if !archs.contains(&Arch::Aarch64) {
                    archs.push(Arch::Aarch64);
                }
            }
            "arm" | "arm32" => {
                if !archs.contains(&Arch::Arm) {
                    archs.push(Arch::Arm);
                }
            }
            _ => {} // Unknown token: treat as unconstrained
        }
    }
    archs
}

/// Infer filetype constraints from document-format rule name prefixes.
///
/// Handles the 23 document-format rules in the collection (PDF, RTF, Office, LNK, etc.).
/// These rules have no platform prefix and no `filetype` metadata, but their names
/// clearly identify what file formats they target.
fn doc_filetypes_from_rule_name(rule_name: &str) -> Vec<&'static str> {
    match rule_name.split('_').next().unwrap_or("") {
        "PDF" | "Pdf" => vec!["pdf"],
        "RTF" | "Rtf" => vec!["rtf", "doc"],
        "Office" | "Word" | "Excel" | "OLEfile" | "OLE" | "Ole" | "Macro" | "Maldoc" => {
            vec!["doc", "docx", "xls", "xlsx", "ole"]
        }
        "OneNote" => vec!["one", "onepkg"],
        "LNK" | "Lnk" | "LNKR" => vec!["lnk"],
        "ISO" => vec!["iso", "img"],
        _ => vec![],
    }
}

fn derive_yaraforge_id(rule_name: &str) -> String {
    let parts: Vec<&str> = rule_name.split('_').collect();

    // Collect leading all-caps parts (vendor prefix candidates)
    let caps_count = parts
        .iter()
        .take_while(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_uppercase()))
        .count();

    // Try longest all-caps prefix first, then progressively shorter ones
    // If caps_count is 0, the iterator is empty and we fall through to capitalize_first
    let (normalized_vendor, vendor_len) = (1..=caps_count)
        .rev()
        .find_map(|len| {
            let key = parts[..len].join("_");
            let known = normalize_yaraforge_vendor(&key);
            if known != "unknown" {
                Some((known.to_string(), len))
            } else {
                None
            }
        })
        .unwrap_or_else(|| {
            let fallback = capitalize_first(parts[0]);
            (fallback, 1)
        });

    let remaining = &parts[vendor_len..];
    let filtered = filter_yaraforge_noise(remaining);

    if filtered.is_empty() {
        format!("third_party/{}", normalized_vendor)
    } else {
        format!("third_party/{}/{}", normalized_vendor, filtered.join("/"))
    }
}

fn filter_yaraforge_noise<'a>(parts: &[&'a str]) -> Vec<&'a str> {
    // Strip leading generic prefixes (MAL, malware)
    let start = parts
        .iter()
        .position(|p| {
            let lower = p.to_lowercase();
            lower != "mal" && lower != "malware"
        })
        .unwrap_or(parts.len());
    let parts = &parts[start..];

    // Strip trailing noise (numeric-only parts, month abbreviations)
    let mut end = parts.len();
    while end > 0 && is_yaraforge_noise(parts[end - 1]) {
        end -= 1;
    }

    parts[..end].to_vec()
}

fn is_yaraforge_noise(part: &str) -> bool {
    // Numeric only
    if part.chars().all(|c| c.is_ascii_digit()) {
        return true;
    }
    // Month abbreviations
    matches!(
        part,
        "Jan"
            | "Feb"
            | "Mar"
            | "Apr"
            | "May"
            | "Jun"
            | "Jul"
            | "Aug"
            | "Sep"
            | "Oct"
            | "Nov"
            | "Dec"
    )
}

fn derive_vendor_id(vendor: &str, subdirs: &[&str], rule_name: &str) -> String {
    let (name, has_hex_hash) = strip_hex_hash(rule_name);
    let parts: Vec<&str> = name.split('_').collect();

    // Strip leading generic words
    let mut start = 0;
    while start < parts.len() {
        let lower = parts[start].to_lowercase();
        if lower == "malware" || lower == "mal" {
            start += 1;
        } else {
            break;
        }
    }
    let parts = &parts[start..];

    let mut result = format!("third_party/{}", vendor);
    for subdir in subdirs {
        result.push('/');
        result.push_str(subdir);
    }

    if has_hex_hash {
        // Elastic-style: {Platform}_{Type}_{Family}_{HexHash}
        let mut idx = 0;

        if idx < parts.len() && is_platform(parts[idx]) {
            result.push('/');
            result.push_str(&parts[idx].to_lowercase());
            idx += 1;
        }

        if idx < parts.len() && is_malware_type(parts[idx]) {
            result.push('/');
            result.push_str(&parts[idx].to_lowercase());
            idx += 1;
        }

        let family = parts[idx..].join("_").to_lowercase();
        if !family.is_empty() {
            result.push('/');
            result.push_str(&family);
        }
    } else {
        // Generic style: strip CVE patterns, numerics, trailing descriptors
        let filtered = filter_vendor_noise(parts);
        let family = filtered.join("_").to_lowercase();
        if !family.is_empty() {
            result.push('/');
            result.push_str(&family);
        }
    }

    result
}

fn filter_vendor_noise<'a>(parts: &[&'a str]) -> Vec<&'a str> {
    let mut result = Vec::new();
    let mut i = 0;
    while i < parts.len() {
        let part = parts[i];
        let lower = part.to_lowercase();

        // Skip CVE keyword and following numeric parts
        if lower == "cve" {
            i += 1;
            while i < parts.len() && parts[i].chars().all(|c| c.is_ascii_digit() || c == '-') {
                i += 1;
            }
            continue;
        }

        // Skip purely numeric parts (version numbers)
        if part.chars().all(|c| c.is_ascii_digit()) {
            i += 1;
            continue;
        }

        result.push(part);
        i += 1;
    }

    // Strip trailing short descriptor suffixes (YARA string type markers)
    while let Some(&last) = result.last() {
        if is_trailing_descriptor(last) {
            result.pop();
        } else {
            break;
        }
    }

    result
}

fn is_trailing_descriptor(part: &str) -> bool {
    let lower = part.to_lowercase();
    matches!(
        lower.as_str(),
        "str" | "hex" | "pe" | "re" | "reg" | "wide" | "bin" | "raw"
    ) && part.len() <= 4
        && part.chars().all(|c| c.is_ascii_alphabetic())
}

/// Strip trailing hex hash suffix (`_[0-9a-fA-F]{8,}`).
/// Returns the stripped name and whether a hash was found.
fn strip_hex_hash(name: &str) -> (&str, bool) {
    if let Some(underscore_pos) = name.rfind('_') {
        let suffix = &name[underscore_pos + 1..];
        if suffix.len() >= 8 && suffix.chars().all(|c| c.is_ascii_hexdigit()) {
            return (&name[..underscore_pos], true);
        }
    }
    (name, false)
}

fn is_platform(s: &str) -> bool {
    matches!(
        s,
        "Win32"
            | "Win64"
            | "Windows"
            | "Linux"
            | "MacOS"
            | "Macos"
            | "OSX"
            | "Android"
            | "Multi"
            | "iOS"
    )
}

fn is_malware_type(s: &str) -> bool {
    matches!(
        s,
        "Trojan"
            | "Backdoor"
            | "Ransomware"
            | "Infostealer"
            | "Cryptominer"
            | "Downloader"
            | "Dropper"
            | "Rootkit"
            | "Worm"
            | "Loader"
            | "Stealer"
            | "Keylogger"
            | "Exploit"
            | "PUA"
            | "Adware"
            | "Miner"
            | "Spyware"
            | "Virus"
            | "Bot"
            | "RAT"
            | "Banker"
    )
}

fn capitalize_first(s: &str) -> String {
    let mut chars = s.chars();
    match chars.next() {
        None => String::new(),
        Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
    }
}

/// Map YARAForge all-caps vendor prefix to proper name.
/// Returns `"unknown"` for unrecognized prefixes (used as sentinel).
fn normalize_yaraforge_vendor(key: &str) -> &'static str {
    match key {
        "REVERSINGLABS" => "ReversingLabs",
        "SIGNATURE_BASE" | "SIGNATURE" => "SigBase",
        "GCTI" => "GCTI",
        "FIREEYE" => "FireEye",
        "MICROSOFT" => "Microsoft",
        "ESET" => "ESET",
        "JPCERTCC" => "JPCERT",
        "HARFANGLAB" => "HarfangLab",
        "MALPEDIA" => "Malpedia",
        "SEKOIA" => "Sekoia",
        "TRELLIX" => "Trellix",
        "VOLEXITY" => "Volexity",
        "EMBEERESEARCH" => "EmbeeResearch",
        "WITHSECURELABS" => "WithSecureLabs",
        "BINARYALERT" => "BinaryAlert",
        "DITEKSHEN" => "Ditekshen",
        "LOLDRIVERS" => "LolDrivers",
        "DELIVRTO" => "DelivrTo",
        "SECUINFRA" => "SecuInfra",
        "ARKBIRD" => "ArkBird",
        "CAPE" => "CAPE",
        "ELCEEF" => "Elceef",
        "NCSC" => "NCSC",
        _ => "unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_yaraforge_reversinglabs_emotet() {
        let id = derive_trait_id("3p.YARAForge", "REVERSINGLABS_Win32_Trojan_Emotet", None);
        assert_eq!(id, "third_party/ReversingLabs/Win32/Trojan/Emotet");
    }

    #[test]
    fn test_yaraforge_signature_base() {
        let id = derive_trait_id(
            "3p.YARAForge",
            "SIGNATURE_BASE_MAL_Netfilter_Dropper_Jun_2021_1_1",
            None,
        );
        assert_eq!(id, "third_party/SigBase/Netfilter/Dropper");
    }

    #[test]
    fn test_elastic_linux_backdoor() {
        let id = derive_trait_id("3p.elastic", "Linux_Backdoor_Bash_e427876d", None);
        assert_eq!(id, "third_party/elastic/linux/backdoor/bash");
    }

    #[test]
    fn test_elastic_macos_infostealer() {
        let id = derive_trait_id(
            "3p.elastic",
            "MacOS_Infostealer_MdQuerySecret_12345678",
            None,
        );
        assert_eq!(id, "third_party/elastic/macos/infostealer/mdquerysecret");
    }

    #[test]
    fn test_jpcert_stealer() {
        let id = derive_trait_id("3p.JPCERT", "malware_DarkCloud_Stealer_str", None);
        assert_eq!(id, "third_party/JPCERT/darkcloud_stealer");
    }

    #[test]
    fn test_bartblaze_apt_subdir() {
        let id = derive_trait_id("3p.bartblaze.APT", "Ganelp", None);
        assert_eq!(id, "third_party/bartblaze/APT/ganelp");
    }

    #[test]
    fn test_huntress_screenconnect() {
        let id = derive_trait_id(
            "3p.huntress",
            "ScreenConnect_CVE_2024_1709_Exploitation",
            None,
        );
        assert_eq!(id, "third_party/huntress/screenconnect_exploitation");
    }

    #[test]
    fn test_huntress_malichus() {
        let id = derive_trait_id("3p.huntress", "Malichus_SFile", None);
        assert_eq!(id, "third_party/huntress/malichus_sfile");
    }

    // ------------------------------------------------------------------
    // Platform inference from rule name
    // ------------------------------------------------------------------

    #[test]
    fn test_platforms_from_win32() {
        assert_eq!(
            platforms_from_name_and_os("Win32_Trojan_Foo", None),
            vec![Platform::Windows]
        );
    }

    #[test]
    fn test_platforms_from_win64() {
        assert_eq!(
            platforms_from_name_and_os("Win64_Backdoor_Bar", None),
            vec![Platform::Windows]
        );
    }

    #[test]
    fn test_platforms_from_linux_prefix() {
        assert_eq!(
            platforms_from_name_and_os("Linux_Backdoor_Bash_e427876d", None),
            vec![Platform::Linux]
        );
    }

    #[test]
    fn test_platforms_from_macos_prefix() {
        assert_eq!(
            platforms_from_name_and_os("MacOS_Infostealer_Foo_12345678", None),
            vec![Platform::MacOS]
        );
    }

    #[test]
    fn test_platforms_from_macos_lowercase_variant() {
        // "Macos" (one capital) appears in some rule names
        assert_eq!(
            platforms_from_name_and_os("Macos_Backdoor_Baz", None),
            vec![Platform::MacOS]
        );
    }

    #[test]
    fn test_platforms_from_osx_prefix() {
        assert_eq!(
            platforms_from_name_and_os("OSX_Stealer_Bar", None),
            vec![Platform::MacOS]
        );
    }

    #[test]
    fn test_platforms_from_android_prefix() {
        assert_eq!(
            platforms_from_name_and_os("Android_Spyware_X", None),
            vec![Platform::Android]
        );
    }

    #[test]
    fn test_platforms_from_ios_prefix() {
        assert_eq!(
            platforms_from_name_and_os("iOS_Spyware_X", None),
            vec![Platform::Ios]
        );
    }

    #[test]
    fn test_platforms_from_no_prefix_returns_empty() {
        // JPCERT/huntress style — no platform prefix
        assert!(platforms_from_name_and_os("DarkCloud_Stealer", None).is_empty());
        assert!(
            platforms_from_name_and_os("ScreenConnect_CVE_2024_1709_Exploitation", None).is_empty()
        );
        assert!(platforms_from_name_and_os("Ganelp", None).is_empty());
    }

    // ------------------------------------------------------------------
    // Platform inference from os metadata
    // ------------------------------------------------------------------

    #[test]
    fn test_platforms_from_os_meta() {
        assert_eq!(
            platforms_from_name_and_os("SomeRule", Some("linux")),
            vec![Platform::Linux]
        );
    }

    #[test]
    fn test_platforms_from_os_meta_windows_variants() {
        assert_eq!(
            platforms_from_name_and_os("Rule", Some("windows")),
            vec![Platform::Windows]
        );
        assert_eq!(
            platforms_from_name_and_os("Rule", Some("win32")),
            vec![Platform::Windows]
        );
        assert_eq!(
            platforms_from_name_and_os("Rule", Some("win64")),
            vec![Platform::Windows]
        );
        assert_eq!(
            platforms_from_name_and_os("Rule", Some("win")),
            vec![Platform::Windows]
        );
    }

    #[test]
    fn test_platforms_from_os_meta_macos_variants() {
        assert_eq!(
            platforms_from_name_and_os("Rule", Some("macos")),
            vec![Platform::MacOS]
        );
        assert_eq!(
            platforms_from_name_and_os("Rule", Some("osx")),
            vec![Platform::MacOS]
        );
        assert_eq!(
            platforms_from_name_and_os("Rule", Some("darwin")),
            vec![Platform::MacOS]
        );
        assert_eq!(
            platforms_from_name_and_os("Rule", Some("mac")),
            vec![Platform::MacOS]
        );
    }

    #[test]
    fn test_platforms_from_os_meta_case_insensitive() {
        assert_eq!(
            platforms_from_name_and_os("Rule", Some("LINUX")),
            vec![Platform::Linux]
        );
        assert_eq!(
            platforms_from_name_and_os("Rule", Some("Linux")),
            vec![Platform::Linux]
        );
        assert_eq!(
            platforms_from_name_and_os("Rule", Some("WINDOWS")),
            vec![Platform::Windows]
        );
    }

    #[test]
    fn test_platforms_from_os_meta_unknown_falls_through_to_name() {
        // Unknown os value → falls through to check rule name
        assert_eq!(
            platforms_from_name_and_os("Win32_Trojan_Foo", Some("freebsd")),
            vec![Platform::Windows],
            "Unknown os value should fall through to rule name inference"
        );
    }

    #[test]
    fn test_platforms_from_os_meta_unknown_no_name_prefix() {
        assert!(platforms_from_name_and_os("SomeRule", Some("freebsd")).is_empty());
    }

    #[test]
    fn test_platforms_os_meta_takes_priority() {
        // os = "linux" overrides Win32_ prefix
        assert_eq!(
            platforms_from_name_and_os("Win32_Something", Some("linux")),
            vec![Platform::Linux]
        );
    }

    #[test]
    fn test_platforms_unknown_returns_empty() {
        assert!(platforms_from_name_and_os("Generic_Rule", None).is_empty());
    }

    #[test]
    fn test_platforms_from_mid_name_win32() {
        // Platform token not in first position (e.g., vendor prefix before platform)
        assert_eq!(
            platforms_from_name_and_os("JPCERT_Win32_Emotet", None),
            vec![Platform::Windows]
        );
    }

    #[test]
    fn test_platforms_from_mid_name_linux() {
        assert_eq!(
            platforms_from_name_and_os("Elastic_Linux_Trojan_Chinaz", None),
            vec![Platform::Linux]
        );
    }

    #[test]
    fn test_platforms_from_mid_name_macos() {
        assert_eq!(
            platforms_from_name_and_os("Huntress_MACOS_LIGHTSPY_LOADER", None),
            vec![Platform::MacOS]
        );
    }

    #[test]
    fn test_platforms_from_os_comma_separated() {
        // os = "win,linux" should yield both platforms
        let result = platforms_from_name_and_os("SomeRule", Some("win,linux"));
        assert_eq!(result, vec![Platform::Windows, Platform::Linux]);
    }

    #[test]
    fn test_platforms_from_os_comma_separated_with_spaces() {
        let result = platforms_from_name_and_os("SomeRule", Some("win, linux"));
        assert_eq!(result, vec![Platform::Windows, Platform::Linux]);
    }

    #[test]
    fn test_platforms_from_os_all_returns_empty() {
        // os = "all" means no platform constraint
        assert!(platforms_from_name_and_os("SomeRule", Some("all")).is_empty());
    }

    #[test]
    fn test_platforms_from_os_darwin() {
        assert_eq!(
            platforms_from_name_and_os("SomeRule", Some("darwin")),
            vec![Platform::MacOS]
        );
    }

    #[test]
    fn test_platforms_from_os_no_duplicates() {
        // "win,win32" should not produce duplicate Windows entries
        let result = platforms_from_name_and_os("SomeRule", Some("win,win32"));
        assert_eq!(result, vec![Platform::Windows]);
    }

    // ------------------------------------------------------------------
    // Filetype mapping from platforms
    // ------------------------------------------------------------------

    #[test]
    fn test_filetypes_from_windows() {
        assert_eq!(
            filetypes_from_platforms(&[Platform::Windows]),
            vec!["pe", "dll"]
        );
    }

    #[test]
    fn test_filetypes_from_linux() {
        assert_eq!(
            filetypes_from_platforms(&[Platform::Linux]),
            vec!["elf", "so"]
        );
    }

    #[test]
    fn test_filetypes_from_unix() {
        // Unix is treated the same as Linux for binary format purposes
        assert_eq!(
            filetypes_from_platforms(&[Platform::Unix]),
            vec!["elf", "so"]
        );
    }

    #[test]
    fn test_filetypes_from_macos() {
        assert_eq!(
            filetypes_from_platforms(&[Platform::MacOS]),
            vec!["macho", "dylib"]
        );
    }

    #[test]
    fn test_filetypes_from_android_empty() {
        // Android doesn't map to a specific binary format we filter on
        assert!(filetypes_from_platforms(&[Platform::Android]).is_empty());
    }

    #[test]
    fn test_filetypes_from_ios_empty() {
        assert!(filetypes_from_platforms(&[Platform::Ios]).is_empty());
    }

    #[test]
    fn test_filetypes_from_all_empty() {
        assert!(filetypes_from_platforms(&[Platform::All]).is_empty());
    }

    #[test]
    fn test_filetypes_from_empty() {
        assert!(filetypes_from_platforms(&[]).is_empty());
    }

    #[test]
    fn test_filetypes_multiple_platforms_no_duplicates() {
        // Linux + Unix both map to ELF — result should have no duplicates
        let types = filetypes_from_platforms(&[Platform::Linux, Platform::Unix]);
        assert_eq!(
            types,
            vec!["elf", "so"],
            "Linux+Unix should deduplicate to a single ELF set"
        );
    }

    #[test]
    fn test_filetypes_windows_and_linux_combined() {
        let types = filetypes_from_platforms(&[Platform::Windows, Platform::Linux]);
        assert!(types.contains(&"pe"));
        assert!(types.contains(&"dll"));
        assert!(types.contains(&"elf"));
        assert!(types.contains(&"so"));
        assert_eq!(types.len(), 4);
    }

    // ------------------------------------------------------------------
    // End-to-end: rule name → platform → filetype strings
    // ------------------------------------------------------------------

    #[test]
    fn test_win32_name_yields_pe_dll_filetypes() {
        let platforms = platforms_from_name_and_os("Win32_Trojan_Foo", None);
        let types = filetypes_from_platforms(&platforms);
        assert!(types.contains(&"pe"));
        assert!(types.contains(&"dll"));
        // Should NOT contain ELF types
        assert!(!types.contains(&"elf"));
        assert!(!types.contains(&"so"));
    }

    #[test]
    fn test_linux_name_yields_elf_so_filetypes() {
        let platforms = platforms_from_name_and_os("Linux_Backdoor_Bash_e427876d", None);
        let types = filetypes_from_platforms(&platforms);
        assert!(types.contains(&"elf"));
        assert!(types.contains(&"so"));
        assert!(!types.contains(&"pe"));
        assert!(!types.contains(&"macho"));
    }

    #[test]
    fn test_macos_name_yields_macho_dylib_filetypes() {
        let platforms =
            platforms_from_name_and_os("MacOS_Infostealer_MdQuerySecret_12345678", None);
        let types = filetypes_from_platforms(&platforms);
        assert!(types.contains(&"macho"));
        assert!(types.contains(&"dylib"));
        assert!(!types.contains(&"pe"));
        assert!(!types.contains(&"elf"));
    }

    #[test]
    fn test_generic_name_yields_no_filetypes() {
        let platforms = platforms_from_name_and_os("DarkCloud_Stealer", None);
        let types = filetypes_from_platforms(&platforms);
        assert!(
            types.is_empty(),
            "Generic rule name should produce no filetype constraint"
        );
    }

    #[test]
    fn test_normalize_reversinglabs() {
        assert_eq!(normalize_yaraforge_vendor("REVERSINGLABS"), "ReversingLabs");
        assert_eq!(normalize_yaraforge_vendor("SIGNATURE_BASE"), "SigBase");
        assert_eq!(normalize_yaraforge_vendor("SIGNATURE"), "SigBase");
        assert_eq!(normalize_yaraforge_vendor("JPCERTCC"), "JPCERT");
    }

    #[test]
    fn test_hex_hash_stripped() {
        let (stripped, found) = strip_hex_hash("Linux_Backdoor_Bash_e427876d");
        assert!(found);
        assert_eq!(stripped, "Linux_Backdoor_Bash");
    }

    #[test]
    fn test_hex_hash_not_stripped_when_absent() {
        let (stripped, found) = strip_hex_hash("Malichus_SFile");
        assert!(!found);
        assert_eq!(stripped, "Malichus_SFile");
    }

    // ------------------------------------------------------------------
    // Document-format filetype inference
    // ------------------------------------------------------------------

    #[test]
    fn test_doc_filetype_pdf_uppercase() {
        assert_eq!(
            doc_filetypes_from_rule_name("PDF_Launch_Action_EXE"),
            vec!["pdf"]
        );
    }

    #[test]
    fn test_doc_filetype_pdf_titlecase() {
        assert_eq!(doc_filetypes_from_rule_name("Pdf_Something"), vec!["pdf"]);
    }

    #[test]
    fn test_doc_filetype_rtf() {
        assert_eq!(
            doc_filetypes_from_rule_name("RTF_Anti_Analysis_Header"),
            vec!["rtf", "doc"]
        );
        assert_eq!(
            doc_filetypes_from_rule_name("RTF_Header_Obfuscation"),
            vec!["rtf", "doc"]
        );
        assert_eq!(
            doc_filetypes_from_rule_name("RTF_Embedded_OLE_Header_Obfuscated"),
            vec!["rtf", "doc"]
        );
    }

    #[test]
    fn test_doc_filetype_office_variants() {
        assert_eq!(
            doc_filetypes_from_rule_name("Office_Document_with_VBA_Project"),
            vec!["doc", "docx", "xls", "xlsx", "ole"]
        );
        assert_eq!(
            doc_filetypes_from_rule_name("Word_Document_with_Suspicious_Metadata"),
            vec!["doc", "docx", "xls", "xlsx", "ole"]
        );
        assert_eq!(
            doc_filetypes_from_rule_name("OLEfile_in_CAD_FAS_LSP"),
            vec!["doc", "docx", "xls", "xlsx", "ole"]
        );
        assert_eq!(
            doc_filetypes_from_rule_name("OLE_Embedded_Executable"),
            vec!["doc", "docx", "xls", "xlsx", "ole"]
        );
    }

    #[test]
    fn test_doc_filetype_onenote() {
        assert_eq!(
            doc_filetypes_from_rule_name("OneNote_BuildPath"),
            vec!["one", "onepkg"]
        );
    }

    #[test]
    fn test_doc_filetype_lnk_variants() {
        assert_eq!(doc_filetypes_from_rule_name("LNK_Malware"), vec!["lnk"]);
        assert_eq!(doc_filetypes_from_rule_name("LNKR_JS_a"), vec!["lnk"]);
        assert_eq!(doc_filetypes_from_rule_name("Lnk_Something"), vec!["lnk"]);
    }

    #[test]
    fn test_doc_filetype_iso() {
        assert_eq!(doc_filetypes_from_rule_name("ISO_exec"), vec!["iso", "img"]);
    }

    #[test]
    fn test_doc_filetype_no_match_generic() {
        assert!(doc_filetypes_from_rule_name("Generic_Phishing").is_empty());
        assert!(doc_filetypes_from_rule_name("DarkCloud_Stealer").is_empty());
        assert!(doc_filetypes_from_rule_name("Win32_Trojan_Foo").is_empty());
        assert!(doc_filetypes_from_rule_name("").is_empty());
    }

    // ------------------------------------------------------------------
    // infer_filetypes: unified function covering both binary and doc formats
    // ------------------------------------------------------------------

    #[test]
    fn test_infer_binary_platform_before_doc() {
        // Binary platform prefix takes priority over any doc inference
        assert_eq!(infer_filetypes("Win32_Trojan_Foo", None), vec!["pe", "dll"]);
        assert_eq!(
            infer_filetypes("Linux_Backdoor_Bash_e427876d", None),
            vec!["elf", "so"]
        );
        assert_eq!(
            infer_filetypes("MacOS_Infostealer_Foo_12345678", None),
            vec!["macho", "dylib"]
        );
    }

    #[test]
    fn test_infer_os_metadata_before_doc() {
        // os metadata takes highest priority
        assert_eq!(
            infer_filetypes("PDF_Something", Some("windows")),
            vec!["pe", "dll"]
        );
        assert_eq!(
            infer_filetypes("RTF_Bad_Doc", Some("linux")),
            vec!["elf", "so"]
        );
    }

    #[test]
    fn test_infer_doc_when_no_platform_signal() {
        // No os meta, no platform prefix → fall through to doc inference
        assert_eq!(infer_filetypes("PDF_Launch_Action_EXE", None), vec!["pdf"]);
        assert_eq!(
            infer_filetypes("RTF_Anti_Analysis_Header", None),
            vec!["rtf", "doc"]
        );
        assert_eq!(
            infer_filetypes("Office_Document_with_VBA_Project", None),
            vec!["doc", "docx", "xls", "xlsx", "ole"]
        );
        assert_eq!(infer_filetypes("LNK_Shortcut_Malware", None), vec!["lnk"]);
        assert_eq!(infer_filetypes("ISO_exec", None), vec!["iso", "img"]);
        assert_eq!(
            infer_filetypes("OneNote_BuildPath", None),
            vec!["one", "onepkg"]
        );
    }

    #[test]
    fn test_infer_empty_for_truly_generic_rules() {
        // Rules with no platform or doc prefix should not be constrained
        assert!(infer_filetypes("DarkCloud_Stealer", None).is_empty());
        assert!(infer_filetypes("ScreenConnect_CVE_2024_1709_Exploitation", None).is_empty());
        assert!(infer_filetypes("Ganelp", None).is_empty());
    }

    #[test]
    fn test_infer_pdf_rule_would_be_filtered_from_pe_scan() {
        // The filetype strings for PDF rules don't overlap with PE scanner's filter set
        let pdf_types = infer_filetypes("PDF_Launch_Action_EXE", None);
        let pe_filter = &["pe", "exe", "dll", "bat", "ps1"];
        let matches = pdf_types.iter().any(|t| pe_filter.contains(t));
        assert!(
            !matches,
            "PDF rule types {:?} should not match PE scan filter {:?}",
            pdf_types, pe_filter
        );
    }

    #[test]
    fn test_infer_rtf_rule_would_be_filtered_from_elf_scan() {
        let rtf_types = infer_filetypes("RTF_Anti_Analysis_Header", None);
        let elf_filter = &["elf", "so", "ko"];
        let matches = rtf_types.iter().any(|t| elf_filter.contains(t));
        assert!(
            !matches,
            "RTF rule types {:?} should not match ELF scan filter {:?}",
            rtf_types, elf_filter
        );
    }

    #[test]
    fn test_infer_lnk_rule_would_be_filtered_from_macho_scan() {
        let lnk_types = infer_filetypes("LNKR_JS_a", None);
        let macho_filter = &["macho", "dylib"];
        let matches = lnk_types.iter().any(|t| macho_filter.contains(t));
        assert!(
            !matches,
            "LNK rule types {:?} should not match MachO scan filter {:?}",
            lnk_types, macho_filter
        );
    }

    // ------------------------------------------------------------------
    // arch_context metadata parsing (Elastic-style rules)
    // ------------------------------------------------------------------

    #[test]
    fn test_arch_context_x86_expands_to_x86_family() {
        // "x86" means the x86 ISA family: both 32-bit x86 and x86-64
        let archs = archs_from_arch_context("x86");
        assert!(archs.contains(&Arch::X86), "x86 should include X86");
        assert!(archs.contains(&Arch::X86_64), "x86 should include X86_64");
        assert_eq!(archs.len(), 2);
    }

    #[test]
    fn test_arch_context_x64_is_x86_64_only() {
        let archs = archs_from_arch_context("x64");
        assert_eq!(archs, vec![Arch::X86_64]);
    }

    #[test]
    fn test_arch_context_arm64() {
        let archs = archs_from_arch_context("arm64");
        assert_eq!(archs, vec![Arch::Aarch64]);
    }

    #[test]
    fn test_arch_context_x86_comma_arm64() {
        // "x86, arm64" — the format seen in Elastic's Windows_Generic_Threat.yar
        let archs = archs_from_arch_context("x86, arm64");
        assert!(archs.contains(&Arch::X86));
        assert!(archs.contains(&Arch::X86_64));
        assert!(archs.contains(&Arch::Aarch64));
        assert_eq!(archs.len(), 3);
    }

    #[test]
    fn test_arch_context_empty_returns_no_constraint() {
        assert!(archs_from_arch_context("").is_empty());
    }

    #[test]
    fn test_arch_context_unknown_token_returns_empty() {
        // Unknown tokens produce no constraint (treated as "all")
        assert!(archs_from_arch_context("mips64el").is_empty());
    }

    #[test]
    fn test_arch_context_no_duplicates_x86_repeated() {
        // Duplicate tokens should not produce duplicate entries
        let archs = archs_from_arch_context("x86, x86");
        let x86_count = archs.iter().filter(|a| **a == Arch::X86).count();
        let x64_count = archs.iter().filter(|a| **a == Arch::X86_64).count();
        assert_eq!(x86_count, 1);
        assert_eq!(x64_count, 1);
    }

    #[test]
    fn test_arch_context_x64_and_arm64() {
        let archs = archs_from_arch_context("x64, arm64");
        assert!(archs.contains(&Arch::X86_64));
        assert!(archs.contains(&Arch::Aarch64));
        assert!(!archs.contains(&Arch::X86), "x64 alone should NOT include 32-bit X86");
        assert_eq!(archs.len(), 2);
    }

    #[test]
    fn test_arch_context_case_insensitive() {
        let archs = archs_from_arch_context("X86");
        assert!(archs.contains(&Arch::X86));
        assert!(archs.contains(&Arch::X86_64));
    }

    // ------------------------------------------------------------------
    // arch_context compatibility checks (simulating process_yara_result logic)
    // ------------------------------------------------------------------

    #[test]
    fn test_arch_context_x86_rule_matches_x86_64_file() {
        // An "x86" rule should match a 64-bit x86-64 file
        let rule_archs = archs_from_arch_context("x86");
        let file_arch = Arch::X86_64;
        assert!(rule_archs.contains(&file_arch));
    }

    #[test]
    fn test_arch_context_x86_rule_matches_x86_file() {
        let rule_archs = archs_from_arch_context("x86");
        let file_arch = Arch::X86;
        assert!(rule_archs.contains(&file_arch));
    }

    #[test]
    fn test_arch_context_x64_rule_does_not_match_x86_file() {
        // A "x64" rule should NOT match a 32-bit x86 file
        let rule_archs = archs_from_arch_context("x64");
        let file_arch = Arch::X86;
        assert!(!rule_archs.contains(&file_arch));
    }

    #[test]
    fn test_arch_context_arm64_rule_does_not_match_x86_64_file() {
        let rule_archs = archs_from_arch_context("arm64");
        let file_arch = Arch::X86_64;
        assert!(!rule_archs.contains(&file_arch));
    }

    #[test]
    fn test_arch_context_x86_arm64_rule_matches_aarch64_file() {
        // "x86, arm64" should match an AArch64 file
        let rule_archs = archs_from_arch_context("x86, arm64");
        assert!(rule_archs.contains(&Arch::Aarch64));
    }

    #[test]
    fn test_arch_context_x86_arm64_rule_matches_x86_file() {
        let rule_archs = archs_from_arch_context("x86, arm64");
        assert!(rule_archs.contains(&Arch::X86));
    }

    // ------------------------------------------------------------------
    // win_ / linux_ lowercase token inference (filename-style rule names)
    // ------------------------------------------------------------------

    #[test]
    fn test_platforms_from_win_lowercase_token() {
        // "win_mal_Matanbuchus_loader" — common RussianPanda95 naming convention
        assert_eq!(
            platforms_from_name_and_os("win_mal_Matanbuchus_loader", None),
            vec![Platform::Windows]
        );
    }

    #[test]
    fn test_platforms_from_linux_lowercase_token() {
        assert_eq!(
            platforms_from_name_and_os("linux_mal_zinfoq", None),
            vec![Platform::Linux]
        );
    }

    #[test]
    fn test_infer_win_lowercase_yields_pe_dll() {
        assert_eq!(
            infer_filetypes("win_mal_Matanbuchus_loader", None),
            vec!["pe", "dll"]
        );
    }

    // ------------------------------------------------------------------
    // Namespace filename component inference (the subtle TextShell case)
    //
    // Rule: TextShell (identifier has no platform prefix)
    // File: win_mal_TextShell.yar
    // Namespace: 3p.RussianPanda95.VanillaTempest.win_mal_TextShell
    //
    // The rule identifier "TextShell" gives no platform signal, but the
    // filename component of the namespace "win_mal_TextShell" does.
    // ------------------------------------------------------------------

    #[test]
    fn test_namespace_filename_win_mal_prefix_yields_pe_dll() {
        let types =
            infer_filetypes_from_namespace("3p.RussianPanda95.VanillaTempest.win_mal_TextShell", None);
        assert_eq!(types, vec!["pe", "dll"],
            "win_mal_ filename in namespace should infer Windows → pe/dll");
    }

    #[test]
    fn test_namespace_filename_no_signal_returns_empty() {
        // A namespace whose last component has no platform signal
        let types = infer_filetypes_from_namespace("3p.huntress.ScreenConnect_CVE_Exploitation", None);
        assert!(types.is_empty());
    }

    #[test]
    fn test_namespace_filename_linux_component() {
        let types =
            infer_filetypes_from_namespace("3p.RussianPanda95.ZinFoq.linux_mal_zinfoq", None);
        assert_eq!(types, vec!["elf", "so"]);
    }

    // ------------------------------------------------------------------
    // Condition-based filetype injection (MZ magic → pe, ELF → elf, etc.)
    // ------------------------------------------------------------------

    #[test]
    fn test_inject_pe_filetype_from_mz_condition() {
        let source = r#"rule TextShell {
    meta:
        description = "Detects TextShell Obfuscator"
        author = "RussianPanda"
    strings:
        $s1 = {41 8B 04 84 48 03 ?? EB}
    condition:
        uint16(0) == 0x5A4D and all of them and #s3 > 1000
}"#;
        let output = inject_condition_filetype_hints(source);
        assert!(
            output.contains("filetype = \"pe\""),
            "Should inject filetype = \"pe\" when condition has MZ magic"
        );
    }

    #[test]
    fn test_inject_does_not_duplicate_existing_filetype() {
        let source = r#"rule AlreadyTagged {
    meta:
        description = "PE MZ rule"
        filetype = "pe"
    condition:
        uint16(0) == 0x5A4D
}"#;
        let output = inject_condition_filetype_hints(source);
        // The source has exactly one `filetype` key; injection must not add another.
        let count = output.matches("filetype = ").count();
        assert_eq!(count, 1, "Should not duplicate existing filetype metadata");
    }

    #[test]
    fn test_inject_elf_filetype_from_condition() {
        let source = r#"rule ElfRule {
    meta:
        description = "ELF detector"
    condition:
        uint32(0) == 0x464c457f
}"#;
        let output = inject_condition_filetype_hints(source);
        assert!(output.contains("filetype = \"elf\""));
    }

    #[test]
    fn test_no_injection_when_no_magic() {
        let source = r#"rule GenericRule {
    meta:
        description = "No magic check"
    strings:
        $s = "suspicious"
    condition:
        $s
}"#;
        let output = inject_condition_filetype_hints(source);
        assert_eq!(output, source, "Source should be unchanged when no magic pattern");
    }

    #[test]
    fn test_inject_preserves_multi_rule_file() {
        let source = r#"rule RuleA {
    meta:
        description = "PE rule"
    condition:
        uint16(0) == 0x5A4D
}

rule RuleB {
    meta:
        description = "Generic rule"
    strings:
        $s = "malware"
    condition:
        $s
}"#;
        let output = inject_condition_filetype_hints(source);
        // RuleA should get filetype injected; RuleB should not
        assert!(output.contains("filetype = \"pe\""), "RuleA should get pe filetype");
        assert_eq!(
            output.matches("filetype").count(), 1,
            "Only the PE rule should get filetype injected"
        );
        assert!(output.contains("RuleB"), "RuleB should still be present");
    }

    #[test]
    fn test_inject_case_insensitive_mz_match() {
        // Some sources write 0x5a4d in lowercase
        let source = r#"rule LowerCase {
    meta:
        description = "lowercase hex"
    condition:
        uint16(0) == 0x5a4d
}"#;
        let output = inject_condition_filetype_hints(source);
        assert!(output.contains("filetype = \"pe\""));
    }
}
