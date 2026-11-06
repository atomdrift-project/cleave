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
#[must_use]
pub(crate) fn derive_trait_id(namespace: &str, rule_name: &str) -> String {
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
                    let platform = if prefers_unix_php_platform(rule_name) {
                        Platform::Unix
                    } else {
                        Platform::Linux
                    };
                    if !platforms.contains(&platform) {
                        platforms.push(platform);
                    }
                }
                "windows" | "win32" | "win64" | "win"
                    if !platforms.contains(&Platform::Windows) =>
                {
                    platforms.push(Platform::Windows);
                }
                "macos" | "osx" | "darwin" | "mac" if !platforms.contains(&Platform::MacOS) => {
                    platforms.push(Platform::MacOS);
                }
                "android" if !platforms.contains(&Platform::Android) => {
                    platforms.push(Platform::Android);
                }
                "ios" if !platforms.contains(&Platform::Ios) => {
                    platforms.push(Platform::Ios);
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
            "Linux" | "linux" => {
                if prefers_unix_php_platform(rule_name) {
                    return vec![Platform::Unix];
                }
                return vec![Platform::Linux];
            }
            "Mac" | "mac" | "MacOS" | "Macos" | "MACOS" | "macos" | "OSX" | "osx" => {
                return vec![Platform::MacOS];
            }
            "Android" | "android" => return vec![Platform::Android],
            "iOS" | "ios" => return vec![Platform::Ios],
            _ => {}
        }
    }
    vec![]
}

fn prefers_unix_php_platform(rule_name: &str) -> bool {
    yara_classify::infer_filetypes(rule_name, None) == vec!["php"]
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
            "x64" | "amd64" | "x86_64" | "x86-64" if !archs.contains(&Arch::X86_64) => {
                archs.push(Arch::X86_64);
            }
            "arm64" | "aarch64" if !archs.contains(&Arch::Aarch64) => {
                archs.push(Arch::Aarch64);
            }
            "arm" | "arm32" if !archs.contains(&Arch::Arm) => {
                archs.push(Arch::Arm);
            }
            _ => {} // Unknown token: treat as unconstrained
        }
    }
    archs
}

/// Infer filetype constraints from document-format rule name signals.
///
/// Handles document-format rules in the collection (PDF, RTF, Office, LNK, OneNote, etc.).
/// The signal may appear as the leading token or later in the rule name
/// (`APT10_ChChes_lnk`, `DELIVRTO_SUSP_Onenote_Win_Script_Encoding_Feb23`).
#[cfg(test)]
fn doc_filetypes_from_rule_name(rule_name: &str) -> Vec<&'static str> {
    yara_classify::doc_filetypes_from_text(rule_name)
}

/// Infer filetype constraints from scripting language signals in rule names.
///
/// Strict mode: a PowerShell rule is tagged as `ps1` only — NOT as `pe` even though
/// PE files can embed PowerShell. The rule author wrote a PowerShell-specific rule,
/// so it should only fire on PowerShell source files.
///
/// Returns empty vec if no scripting signal is found.
#[cfg(test)]
fn platform_filetypes_from_rule_name(rule_name: &str) -> Vec<&'static str> {
    yara_classify::platform_filetypes_from_rule_name(rule_name)
}

/// Log the inferred filetype association for a YARA rule at debug level.
///
/// Called from `yara_engine::build_yara_match` when a rule gets filetype tags.
/// At `--verbose` log level this lets operators see which rules map to which types.
pub(crate) fn log_filetype_association(
    rule_name: &str,
    namespace: &str,
    filetypes: &[String],
    source: &str,
) {
    if filetypes.is_empty() {
        tracing::debug!(
            rule = %rule_name,
            namespace = %namespace,
            "YARA rule has no filetype constraint (matches all file types)"
        );
    } else {
        tracing::debug!(
            rule = %rule_name,
            namespace = %namespace,
            filetypes = ?filetypes,
            inferred_from = %source,
            "YARA rule filetype association"
        );
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
mod tests;
