//! YAML data processing and default application.
//!
//! This module handles:
//! - Applying file-level defaults to raw trait and composite rule definitions
//! - Parsing string fields into typed enums (FileType, Platform, Criticality)
//! - Supporting the "none" keyword to explicitly unset defaults

use crate::composite_rules::types::Arch;
use crate::composite_rules::{
    CommentQuery, EncodedQuery, LiteralQuery, PathQuery, RawQuery, SectionQuery, SymbolQuery,
    TextQuery, TreeSitterQuery,
};
use crate::composite_rules::{
    CompositeTrait, Condition, FileType as RuleFileType, Platform, TraitDefinition,
};
use crate::types::Criticality;
use std::collections::HashSet;

use super::models::{RawCompositeRule, RawTraitDefinition, TraitDefaults};

/// True if a `for:` entry includes the forbidden `all` / `*` aggregator (as an
/// inclusion, not an exclusion). Comma-separated entries are split.
fn for_entry_contains_all(entry: &str) -> bool {
    entry.split(',').any(|part| {
        let part = part.trim();
        if part.is_empty() || part.starts_with('!') || part.starts_with('-') {
            return false;
        }
        part.eq_ignore_ascii_case("all") || part == "*"
    })
}

fn for_list_contains_all(types: &[String]) -> bool {
    types.iter().any(|s| for_entry_contains_all(s))
}

const FOR_ALL_REJECTED: &str = "for: [all] is not allowed — use concrete types \
     (elf, python, ...) or named groups (binaries, scripts, source, manifests, \
     documents, media, data). Combine groups explicitly \
     (e.g. for: [binaries, scripts]) instead of for: [all].";

const FOR_ALL_REJECTED_DEFAULTS: &str = "for: [all] is not allowed in file default \
     'for:' — use concrete types or named groups (binaries, scripts, source, manifests, \
     documents, media, data). Combine groups explicitly instead of for: [all].";

/// Apply default for Option<String> fields, supporting "none" to unset
/// - If raw is Some("none"), return None (explicit unset)
/// - If raw is Some(value), return Some(value)
/// - If raw is None, return default
pub(crate) fn apply_string_default(
    raw: Option<String>,
    default: &Option<String>,
) -> Option<String> {
    match &raw {
        Some(v) if v.eq_ignore_ascii_case("none") => None,
        Some(_) => raw,
        None => default.clone(),
    }
}

/// Apply default for Vec<String> fields (file_types, platforms), supporting "none" to unset
/// - If raw contains "none", return empty/default behavior
/// - If raw is Some with values, use those
/// - If raw is None, use default
pub(crate) fn apply_vec_default(
    raw: Option<Vec<String>>,
    default: &Option<Vec<String>>,
) -> Option<Vec<String>> {
    match &raw {
        Some(v) if v.iter().any(|s| s.eq_ignore_ascii_case("none")) => None,
        Some(_) => raw,
        None => match default {
            Some(v) if v.iter().any(|s| s.eq_ignore_ascii_case("none")) => None,
            _ => default.clone(),
        },
    }
}

/// Prefix of the warning for a rule whose resolved `for:` targets no file type.
/// The directory loader routes it to the `empty-file-type` validator.
pub(crate) const EMPTY_RESOLVED_FOR: &str = "Empty resolved 'for:'";

/// Resolve a rule's `for:` against the file default: the rule's own list
/// (unless `none`), else `defaults: for:`, else `[All]`.
///
/// Unknown names in an inherited default are not reported here -- they are
/// the file's problem, reported once by [`default_file_type_warnings`], not
/// once per rule that inherits them.
fn resolve_rule_file_types(
    raw_for: Option<Vec<String>>,
    defaults: &TraitDefaults,
    warnings: &mut Vec<String>,
) -> ParsedFileTypes {
    let inherited = raw_for.is_none();
    match apply_vec_default(raw_for, &defaults.r#for) {
        Some(types) if inherited => parse_file_types(&types, &mut Vec::new()),
        Some(types) => parse_file_types(&types, warnings),
        None => ParsedFileTypes {
            types: vec![RuleFileType::All],
            from_groups: false,
        },
    }
}

/// Unknown or banned names in a file's `defaults: for:`, one warning each.
///
/// Checked once per file whether or not any rule inherits the default: a bad
/// name there would otherwise surface only through inheriting rules (so not at
/// all when every rule overrides `for:`), and once per rule when many do.
/// `none`/`unknown`/`[]`/`all` in the default are invalid-file-type problems
/// reported by [`apply_trait_defaults`], so they are skipped here.
pub(crate) fn default_file_type_warnings(
    defaults: &TraitDefaults,
    path: &std::path::Path,
) -> Vec<String> {
    let Some(types) = defaults.r#for.as_deref() else {
        return Vec::new();
    };
    let names: Vec<String> = types
        .iter()
        .flat_map(|entry| entry.split(','))
        .map(str::trim)
        .filter(|name| {
            let bare = name.trim_start_matches(['!', '-']);
            !bare.eq_ignore_ascii_case("none") && !bare.eq_ignore_ascii_case("unknown")
        })
        .map(str::to_string)
        .collect();
    let mut warnings = Vec::new();
    parse_file_types(&names, &mut warnings);
    for w in &mut warnings {
        *w = format!("{w} (file-level 'defaults: for:' in {})", path.display());
    }
    warnings
}

/// Warn when a rule's final `for:` is empty. Such a rule is dead: the file-type
/// gate (`FileType::rule_applies_to`) and the per-type trait index both admit
/// nothing, so it never evaluates standalone, as a composite leg, or on a
/// container. Callers skip it when an `Invalid file type` warning (`for: []`)
/// already covers the rule.
fn check_empty_resolved_for(file_types: &[RuleFileType], warnings: &mut Vec<String>) {
    if file_types.is_empty() {
        warnings.push(format!(
            "{EMPTY_RESOLVED_FOR}: targets no file type after defaults, unknown names, \
             exclusions and platform filtering, so the rule can never fire"
        ));
    }
}

/// Convert a raw trait definition to a final TraitDefinition, applying file-level defaults
/// Collects warnings into the provided vector instead of printing them.
pub(crate) fn apply_trait_defaults(
    raw: RawTraitDefinition,
    defaults: &TraitDefaults,
    warnings: &mut Vec<String>,
    path: &std::path::Path,
    enable_precision_scoring: bool,
) -> TraitDefinition {
    // Validation: require explicit for: either on trait or in file defaults.
    // Silently defaulting to [All] is not allowed — authors must be explicit about target file types.
    if raw.file_types.is_none() && defaults.r#for.is_none() {
        warnings.push(format!(
            "Trait '{}' in {}: missing 'for:' declaration. Every trait must specify which file types it \
             targets. Use specific types (elf, python, ...) or named groups \
             (binaries, scripts, source, manifests, documents, media, data). To avoid repeating \
             this on every trait in the file, add a file-wide default in the top-level \
             'defaults:' section, e.g.: 'defaults:\\n  for: [binaries]'.",
            raw.id,
            path.display()
        ));
    }

    // Parse file_types: use trait-specific if present (unless "none"), else defaults, else [All]
    let warn_start = warnings.len();
    // Detect always-fatal for: errors before apply_vec_default handles "none"
    if let Some(types) = raw.file_types.as_deref() {
        if types.is_empty() {
            warnings.push(
                "Invalid file type: '' (empty 'for: []' is not valid — specify at least one file type)"
                    .to_string(),
            );
        } else if types.iter().any(|s| s.eq_ignore_ascii_case("none")) {
            warnings.push(
                "Invalid file type: 'none' is not valid in 'for:' — every trait must target at \
                 least one file type. Specify concrete types (elf, python, ...) or named groups \
                 (binaries, scripts, source, manifests, documents, media, data)."
                    .to_string(),
            );
        } else if types.iter().any(|s| s.eq_ignore_ascii_case("unknown")) {
            warnings.push(
                "Invalid file type: 'unknown' is not valid in 'for:' — it isn't useful or \
                 supported to write rules that target unknown file types. cleave only invokes \
                 rules whose 'for:' matches the detected type, and 'unknown' files have no \
                 detected type, so the rule could never fire. Specify concrete types (elf, \
                 python, ...) or named groups (binaries, scripts, source, manifests, documents, \
                 media, data)."
                    .to_string(),
            );
        } else if for_list_contains_all(types) {
            warnings.push(FOR_ALL_REJECTED.to_string());
        }
    } else if defaults.r#for.as_deref().is_some_and(<[String]>::is_empty) {
        warnings.push(
            "Invalid file type: '' (file default 'for: []' is empty — specify at least one file type)"
                .to_string(),
        );
    } else if defaults
        .r#for
        .as_deref()
        .is_some_and(|v| v.iter().any(|s| s.eq_ignore_ascii_case("none")))
    {
        warnings.push(
            "Invalid file type: 'none' is not valid in file default 'for:' — every trait must \
             target at least one file type. Specify concrete types or named groups."
                .to_string(),
        );
    } else if defaults
        .r#for
        .as_deref()
        .is_some_and(|v| v.iter().any(|s| s.eq_ignore_ascii_case("unknown")))
    {
        warnings.push(
            "Invalid file type: 'unknown' is not valid in file default 'for:' — it isn't useful \
             or supported to write rules for unknown file types. Specify concrete types or \
             named groups."
                .to_string(),
        );
    } else if defaults.r#for.as_deref().is_some_and(for_list_contains_all) {
        warnings.push(FOR_ALL_REJECTED_DEFAULTS.to_string());
    }
    let parsed_ft = resolve_rule_file_types(raw.file_types, defaults, warnings);
    let mut file_types = parsed_ft.types;
    let from_groups = parsed_ft.from_groups;
    let for_invalid = warnings[warn_start..]
        .iter()
        .any(|w| w.starts_with("Invalid file type"));
    for w in &mut warnings[warn_start..] {
        *w = format!("{} (trait '{}' in {})", w, raw.id, path.display());
    }

    // Validation: require explicit platforms: either on trait or in file defaults.
    if raw.platforms.is_none() && defaults.platforms.is_none() {
        warnings.push(format!(
            "Trait '{}' in {}: missing 'platforms:' declaration. Every trait must specify which \
             platforms it targets. List explicit platforms such as [unix, windows, macos], or \
             set a file-wide default in the top-level 'defaults:' section.",
            raw.id,
            path.display()
        ));
    }

    // Parse platforms: use trait-specific if present (unless "none"), else defaults, else [All]
    let warn_start = warnings.len();
    let platforms = match apply_vec_default(raw.platforms, &defaults.platforms) {
        Some(plats) => {
            let parsed = parse_platforms(&plats, warnings);
            if parsed.is_empty() {
                vec![Platform::All]
            } else {
                parsed
            }
        }
        None => vec![Platform::All],
    };

    // Filter or warn about platform/filetype conflicts
    resolve_platform_filetype_conflicts(
        &raw.id,
        &platforms,
        &mut file_types,
        from_groups,
        warnings,
    );
    if !for_invalid {
        check_empty_resolved_for(&file_types, warnings);
    }
    for w in &mut warnings[warn_start..] {
        *w = format!("{} (trait '{}' in {})", w, raw.id, path.display());
    }

    // Parse arch: use trait-specific if present (unless "none"), else defaults, else [All]
    let arch_warn_start = warnings.len();
    let arch = apply_vec_default(raw.arch, &defaults.arch)
        .map(|archs| parse_arch(&archs, warnings))
        .unwrap_or_else(|| vec![Arch::All]);
    for w in &mut warnings[arch_warn_start..] {
        *w = format!("{} (trait '{}' in {})", w, raw.id, path.display());
    }

    let mut criticality = resolve_criticality(
        raw.crit.as_deref(),
        defaults.crit.as_deref(),
        &raw.id,
        path,
        warnings,
    );

    // Hostile describes attack intent, not rule form. TAXONOMY.md permits
    // precise atomic observations in objectives/ and malware identities.
    // A neutral capability or artifact property still cannot be hostile.
    let intent_tier = path
        .components()
        .rev()
        .find_map(|part| match part.as_os_str().to_str()? {
            "objectives" | "well-known" => Some(true),
            "micro-behaviors" | "metadata" => Some(false),
            _ => None,
        })
        .unwrap_or(false);
    if criticality == Criticality::Hostile && !intent_tier {
        warnings.push(format!(
            "Trait '{}' in {}: atomic trait marked 'crit: hostile'. Atomic (micro-behaviors/) traits cannot \
             be hostile — hostile criticality requires intent inference and belongs in objectives/. \
             Move this to objectives/ and categorize by attacker objective (e.g., objectives/command-and-control/, objectives/exfiltration/, \
             objectives/impact/). See TAXONOMY.md: micro-behaviors/ max criticality is 'suspicious'.",
            raw.id,
            path.display()
        ));
        criticality = Criticality::Suspicious;
    }

    // Additional strictness for SUSPICIOUS/HOSTILE traits
    if criticality >= Criticality::Suspicious && raw.desc.len() < 15 {
        warnings.push(format!(
            "Trait '{}' in {}: overly short description for its criticality.",
            raw.id,
            path.display()
        ));
    }

    // Warn about overly long descriptions (> 7 words)
    let word_count = raw.desc.split_whitespace().count();
    if word_count > 7 {
        warnings.push(format!(
            "Trait '{}' in {}: overly long description ({} words, max 7 recommended).",
            raw.id,
            path.display(),
            word_count
        ));
    }

    // Without a condition and with no size, entropy or count filter, a trait
    // that carries `unless:` or `downgrade:` is an override: it tunes the
    // engine-emitted finding at its id and never matches on its own.
    let is_override = raw.condition.is_none()
        && raw.size_min.is_none()
        && raw.size_max.is_none()
        && raw.count_min.is_none()
        && raw.count_max.is_none()
        && raw.per_kb_min.is_none()
        && raw.per_kb_max.is_none()
        && raw.entropy_min.is_none()
        && raw.entropy_max.is_none()
        && (raw.unless.is_some() || raw.downgrade.is_some());
    // Other size-only traits without a condition get a synthetic "always-true"
    // condition: a basename regex that matches everything.
    let mut condition = raw.condition.unwrap_or_else(|| {
        if is_override {
            return crate::composite_rules::inert_condition();
        }
        crate::composite_rules::Condition::Path(PathQuery {
            exact: None,
            substr: None,
            regex: Some(".".to_string()),
            case_insensitive: false,
            is_check: None,
            basename: false,
            dirname: false,
        })
    });

    // Auto-fix: Convert literal regex patterns to substr for better performance
    // If a regex pattern contains only alphanumeric chars and underscores, it's a literal
    fix_literal_regex_patterns(&mut condition);

    // Validate regex size and alternation shape. Alternation reuse checks are
    // meaningful for counted traits, where a single branch can satisfy
    // count_min repeatedly; ordinary vocabulary/path matchers should retain
    // their compact context-aware regex.
    let warn_start = warnings.len();
    check_regex_length_with_reuse(
        &raw.id,
        &condition,
        Some(path),
        warnings,
        raw.count_min.is_some(),
    );
    if raw.count_min.is_some() {
        check_count_min_regex_alternation(&raw.id, &condition, warnings);
    }

    // Also check regex patterns in unless: conditions
    if let Some(ref unless_conditions) = raw.unless {
        for (idx, cond) in unless_conditions.iter().enumerate() {
            let ctx = format!("{} unless[{}]", raw.id, idx);
            check_regex_length(&ctx, cond, Some(path), warnings);
        }
    }

    // Also check regex patterns in downgrade: conditions
    if let Some(ref downgrade) = raw.downgrade {
        if let Some(ref any) = downgrade.any {
            for (idx, cond) in any.iter().enumerate() {
                let ctx = format!("{} downgrade.any[{}]", raw.id, idx);
                check_regex_length_with_reuse(&ctx, cond, Some(path), warnings, false);
            }
        }
        if let Some(ref all) = downgrade.all {
            for (idx, cond) in all.iter().enumerate() {
                let ctx = format!("{} downgrade.all[{}]", raw.id, idx);
                check_regex_length_with_reuse(&ctx, cond, Some(path), warnings, false);
            }
        }
    }
    let exempt = resolve_exemptions(&raw.exempt, defaults, &raw.id, warnings);
    for w in &mut warnings[warn_start..] {
        *w = format!("{} (in {})", w, path.display());
    }

    let mut trait_def = TraitDefinition {
        id_shared: std::sync::OnceLock::new(),
        desc_shared: std::sync::OnceLock::new(),
        requires_non_ascii: std::sync::OnceLock::new(),
        id: raw.id,
        desc: raw.desc,
        conf: raw.conf.or(defaults.conf).unwrap_or(1.0),
        crit: criticality,
        mbc: apply_string_default(raw.mbc, &defaults.mbc),
        attack: apply_string_default(raw.attack, &defaults.attack),
        r#ref: raw.r#ref,
        platforms,
        arch,
        r#for: file_types,
        for_from_groups: from_groups,
        r#if: condition,
        size_min: raw.size_min.or(defaults.size_min),
        size_max: raw.size_max.or(defaults.size_max),
        count_min: raw.count_min,
        count_max: raw.count_max,
        per_kb_min: raw.per_kb_min,
        per_kb_max: raw.per_kb_max,
        entropy_min: raw.entropy_min.or(defaults.entropy_min),
        entropy_max: raw.entropy_max.or(defaults.entropy_max),
        not: raw.not,
        unless: raw.unless,
        downgrade: raw.downgrade,
        exempt,
        defined_in: path.to_path_buf(),
        precision: None,
    };

    if enable_precision_scoring {
        trait_def.precision = Some(super::precision::calculate_trait_precision(&trait_def));
    }

    trait_def
}

/// Result of parsing file types, tracking whether groups were used.
/// When `from_groups` is true, platform-incompatible types can be silently
/// filtered instead of producing validation warnings.
pub(crate) struct ParsedFileTypes {
    pub types: Vec<RuleFileType>,
    /// True if any group name (binaries, scripts, source, etc.) was used in the `for:` field.
    /// Explicit type names like `pe`, `macho` set this to false.
    pub from_groups: bool,
}

/// Parse file type strings into FileType enum
/// Collects warnings about unknown file types into the provided vector.
pub(crate) fn parse_file_types(types: &[String], warnings: &mut Vec<String>) -> ParsedFileTypes {
    let mut inclusions = HashSet::new();
    let mut exclusions = HashSet::new();
    let mut has_explicit_inclusion = false;
    let mut used_groups = false;

    for type_str in types {
        for part in type_str.split(',') {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }

            let (is_exclusion, name) = if let Some(stripped) = part.strip_prefix('!') {
                (true, stripped)
            } else if let Some(stripped) = part.strip_prefix('-') {
                // Support YAML-safe exclusion syntax: -python, -c, etc.
                (true, stripped)
            } else {
                (false, part)
            };

            let lower_name = name.to_lowercase();
            let is_group = matches!(
                lower_name.as_str(),
                "all"
                    | "*"
                    | "archives"
                    | "binaries"
                    | "scripts"
                    | "source"
                    | "manifests"
                    | "build"
                    | "documents"
                    | "images"
                    | "media"
                    | "ipa"
            );
            if is_group && !is_exclusion {
                used_groups = true;
            }

            let variants = match lower_name.as_str() {
                "all" | "*" => vec![],
                // Explicit archive-family scope. This is an ordinary list of
                // concrete types; it does not grant an applies_to bypass.
                "archives" => RuleFileType::archive_family_types().to_vec(),
                // Groups
                "binaries" => vec![
                    RuleFileType::Elf,
                    RuleFileType::Macho,
                    RuleFileType::Pe,
                    RuleFileType::Class,
                    RuleFileType::Pyc,
                    RuleFileType::Beam,
                    RuleFileType::Wasm,
                    RuleFileType::Dex,
                    RuleFileType::StaticLib,
                ],
                "scripts" => vec![
                    RuleFileType::Shell,
                    RuleFileType::Batch,
                    RuleFileType::Jcl,
                    RuleFileType::Python,
                    RuleFileType::JavaScript,
                    RuleFileType::Ruby,
                    RuleFileType::Php,
                    RuleFileType::Perl,
                    RuleFileType::Lua,
                    RuleFileType::PowerShell,
                    RuleFileType::AppleScript,
                    RuleFileType::Vbs,
                    RuleFileType::Mirc,
                    RuleFileType::IrcII,
                ],
                "source" => vec![
                    RuleFileType::TypeScript,
                    RuleFileType::Rust,
                    RuleFileType::Java,
                    RuleFileType::C,
                    RuleFileType::Cpp,
                    RuleFileType::Go,
                    RuleFileType::CSharp,
                    RuleFileType::Swift,
                    RuleFileType::ObjectiveC,
                    RuleFileType::Groovy,
                    RuleFileType::Kotlin,
                    RuleFileType::Scala,
                    RuleFileType::Zig,
                    RuleFileType::Elixir,
                    RuleFileType::Clojure,
                ],
                "manifests" => vec![
                    RuleFileType::Yaml,
                    RuleFileType::PackageJson,
                    RuleFileType::PackageLockJson,
                    RuleFileType::CargoLock,
                    RuleFileType::RequirementsTxt,
                    RuleFileType::PoetryLock,
                    RuleFileType::PipfileLock,
                    RuleFileType::GemfileLock,
                    RuleFileType::ComposerLock,
                    RuleFileType::YarnLock,
                    RuleFileType::PnpmLock,
                    RuleFileType::GoMod,
                    RuleFileType::GoSum,
                    RuleFileType::Gyp,
                    RuleFileType::ChromeManifest,
                    RuleFileType::VsixManifest,
                    RuleFileType::CargoToml,
                    RuleFileType::PyProjectToml,
                    RuleFileType::GithubActions,
                    RuleFileType::SystemdService,
                    RuleFileType::DesktopEntry,
                    RuleFileType::Xml,
                    RuleFileType::ComposerJson,
                    RuleFileType::PkgInfo,
                    RuleFileType::SrcInfo,
                    RuleFileType::Registry,
                    RuleFileType::Reg,
                    RuleFileType::Plist,
                    RuleFileType::Nib,
                    RuleFileType::Lnk,
                    RuleFileType::Dockerfile,
                ],
                // Build definitions: executable build logic, as opposed to the
                // declarative metadata in `manifests`. A Makefile recipe, a
                // Dockerfile `RUN`, a CMake `execute_process`, and an Xcode
                // build phase all run commands on the machine that builds the
                // project, which is what a supply-chain rule needs to name.
                // Overlaps `manifests` on Dockerfile deliberately -- it is both
                // an image manifest and a script -- so existing rules that
                // reach it through `manifests` keep working.
                "build" => vec![
                    RuleFileType::Makefile,
                    RuleFileType::Cmake,
                    RuleFileType::Pbxproj,
                    RuleFileType::Dockerfile,
                ],
                "documents" => vec![
                    RuleFileType::Pdf,
                    RuleFileType::Rtf,
                    RuleFileType::Html,
                    RuleFileType::Markdown,
                    RuleFileType::Text,
                    RuleFileType::OleDoc,
                    RuleFileType::Ooxml,
                    RuleFileType::Odf,
                ],
                // Every passive container a package copies verbatim and no
                // reviewer opens: fonts, raster and vector images, audio and
                // video. One group, so a carrier rule is written once rather
                // than a dozen times, and every file type belongs to exactly
                // one group in the validator's table.
                "media" | "carriers" => vec![
                    RuleFileType::Font,
                    RuleFileType::Png,
                    RuleFileType::Tiff,
                    RuleFileType::Avif,
                    RuleFileType::Jpeg,
                    RuleFileType::Svg,
                    RuleFileType::Wav,
                    RuleFileType::Aiff,
                    RuleFileType::Mp3,
                    RuleFileType::Mp4,
                    RuleFileType::Ico,
                    RuleFileType::Gif,
                    RuleFileType::Bmp,
                    RuleFileType::Webp,
                ],
                // Convenience subsets, not groups: a rule naming one of these
                // is writing a short explicit list, which is what the
                // group-expressibility check will treat it as.
                "images" => vec![
                    RuleFileType::Jpeg,
                    RuleFileType::Png,
                    RuleFileType::Tiff,
                    RuleFileType::Avif,
                    RuleFileType::Ico,
                    RuleFileType::Gif,
                    RuleFileType::Bmp,
                    RuleFileType::Webp,
                ],
                "fonts" => vec![RuleFileType::Font],
                "audio" => vec![RuleFileType::Wav, RuleFileType::Aiff, RuleFileType::Mp3],
                "ipa" => vec![RuleFileType::Ipa],
                "unknown" => vec![RuleFileType::Unknown],
                // Binary formats
                "elf" | "so" => vec![RuleFileType::Elf],
                "macho" | "dylib" => vec![RuleFileType::Macho],
                "pe" | "dll" => vec![RuleFileType::Pe],
                "ne" => vec![RuleFileType::Ne],
                "static-lib" | "staticlib" | "a" => vec![RuleFileType::StaticLib],
                // Scripting languages (fullname + extension)
                "shell" | "sh" => vec![RuleFileType::Shell],
                "batch" | "bat" | "cmd" => vec![RuleFileType::Batch],
                "jcl" => vec![RuleFileType::Jcl],
                "python" | "py" => vec![RuleFileType::Python],
                "javascript" | "js" | "typescript" | "ts" => vec![RuleFileType::JavaScript],
                "ruby" | "rb" => vec![RuleFileType::Ruby],
                "php" => vec![RuleFileType::Php],
                "perl" | "pl" => vec![RuleFileType::Perl],
                "powershell" | "ps1" => vec![RuleFileType::PowerShell],
                "lua" => vec![RuleFileType::Lua],
                "applescript" | "scpt" => vec![RuleFileType::AppleScript],
                "vbs" | "vbe" | "wsf" | "wsc" | "vbscript" => vec![RuleFileType::Vbs],
                "html" | "htm" => vec![RuleFileType::Html],
                "jsp" | "jspx" => vec![RuleFileType::Jsp],
                "asp" | "aspx" => vec![RuleFileType::Asp],
                "cfml" | "cfm" | "cfc" => vec![RuleFileType::Cfml],
                "mirc" | "mrc" => vec![RuleFileType::Mirc],
                "ircii" => vec![RuleFileType::IrcII],
                "tex" => vec![RuleFileType::Tex],
                "yara" | "yar" => vec![RuleFileType::Yara],
                "postscript" | "ps" | "eps" => vec![RuleFileType::PostScript],
                "dos_com" | "dos-com" | "doscom" => vec![RuleFileType::DosCom],
                // Headerless x86 / x86-64 code. Standalone, not in `binaries`:
                // those rules assume a parsed container (imports, sections,
                // headers) that raw code does not have.
                "shellcode" => vec![RuleFileType::Shellcode],
                "markdown" | "md" => vec![RuleFileType::Markdown],
                "makefile" | "make" | "mk" | "mak" => vec![RuleFileType::Makefile],
                "dockerfile" | "docker" | "containerfile" => vec![RuleFileType::Dockerfile],
                "text" | "txt" | "b64" | "base64" => vec![RuleFileType::Text],
                // `data` maps to the concrete Data type (opaque .dat/.bin/.payload
                // content) — NOT a group. An alias that collides with a real file
                // type must resolve to that type; authors who want loose text-ish
                // content write `[text, data, json]` explicitly.
                "data" | "dat" | "bin" | "payload" | "raw" => vec![RuleFileType::Data],
                "pgp_signature" => vec![RuleFileType::PgpSignature],
                "yaml" | "yml" => vec![RuleFileType::Yaml],
                "json" => vec![RuleFileType::Json],
                "gyp" | "gypi" | "binding.gyp" => vec![RuleFileType::Gyp],
                // Compiled languages (fullname + extension)
                "java" => vec![RuleFileType::Java],
                "class" | "java_class" | "javaclass" => vec![RuleFileType::Class],
                "pyc" | "python-bytecode" | "pythonbytecode" => vec![RuleFileType::Pyc],
                "wasm" | "webassembly" => vec![RuleFileType::Wasm],
                "dex" | "dalvik" => vec![RuleFileType::Dex],
                "c" | "cpp" | "c++" | "cc" | "cxx" => vec![RuleFileType::C],
                "rust" => vec![RuleFileType::Rust],
                "go" => vec![RuleFileType::Go],
                "csharp" | "cs" => vec![RuleFileType::CSharp],
                "swift" => vec![RuleFileType::Swift],
                "objective-c" | "objc" => vec![RuleFileType::ObjectiveC],
                "groovy" => vec![RuleFileType::Groovy],
                "kotlin" | "kt" => vec![RuleFileType::Kotlin],
                "scala" => vec![RuleFileType::Scala],
                "zig" => vec![RuleFileType::Zig],
                "elixir" => vec![RuleFileType::Elixir],
                // Specific filenames
                "package.json" => vec![RuleFileType::PackageJson],
                "package-lock.json" => vec![RuleFileType::PackageLockJson],
                "go.mod" | "gomod" | "go-mod" => vec![RuleFileType::GoMod],
                "cargo.toml" => vec![RuleFileType::CargoToml],
                "pyproject.toml" => vec![RuleFileType::PyProjectToml],
                "composer.json" => vec![RuleFileType::ComposerJson],
                // Logical types with hyphens
                "chrome-manifest" | "manifest.json" => vec![RuleFileType::ChromeManifest],
                "vsixmanifest" | "vsix-manifest" => vec![RuleFileType::VsixManifest],
                "github-actions" => vec![RuleFileType::GithubActions],
                "systemd-service" | "systemd_service" | "systemd" | "service" | ".service" => {
                    vec![RuleFileType::SystemdService]
                }
                "desktop-entry" | "desktop_entry" | "desktop" | ".desktop" | "xdg-desktop" => {
                    vec![RuleFileType::DesktopEntry]
                }
                "xml" | "csproj" | "msbuild" | "xaml" | "xml-document" => {
                    vec![RuleFileType::Xml]
                }
                "svg" => vec![RuleFileType::Svg],
                // Image formats
                "jpeg" | "jpg" => vec![RuleFileType::Jpeg],
                "png" => vec![RuleFileType::Png],
                "tiff" | "tif" => vec![RuleFileType::Tiff],
                "avif" | "avifs" => vec![RuleFileType::Avif],
                // Font containers
                "font" | "ttf" | "otf" | "ttc" | "woff" | "woff2" | "eot" => {
                    vec![RuleFileType::Font]
                }
                "wav" | "wave" => vec![RuleFileType::Wav],
                "aiff" | "aif" | "aifc" => vec![RuleFileType::Aiff],
                "mp3" => vec![RuleFileType::Mp3],
                // `video` is an alias here rather than its own arm: it
                // resolves to the one ISO base-media type.
                "mp4" | "m4a" | "m4v" | "mov" | "video" => vec![RuleFileType::Mp4],
                "ico" | "cur" | "favicon" => vec![RuleFileType::Ico],
                "gif" => vec![RuleFileType::Gif],
                "bmp" | "dib" => vec![RuleFileType::Bmp],
                "webp" => vec![RuleFileType::Webp],
                // Serialized data
                "pickle" | "pkl" => vec![RuleFileType::Pickle],
                // Other formats
                "plist" => vec![RuleFileType::Plist],
                "nib" => vec![RuleFileType::Nib],
                "pbxproj" | "xcodeproj" => vec![RuleFileType::Pbxproj],
                "cmake" | "cmakelists" => vec![RuleFileType::Cmake],
                "pkginfo" => vec![RuleFileType::PkgInfo],
                "rtf" => vec![RuleFileType::Rtf],
                "lnk" => vec![RuleFileType::Lnk],
                "pdf" => vec![RuleFileType::Pdf],
                // Microsoft Office formats
                "oledoc" | "ole" | "doc" | "xls" | "ppt" | "msg" => {
                    vec![RuleFileType::OleDoc]
                }
                "msi" | "msp" | "mst" | "msm" => vec![RuleFileType::Msi],
                "ooxml" | "docx" | "xlsx" | "pptx" | "docm" | "xlsm" | "pptm" => {
                    vec![RuleFileType::Ooxml]
                }
                "zip" => vec![RuleFileType::Zip],
                "apk" | "apk_android" | "android_apk" => vec![RuleFileType::AndroidApk],
                "apk_alpine" | "alpine_apk" => vec![RuleFileType::AlpineApk],
                "jar" => vec![RuleFileType::Jar],
                "tar" | "tgz" => vec![RuleFileType::Tar],
                "npm" => vec![RuleFileType::Npm],
                "nupkg" => vec![RuleFileType::Nupkg],
                "crate" => vec![RuleFileType::Crate],
                "conda" => vec![RuleFileType::Conda],
                "egg" => vec![RuleFileType::Egg],
                "pkg" => vec![RuleFileType::Pkg],
                "gem" => vec![RuleFileType::Gem],
                "whl" => vec![RuleFileType::Whl],
                "python_sdist" | "python-sdist" | "sdist" => vec![RuleFileType::PythonSdist],
                "deb" => vec![RuleFileType::Deb],
                "rpm" => vec![RuleFileType::Rpm],
                "crx" => vec![RuleFileType::Crx],
                "chm" => vec![RuleFileType::Chm],
                "cab" => vec![RuleFileType::Cab],
                "iso" => vec![RuleFileType::Iso],
                "vsix-archive" => vec![RuleFileType::VsixArchive],
                "xpi" => vec![RuleFileType::Xpi],
                "zst" => vec![RuleFileType::Zst],
                _ => {
                    // Keep the file-type vocabulary in `composite_rules::types`
                    // (which is bridged to filefacts) rather than requiring a
                    // second match arm here whenever filefacts gains a type.
                    let parsed = RuleFileType::from_str(&lower_name);
                    if parsed == RuleFileType::Unknown && lower_name != "unknown" {
                        warnings.push(format!("Unknown file type: '{}'", name));
                        vec![]
                    } else {
                        vec![parsed]
                    }
                }
            };

            if name == "*" || name.eq_ignore_ascii_case("all") {
                if !is_exclusion {
                    has_explicit_inclusion = true;
                    inclusions.insert(RuleFileType::All);
                } else {
                    for v in RuleFileType::all_concrete_variants() {
                        exclusions.insert(v);
                    }
                }
                continue;
            }

            for v in variants {
                if is_exclusion {
                    exclusions.insert(v);
                } else {
                    has_explicit_inclusion = true;
                    inclusions.insert(v);
                }
            }
        }
    }

    let mut final_set: HashSet<RuleFileType>;

    if inclusions.contains(&RuleFileType::All)
        || (!has_explicit_inclusion && !exclusions.is_empty())
    {
        final_set = RuleFileType::all_concrete_variants().into_iter().collect();
    } else {
        final_set = inclusions.clone();
    }

    for exc in &exclusions {
        final_set.remove(exc);
    }

    let types = if !exclusions.is_empty() {
        let mut v: Vec<_> = final_set.into_iter().collect();
        v.sort_unstable();
        v
    } else if inclusions.contains(&RuleFileType::All) {
        vec![RuleFileType::All]
    } else {
        let mut v: Vec<_> = final_set.into_iter().collect();
        v.sort_unstable();
        v
    };

    ParsedFileTypes {
        types,
        from_groups: used_groups,
    }
}

/// Check file type / platform compatibility.
///
/// When file types came from **group expansion** (`from_groups=true`), incompatible
/// types are silently filtered out — e.g. `for: [scripts, binaries]` with
/// `platforms: [macos]` drops PE/DLL/ELF/Batch/VBS and keeps Mach-O/Shell/etc.
///
/// When file types were **explicitly specified** (`from_groups=false`), incompatible
/// types produce a validation warning — e.g. `for: [pe]` with `platforms: [macos]`.
///
/// Skipped when either list contains an `All` sentinel (unconstrained).
///
/// Platform support:
/// - PE / Batch / VBS → windows
/// - ELF              → linux, unix, android
/// - Mach-O           → macos, ios
/// - Shell                  → linux, unix, macos, android, ios (not windows)
pub(crate) fn resolve_platform_filetype_conflicts(
    id: &str,
    platforms: &[Platform],
    file_types: &mut Vec<RuleFileType>,
    from_groups: bool,
    warnings: &mut Vec<String>,
) {
    if platforms.contains(&Platform::All) || file_types.contains(&RuleFileType::All) {
        return;
    }

    let has_windows = platforms.contains(&Platform::Windows);
    // The `unix` umbrella platform: generic Unix (Linux, BSD, AIX, Solaris, …).
    // macOS is itself a Unix, so the `unix` umbrella conceptually includes it —
    // but `has_unix` deliberately does NOT flip on for a *macos-only* trait,
    // because that proxy also gates Linux/BSD-only formats like ELF (which do
    // not run on macOS). Apple-format arms therefore test `has_unix || has_macos
    // || has_ios` so a `[unix]` trait still reaches macOS-native formats.
    // Android is a mobile OS, not a traditional Unix flavor, so it is separate.
    let has_unix = platforms.iter().any(|p| {
        matches!(
            p,
            Platform::Linux
                | Platform::Unix
                | Platform::Aix
                | Platform::Solaris
                | Platform::FreeBsd
                | Platform::OpenBsd
                | Platform::NetBsd
                | Platform::DragonFlyBsd
                | Platform::OpenWrt
                | Platform::Qnx
                | Platform::Esxi
                | Platform::Zos
        )
    });
    // Linux-specific features: systemd, deb, rpm require Linux, not generic Unix.
    let has_linux = platforms
        .iter()
        .any(|p| matches!(p, Platform::Linux | Platform::OpenWrt));
    let has_android = platforms.contains(&Platform::Android);
    let has_macos = platforms.contains(&Platform::MacOS);
    let has_ios = platforms.contains(&Platform::Ios);
    let has_zos = platforms.contains(&Platform::Zos);
    let has_appliance = platforms.iter().any(Platform::is_appliance_family);
    // macOS is a Unix, so the unix umbrella reaches macOS-native formats too.
    let has_darwin = has_unix || has_macos || has_ios;
    // True when the platform set includes at least one desktop/server OS.
    // Unix covers Linux and macOS for scripting language purposes.
    let has_desktop = has_windows || has_unix || has_macos || has_appliance;

    if from_groups {
        // Silently filter incompatible types from group expansions
        file_types.retain(|ft| {
            match ft {
                // Windows-only formats and languages
                RuleFileType::Pe
                | RuleFileType::Batch
                | RuleFileType::Vbs
                | RuleFileType::PowerShell
                | RuleFileType::Mirc
                | RuleFileType::Asp
                | RuleFileType::DosCom
                | RuleFileType::Lnk
                | RuleFileType::Msi
                | RuleFileType::Nupkg
                | RuleFileType::Cab
                | RuleFileType::Chm => has_windows,
                // ELF runs on Linux/Unix generally; Android APKs and Dex are
                // Android-specific, and Alpine's package format is
                // Linux-specific like systemd/deb/rpm below.
                RuleFileType::Elf => has_unix || has_android,
                RuleFileType::AndroidApk | RuleFileType::Dex => has_android,
                RuleFileType::Jcl => has_zos,
                // Mach-O/Plist/Nib/Ipa and AppleScript/ObjC are macOS/iOS-native;
                // Shell runs on all unix-like systems. macOS is a Unix, so the
                // `unix` umbrella reaches all of them.
                RuleFileType::Macho
                | RuleFileType::Shell
                | RuleFileType::AppleScript
                | RuleFileType::ObjectiveC
                | RuleFileType::IrcII
                | RuleFileType::Plist
                | RuleFileType::Nib
                | RuleFileType::Pbxproj
                | RuleFileType::Ipa
                | RuleFileType::Pkg
                | RuleFileType::Dmg => has_darwin,
                // Swift packages can target Windows, Linux, macOS, and iOS.
                RuleFileType::Swift => has_windows || has_unix || has_macos || has_ios,
                // Server/desktop-only languages — not meaningful on mobile-only
                // targets. Perl belongs here: it is a normal script carrier on
                // every desktop/server OS. PowerShell intentionally remains
                // Windows-only above — its runtime is cross-platform, but
                // non-Windows package delivery is not a realistic malware
                // distribution model for our rules.
                RuleFileType::Perl
                | RuleFileType::Python
                | RuleFileType::Pyc
                | RuleFileType::Ruby
                | RuleFileType::Php
                | RuleFileType::Groovy
                | RuleFileType::Elixir
                | RuleFileType::Scala
                | RuleFileType::Clojure
                | RuleFileType::Jsp
                | RuleFileType::Cfml
                | RuleFileType::Beam
                | RuleFileType::Makefile
                | RuleFileType::Cmake
                | RuleFileType::Dockerfile
                | RuleFileType::PostScript
                | RuleFileType::Tex
                | RuleFileType::Ooxml
                | RuleFileType::OleDoc
                | RuleFileType::Rtf => has_desktop,
                // These languages and their bytecode ship on desktops and on
                // both phone platforms. iOS rules already match C, Rust, Go,
                // Zig, Kotlin, and C#; Android rules match class and jar files.
                RuleFileType::C
                | RuleFileType::Cpp
                | RuleFileType::Rust
                | RuleFileType::Go
                | RuleFileType::Zig
                | RuleFileType::CSharp
                | RuleFileType::StaticLib
                | RuleFileType::Java
                | RuleFileType::Kotlin
                | RuleFileType::Class
                | RuleFileType::Jar => has_desktop || has_android || has_ios,
                // systemd/deb/rpm/AlpineApk are Linux-specific, not generic Unix
                RuleFileType::AlpineApk
                | RuleFileType::SystemdService
                | RuleFileType::DesktopEntry
                | RuleFileType::Deb
                | RuleFileType::Rpm
                | RuleFileType::SrcInfo
                | RuleFileType::Xbps
                | RuleFileType::GentooBinpkg => has_linux,
                _ => true,
            }
        });
    } else {
        // Warn on explicitly specified incompatible types
        for ft in file_types.iter() {
            let (supported, required) = match ft {
                // Windows-only formats and languages
                RuleFileType::Pe
                | RuleFileType::Batch
                | RuleFileType::Vbs
                | RuleFileType::PowerShell
                | RuleFileType::Mirc
                | RuleFileType::Asp
                | RuleFileType::DosCom
                | RuleFileType::Lnk
                | RuleFileType::Msi
                | RuleFileType::Nupkg
                | RuleFileType::Cab
                | RuleFileType::Chm => (has_windows, "windows"),
                RuleFileType::Elf => (has_unix || has_android, "linux, unix, or android"),
                RuleFileType::AndroidApk | RuleFileType::Dex => (has_android, "android"),
                RuleFileType::Jcl => (has_zos, "zos"),
                RuleFileType::Macho
                | RuleFileType::Shell
                | RuleFileType::AppleScript
                | RuleFileType::ObjectiveC
                | RuleFileType::IrcII
                | RuleFileType::Plist
                | RuleFileType::Nib
                | RuleFileType::Pbxproj
                | RuleFileType::Ipa
                | RuleFileType::Pkg
                | RuleFileType::Dmg => (has_darwin, "linux, unix, macos, or ios"),
                RuleFileType::Swift => (
                    has_windows || has_unix || has_macos || has_ios,
                    "windows, linux, unix, macos, or ios",
                ),
                RuleFileType::Perl
                | RuleFileType::Python
                | RuleFileType::Pyc
                | RuleFileType::Ruby
                | RuleFileType::Php
                | RuleFileType::Groovy
                | RuleFileType::Elixir
                | RuleFileType::Scala
                | RuleFileType::Clojure
                | RuleFileType::Jsp
                | RuleFileType::Cfml
                | RuleFileType::Beam
                | RuleFileType::Makefile
                | RuleFileType::Cmake
                | RuleFileType::Dockerfile
                | RuleFileType::PostScript
                | RuleFileType::Tex
                | RuleFileType::Ooxml
                | RuleFileType::OleDoc
                | RuleFileType::Rtf => (has_desktop, "linux, unix, macos, or windows"),
                RuleFileType::C
                | RuleFileType::Cpp
                | RuleFileType::Rust
                | RuleFileType::Go
                | RuleFileType::Zig
                | RuleFileType::CSharp
                | RuleFileType::StaticLib
                | RuleFileType::Java
                | RuleFileType::Kotlin
                | RuleFileType::Class
                | RuleFileType::Jar => (
                    has_desktop || has_android || has_ios,
                    "linux, unix, macos, windows, android, or ios",
                ),
                RuleFileType::AlpineApk
                | RuleFileType::SystemdService
                | RuleFileType::DesktopEntry
                | RuleFileType::Deb
                | RuleFileType::Rpm
                | RuleFileType::SrcInfo
                | RuleFileType::Xbps
                | RuleFileType::GentooBinpkg => (has_linux, "linux"),
                _ => continue,
            };
            if !supported {
                warnings.push(format!(
                    "'{}': file type '{ft:?}' requires [{required}] but none are in the platforms list.",
                    id
                ));
            }
        }
    }
}

/// Parse platform strings into Platform enum. `all` is a deliberate scope
/// for evidence that is independent of the target operating system.
pub(crate) fn parse_platforms(platforms: &[String], warnings: &mut Vec<String>) -> Vec<Platform> {
    if platforms.iter().any(|p| p.eq_ignore_ascii_case("all")) && platforms.len() != 1 {
        warnings.push("'platforms: [all]' cannot be combined with other platforms.".to_string());
    }
    platforms
        .iter()
        .filter_map(|p| match p.to_lowercase().as_str() {
            "all" => Some(Platform::All),
            "linux" => Some(Platform::Linux),
            "macos" => Some(Platform::MacOS),
            "windows" => Some(Platform::Windows),
            "unix" => Some(Platform::Unix),
            "android" => Some(Platform::Android),
            "ios" => Some(Platform::Ios),
            "aix" => Some(Platform::Aix),
            "solaris" => Some(Platform::Solaris),
            "freebsd" => Some(Platform::FreeBsd),
            "openbsd" => Some(Platform::OpenBsd),
            "netbsd" => Some(Platform::NetBsd),
            "dragonflybsd" | "dragonfly" => Some(Platform::DragonFlyBsd),
            "openwrt" => Some(Platform::OpenWrt),
            "qnx" => Some(Platform::Qnx),
            "esxi" => Some(Platform::Esxi),
            "zos" | "z/os" => Some(Platform::Zos),
            "appliance" | "network-appliance" => Some(Platform::Appliance),
            "routeros" => Some(Platform::RouterOs),
            "fortios" => Some(Platform::FortiOs),
            "panos" | "pan-os" => Some(Platform::PanOs),
            "iosxe" | "ios-xe" => Some(Platform::IosXe),
            "junos" => Some(Platform::Junos),
            "netscaler" => Some(Platform::Netscaler),
            "ivanti" => Some(Platform::Ivanti),
            "vxworks" => Some(Platform::VxWorks),
            "commodore64" | "c64" => Some(Platform::Commodore64),
            "apple2" | "apple-ii" => Some(Platform::Apple2),
            "vmcms" | "vm/cms" => Some(Platform::VmCms),
            "sapabap" | "sap-abap" => Some(Platform::SapAbap),
            "zxspectrum" | "zx-spectrum" => Some(Platform::ZxSpectrum),
            _ => None,
        })
        .collect()
}

/// Parse architecture strings into Arch enum
/// Parse a rule's `arch:` list. An unknown name is reported and dropped, never
/// read as `all`: a misspelled entry used to widen the rule to every
/// architecture. With nothing recognized the list is empty and the rule runs
/// only on files that carry no architecture.
pub(crate) fn parse_arch(archs: &[String], warnings: &mut Vec<String>) -> Vec<Arch> {
    archs
        .iter()
        .filter_map(|name| {
            let arch = Arch::parse(name);
            if arch.is_none() {
                warnings.push(format!(
                    "Unknown arch '{name}'. Valid values: {}",
                    Arch::RULE_NAMES
                ));
            }
            arch
        })
        .collect()
}

/// Parse criticality string into Criticality enum
/// Returns an error for invalid criticality values instead of silently defaulting
/// A rule's criticality: its own `crit:`, else the file default, else
/// baseline (`none` also means baseline). An unrecognized value falls back to
/// baseline, which would quietly neuter a rule, so it is logged as well as
/// recorded for `cleave validate`.
fn resolve_criticality(
    own: Option<&str>,
    default: Option<&str>,
    rule_id: &str,
    path: &std::path::Path,
    warnings: &mut Vec<String>,
) -> Criticality {
    let Some(value) = own.or(default) else {
        return Criticality::Baseline;
    };
    if value.eq_ignore_ascii_case("none") {
        return Criticality::Baseline;
    }
    parse_criticality(value).unwrap_or_else(|e| {
        tracing::warn!(rule = rule_id, path = %path.display(), "{e}; treating as baseline");
        warnings.push(format!("Rule '{rule_id}' in {}: {e}", path.display()));
        Criticality::Baseline
    })
}

/// The validators a rule is exempt from: its file's default `exempt:` entries
/// and its own. Each must name a known validator and give a reason; one that
/// does not is reported and ignored.
fn resolve_exemptions(
    own: &std::collections::BTreeMap<String, String>,
    defaults: &TraitDefaults,
    rule_id: &str,
    warnings: &mut Vec<String>,
) -> Box<[Box<str>]> {
    let mut ids: Vec<Box<str>> = Vec::new();
    for (validator, reason) in defaults.exempt.iter().chain(own) {
        if crate::validation_controls::validator_spec(validator).is_none() {
            warnings.push(format!(
                "Invalid exemption on rule '{rule_id}': no validator is named '{validator}'"
            ));
        } else if reason.trim().is_empty() {
            warnings.push(format!(
                "Invalid exemption on rule '{rule_id}': exempting it from '{validator}' needs a reason"
            ));
        } else {
            ids.push(validator.as_str().into());
        }
    }
    ids.sort_unstable();
    ids.dedup();
    ids.into_boxed_slice()
}

/// A rule's `crit:`. `filtered` is an output-only level a rule cannot claim.
pub(crate) fn parse_criticality(s: &str) -> Result<Criticality, String> {
    match s.parse() {
        Ok(Criticality::Filtered) | Err(_) => Err(format!(
            "Invalid criticality '{s}'. Valid values: exception, component, baseline, notable, suspicious, hostile"
        )),
        Ok(crit) => Ok(crit),
    }
}

/// Exact exception for the reviewed registry security-hold classification policy.
/// Restrict it to the canonical rule, registry files, file scope and both named
/// alternatives. Neither a copied ID nor an unrelated leg grants an exception.
pub(crate) fn is_registry_security_hold_policy(
    id: &str,
    any: Option<&[Condition]>,
    file_types: &[RuleFileType],
    scope: Option<crate::composite_rules::Scope>,
) -> bool {
    const LEGS: [&str; 2] = [
        "metadata/registry::registry-security-hold",
        "metadata/registry::registry-security-hold-record",
    ];
    id == "objectives/supply-chain/security-hold::registry-security-held-package"
        && file_types == [RuleFileType::Registry]
        && scope == Some(crate::composite_rules::Scope::File)
        && any.is_some_and(|any| {
            any.len() == LEGS.len()
                && LEGS.iter().all(|expected| {
                    any.iter().any(
                        |condition| matches!(condition, Condition::Trait { id } if id == expected),
                    )
                })
        })
}

/// Exact policy exception for a provider-confirmed held dependency on the
/// manifest that declared it. This fact independently determines the verdict.
pub(crate) fn is_declared_dependency_security_hold_policy(
    id: &str,
    all: Option<&[Condition]>,
    file_types: &[RuleFileType],
    scope: Option<crate::composite_rules::Scope>,
) -> bool {
    id == "objectives/supply-chain/security-hold::declared-dependency-security-held"
        && file_types == [RuleFileType::PackageJson]
        && scope == Some(crate::composite_rules::Scope::File)
        && all.is_some_and(|all| {
            matches!(all, [Condition::Trait { id }]
            if id == "metadata/package/dependencies/declaration::declared-dependency-security-held")
        })
}

/// Convert a raw composite rule to a final CompositeTrait, applying file-level defaults
/// Collects warnings into the provided vector instead of printing them.
pub(crate) fn apply_composite_defaults(
    raw: RawCompositeRule,
    defaults: &TraitDefaults,
    warnings: &mut Vec<String>,
    path: &std::path::Path,
) -> CompositeTrait {
    // Parse file_types: use rule-specific if present (unless "none"), else defaults, else [All]
    let warn_start = warnings.len();
    // Detect always-fatal for: errors before apply_vec_default handles "none"
    if let Some(types) = raw.file_types.as_deref() {
        if types.is_empty() {
            warnings.push(
                "Invalid file type: '' (empty 'for: []' is not valid — specify at least one file type)"
                    .to_string(),
            );
        } else if types.iter().any(|s| s.eq_ignore_ascii_case("none")) {
            warnings.push(
                "Invalid file type: 'none' is not valid in 'for:' — every rule must target at \
                 least one file type. Specify concrete types (elf, python, ...) or named groups \
                 (binaries, scripts, source, manifests, documents, media, data)."
                    .to_string(),
            );
        } else if types.iter().any(|s| s.eq_ignore_ascii_case("unknown")) {
            warnings.push(
                "Invalid file type: 'unknown' is not valid in 'for:' — it isn't useful or \
                 supported to write rules that target unknown file types. cleave only invokes \
                 rules whose 'for:' matches the detected type, and 'unknown' files have no \
                 detected type, so the rule could never fire. Specify concrete types or named \
                 groups."
                    .to_string(),
            );
        } else if for_list_contains_all(types) {
            warnings.push(FOR_ALL_REJECTED.to_string());
        }
    } else if defaults.r#for.as_deref().is_some_and(<[String]>::is_empty) {
        warnings.push(
            "Invalid file type: '' (file default 'for: []' is empty — specify at least one file type)"
                .to_string(),
        );
    } else if defaults
        .r#for
        .as_deref()
        .is_some_and(|v| v.iter().any(|s| s.eq_ignore_ascii_case("none")))
    {
        warnings.push(
            "Invalid file type: 'none' is not valid in file default 'for:' — every rule must \
             target at least one file type. Specify concrete types or named groups."
                .to_string(),
        );
    } else if defaults
        .r#for
        .as_deref()
        .is_some_and(|v| v.iter().any(|s| s.eq_ignore_ascii_case("unknown")))
    {
        warnings.push(
            "Invalid file type: 'unknown' is not valid in file default 'for:' — it isn't useful \
             or supported to write rules for unknown file types. Specify concrete types or named \
             groups."
                .to_string(),
        );
    } else if defaults.r#for.as_deref().is_some_and(for_list_contains_all) {
        warnings.push(FOR_ALL_REJECTED_DEFAULTS.to_string());
    }
    let parsed_ft = resolve_rule_file_types(raw.file_types, defaults, warnings);
    let mut file_types = parsed_ft.types;
    let from_groups = parsed_ft.from_groups;
    let for_invalid = warnings[warn_start..]
        .iter()
        .any(|w| w.starts_with("Invalid file type"));
    for w in &mut warnings[warn_start..] {
        *w = format!("{} (composite rule '{}' in {})", w, raw.id, path.display());
    }

    // Validation: require explicit platforms: either on rule or in file defaults.
    if raw.platforms.is_none() && defaults.platforms.is_none() {
        warnings.push(format!(
            "Composite rule '{}' in {}: missing 'platforms:' declaration. Every rule must specify \
             which platforms it targets. List explicit platforms such as [unix, windows, macos], \
             or set a file-wide default in the top-level 'defaults:' section.",
            raw.id,
            path.display()
        ));
    }

    // Parse platforms: use rule-specific if present (unless "none"), else defaults, else [All]
    let warn_start = warnings.len();
    let platforms = match apply_vec_default(raw.platforms, &defaults.platforms) {
        Some(plats) => {
            let parsed = parse_platforms(&plats, warnings);
            if parsed.is_empty() {
                vec![Platform::All]
            } else {
                parsed
            }
        }
        None => vec![Platform::All],
    };

    // Filter or warn about platform/filetype conflicts
    resolve_platform_filetype_conflicts(
        &raw.id,
        &platforms,
        &mut file_types,
        from_groups,
        warnings,
    );
    if !for_invalid {
        check_empty_resolved_for(&file_types, warnings);
    }
    for w in &mut warnings[warn_start..] {
        *w = format!("{} (composite rule '{}' in {})", w, raw.id, path.display());
    }

    // Parse arch: use rule-specific if present (unless "none"), else defaults, else [All]
    let arch_warn_start = warnings.len();
    let arch = apply_vec_default(raw.arch, &defaults.arch)
        .map(|archs| parse_arch(&archs, warnings))
        .unwrap_or_else(|| vec![Arch::All]);
    for w in &mut warnings[arch_warn_start..] {
        *w = format!("{} (composite rule '{}' in {})", w, raw.id, path.display());
    }

    let criticality = resolve_criticality(
        raw.crit.as_deref(),
        defaults.crit.as_deref(),
        &raw.id,
        path,
        warnings,
    );

    // Handle single condition by converting to requires_all
    let requires_all = raw.all.or_else(|| raw.condition.map(|c| vec![c]));

    // Hostile requires intent inference, and a bare OR infers nothing: it fires
    // on whichever single leg matched, which is exactly what an atomic trait
    // does. Atomic traits are held to `suspicious` for this reason (see the
    // clamp in `apply_trait_defaults`); a composite that combines nothing is
    // held to the same ceiling rather than laundering one leg's match into a
    // hostile verdict. Earning hostile means combining distinct signals: an
    // `all:` clause, or `needs: 2`+ across the `any:`.
    let combines_signals = requires_all.as_ref().is_some_and(|all| !all.is_empty())
        || raw.needs.is_some_and(|n| n > 1);
    // Provider security-hold status is hostile by explicit classification policy,
    // rather than by inference of payload behavior. Keep the generic cap intact.
    let security_hold_policy =
        is_registry_security_hold_policy(&raw.id, raw.any.as_deref(), &file_types, raw.scope);
    let criticality =
        if criticality == Criticality::Hostile && !combines_signals && !security_hold_policy {
            warnings.push(format!(
            "Composite '{}' in {}: bare `any:` rule marked 'crit: hostile'. A rule that fires on \
             any single leg performs no intent inference, so it is capped at 'suspicious' like an \
             atomic trait. Add an `all:` leg or raise `needs:` to combine distinct signals, or \
             lower the composite to 'suspicious'.",
            raw.id,
            path.display()
        ));
            Criticality::Suspicious
        } else {
            criticality
        };

    // Check regex patterns in all condition lists
    let warn_start = warnings.len();
    let mut check_conditions = |conditions: &Option<Vec<crate::composite_rules::Condition>>,
                                clause_name: &str| {
        if let Some(conds) = conditions {
            for (idx, cond) in conds.iter().enumerate() {
                let ctx = format!("{} {}[{}]", raw.id, clause_name, idx);
                check_regex_length_with_reuse(&ctx, cond, Some(path), warnings, false);
            }
        }
    };

    check_conditions(&requires_all, "all");
    check_conditions(&raw.any, "any");
    check_conditions(&raw.unless, "unless");

    if let Some(ref downgrade) = raw.downgrade {
        check_conditions(&downgrade.any, "downgrade.any");
        check_conditions(&downgrade.all, "downgrade.all");
    }
    let exempt = resolve_exemptions(&raw.exempt, defaults, &raw.id, warnings);
    for w in &mut warnings[warn_start..] {
        *w = format!("{} (in {})", w, path.display());
    }

    CompositeTrait {
        for_mask_cache: std::sync::OnceLock::new(),
        default_scope_cache: std::sync::OnceLock::new(),
        id: raw.id,
        desc: raw.desc,
        id_shared: std::sync::OnceLock::new(),
        desc_shared: std::sync::OnceLock::new(),
        conf: raw.conf.or(defaults.conf).unwrap_or(1.0),
        crit: criticality,
        mbc: apply_string_default(raw.mbc, &defaults.mbc),
        attack: apply_string_default(raw.attack, &defaults.attack),
        r#ref: raw.r#ref,
        platforms,
        arch,
        r#for: file_types,
        for_from_groups: from_groups,
        size_min: raw.size_min.or(defaults.size_min),
        size_max: raw.size_max.or(defaults.size_max),
        all: requires_all,
        any: raw.any,
        needs: raw.needs,
        near_lines: raw.near_lines,
        near_bytes: raw.near_bytes,
        scope: raw.scope,
        unless: raw.unless,
        not: raw.not,
        downgrade: raw.downgrade,
        exempt,
        defined_in: path.to_path_buf(),
        precision: None,
        required_trait_indices: Vec::new(),
    }
}

/// Auto-fix literal regex patterns by converting them to substr.
/// A pattern is considered literal if it contains only alphanumeric chars and underscores.
/// This provides better performance than regex matching for simple string searches.
fn fix_literal_regex_patterns(condition: &mut crate::composite_rules::Condition) {
    use crate::composite_rules::Condition;

    // Helper to check if a pattern is a literal (no regex metacharacters)
    // Regex metacharacters: . * + ? ^ $ ( ) [ ] { } | \
    let is_literal = |pattern: &str| -> bool {
        !pattern.is_empty()
            && !pattern.chars().any(|c| {
                matches!(
                    c,
                    '.' | '*'
                        | '+'
                        | '?'
                        | '^'
                        | '$'
                        | '('
                        | ')'
                        | '['
                        | ']'
                        | '{'
                        | '}'
                        | '|'
                        | '\\'
                )
            })
    };

    match condition {
        Condition::Raw(RawQuery {
            regex: regex_opt,
            substr,
            ..
        }) if substr.is_none() => {
            if let Some(pattern) = regex_opt
                && is_literal(pattern)
            {
                // Convert regex to substr
                *substr = Some(pattern.clone());
                *regex_opt = None;
            }
        }
        Condition::Symbol(SymbolQuery {
            regex: regex_opt,
            substr,
            ..
        }) if substr.is_none() => {
            if let Some(pattern) = regex_opt
                && is_literal(pattern)
            {
                // Convert regex to substr
                *substr = Some(pattern.clone());
                *regex_opt = None;
            }
        }
        Condition::Path(PathQuery {
            regex: regex_opt,
            substr,
            ..
        }) if substr.is_none() => {
            if let Some(pattern) = regex_opt
                && is_literal(pattern)
            {
                // Convert regex to substr
                *substr = Some(pattern.clone());
                *regex_opt = None;
            }
        }
        _ => {}
    }
}

/// Check that the regex pattern in a condition does not exceed 80 bytes.
const MAX_REGEX_LENGTH_BYTES: usize = 90;
const MAX_REGEX_OR_SYMBOLS: usize = 3;
const MAX_REGEX_OR_SYMBOLS_DATA_TEXT: usize = MAX_REGEX_OR_SYMBOLS * 2;

fn is_data_text_trait_path(path: &std::path::Path) -> bool {
    let mut saw_micro_behaviors = false;
    let mut saw_data = false;
    for component in path.components() {
        let Some(part) = component.as_os_str().to_str() else {
            continue;
        };
        match (saw_micro_behaviors, saw_data, part) {
            (false, _, "micro-behaviors") => saw_micro_behaviors = true,
            (true, false, "data") => saw_data = true,
            (true, true, "text") => return true,
            _ => {}
        }
    }
    false
}

/// Count regex alternation symbols (`|`) outside character classes.
fn count_regex_or_symbols(pattern: &str) -> usize {
    let mut count = 0usize;
    let mut in_char_class = false;
    let mut escaped = false;

    for ch in pattern.chars() {
        if escaped {
            escaped = false;
            continue;
        }

        match ch {
            '\\' => escaped = true,
            '[' if !in_char_class => in_char_class = true,
            ']' if in_char_class => in_char_class = false,
            '|' if !in_char_class => count += 1,
            _ => {}
        }
    }

    count
}

/// Strip leading/trailing regex boundary anchors (`^`, `$`, `\b`) from a
/// pattern fragment, repeatedly so stacked anchors (`\b^…$\b`) collapse fully.
fn strip_boundary_anchors(s: &str) -> &str {
    let mut s = s.trim();
    loop {
        let start = s;
        for prefix in ["^", r"\b"] {
            if let Some(rest) = s.strip_prefix(prefix) {
                s = rest;
                break;
            }
        }
        for suffix in ["$", r"\b"] {
            if let Some(rest) = s.strip_suffix(suffix) {
                s = rest;
                break;
            }
        }
        if s == start {
            return s;
        }
    }
}

/// Detect simple alphanumeric alternation chains like:
/// `word1|word2|word3`, `^word1|word2$`, or the word-boundary-anchored
/// `\b(crond|xinetd|inetd)\b` form (after stripping anchors and a single
/// wrapping group, plus any per-branch boundaries like `\bword\b`).
/// These should be split into atomic exact/word traits instead of one regex.
fn is_simple_alphanumeric_or_chain(pattern: &str) -> bool {
    let mut p = strip_boundary_anchors(pattern);

    // Peel a single alternation-wrapping group: `(…)` or `(?:…)`. The closing
    // `)` must be the last char, so a group around only part of the pattern
    // (e.g. `(foo)|bar`) is left intact and correctly fails the pl-word check.
    if let Some(inner) = p.strip_prefix("(?:").or_else(|| p.strip_prefix('('))
        && let Some(inner) = inner.strip_suffix(')')
    {
        p = strip_boundary_anchors(inner);
    }

    // Must be an alternation to trigger this rule.
    if !p.contains('|') {
        return false;
    }

    let parts: Vec<&str> = p.split('|').collect();
    if parts.len() < 2 {
        return false;
    }

    parts.into_iter().all(|part| {
        let word = strip_boundary_anchors(part);
        !word.is_empty() && word.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
    })
}

fn check_regex_length(
    trait_id: &str,
    condition: &crate::composite_rules::Condition,
    source_path: Option<&std::path::Path>,
    warnings: &mut Vec<String>,
) {
    check_regex_length_with_reuse(trait_id, condition, source_path, warnings, true);
}

// This reviewed SQL grammar binds COPY, an identifier (including quoted and
// schema-qualified forms), optional columns, direction and destination in one
// match. Proximity atoms could combine unrelated SQL statements. Keep the
// exception exact: edits to its language must undergo validation again.
fn reviewed_copy_statement_pattern(
    trait_id: &str,
    pattern: &str,
    source_path: Option<&std::path::Path>,
) -> bool {
    trait_id.rsplit("::").next() == Some("copy-table-source")
        && source_path.is_some_and(|path| {
            path.ends_with("micro-behaviors/data/db/postgresql/copy-program.yaml")
        })
        && pattern
            == r###"(?i)\bCOPY\s+(BINARY\s+)?("([^"\r\n]|""){1,128}"|[A-Za-z_][A-Za-z0-9_$]*)(\s*\.\s*("([^"\r\n]|""){1,128}"|[A-Za-z_][A-Za-z0-9_$]*))?(\s*\([^;]{1,256}\))?\s+(TO\s+(PROGRAM\s+(E\s*)?['$]|(E\s*)?['$]|STDOUT\b)|FROM\s+(PROGRAM\s+(E\s*)?['$]|(E\s*)?['$]|STDIN\b))"###
}

fn check_regex_length_with_reuse(
    trait_id: &str,
    condition: &crate::composite_rules::Condition,
    source_path: Option<&std::path::Path>,
    warnings: &mut Vec<String>,
    enforce_reuse: bool,
) {
    use crate::composite_rules::{Condition, PathQuery};

    if let Some(pattern) = condition_regex(condition) {
        // Comment matchers intentionally combine a short cue with a bounded
        // vocabulary/proximity expression; splitting these into independent
        // comment atoms would lose the context that prevents ordinary prose
        // false positives.
        let comment_context_pattern = matches!(condition, Condition::Comment(_));
        if pattern.len() > MAX_REGEX_LENGTH_BYTES
            && !comment_context_pattern
            && !reviewed_copy_statement_pattern(trait_id, pattern, source_path)
            && !crate::validation_controls::is_validator_disabled("regex-length")
        {
            warnings.push(regex_length_warning(trait_id, pattern));
        }

        let max_or_symbols = if source_path.is_some_and(is_data_text_trait_path) {
            MAX_REGEX_OR_SYMBOLS_DATA_TEXT
        } else {
            MAX_REGEX_OR_SYMBOLS
        };
        let or_symbol_count = count_regex_or_symbols(pattern);
        // `path` matchers idiomatically anchor with `(^|[\\/])…([\\/]|$)` (two
        // pipes before any content) and alternate over extensions/dir names;
        // "decompose into multiple traits" doesn't fit a path-structure matcher,
        // so they are exempt from the alternation-chain check.
        if enforce_reuse
            && or_symbol_count > max_or_symbols
            && !matches!(condition, Condition::Path(PathQuery { .. }))
            && !crate::validation_controls::is_validator_disabled("simple-alternation-chain")
        {
            warnings.push(format!(
                "Trait '{}': regex uses too many '|' symbols ({} > {}). Decompose into multiple traits for better ML analysis: {:?}",
                trait_id, or_symbol_count, max_or_symbols, pattern
            ));
        }

        if enforce_reuse
            && is_simple_alphanumeric_or_chain(pattern)
            && !crate::validation_controls::is_validator_disabled("simple-alternation-chain")
        {
            // `\b`-anchored alternatives match whole words, so each maps cleanly
            // to a `word:` atom; without boundaries, `exact` or `word` may fit.
            let matcher = if pattern.contains(r"\b") {
                "word"
            } else {
                "exact/word"
            };
            warnings.push(format!(
                "Trait '{}': regex is a simple alphanumeric alternation chain. Decompose into one atomic `{}` trait per alternative, joined with an `any:` composite: {:?}",
                trait_id, matcher, pattern
            ));
        }
    }
}

fn condition_regex(condition: &crate::composite_rules::Condition) -> Option<&str> {
    use crate::composite_rules::{Condition, KvQuery};

    match condition {
        Condition::Symbol(SymbolQuery { regex, .. })
        | Condition::Text(TextQuery { regex, .. })
        | Condition::Comment(CommentQuery { regex, .. })
        | Condition::Literal(LiteralQuery { regex, .. })
        | Condition::Raw(RawQuery { regex, .. })
        | Condition::TreeSitter(TreeSitterQuery { regex, .. })
        | Condition::Section(SectionQuery { regex, .. })
        | Condition::Encoded(EncodedQuery { regex, .. })
        | Condition::Path(PathQuery { regex, .. })
        | Condition::Kv(KvQuery { regex, .. }) => regex.as_deref(),
        _ => None,
    }
}

fn check_count_min_regex_alternation(
    trait_id: &str,
    condition: &crate::composite_rules::Condition,
    warnings: &mut Vec<String>,
) {
    let Some(pattern) = condition_regex(condition) else {
        return;
    };
    if count_regex_or_symbols(pattern) == 0
        || crate::validation_controls::is_validator_disabled("count-min-regex-alternation")
    {
        return;
    }

    warnings.push(format!(
        "Trait '{}': count_min with regex alternation may count repeated matches of the same alternative and may not behave as intended. Split the alternatives into atomic conditions and combine them with a composite using `any:` and `needs:`: {:?}",
        trait_id, pattern
    ));
}

fn regex_length_warning(trait_id: &str, pattern: &str) -> String {
    format!(
        "Trait '{}': regex pattern exceeds {} bytes ({} bytes): {:?}. Consider decomposing into a composite of multiple atomic conditions (kv, symbol, ast, text) joined with near_lines/near_bytes for proximity matching.",
        trait_id,
        MAX_REGEX_LENGTH_BYTES,
        pattern.len(),
        pattern
    )
}

/// Auto-prefix trait references in composite rule conditions.
///
/// If a trait reference doesn't contain '::' or '/', prepend the given prefix with ::.
/// This allows local trait references within a file to be automatically namespaced.
pub(crate) fn autoprefix_trait_refs(rule: &mut CompositeTrait, prefix: &str) {
    fn prefix_conditions(conditions: &mut [Condition], prefix: &str) {
        for cond in conditions {
            for id in cond.trait_references_mut() {
                // Only prefix if ID doesn't already contain '::' or '/' (i.e., it's local to this file)
                if !id.contains("::") && !id.contains('/') {
                    *id = format!("{}::{}", prefix, id);
                }
            }
        }
    }

    if let Some(ref mut conditions) = rule.all {
        prefix_conditions(conditions, prefix);
    }
    if let Some(ref mut conditions) = rule.any {
        prefix_conditions(conditions, prefix);
    }
    if let Some(ref mut conditions) = rule.unless {
        prefix_conditions(conditions, prefix);
    }
    if let Some(ref mut downgrade) = rule.downgrade {
        if let Some(ref mut conditions) = downgrade.all {
            prefix_conditions(conditions, prefix);
        }
        if let Some(ref mut conditions) = downgrade.any {
            prefix_conditions(conditions, prefix);
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests;

#[test]
fn test_parse_file_types_ipa() {
    let mut warnings = Vec::new();
    let result = parse_file_types(&["ipa".to_string()], &mut warnings);
    assert!(result.types.contains(&RuleFileType::Ipa));
    assert!(warnings.is_empty());
}

#[cfg(test)]
mod declared_security_hold_policy_tests;
