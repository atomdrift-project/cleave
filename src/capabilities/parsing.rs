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
use crate::composite_rules::{CompositeTrait, FileType as RuleFileType, Platform, TraitDefinition};
use crate::types::Criticality;
use std::collections::HashSet;

use super::models::{RawCompositeRule, RawTraitDefinition, TraitDefaults};

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
    }
    let parsed_ft = apply_vec_default(raw.file_types, &defaults.r#for)
        .map(|types| parse_file_types(&types, warnings))
        .unwrap_or_else(|| ParsedFileTypes {
            types: vec![RuleFileType::All],
            from_groups: false,
        });
    let mut file_types = parsed_ft.types;
    let from_groups = parsed_ft.from_groups;
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
    for w in &mut warnings[warn_start..] {
        *w = format!("{} (trait '{}' in {})", w, raw.id, path.display());
    }

    // Parse arch: use trait-specific if present (unless "none"), else defaults, else [All]
    let arch = apply_vec_default(raw.arch, &defaults.arch)
        .map(|archs| parse_arch(&archs))
        .unwrap_or_else(|| vec![Arch::All]);

    // Parse criticality: "none" means baseline
    let mut criticality = match &raw.crit {
        Some(v) if v.eq_ignore_ascii_case("none") => Criticality::Baseline,
        Some(v) => match parse_criticality(v) {
            Ok(crit) => crit,
            Err(e) => {
                warnings.push(format!("Trait '{}' in {}: {}", raw.id, path.display(), e));
                Criticality::Baseline
            }
        },
        None => match defaults.crit.as_deref() {
            Some(v) => match parse_criticality(v) {
                Ok(crit) => crit,
                Err(e) => {
                    warnings.push(format!(
                        "Default criticality in {} (trait '{}'): {}",
                        path.display(),
                        raw.id,
                        e
                    ));
                    Criticality::Baseline
                }
            },
            None => Criticality::Baseline,
        },
    };

    // Stricter validation for HOSTILE traits: atomic traits cannot be HOSTILE
    if criticality == Criticality::Hostile {
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

    // For size-only traits without a condition, create a synthetic "always-true" condition
    // This uses a basename regex that matches everything
    let mut condition = raw.condition.unwrap_or_else(|| {
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

    // Validate regex size and alternation shape. Count/density constraints do
    // not exempt a pattern: they change how matches are tallied, not whether a
    // large alternation should be decomposed into independently meaningful
    // conditions.
    let warn_start = warnings.len();
    check_regex_length(&raw.id, &condition, Some(path), warnings);
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
                check_regex_length(&ctx, cond, Some(path), warnings);
            }
        }
        if let Some(ref all) = downgrade.all {
            for (idx, cond) in all.iter().enumerate() {
                let ctx = format!("{} downgrade.all[{}]", raw.id, idx);
                check_regex_length(&ctx, cond, Some(path), warnings);
            }
        }
        if let Some(ref none) = downgrade.none {
            for (idx, cond) in none.iter().enumerate() {
                let ctx = format!("{} downgrade.none[{}]", raw.id, idx);
                check_regex_length(&ctx, cond, Some(path), warnings);
            }
        }
    }
    for w in &mut warnings[warn_start..] {
        *w = format!("{} (in {})", w, path.display());
    }

    let mut trait_def = TraitDefinition {
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
        defined_in: path.to_path_buf(),
        precision: None,
    };

    if enable_precision_scoring {
        trait_def.precision = Some(super::validation::calculate_trait_precision(&trait_def));
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
                    | "binaries"
                    | "scripts"
                    | "source"
                    | "manifests"
                    | "documents"
                    | "images"
                    | "media"
                    | "ipa"
                    | "archives"
            );
            if is_group && !is_exclusion {
                used_groups = true;
            }

            let variants = match lower_name.as_str() {
                "all" | "*" => vec![],
                // Groups
                "binaries" => vec![
                    RuleFileType::Elf,
                    RuleFileType::Macho,
                    RuleFileType::Pe,
                    RuleFileType::Class,
                    RuleFileType::Pyc,
                    RuleFileType::Beam,
                    RuleFileType::Wasm,
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
                    RuleFileType::Plist,
                    RuleFileType::Lnk,
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
                "images" | "media" => vec![RuleFileType::Jpeg, RuleFileType::Png],
                "ipa" => vec![RuleFileType::Ipa],
                "archives" => RuleFileType::archive_family_types().to_vec(),
                "unknown" => vec![RuleFileType::Unknown],
                // Binary formats
                "elf" | "so" => vec![RuleFileType::Elf],
                "macho" | "dylib" => vec![RuleFileType::Macho],
                "pe" | "dll" => vec![RuleFileType::Pe],
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
                "markdown" | "md" => vec![RuleFileType::Markdown],
                "makefile" | "make" | "mk" | "mak" => vec![RuleFileType::Makefile],
                "dockerfile" | "docker" | "containerfile" => vec![RuleFileType::Dockerfile],
                "text" | "txt" | "b64" | "base64" => vec![RuleFileType::Text],
                // `data` maps to the concrete Data type (opaque .dat/.bin/.payload
                // content) — NOT a group. An alias that collides with a real file
                // type must resolve to that type; authors who want loose text-ish
                // content write `[text, data, json]` explicitly.
                "data" | "dat" | "bin" | "payload" | "raw" => vec![RuleFileType::Data],
                "json" => vec![RuleFileType::Json],
                "gyp" | "gypi" | "binding.gyp" => vec![RuleFileType::Gyp],
                // Compiled languages (fullname + extension)
                "java" => vec![RuleFileType::Java],
                "class" | "java_class" | "javaclass" => vec![RuleFileType::Class],
                "pyc" | "python-bytecode" | "pythonbytecode" => vec![RuleFileType::Pyc],
                "wasm" | "webassembly" => vec![RuleFileType::Wasm],
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
                "xml" | "csproj" | "msbuild" | "xaml" | "svg" | "xml-document" => {
                    vec![RuleFileType::Xml]
                }
                // Image formats
                "jpeg" | "jpg" => vec![RuleFileType::Jpeg],
                "png" => vec![RuleFileType::Png],
                // Serialized data
                "pickle" | "pkl" => vec![RuleFileType::Pickle],
                // Other formats
                "plist" => vec![RuleFileType::Plist],
                "pkginfo" => vec![RuleFileType::PkgInfo],
                "rtf" => vec![RuleFileType::Rtf],
                "lnk" => vec![RuleFileType::Lnk],
                "pdf" => vec![RuleFileType::Pdf],
                // Microsoft Office formats
                "oledoc" | "ole" | "doc" | "xls" | "ppt" | "msg" => {
                    vec![RuleFileType::OleDoc]
                }
                "ooxml" | "docx" | "xlsx" | "pptx" | "docm" | "xlsm" | "pptm" => {
                    vec![RuleFileType::Ooxml]
                }
                "archive" | "rar" | "7z" => vec![RuleFileType::Archive],
                "zip" => vec![RuleFileType::Zip],
                "apk" => vec![RuleFileType::Apk],
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
                | RuleFileType::Lnk
                | RuleFileType::Nupkg => has_windows,
                // ELF and APK both run on Linux/Android
                RuleFileType::Elf | RuleFileType::Apk => has_unix || has_android,
                RuleFileType::Jcl => has_zos,
                // Mach-O/Plist/Ipa and AppleScript/Swift/ObjC are macOS/iOS-native;
                // Shell runs on all unix-like systems. macOS is a Unix, so the
                // `unix` umbrella reaches all of them.
                RuleFileType::Macho
                | RuleFileType::Shell
                | RuleFileType::AppleScript
                | RuleFileType::Swift
                | RuleFileType::ObjectiveC
                | RuleFileType::Plist
                | RuleFileType::Ipa => has_darwin,
                // Perl is a unix/linux scripting language, not a macOS-native concern
                RuleFileType::Perl => has_unix,
                // Server/desktop-only languages — not meaningful on mobile-only targets
                RuleFileType::Python
                | RuleFileType::Pyc
                | RuleFileType::Ruby
                | RuleFileType::Php
                | RuleFileType::Groovy
                | RuleFileType::Elixir
                | RuleFileType::Scala => has_desktop,
                // systemd/deb/rpm are Linux-specific, not generic Unix
                RuleFileType::SystemdService
                | RuleFileType::DesktopEntry
                | RuleFileType::Deb
                | RuleFileType::Rpm => has_linux,
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
                | RuleFileType::Lnk
                | RuleFileType::Nupkg => (has_windows, "windows"),
                // ELF and APK both run on Linux/Android
                RuleFileType::Elf | RuleFileType::Apk => {
                    (has_unix || has_android, "linux, unix, or android")
                }
                RuleFileType::Jcl => (has_zos, "zos"),
                RuleFileType::Shell => (has_darwin, "linux, unix, macos, or ios"),
                // macOS/iOS-native languages and formats — the `unix` umbrella
                // includes macOS, so a unix-targeting trait satisfies them.
                RuleFileType::Macho
                | RuleFileType::AppleScript
                | RuleFileType::Swift
                | RuleFileType::ObjectiveC
                | RuleFileType::Plist
                | RuleFileType::Ipa => (has_darwin, "macos, ios, or unix"),
                RuleFileType::Perl => (has_unix, "linux or unix"),
                RuleFileType::Python
                | RuleFileType::Pyc
                | RuleFileType::Ruby
                | RuleFileType::Php
                | RuleFileType::Groovy
                | RuleFileType::Elixir
                | RuleFileType::Scala => (has_desktop, "linux, unix, macos, or windows"),
                RuleFileType::SystemdService
                | RuleFileType::DesktopEntry
                | RuleFileType::Deb
                | RuleFileType::Rpm => (has_linux, "linux"),
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

/// Parse platform strings into Platform enum.
/// Emits a warning if "all" is explicitly specified — omit `platforms:` instead.
pub(crate) fn parse_platforms(platforms: &[String], warnings: &mut Vec<String>) -> Vec<Platform> {
    platforms
        .iter()
        .filter_map(|p| match p.to_lowercase().as_str() {
            "all" => {
                warnings.push(
                    "'platforms: [all]' is not allowed. Specify explicit platforms: \
                     linux, macos, windows, unix, android, ios, aix, solaris, freebsd, openbsd, \
                     netbsd, dragonflybsd, openwrt, qnx, esxi, zos, appliance, routeros, fortios."
                        .to_string(),
                );
                None
            }
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
            _ => None,
        })
        .collect()
}

/// Parse architecture strings into Arch enum
pub(crate) fn parse_arch(archs: &[String]) -> Vec<Arch> {
    archs.iter().map(|a| Arch::from_str(a)).collect()
}

/// Parse criticality string into Criticality enum
/// Returns an error for invalid criticality values instead of silently defaulting
pub(crate) fn parse_criticality(s: &str) -> Result<Criticality, String> {
    match s.to_lowercase().as_str() {
        "exception" => Ok(Criticality::Exception),
        "component" => Ok(Criticality::Component),
        "baseline" => Ok(Criticality::Baseline),
        "notable" => Ok(Criticality::Notable),
        "suspicious" => Ok(Criticality::Suspicious),
        "hostile" | "malicious" => Ok(Criticality::Hostile),
        unknown => Err(format!(
            "Invalid criticality '{}'. Valid values: exception, component, baseline, notable, suspicious, hostile",
            unknown
        )),
    }
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
    }
    let parsed_ft = apply_vec_default(raw.file_types, &defaults.r#for)
        .map(|types| parse_file_types(&types, warnings))
        .unwrap_or_else(|| ParsedFileTypes {
            types: vec![RuleFileType::All],
            from_groups: false,
        });
    let mut file_types = parsed_ft.types;
    let from_groups = parsed_ft.from_groups;
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
    for w in &mut warnings[warn_start..] {
        *w = format!("{} (composite rule '{}' in {})", w, raw.id, path.display());
    }

    // Parse arch: use rule-specific if present (unless "none"), else defaults, else [All]
    let arch = apply_vec_default(raw.arch, &defaults.arch)
        .map(|archs| parse_arch(&archs))
        .unwrap_or_else(|| vec![Arch::All]);

    // Parse criticality: "none" means baseline
    let criticality = match &raw.crit {
        Some(v) if v.eq_ignore_ascii_case("none") => Criticality::Baseline,
        Some(v) => match parse_criticality(v) {
            Ok(crit) => crit,
            Err(e) => {
                warnings.push(format!(
                    "Composite rule '{}' in {}: {}",
                    raw.id,
                    path.display(),
                    e
                ));
                Criticality::Baseline
            }
        },
        None => match defaults.crit.as_deref() {
            Some(v) => match parse_criticality(v) {
                Ok(crit) => crit,
                Err(e) => {
                    warnings.push(format!(
                        "Default criticality in {} (composite rule '{}'): {}",
                        path.display(),
                        raw.id,
                        e
                    ));
                    Criticality::Baseline
                }
            },
            None => Criticality::Baseline,
        },
    };

    // Handle single condition by converting to requires_all
    let requires_all = raw.all.or_else(|| raw.condition.map(|c| vec![c]));

    // Check regex patterns in all condition lists
    let warn_start = warnings.len();
    let mut check_conditions = |conditions: &Option<Vec<crate::composite_rules::Condition>>,
                                clause_name: &str| {
        if let Some(conds) = conditions {
            for (idx, cond) in conds.iter().enumerate() {
                let ctx = format!("{} {}[{}]", raw.id, clause_name, idx);
                check_regex_length(&ctx, cond, Some(path), warnings);
            }
        }
    };

    check_conditions(&requires_all, "all");
    check_conditions(&raw.any, "any");
    check_conditions(&raw.unless, "unless");

    if let Some(ref downgrade) = raw.downgrade {
        check_conditions(&downgrade.any, "downgrade.any");
        check_conditions(&downgrade.all, "downgrade.all");
        check_conditions(&downgrade.none, "downgrade.none");
    }
    for w in &mut warnings[warn_start..] {
        *w = format!("{} (in {})", w, path.display());
    }

    CompositeTrait {
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
    use crate::composite_rules::{Condition, PathQuery};

    if let Some(pattern) = condition_regex(condition) {
        // Comment matchers intentionally combine a short cue with a bounded
        // vocabulary/proximity expression; splitting these into independent
        // comment atoms would lose the context that prevents ordinary prose
        // false positives.
        let comment_context_pattern = matches!(condition, Condition::Comment(_));
        if pattern.len() > MAX_REGEX_LENGTH_BYTES
            && !comment_context_pattern
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
        if or_symbol_count > max_or_symbols
            && !matches!(condition, Condition::Path(PathQuery { .. }))
            && !crate::validation_controls::is_validator_disabled("simple-alternation-chain")
        {
            warnings.push(format!(
                "Trait '{}': regex uses too many '|' symbols ({} > {}). Decompose into multiple traits for better ML analysis: {:?}",
                trait_id, or_symbol_count, max_or_symbols, pattern
            ));
        }

        if is_simple_alphanumeric_or_chain(pattern)
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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    // ==================== apply_string_default Tests ====================

    #[test]
    fn test_apply_string_default_raw_value() {
        let result = apply_string_default(Some("custom".to_string()), &Some("default".to_string()));
        assert_eq!(result, Some("custom".to_string()));
    }

    #[test]
    fn test_apply_string_default_uses_default() {
        let result = apply_string_default(None, &Some("default".to_string()));
        assert_eq!(result, Some("default".to_string()));
    }

    #[test]
    fn test_apply_string_default_none_unsets() {
        let result = apply_string_default(Some("none".to_string()), &Some("default".to_string()));
        assert_eq!(result, None);
    }

    #[test]
    fn test_apply_string_default_both_none() {
        let result = apply_string_default(None, &None);
        assert_eq!(result, None);
    }

    // ==================== apply_vec_default Tests ====================

    #[test]
    fn test_apply_vec_default_raw_value() {
        let result = apply_vec_default(
            Some(vec!["a".to_string(), "b".to_string()]),
            &Some(vec!["default".to_string()]),
        );
        assert_eq!(result, Some(vec!["a".to_string(), "b".to_string()]));
    }

    #[test]
    fn test_apply_vec_default_uses_default() {
        let result = apply_vec_default(None, &Some(vec!["default".to_string()]));
        assert_eq!(result, Some(vec!["default".to_string()]));
    }

    #[test]
    fn test_apply_vec_default_none_unsets() {
        let result = apply_vec_default(
            Some(vec!["none".to_string()]),
            &Some(vec!["default".to_string()]),
        );
        assert_eq!(result, None);
    }

    #[test]
    fn test_apply_vec_default_none_mixed() {
        // If "none" appears anywhere in the vec, it unsets
        let result = apply_vec_default(
            Some(vec!["value".to_string(), "NONE".to_string()]),
            &Some(vec!["default".to_string()]),
        );
        assert_eq!(result, None);
    }

    // ==================== parse_criticality Tests ====================

    #[test]
    fn test_parse_criticality_baseline() {
        assert_eq!(
            parse_criticality("baseline").unwrap(),
            Criticality::Baseline
        );
        assert_eq!(
            parse_criticality("baseline").unwrap(),
            Criticality::Baseline
        );
    }

    #[test]
    fn test_parse_criticality_notable() {
        assert_eq!(parse_criticality("notable").unwrap(), Criticality::Notable);
        assert_eq!(parse_criticality("NOTABLE").unwrap(), Criticality::Notable);
    }

    #[test]
    fn test_parse_criticality_suspicious() {
        assert_eq!(
            parse_criticality("suspicious").unwrap(),
            Criticality::Suspicious
        );
        assert_eq!(
            parse_criticality("SUSPICIOUS").unwrap(),
            Criticality::Suspicious
        );
    }

    #[test]
    fn test_parse_criticality_hostile() {
        assert_eq!(parse_criticality("hostile").unwrap(), Criticality::Hostile);
        assert_eq!(parse_criticality("HOSTILE").unwrap(), Criticality::Hostile);
        assert_eq!(
            parse_criticality("malicious").unwrap(),
            Criticality::Hostile
        );
    }

    #[test]
    fn test_parse_criticality_unknown_returns_error() {
        assert!(parse_criticality("unknown").is_err());
        assert!(parse_criticality("").is_err());
        assert!(parse_criticality("high").is_err());
        assert!(parse_criticality("critical").is_err());
        assert!(parse_criticality("dangerous").is_err());

        // Check error message
        let err = parse_criticality("dangerous").unwrap_err();
        assert!(err.contains("dangerous"));
        assert!(err.contains("baseline"));
        assert!(err.contains("hostile"));
    }

    // ==================== parse_platforms Tests ====================

    #[test]
    fn test_parse_platforms_all_is_invalid() {
        let mut warnings = Vec::new();
        let result = parse_platforms(&["all".to_string()], &mut warnings);
        assert!(
            result.is_empty(),
            "Platform::All should not be produced from 'all'"
        );
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("platforms: [all]"));
    }

    #[test]
    fn test_parse_platforms_multiple() {
        let mut warnings = Vec::new();
        let result = parse_platforms(
            &[
                "linux".to_string(),
                "macos".to_string(),
                "windows".to_string(),
            ],
            &mut warnings,
        );
        assert!(warnings.is_empty());
        assert!(result.contains(&Platform::Linux));
        assert!(result.contains(&Platform::MacOS));
        assert!(result.contains(&Platform::Windows));
    }

    #[test]
    fn test_parse_platforms_case_insensitive() {
        let mut warnings = Vec::new();
        let result = parse_platforms(&["LINUX".to_string(), "MacOS".to_string()], &mut warnings);
        assert!(warnings.is_empty());
        assert!(result.contains(&Platform::Linux));
        assert!(result.contains(&Platform::MacOS));
    }

    #[test]
    fn test_parse_platforms_unknown_ignored() {
        let mut warnings = Vec::new();
        let result = parse_platforms(&["linux".to_string(), "unknown".to_string()], &mut warnings);
        assert_eq!(result.len(), 1);
        assert!(result.contains(&Platform::Linux));
    }

    #[test]
    fn test_parse_platforms_unix_android_ios() {
        let mut warnings = Vec::new();
        let result = parse_platforms(
            &["unix".to_string(), "android".to_string(), "ios".to_string()],
            &mut warnings,
        );
        assert!(warnings.is_empty());
        assert!(result.contains(&Platform::Unix));
        assert!(result.contains(&Platform::Android));
        assert!(result.contains(&Platform::Ios));
    }

    // ==================== check_platform_filetype_conflicts Tests ====================

    #[test]
    fn test_no_conflict_windows_pe() {
        let mut w = Vec::new();
        resolve_platform_filetype_conflicts(
            "test",
            &[Platform::Windows],
            &mut vec![RuleFileType::Pe, RuleFileType::Batch],
            false,
            &mut w,
        );
        assert!(w.is_empty(), "Windows + PE/Batch should be valid");
    }

    #[test]
    fn test_no_conflict_unix_elf() {
        let mut w = Vec::new();
        resolve_platform_filetype_conflicts(
            "test",
            &[Platform::Linux, Platform::Unix, Platform::Android],
            &mut vec![RuleFileType::Elf],
            false,
            &mut w,
        );
        assert!(w.is_empty(), "Linux/Unix/Android + ELF should be valid");
    }

    #[test]
    fn test_no_conflict_apple_macho() {
        let mut w = Vec::new();
        resolve_platform_filetype_conflicts(
            "test",
            &[Platform::MacOS, Platform::Ios],
            &mut vec![RuleFileType::Macho],
            false,
            &mut w,
        );
        assert!(w.is_empty(), "macOS/iOS + Mach-O should be valid");
    }

    #[test]
    fn test_no_conflict_unix_shell() {
        let mut w = Vec::new();
        resolve_platform_filetype_conflicts(
            "test",
            &[Platform::Linux, Platform::MacOS, Platform::Android],
            &mut vec![RuleFileType::Shell],
            false,
            &mut w,
        );
        assert!(w.is_empty(), "Unix/macOS + Shell should be valid");
    }

    #[test]
    fn test_conflict_windows_elf() {
        let mut w = Vec::new();
        resolve_platform_filetype_conflicts(
            "rule.test",
            &[Platform::Windows],
            &mut vec![RuleFileType::Elf],
            false,
            &mut w,
        );
        assert_eq!(w.len(), 1);
        assert!(
            w[0].contains("linux, unix, or android"),
            "message should name required platforms"
        );
    }

    #[test]
    fn test_conflict_windows_shell() {
        let mut w = Vec::new();
        resolve_platform_filetype_conflicts(
            "rule.test",
            &[Platform::Windows],
            &mut vec![RuleFileType::Shell],
            false,
            &mut w,
        );
        assert_eq!(w.len(), 1);
        assert!(w[0].contains("Shell"));
    }

    #[test]
    fn test_conflict_windows_macho() {
        let mut w = Vec::new();
        resolve_platform_filetype_conflicts(
            "rule.test",
            &[Platform::Windows],
            &mut vec![RuleFileType::Macho],
            false,
            &mut w,
        );
        assert_eq!(w.len(), 1);
        assert!(
            w[0].contains("macos, ios, or unix"),
            "message should name required platforms"
        );
    }

    #[test]
    fn test_conflict_linux_pe() {
        let mut w = Vec::new();
        resolve_platform_filetype_conflicts(
            "rule.test",
            &[Platform::Linux],
            &mut vec![RuleFileType::Pe],
            false,
            &mut w,
        );
        assert_eq!(w.len(), 1);
        assert!(
            w[0].contains("windows"),
            "message should name required platform"
        );
    }

    #[test]
    fn test_conflict_unix_pe() {
        let mut w = Vec::new();
        resolve_platform_filetype_conflicts(
            "rule.test",
            &[Platform::Unix],
            &mut vec![RuleFileType::Pe],
            false,
            &mut w,
        );
        assert_eq!(w.len(), 1);
    }

    #[test]
    fn test_conflict_macos_elf() {
        let mut w = Vec::new();
        resolve_platform_filetype_conflicts(
            "rule.test",
            &[Platform::MacOS],
            &mut vec![RuleFileType::Elf],
            false,
            &mut w,
        );
        assert_eq!(w.len(), 1);
        assert!(
            w[0].contains("linux, unix, or android"),
            "message should name required platforms"
        );
    }

    #[test]
    fn test_conflict_ios_pe() {
        let mut w = Vec::new();
        resolve_platform_filetype_conflicts(
            "rule.test",
            &[Platform::Ios],
            &mut vec![RuleFileType::Pe],
            false,
            &mut w,
        );
        assert_eq!(w.len(), 1);
    }

    #[test]
    fn test_conflict_linux_macho() {
        // Linux sets has_unix (linux | unix), which now permits Mach-O since unix is the superset
        // of macOS. Linux alone is sufficient to allow macho — no conflict expected.
        let mut w = Vec::new();
        resolve_platform_filetype_conflicts(
            "rule.test",
            &[Platform::Linux],
            &mut vec![RuleFileType::Macho],
            false,
            &mut w,
        );
        assert!(w.is_empty(), "Linux covers Macho via unix superset: {w:?}");
    }

    #[test]
    fn test_no_conflict_when_platform_all() {
        // Platform::All skips the check entirely
        let mut w = Vec::new();
        resolve_platform_filetype_conflicts(
            "rule.test",
            &[Platform::All],
            &mut vec![RuleFileType::Pe],
            false,
            &mut w,
        );
        assert!(w.is_empty(), "Platform::All should bypass conflict check");
    }

    #[test]
    fn test_no_conflict_when_filetype_all() {
        let mut w = Vec::new();
        resolve_platform_filetype_conflicts(
            "rule.test",
            &[Platform::Windows],
            &mut vec![RuleFileType::All],
            false,
            &mut w,
        );
        assert!(w.is_empty(), "FileType::All should bypass conflict check");
    }

    #[test]
    fn test_elf_valid_on_android() {
        // ELF is the native format on Android — no conflict
        let mut w = Vec::new();
        resolve_platform_filetype_conflicts(
            "rule.test",
            &[Platform::Android],
            &mut vec![RuleFileType::Elf],
            false,
            &mut w,
        );
        assert!(w.is_empty(), "Android + ELF should be valid");
    }

    #[test]
    fn test_multiple_conflicts_reported() {
        // Windows + [ELF, Shell] → two warnings, one per unsupported file type
        let mut w = Vec::new();
        resolve_platform_filetype_conflicts(
            "rule.test",
            &[Platform::Windows],
            &mut vec![RuleFileType::Elf, RuleFileType::Shell],
            false,
            &mut w,
        );
        assert_eq!(w.len(), 2);
    }

    #[test]
    fn test_no_conflict_multiplatform_binaries() {
        // platforms=[windows,unix] + for=[pe,elf] is valid:
        // PE is covered by windows, ELF is covered by unix.
        let mut w = Vec::new();
        resolve_platform_filetype_conflicts(
            "rule.test",
            &[Platform::Windows, Platform::Unix],
            &mut vec![RuleFileType::Pe, RuleFileType::Elf],
            false,
            &mut w,
        );
        assert!(
            w.is_empty(),
            "windows+unix covering pe+elf should be valid: {w:?}"
        );
    }

    #[test]
    fn test_no_conflict_multiplatform_all_binaries() {
        // windows+unix+macos covering pe+elf+macho — fully covered
        let mut w = Vec::new();
        resolve_platform_filetype_conflicts(
            "rule.test",
            &[Platform::Windows, Platform::Unix, Platform::MacOS],
            &mut vec![RuleFileType::Pe, RuleFileType::Elf, RuleFileType::Macho],
            false,
            &mut w,
        );
        assert!(w.is_empty(), "all three covered: {w:?}");
    }

    #[test]
    fn test_conflict_partial_multiplatform() {
        // windows+unix covers pe+elf+macho: unix is the superset including macOS, so no conflict
        let mut w = Vec::new();
        resolve_platform_filetype_conflicts(
            "rule.test",
            &[Platform::Windows, Platform::Unix],
            &mut vec![RuleFileType::Pe, RuleFileType::Elf, RuleFileType::Macho],
            false,
            &mut w,
        );
        assert!(
            w.is_empty(),
            "windows+unix should cover pe+elf+macho: {w:?}"
        );
    }

    // ==================== from_groups filtering Tests ====================

    #[test]
    fn test_group_filter_macos_binaries() {
        let mut w = Vec::new();
        let mut ft = vec![
            RuleFileType::Elf,
            RuleFileType::Macho,
            RuleFileType::Pe,
            RuleFileType::Class,
            RuleFileType::Pyc,
        ];
        resolve_platform_filetype_conflicts("test", &[Platform::MacOS], &mut ft, true, &mut w);
        assert!(w.is_empty(), "from_groups should not warn: {w:?}");
        assert!(ft.contains(&RuleFileType::Macho));
        assert!(ft.contains(&RuleFileType::Class));
        assert!(ft.contains(&RuleFileType::Pyc));
        assert!(!ft.contains(&RuleFileType::Pe));
        assert!(!ft.contains(&RuleFileType::Elf));
    }

    #[test]
    fn test_group_filter_windows_scripts() {
        let mut w = Vec::new();
        let mut ft = vec![
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
        ];
        resolve_platform_filetype_conflicts("test", &[Platform::Windows], &mut ft, true, &mut w);
        assert!(w.is_empty(), "from_groups should not warn: {w:?}");
        // Windows-specific script types kept
        assert!(ft.contains(&RuleFileType::Batch));
        assert!(ft.contains(&RuleFileType::Vbs));
        // Platform-agnostic script types kept
        assert!(ft.contains(&RuleFileType::Python));
        assert!(ft.contains(&RuleFileType::JavaScript));
        assert!(ft.contains(&RuleFileType::Ruby));
        assert!(ft.contains(&RuleFileType::Php));
        assert!(ft.contains(&RuleFileType::Lua));
        assert!(ft.contains(&RuleFileType::PowerShell));
        // Perl requires unix — filtered out for windows-only
        assert!(!ft.contains(&RuleFileType::Perl));
        // AppleScript requires macos/ios — filtered out for windows-only
        assert!(!ft.contains(&RuleFileType::AppleScript));
        // Shell requires unix/apple — filtered out for windows-only
        assert!(!ft.contains(&RuleFileType::Shell));
        // JCL requires z/OS — filtered out for windows-only
        assert!(!ft.contains(&RuleFileType::Jcl));
    }

    #[test]
    fn test_group_filter_preserves_agnostic() {
        let mut w = Vec::new();
        let mut ft = vec![
            RuleFileType::Python,
            RuleFileType::JavaScript,
            RuleFileType::Shell,
            RuleFileType::Pe,
            RuleFileType::Elf,
            RuleFileType::Macho,
        ];
        resolve_platform_filetype_conflicts("test", &[Platform::MacOS], &mut ft, true, &mut w);
        assert!(w.is_empty(), "from_groups should not warn: {w:?}");
        assert!(ft.contains(&RuleFileType::Python));
        assert!(ft.contains(&RuleFileType::JavaScript));
        assert!(ft.contains(&RuleFileType::Shell));
        assert!(ft.contains(&RuleFileType::Macho));
        assert!(!ft.contains(&RuleFileType::Pe));
        assert!(!ft.contains(&RuleFileType::Elf));
    }

    // ==================== parse_file_types Tests ====================

    #[test]
    fn test_parse_file_types_all() {
        let mut warnings = Vec::new();
        let result = parse_file_types(&["all".to_string()], &mut warnings);
        assert_eq!(result.types, vec![RuleFileType::All]);
        assert!(warnings.is_empty());
    }

    #[test]
    fn test_parse_file_types_star() {
        let mut warnings = Vec::new();
        let result = parse_file_types(&["*".to_string()], &mut warnings);
        assert_eq!(result.types, vec![RuleFileType::All]);
        assert!(warnings.is_empty());
    }

    #[test]
    fn test_parse_file_types_specific() {
        let mut warnings = Vec::new();
        let result = parse_file_types(
            &["python".to_string(), "javascript".to_string()],
            &mut warnings,
        );
        assert!(result.types.contains(&RuleFileType::Python));
        assert!(result.types.contains(&RuleFileType::JavaScript));
        assert!(warnings.is_empty());
    }

    #[test]
    fn test_parse_file_types_new_filefacts_labels_without_parser_arms() {
        let mut warnings = Vec::new();
        let result = parse_file_types(
            &[
                "dmg".to_string(),
                "asar".to_string(),
                "oci_image".to_string(),
                "xbps".to_string(),
                "gentoo_binpkg".to_string(),
                "cargo.lock".to_string(),
            ],
            &mut warnings,
        );

        assert!(result.types.contains(&RuleFileType::Dmg));
        assert!(result.types.contains(&RuleFileType::Asar));
        assert!(result.types.contains(&RuleFileType::OciImage));
        assert!(result.types.contains(&RuleFileType::Xbps));
        assert!(result.types.contains(&RuleFileType::GentooBinpkg));
        assert!(result.types.contains(&RuleFileType::CargoLock));
        assert!(warnings.is_empty(), "unexpected warnings: {warnings:?}");
    }

    #[test]
    fn test_archives_group_uses_generated_archive_family() {
        let mut warnings = Vec::new();
        let result = parse_file_types(&["archives".to_string()], &mut warnings);

        assert_eq!(result.types, RuleFileType::archive_family_types().to_vec());
        assert!(warnings.is_empty(), "unexpected warnings: {warnings:?}");
    }

    #[test]
    fn test_parse_file_types_aliases() {
        let mut warnings = Vec::new();
        let result = parse_file_types(
            &[
                "py".to_string(),
                "js".to_string(),
                "ts".to_string(),
                "rb".to_string(),
                "java_class".to_string(),
                "javaclass".to_string(),
                "systemd-service".to_string(),
                "systemd".to_string(),
            ],
            &mut warnings,
        );
        assert!(result.types.contains(&RuleFileType::Python));
        assert!(result.types.contains(&RuleFileType::JavaScript)); // "ts" also maps to JavaScript
        assert!(result.types.contains(&RuleFileType::Ruby));
        assert!(result.types.contains(&RuleFileType::Class));
        assert!(result.types.contains(&RuleFileType::SystemdService));
        assert!(warnings.is_empty());
    }

    #[test]
    fn test_parse_file_types_binaries() {
        let mut warnings = Vec::new();
        let result = parse_file_types(&["binaries".to_string()], &mut warnings);
        assert!(result.types.contains(&RuleFileType::Elf));
        assert!(result.types.contains(&RuleFileType::Macho));
        assert!(result.types.contains(&RuleFileType::Pe));
        assert!(warnings.is_empty());
    }

    #[test]
    fn test_parse_file_types_scripts() {
        let mut warnings = Vec::new();
        let result = parse_file_types(&["scripts".to_string()], &mut warnings);
        assert!(result.types.contains(&RuleFileType::Shell));
        assert!(result.types.contains(&RuleFileType::Python));
        assert!(result.types.contains(&RuleFileType::JavaScript));
        assert!(warnings.is_empty());
    }

    #[test]
    fn test_parse_file_types_exclusion() {
        let mut warnings = Vec::new();
        let result = parse_file_types(&["all".to_string(), "-python".to_string()], &mut warnings);
        assert!(!result.types.contains(&RuleFileType::Python));
        assert!(result.types.contains(&RuleFileType::JavaScript));
        assert!(result.types.contains(&RuleFileType::Shell));
        assert!(warnings.is_empty());
    }

    #[test]
    fn test_parse_file_types_comma_separated() {
        let mut warnings = Vec::new();
        let result = parse_file_types(&["python,javascript,ruby".to_string()], &mut warnings);
        assert!(result.types.contains(&RuleFileType::Python));
        assert!(result.types.contains(&RuleFileType::JavaScript));
        assert!(result.types.contains(&RuleFileType::Ruby));
        assert!(warnings.is_empty());
    }

    #[test]
    fn test_parse_file_types_case_insensitive() {
        let mut warnings = Vec::new();
        let result = parse_file_types(
            &["PYTHON".to_string(), "JavaScript".to_string()],
            &mut warnings,
        );
        assert!(result.types.contains(&RuleFileType::Python));
        assert!(result.types.contains(&RuleFileType::JavaScript));
        assert!(warnings.is_empty());
    }

    #[test]
    fn test_parse_file_types_package_files() {
        let mut warnings = Vec::new();
        let result = parse_file_types(
            &[
                "package.json".to_string(),
                "package-lock.json".to_string(),
                "go.mod".to_string(),
                "cargo.toml".to_string(),
                "pyproject.toml".to_string(),
            ],
            &mut warnings,
        );
        assert!(result.types.contains(&RuleFileType::PackageJson));
        assert!(result.types.contains(&RuleFileType::PackageLockJson));
        assert!(result.types.contains(&RuleFileType::GoMod));
        assert!(result.types.contains(&RuleFileType::CargoToml));
        assert!(result.types.contains(&RuleFileType::PyProjectToml));
        assert!(warnings.is_empty());
    }

    #[test]
    fn test_parse_file_types_image_formats() {
        let mut warnings = Vec::new();
        let result = parse_file_types(&["jpeg".to_string(), "png".to_string()], &mut warnings);
        assert!(result.types.contains(&RuleFileType::Jpeg));
        assert!(result.types.contains(&RuleFileType::Png));
        assert!(warnings.is_empty());
    }

    #[test]
    fn test_parse_file_types_exclusion_only() {
        // When only exclusions are provided, start with all and remove
        let mut warnings = Vec::new();
        let result = parse_file_types(
            &["-python".to_string(), "-javascript".to_string()],
            &mut warnings,
        );
        assert!(!result.types.contains(&RuleFileType::Python));
        assert!(!result.types.contains(&RuleFileType::JavaScript));
        assert!(result.types.contains(&RuleFileType::Shell));
        assert!(result.types.contains(&RuleFileType::Ruby));
        assert!(warnings.is_empty());
    }

    #[test]
    fn test_parse_file_types_bang_exclusion_backcompat() {
        let mut warnings = Vec::new();
        let result = parse_file_types(&["all".to_string(), "!python".to_string()], &mut warnings);
        assert!(!result.types.contains(&RuleFileType::Python));
        assert!(result.types.contains(&RuleFileType::JavaScript));
        assert!(warnings.is_empty());
    }

    #[test]
    fn test_parse_file_types_unknown_type() {
        let mut warnings = Vec::new();
        let result = parse_file_types(
            &["python".to_string(), "invalid_type".to_string()],
            &mut warnings,
        );
        assert!(result.types.contains(&RuleFileType::Python));
        assert_eq!(warnings.len(), 1);
        assert_eq!(warnings[0], "Unknown file type: 'invalid_type'");
    }

    #[test]
    fn test_parse_file_types_multiple_unknown() {
        let mut warnings = Vec::new();
        let result = parse_file_types(
            &["pyton".to_string(), "javascrpt".to_string()],
            &mut warnings,
        );
        assert!(result.types.is_empty());
        assert_eq!(warnings.len(), 2);
        assert!(warnings.contains(&"Unknown file type: 'pyton'".to_string()));
        assert!(warnings.contains(&"Unknown file type: 'javascrpt'".to_string()));
    }

    // ==================== for: validation Tests ====================

    fn make_raw_trait(
        id: &str,
        file_types: Option<Vec<String>>,
    ) -> super::super::models::RawTraitDefinition {
        super::super::models::RawTraitDefinition {
            id: id.to_string(),
            desc: "A valid trait description here".to_string(),
            conf: None,
            crit: None,
            mbc: None,
            attack: None,
            platforms: None,
            arch: None,
            file_types,
            size_min: None,
            size_max: None,
            count_min: None,
            count_max: None,
            per_kb_min: None,
            per_kb_max: None,
            entropy_min: None,
            entropy_max: None,
            condition: None,
            not: None,
            unless: None,
            downgrade: None,
            ..Default::default()
        }
    }

    #[test]
    fn test_for_missing_on_trait_and_defaults_warns() {
        let defaults = super::super::models::TraitDefaults::default();
        let raw = make_raw_trait("test-trait", None);
        let mut warnings = Vec::new();
        super::apply_trait_defaults(
            raw,
            &defaults,
            &mut warnings,
            std::path::Path::new("test.yaml"),
            true,
        );
        assert!(
            warnings
                .iter()
                .any(|w| w.contains("missing 'for:' declaration")),
            "expected for: warning, got: {:?}",
            warnings
        );
    }

    #[test]
    fn test_for_on_trait_suppresses_warning() {
        let defaults = super::super::models::TraitDefaults::default();
        let raw = make_raw_trait("test-trait", Some(vec!["python".to_string()]));
        let mut warnings = Vec::new();
        super::apply_trait_defaults(
            raw,
            &defaults,
            &mut warnings,
            std::path::Path::new("test.yaml"),
            true,
        );
        assert!(
            !warnings
                .iter()
                .any(|w| w.contains("missing 'for:' declaration")),
            "unexpected for: warning"
        );
    }

    #[test]
    fn test_for_in_defaults_suppresses_warning() {
        let defaults = super::super::models::TraitDefaults {
            r#for: Some(vec!["all".to_string()]),
            ..Default::default()
        };
        let raw = make_raw_trait("test-trait", None);
        let mut warnings = Vec::new();
        super::apply_trait_defaults(
            raw,
            &defaults,
            &mut warnings,
            std::path::Path::new("test.yaml"),
            true,
        );
        assert!(
            !warnings
                .iter()
                .any(|w| w.contains("missing 'for:' declaration")),
            "unexpected for: warning"
        );
    }

    #[test]
    fn test_for_none_is_rejected_with_clear_warning() {
        // `for: [none]` used to be a way to unset inherited file types
        // back to All. Commit 60975df2 ("clearer err message when for:
        // [none] is used") intentionally turned this into an error so
        // trait authors are forced to either omit `for:` or list
        // concrete types. The pipeline still defaults `r#for` to
        // `[All]` so downstream code keeps working, but a warning is
        // emitted to surface the misuse.
        let defaults = super::super::models::TraitDefaults {
            platforms: Some(vec![
                "linux".to_string(),
                "macos".to_string(),
                "windows".to_string(),
            ]),
            r#for: Some(vec!["python".to_string()]),
            ..super::super::models::TraitDefaults::default()
        };
        let raw = make_raw_trait("test-trait", Some(vec!["none".to_string()]));
        let mut warnings = Vec::new();
        let result = super::apply_trait_defaults(
            raw,
            &defaults,
            &mut warnings,
            std::path::Path::new("test.yaml"),
            true,
        );
        assert!(
            result
                .r#for
                .contains(&crate::composite_rules::FileType::All),
            "for: [none] should still fall back to All for downstream safety, got: {:?}",
            result.r#for
        );
        assert!(
            warnings.iter().any(|w| w.contains("'none' is not valid")),
            "expected a clear-error warning explaining 'none' is invalid in 'for:', got: {:?}",
            warnings
        );
    }

    #[test]
    fn test_for_unknown_is_rejected_with_clear_warning() {
        // `for: [unknown]` looks plausible — `FileType::Unknown` exists
        // as an internal sentinel for files cleave couldn't identify —
        // but rules targeting "unknown" can never fire usefully because
        // the engine only invokes rules whose `for:` matches the
        // detected type. The warning steers authors toward concrete
        // types or named groups.
        let defaults = super::super::models::TraitDefaults {
            platforms: Some(vec!["linux".to_string()]),
            ..super::super::models::TraitDefaults::default()
        };
        let raw = make_raw_trait("test-trait", Some(vec!["unknown".to_string()]));
        let mut warnings = Vec::new();
        super::apply_trait_defaults(
            raw,
            &defaults,
            &mut warnings,
            std::path::Path::new("test.yaml"),
            true,
        );
        assert!(
            warnings.iter().any(|w| {
                w.contains("'unknown' is not valid") && w.contains("isn't useful or supported")
            }),
            "expected a clear-error warning explaining 'unknown' is invalid in 'for:', got: {:?}",
            warnings
        );
    }

    #[test]
    fn test_for_empty_is_fatal_error() {
        let defaults = super::super::models::TraitDefaults::default();
        let raw = make_raw_trait("test-trait", Some(vec![]));
        let mut warnings = Vec::new();
        super::apply_trait_defaults(
            raw,
            &defaults,
            &mut warnings,
            std::path::Path::new("test.yaml"),
            true,
        );
        assert!(
            warnings
                .iter()
                .any(|w| w.contains("Invalid file type") && w.contains("empty")),
            "expected fatal empty for: error, got: {:?}",
            warnings
        );
    }

    #[test]
    fn test_for_empty_defaults_is_fatal_error() {
        let defaults = super::super::models::TraitDefaults {
            r#for: Some(vec![]),
            ..Default::default()
        };
        let raw = make_raw_trait("test-trait", None);
        let mut warnings = Vec::new();
        super::apply_trait_defaults(
            raw,
            &defaults,
            &mut warnings,
            std::path::Path::new("test.yaml"),
            true,
        );
        assert!(
            warnings
                .iter()
                .any(|w| w.contains("Invalid file type") && w.contains("empty")),
            "expected fatal empty defaults error, got: {:?}",
            warnings
        );
    }

    // ==================== Regex length Tests ====================

    #[test]
    fn test_regex_length_ok() {
        let pattern = "a".repeat(MAX_REGEX_LENGTH_BYTES);
        let condition = crate::composite_rules::Condition::Path(PathQuery {
            exact: None,
            substr: None,
            regex: Some(pattern),
            case_insensitive: false,
            is_check: None,
            basename: true,
            dirname: false,
        });
        let mut warnings = Vec::new();
        super::check_regex_length("test-trait", &condition, None, &mut warnings);
        assert!(warnings.is_empty());
    }

    #[test]
    fn test_regex_length_over_limit_warns() {
        let pattern = "a".repeat(MAX_REGEX_LENGTH_BYTES + 1);
        let condition = crate::composite_rules::Condition::Path(PathQuery {
            exact: None,
            substr: None,
            regex: Some(pattern),
            case_insensitive: false,
            is_check: None,
            basename: true,
            dirname: false,
        });
        let mut warnings = Vec::new();
        super::check_regex_length("test-trait", &condition, None, &mut warnings);
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("regex pattern exceeds 90 bytes"));
        assert!(warnings[0].contains("91 bytes"));
    }

    #[test]
    fn test_regex_length_warning_uses_limit() {
        let pattern = "a".repeat(MAX_REGEX_LENGTH_BYTES + 1);
        let warning = super::regex_length_warning("test-trait", &pattern);
        assert!(warning.contains("regex pattern exceeds 90 bytes"));
        assert!(warning.contains("91 bytes"));
    }

    #[test]
    fn test_regex_length_no_regex_no_warning() {
        let condition = crate::composite_rules::Condition::Path(PathQuery {
            exact: None,
            substr: Some("some substring".to_string()),
            regex: None,
            case_insensitive: false,
            is_check: None,
            basename: true,
            dirname: false,
        });
        let mut warnings = Vec::new();
        super::check_regex_length("test-trait", &condition, None, &mut warnings);
        assert!(warnings.is_empty());
    }

    #[test]
    fn test_regex_length_non_regex_condition_no_warning() {
        let condition = crate::composite_rules::Condition::Trait {
            id: "some-trait-id".to_string(),
        };
        let mut warnings = Vec::new();
        super::check_regex_length("test-trait", &condition, None, &mut warnings);
        assert!(warnings.is_empty());
    }

    #[test]
    fn test_regex_or_symbol_limit_warns() {
        // `path` matchers are exempt from the alternation-chain check (their
        // `(^|[\\/])…` anchoring spends pipes structurally), so exercise the
        // limit with a content matcher that is subject to it.
        let condition = crate::composite_rules::Condition::Text(TextQuery {
            length_min: None,
            length_max: None,
            exact: None,
            substr: None,
            regex: Some("a|b|c|d|e".to_string()),
            word: None,
            case_insensitive: false,
            is_check: None,
            not: None,
            platforms: None,
            section: None,
            offset: None,
            offset_range: None,
            section_offset: None,
            section_offset_range: None,
        });
        let mut warnings = Vec::new();
        super::check_regex_length("test-trait", &condition, None, &mut warnings);
        assert!(warnings.iter().any(|w| w.contains("too many '|' symbols")));
    }

    #[test]
    fn test_regex_or_symbol_limit_allows_escaped_and_charclass_pipes() {
        let condition = crate::composite_rules::Condition::Text(TextQuery {
            length_min: None,
            length_max: None,
            exact: None,
            substr: None,
            regex: Some(r"a\|b|[|]|c|d".to_string()),
            word: None,
            case_insensitive: false,
            is_check: None,
            not: None,
            platforms: None,
            section: None,
            offset: None,
            offset_range: None,
            section_offset: None,
            section_offset_range: None,
        });
        let mut warnings = Vec::new();
        super::check_regex_length("test-trait", &condition, None, &mut warnings);
        assert!(!warnings.iter().any(|w| w.contains("too many '|' symbols")));
    }

    #[test]
    fn test_regex_or_symbol_limit_relaxed_for_data_text_traits() {
        let condition = crate::composite_rules::Condition::Text(TextQuery {
            length_min: None,
            length_max: None,
            exact: None,
            substr: None,
            regex: Some("a|b|c|d|e|f|g".to_string()),
            word: None,
            case_insensitive: false,
            is_check: None,
            not: None,
            platforms: None,
            section: None,
            offset: None,
            offset_range: None,
            section_offset: None,
            section_offset_range: None,
        });
        let mut warnings = Vec::new();
        super::check_regex_length(
            "test-trait",
            &condition,
            Some(std::path::Path::new(
                "micro-behaviors/data/text/llm/action/traits.yaml",
            )),
            &mut warnings,
        );
        assert!(!warnings.iter().any(|w| w.contains("too many '|' symbols")));
    }

    #[test]
    fn test_regex_or_symbol_limit_still_caps_data_text_traits() {
        let condition = crate::composite_rules::Condition::Text(TextQuery {
            length_min: None,
            length_max: None,
            exact: None,
            substr: None,
            regex: Some("a|b|c|d|e|f|g|h".to_string()),
            word: None,
            case_insensitive: false,
            is_check: None,
            not: None,
            platforms: None,
            section: None,
            offset: None,
            offset_range: None,
            section_offset: None,
            section_offset_range: None,
        });
        let mut warnings = Vec::new();
        super::check_regex_length(
            "test-trait",
            &condition,
            Some(std::path::Path::new(
                "micro-behaviors/data/text/llm/action/traits.yaml",
            )),
            &mut warnings,
        );
        assert!(warnings.iter().any(|w| w.contains("too many '|' symbols")));
    }

    #[test]
    fn test_simple_alphanumeric_alternation_warns() {
        let condition = crate::composite_rules::Condition::Path(PathQuery {
            exact: None,
            substr: None,
            regex: Some("word1|word2|word3".to_string()),
            case_insensitive: false,
            is_check: None,
            basename: true,
            dirname: false,
        });
        let mut warnings = Vec::new();
        super::check_regex_length("test-trait", &condition, None, &mut warnings);
        assert!(
            warnings
                .iter()
                .any(|w| w.contains("simple alphanumeric alternation chain"))
        );
    }

    #[test]
    fn test_count_density_trait_not_exempt_from_alternation_warning() {
        let condition = crate::composite_rules::Condition::Text(TextQuery {
            regex: Some(r"\b(MODE_GCM|MODE_CTR)\b".to_string()),
            ..Default::default()
        });
        let mut warnings = Vec::new();
        super::check_regex_length("test-trait", &condition, None, &mut warnings);
        assert!(
            warnings
                .iter()
                .any(|w| w.contains("simple alphanumeric alternation chain")),
            "count/density traits must follow the normal alternation policy: {warnings:?}"
        );
    }

    #[test]
    fn test_count_min_regex_alternation_warns_about_repeated_branch_counts() {
        let condition = crate::composite_rules::Condition::Literal(LiteralQuery {
            regex: Some("^(location|screen)=".to_string()),
            ..Default::default()
        });
        let mut warnings = Vec::new();
        super::check_count_min_regex_alternation("profile-fields", &condition, &mut warnings);
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].contains("may count repeated matches of the same alternative"));
        assert!(warnings[0].contains("`any:` and `needs:`"));
    }

    #[test]
    fn test_apply_trait_defaults_rejects_count_min_regex_alternation() {
        let mut raw = make_raw_trait("profile-fields", Some(vec!["javascript".to_string()]));
        raw.count_min = Some(3);
        raw.condition = Some(crate::composite_rules::Condition::Literal(LiteralQuery {
            regex: Some("^(location|screen)=".to_string()),
            ..Default::default()
        }));
        let mut warnings = Vec::new();
        super::apply_trait_defaults(
            raw,
            &super::super::models::TraitDefaults::default(),
            &mut warnings,
            std::path::Path::new("profile-fields.yaml"),
            true,
        );
        assert!(
            warnings
                .iter()
                .any(|warning| warning.contains("count_min with regex alternation")),
            "expected count_min/alternation warning, got: {warnings:?}"
        );
    }

    #[test]
    fn test_count_min_regex_alternation_ignores_literal_pipes() {
        for pattern in [r"a\|b", r"[|]"] {
            let condition = crate::composite_rules::Condition::Text(TextQuery {
                regex: Some(pattern.to_string()),
                ..Default::default()
            });
            let mut warnings = Vec::new();
            super::check_count_min_regex_alternation("literal-pipe", &condition, &mut warnings);
            assert!(
                warnings.is_empty(),
                "literal pipe was treated as alternation: {pattern}"
            );
        }
    }

    #[test]
    fn test_word_boundary_grouped_alternation_warns() {
        // `\b(crond|xinetd|inetd)\b` has only 2 pipes (under the or-symbol cap)
        // and the `\b`/`()` previously hid it from the alternation-chain check.
        let condition = crate::composite_rules::Condition::Text(TextQuery {
            regex: Some(r"\b(crond|xinetd|inetd)\b".to_string()),
            ..Default::default()
        });
        let mut warnings = Vec::new();
        super::check_regex_length("test-trait", &condition, None, &mut warnings);
        let warning = warnings
            .iter()
            .find(|w| w.contains("simple alphanumeric alternation chain"))
            .expect("word-boundary grouped alternation should warn");
        // Boundary-anchored alternatives should be steered to `word:` atoms.
        assert!(
            warning.contains("`word`"),
            "expected word: advice: {warning}"
        );
    }

    #[test]
    fn test_per_branch_word_boundary_alternation_warns() {
        let condition = crate::composite_rules::Condition::Text(TextQuery {
            regex: Some(r"\bcrond\b|\bxinetd\b".to_string()),
            ..Default::default()
        });
        let mut warnings = Vec::new();
        super::check_regex_length("test-trait", &condition, None, &mut warnings);
        assert!(
            warnings
                .iter()
                .any(|w| w.contains("simple alphanumeric alternation chain"))
        );
    }

    #[test]
    fn test_partial_group_alternation_does_not_warn() {
        // `(foo)|bar` is not a single wrapping group; must not be misread as a
        // simple chain (the `)` survives and fails the plain-word check).
        assert!(!super::is_simple_alphanumeric_or_chain("(foo)|bar"));
        assert!(!super::is_simple_alphanumeric_or_chain(r"(a|b)(c|d)"));
    }

    #[test]
    fn test_non_simple_alternation_does_not_warn() {
        let condition = crate::composite_rules::Condition::Path(PathQuery {
            exact: None,
            substr: None,
            regex: Some(r"word1|word-2|\d+".to_string()),
            case_insensitive: false,
            is_check: None,
            basename: true,
            dirname: false,
        });
        let mut warnings = Vec::new();
        super::check_regex_length("test-trait", &condition, None, &mut warnings);
        assert!(
            !warnings
                .iter()
                .any(|w| w.contains("simple alphanumeric alternation chain"))
        );
    }
}

#[test]
fn test_parse_file_types_ipa() {
    let mut warnings = Vec::new();
    let result = parse_file_types(&["ipa".to_string()], &mut warnings);
    assert!(result.types.contains(&RuleFileType::Ipa));
    assert!(warnings.is_empty());
}
