use super::*;

/// A misspelled `arch:` entry is reported and dropped. It used to parse as
/// `all`, silently widening the rule to every architecture.
#[test]
fn unknown_rule_arch_is_reported_not_widened() {
    let mut warnings = Vec::new();
    let archs = parse_arch(&["x86".to_string(), "x86_46".to_string()], &mut warnings);
    assert_eq!(archs, vec![Arch::X86]);
    assert_eq!(warnings.len(), 1);
    assert!(
        warnings[0].contains("Unknown arch 'x86_46'"),
        "{warnings:?}"
    );
}

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
fn test_parse_apple2_platform_alias() {
    let mut warnings = Vec::new();
    let result = parse_platforms(&["apple2".into(), "apple-ii".into()], &mut warnings);
    assert_eq!(result, vec![Platform::Apple2, Platform::Apple2]);
    assert!(warnings.is_empty());
}

#[test]
fn test_parse_commodore_platform_alias() {
    let mut warnings = Vec::new();
    let result = parse_platforms(&["commodore64".into(), "c64".into()], &mut warnings);
    assert_eq!(result, vec![Platform::Commodore64, Platform::Commodore64]);
    assert!(warnings.is_empty());
}

#[test]
fn test_parse_vm_cms_platform_alias() {
    let mut warnings = Vec::new();
    let result = parse_platforms(&["vmcms".into(), "vm/cms".into()], &mut warnings);
    assert_eq!(result, vec![Platform::VmCms, Platform::VmCms]);
    assert!(warnings.is_empty());
}

#[test]
fn test_parse_sap_abap_platform_alias() {
    let mut warnings = Vec::new();
    let result = parse_platforms(&["sapabap".into(), "sap-abap".into()], &mut warnings);
    assert_eq!(result, vec![Platform::SapAbap, Platform::SapAbap]);
    assert!(warnings.is_empty());
}

#[test]
fn test_parse_zx_spectrum_platform_alias() {
    let mut warnings = Vec::new();
    let result = parse_platforms(&["zxspectrum".into(), "zx-spectrum".into()], &mut warnings);
    assert_eq!(result, vec![Platform::ZxSpectrum, Platform::ZxSpectrum]);
    assert!(warnings.is_empty());
}

#[test]
fn test_parse_platforms_all_is_valid() {
    let mut warnings = Vec::new();
    let result = parse_platforms(&["all".to_string()], &mut warnings);
    assert_eq!(result, vec![Platform::All]);
    assert!(warnings.is_empty());
}

#[test]
fn test_parse_platforms_all_cannot_be_combined() {
    let mut warnings = Vec::new();
    let result = parse_platforms(&["all".to_string(), "windows".to_string()], &mut warnings);
    assert_eq!(result, vec![Platform::All, Platform::Windows]);
    assert_eq!(warnings.len(), 1);
    assert!(warnings[0].contains("cannot be combined"));
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
        w[0].contains("linux, unix, macos, or ios"),
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
        RuleFileType::Mirc,
        RuleFileType::IrcII,
    ];
    resolve_platform_filetype_conflicts("test", &[Platform::Windows], &mut ft, true, &mut w);
    assert!(w.is_empty(), "from_groups should not warn: {w:?}");
    // Windows-specific script types kept
    assert!(ft.contains(&RuleFileType::Batch));
    assert!(ft.contains(&RuleFileType::Vbs));
    assert!(ft.contains(&RuleFileType::Mirc));
    assert!(!ft.contains(&RuleFileType::IrcII));
    // Platform-agnostic script types kept
    assert!(ft.contains(&RuleFileType::Python));
    assert!(ft.contains(&RuleFileType::JavaScript));
    assert!(ft.contains(&RuleFileType::Ruby));
    assert!(ft.contains(&RuleFileType::Php));
    assert!(ft.contains(&RuleFileType::Lua));
    assert!(ft.contains(&RuleFileType::PowerShell));
    assert!(ft.contains(&RuleFileType::Perl));
    // AppleScript requires macos/ios — filtered out for windows-only
    assert!(!ft.contains(&RuleFileType::AppleScript));
    // Shell requires unix/apple — filtered out for windows-only
    assert!(!ft.contains(&RuleFileType::Shell));
    // JCL requires z/OS — filtered out for windows-only
    assert!(!ft.contains(&RuleFileType::Jcl));
}

#[test]
fn test_group_filter_unix_keeps_ircii_not_mirc() {
    let mut w = Vec::new();
    let mut ft = vec![
        RuleFileType::Shell,
        RuleFileType::Batch,
        RuleFileType::Mirc,
        RuleFileType::IrcII,
        RuleFileType::JavaScript,
        RuleFileType::Lua,
        RuleFileType::PowerShell,
    ];
    resolve_platform_filetype_conflicts("test", &[Platform::Unix], &mut ft, true, &mut w);
    assert!(w.is_empty(), "from_groups should not warn: {w:?}");
    assert!(ft.contains(&RuleFileType::Shell));
    assert!(ft.contains(&RuleFileType::IrcII));
    assert!(ft.contains(&RuleFileType::JavaScript));
    assert!(ft.contains(&RuleFileType::Lua));
    assert!(!ft.contains(&RuleFileType::Mirc));
    assert!(!ft.contains(&RuleFileType::Batch));
    assert!(!ft.contains(&RuleFileType::PowerShell));
}

#[test]
fn legacy_platforms_remain_distinct_from_all_and_other_platforms() {
    let mut warnings = Vec::new();
    let names = ["sapabap", "vmcms", "commodore64", "zxspectrum", "apple2"];
    let parsed = parse_platforms(
        &names
            .iter()
            .map(|name| (*name).to_string())
            .collect::<Vec<_>>(),
        &mut warnings,
    );
    assert!(warnings.is_empty(), "{warnings:?}");
    assert_eq!(
        parsed,
        vec![
            Platform::SapAbap,
            Platform::VmCms,
            Platform::Commodore64,
            Platform::ZxSpectrum,
            Platform::Apple2
        ]
    );
    for (platform, name) in parsed.iter().zip(names) {
        assert_eq!(platform.label(), name);
        assert!(platform.matches_filter(platform));
        assert!(platform.matches_filter(&Platform::All));
        assert!(!platform.matches_filter(&Platform::Windows));
    }
}

#[test]
fn jsp_token_stays_on_desktop_platforms() {
    let mut w = Vec::new();
    let parsed = parse_file_types(
        &["jsp".to_string(), "python".to_string(), "html".to_string()],
        &mut w,
    );
    assert!(w.is_empty(), "{w:?} types {:?}", parsed.types);
    assert!(parsed.types.contains(&RuleFileType::Jsp));
    let mut types = parsed.types;
    let platforms = parse_platforms(&["unix".to_string(), "windows".to_string()], &mut w);
    resolve_platform_filetype_conflicts("t", &platforms, &mut types, parsed.from_groups, &mut w);
    assert!(
        types.contains(&RuleFileType::Jsp),
        "jsp dropped: {types:?} from_groups {} warnings {w:?}",
        parsed.from_groups
    );
}

#[test]
fn test_explicit_mirc_requires_windows_and_ircii_requires_unix() {
    let mut w = Vec::new();
    resolve_platform_filetype_conflicts(
        "rule.test",
        &[Platform::Unix],
        &mut vec![RuleFileType::Mirc],
        false,
        &mut w,
    );
    assert_eq!(w.len(), 1, "{w:?}");
    w.clear();
    resolve_platform_filetype_conflicts(
        "rule.test",
        &[Platform::Windows],
        &mut vec![RuleFileType::IrcII],
        false,
        &mut w,
    );
    assert_eq!(w.len(), 1, "{w:?}");
    w.clear();
    resolve_platform_filetype_conflicts(
        "rule.test",
        &[Platform::Windows, Platform::Unix],
        &mut vec![RuleFileType::Mirc, RuleFileType::IrcII],
        false,
        &mut w,
    );
    assert!(w.is_empty(), "{w:?}");
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

#[test]
fn test_group_filter_macos_keeps_perl_not_powershell() {
    let mut w = Vec::new();
    let mut ft = vec![RuleFileType::Perl, RuleFileType::PowerShell];
    resolve_platform_filetype_conflicts("test", &[Platform::MacOS], &mut ft, true, &mut w);
    assert!(w.is_empty(), "group filtering should not warn: {w:?}");
    assert!(ft.contains(&RuleFileType::Perl));
    assert!(!ft.contains(&RuleFileType::PowerShell));
}

#[test]
fn test_group_filter_windows_keeps_swift() {
    let mut w = Vec::new();
    let mut ft = vec![RuleFileType::Swift, RuleFileType::ObjectiveC];
    resolve_platform_filetype_conflicts("test", &[Platform::Windows], &mut ft, true, &mut w);
    assert!(w.is_empty(), "group filtering should not warn: {w:?}");
    assert!(ft.contains(&RuleFileType::Swift));
    assert!(!ft.contains(&RuleFileType::ObjectiveC));
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
fn test_rar_7z_cpio_resolve_through_parse_file_types() {
    let mut warnings = Vec::new();
    let result = parse_file_types(
        &["rar".to_string(), "7z".to_string(), "cpio".to_string()],
        &mut warnings,
    );
    assert!(result.types.contains(&RuleFileType::Rar));
    assert!(result.types.contains(&RuleFileType::SevenZ));
    assert!(result.types.contains(&RuleFileType::Cpio));
    assert!(warnings.is_empty(), "unexpected warnings: {warnings:?}");
}

fn defaults_for(types: &[&str]) -> super::super::models::TraitDefaults {
    super::super::models::TraitDefaults {
        r#for: Some(types.iter().map(|t| (*t).to_string()).collect()),
        platforms: Some(vec!["linux".to_string()]),
        ..super::super::models::TraitDefaults::default()
    }
}

fn trait_warnings(
    defaults: &super::super::models::TraitDefaults,
    file_types: Option<Vec<String>>,
) -> (Vec<RuleFileType>, Vec<String>) {
    let mut warnings = Vec::new();
    let t = super::apply_trait_defaults(
        make_raw_trait("t", file_types),
        defaults,
        &mut warnings,
        std::path::Path::new("x.yaml"),
        false,
    );
    (t.r#for, warnings)
}

#[test]
fn default_file_type_warnings_names_unknown_default_entries() {
    let path = std::path::Path::new("dir/x.yaml");
    let w = super::default_file_type_warnings(&defaults_for(&["archive-typo", "zip"]), path);
    assert_eq!(w.len(), 1, "{w:?}");
    assert!(
        w[0].starts_with("Unknown file type: 'archive-typo'"),
        "{w:?}"
    );
    assert!(w[0].contains("'defaults: for:' in dir/x.yaml"), "{w:?}");

    // Exclusions and comma-joined entries are checked too.
    let w = super::default_file_type_warnings(&defaults_for(&["zip,-archivez"]), path);
    assert_eq!(w.len(), 1, "{w:?}");

    // Valid, absent, or invalid-file-type-owned values raise nothing here.
    for ok in [
        &["zip", "scripts"][..],
        &["none"],
        &["unknown"],
        &["-python"],
    ] {
        let w = super::default_file_type_warnings(&defaults_for(ok), path);
        assert!(w.is_empty(), "{ok:?}: {w:?}");
    }
    let none = super::super::models::TraitDefaults::default();
    assert!(super::default_file_type_warnings(&none, path).is_empty());
}

#[test]
fn inherited_unknown_default_is_not_repeated_per_rule() {
    let defaults = defaults_for(&["archive-typo", "zip"]);
    let (types, w) = trait_warnings(&defaults, None);
    assert_eq!(types, vec![RuleFileType::Zip]);
    assert!(w.is_empty(), "{w:?}");

    // A rule's own unknown name is still reported against the rule.
    let (_, w) = trait_warnings(&defaults, Some(vec!["archive-typo".into(), "zip".into()]));
    assert!(
        w.iter()
            .any(|w| w.starts_with("Unknown file type: 'archive-typo'") && w.contains("trait 't'")),
        "{w:?}"
    );
}

#[test]
fn empty_resolved_for_is_reported() {
    // Inherited default that resolves to nothing.
    let (types, w) = trait_warnings(&defaults_for(&["archive-typo"]), None);
    assert!(types.is_empty());
    assert!(
        w.iter()
            .any(|w| w.starts_with(super::EMPTY_RESOLVED_FOR) && w.contains("trait 't'")),
        "{w:?}"
    );

    // The rule's own list, including one excluded away to nothing.
    for own in [vec!["archive-typo"], vec!["python", "-python"]] {
        let own = own.into_iter().map(String::from).collect();
        let (types, w) = trait_warnings(&defaults_for(&["zip"]), Some(own));
        assert!(types.is_empty());
        assert!(
            w.iter().any(|w| w.starts_with(super::EMPTY_RESOLVED_FOR)),
            "{w:?}"
        );
    }

    // `for: []` is already an invalid-file-type error; no second report.
    let (_, w) = trait_warnings(&defaults_for(&["zip"]), Some(Vec::new()));
    assert!(
        w.iter().any(|w| w.starts_with("Invalid file type")),
        "{w:?}"
    );
    assert!(
        !w.iter().any(|w| w.starts_with(super::EMPTY_RESOLVED_FOR)),
        "{w:?}"
    );

    // A non-empty resolution raises nothing.
    let (_, w) = trait_warnings(&defaults_for(&["zip"]), None);
    assert!(w.is_empty(), "{w:?}");
}

#[test]
#[allow(clippy::expect_used)]
fn empty_resolved_for_is_reported_for_composites() {
    let raw: super::super::models::RawCompositeRule =
        crate::yaml::from_str("{id: c, desc: composite rule here, all: [{id: a}]}")
            .expect("composite yaml");
    let mut warnings = Vec::new();
    let rule = super::apply_composite_defaults(
        raw,
        &defaults_for(&["archive-typo"]),
        &mut warnings,
        std::path::Path::new("x.yaml"),
    );
    assert!(rule.r#for.is_empty());
    assert!(
        warnings
            .iter()
            .any(|w| w.starts_with(super::EMPTY_RESOLVED_FOR) && w.contains("composite rule 'c'")),
        "{warnings:?}"
    );
    assert!(
        !warnings.iter().any(|w| w.starts_with("Unknown file type")),
        "{warnings:?}"
    );
}

#[test]
fn test_archive_family_group_preserves_explicit_exclusions() {
    let mut warnings = Vec::new();
    let parsed = parse_file_types(&["archives".into(), "-zip".into()], &mut warnings);
    assert!(warnings.is_empty(), "{warnings:?}");
    let expected: std::collections::HashSet<_> = RuleFileType::archive_family_types()
        .iter()
        .copied()
        .filter(|t| *t != RuleFileType::Zip)
        .collect();
    assert_eq!(
        parsed
            .types
            .into_iter()
            .collect::<std::collections::HashSet<_>>(),
        expected
    );
    assert!(parsed.from_groups);
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
    assert!(result.types.contains(&RuleFileType::Dex));
    assert!(warnings.is_empty());
}

#[test]
fn pgp_signature_scope_is_a_distinct_routing_bucket() {
    let mut warnings = Vec::new();
    let result = parse_file_types(&["pgp_signature".to_string()], &mut warnings);
    assert_eq!(result.types, vec![RuleFileType::PgpSignature]);
    assert!(warnings.is_empty());
    assert_eq!(RuleFileType::from_str("pgp_signature"), result.types[0]);
    assert_ne!(result.types[0], RuleFileType::Data);
    assert_ne!(result.types[0], RuleFileType::Unknown);
}

#[test]
fn yaml_scope_and_manifest_alias_route_the_real_file_type() {
    let mut warnings = Vec::new();
    for label in ["yaml", "yml"] {
        let result = parse_file_types(&[label.to_string()], &mut warnings);
        assert_eq!(result.types, vec![RuleFileType::Yaml]);
    }
    let result = parse_file_types(&["manifests".to_string()], &mut warnings);
    assert!(result.types.contains(&RuleFileType::Yaml));
    assert_eq!(RuleFileType::from_str("yaml"), RuleFileType::Yaml);
    assert_eq!(
        RuleFileType::from(filefacts::FileType::Yaml),
        RuleFileType::Yaml
    );
    assert!(RuleFileType::Yaml.uses_raw_text_search());
    assert!(!RuleFileType::Yaml.is_source_code());
}

#[test]
fn test_parse_file_types_dex_and_msi() {
    let mut warnings = Vec::new();
    let dex = parse_file_types(&["dex".to_string()], &mut warnings);
    assert_eq!(dex.types, vec![RuleFileType::Dex]);
    let dalvik = parse_file_types(&["dalvik".to_string()], &mut warnings);
    assert_eq!(dalvik.types, vec![RuleFileType::Dex]);
    let msi = parse_file_types(&["msi".to_string()], &mut warnings);
    assert_eq!(msi.types, vec![RuleFileType::Msi]);
    let msp = parse_file_types(&["msp".to_string()], &mut warnings);
    assert_eq!(msp.types, vec![RuleFileType::Msi]);
    let mst = parse_file_types(&["mst".to_string()], &mut warnings);
    assert_eq!(mst.types, vec![RuleFileType::Msi]);
    let msm = parse_file_types(&["msm".to_string()], &mut warnings);
    assert_eq!(msm.types, vec![RuleFileType::Msi]);
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

#[test]
fn hostile_atomic_rule_criticality_respects_its_tier() {
    for (path, expected) in [
        ("objectives/impact/test.yaml", Criticality::Hostile),
        ("well-known/malware/rat/test.yaml", Criticality::Hostile),
        ("micro-behaviors/process/test.yaml", Criticality::Suspicious),
        ("metadata/file/test.yaml", Criticality::Suspicious),
        (
            "/tmp/objectives/repo/metadata/file/test.yaml",
            Criticality::Suspicious,
        ),
    ] {
        let mut raw = make_raw_trait("example", Some(vec!["elf".to_string()]));
        raw.crit = Some("hostile".to_string());
        let mut warnings = Vec::new();
        let rule = apply_trait_defaults(
            raw,
            &defaults_for(&["elf"]),
            &mut warnings,
            std::path::Path::new(path),
            false,
        );
        assert_eq!(rule.crit, expected, "{path}: {warnings:?}");
        assert_eq!(
            warnings.iter().any(|w| w.contains("atomic trait marked")),
            expected == Criticality::Suspicious,
            "{path}: {warnings:?}"
        );
    }
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
        r#for: Some(vec!["binaries".to_string()]),
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
fn test_for_all_is_rejected_with_clear_warning() {
    // RULES.md: `for: [all]` is no longer valid — authors must name concrete
    // types or groups. Runtime still materialises FileType::All so existing
    // traits keep matching until they are rewritten. This is a Soft
    // authoring issue (`for-all`), not a load-breaking invalid file type.
    let defaults = super::super::models::TraitDefaults {
        platforms: Some(vec!["linux".to_string()]),
        ..super::super::models::TraitDefaults::default()
    };
    let raw = make_raw_trait("test-trait", Some(vec!["all".to_string()]));
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
        "for: [all] should still parse as All for downstream safety, got: {:?}",
        result.r#for
    );
    assert!(
        warnings
            .iter()
            .any(|w| { w.contains("for: [all] is not allowed") && w.contains("named groups") }),
        "expected for: [all] soft warning, got: {:?}",
        warnings
    );
}

#[test]
fn test_for_star_is_rejected_like_all() {
    let defaults = super::super::models::TraitDefaults {
        platforms: Some(vec!["linux".to_string()]),
        ..super::super::models::TraitDefaults::default()
    };
    let raw = make_raw_trait("test-trait", Some(vec!["*".to_string()]));
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
            .any(|w| w.contains("for: [all] is not allowed")),
        "expected for: [*] soft warning, got: {:?}",
        warnings
    );
}

#[test]
fn test_for_all_in_defaults_is_rejected() {
    let defaults = super::super::models::TraitDefaults {
        platforms: Some(vec!["linux".to_string()]),
        r#for: Some(vec!["all".to_string()]),
        ..super::super::models::TraitDefaults::default()
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
            .any(|w| { w.contains("for: [all] is not allowed") && w.contains("file default") }),
        "expected defaults for: [all] soft warning, got: {:?}",
        warnings
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
fn reviewed_copy_statement_pattern_has_exact_boundaries() {
    let pattern = r###"(?i)\bCOPY\s+(BINARY\s+)?("([^"\r\n]|""){1,128}"|[A-Za-z_][A-Za-z0-9_$]*)(\s*\.\s*("([^"\r\n]|""){1,128}"|[A-Za-z_][A-Za-z0-9_$]*))?(\s*\([^;]{1,256}\))?\s+(TO\s+(PROGRAM\s+(E\s*)?['$]|(E\s*)?['$]|STDOUT\b)|FROM\s+(PROGRAM\s+(E\s*)?['$]|(E\s*)?['$]|STDIN\b))"###;
    let path = std::path::Path::new("/traits/micro-behaviors/data/db/postgresql/copy-program.yaml");
    assert!(super::reviewed_copy_statement_pattern(
        "micro-behaviors/data/db/postgresql::copy-table-source",
        pattern,
        Some(path),
    ));
    assert!(!super::reviewed_copy_statement_pattern(
        "other",
        pattern,
        Some(path)
    ));
    assert!(!super::reviewed_copy_statement_pattern(
        "copy-table-source",
        pattern,
        None
    ));
    assert!(!super::reviewed_copy_statement_pattern(
        "copy-table-source",
        &format!("{pattern}.*"),
        Some(path),
    ));
    assert!(!super::reviewed_copy_statement_pattern(
        "copy-table-source",
        pattern,
        Some(std::path::Path::new("elsewhere/copy-program.yaml")),
    ));
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
        encoding: None,
        length_min: None,
        length_max: None,
        exclude_html_comments: false,
        exclude_comments: false,
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
        encoding: None,
        length_min: None,
        length_max: None,
        exclude_html_comments: false,
        exclude_comments: false,
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
        encoding: None,
        length_min: None,
        length_max: None,
        exclude_html_comments: false,
        exclude_comments: false,
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
        encoding: None,
        length_min: None,
        length_max: None,
        exclude_html_comments: false,
        exclude_comments: false,
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
