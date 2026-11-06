use super::super::duplicates::*;
use super::super::helpers::extract_tier;
use crate::composite_rules::condition::{ArgFilter, EncodingSpec, SymbolKind};
use crate::composite_rules::{
    Arch, Condition, EncodedQuery, FileType, LiteralQuery, PathQuery, Platform, RawQuery,
    SymbolQuery, TextQuery, TraitDefinition,
};
use std::path::PathBuf;

// ========================================================================
// Test Helpers
// ========================================================================

/// Create a minimal trait definition for testing
/// A `type: text` `substr:` condition, optionally pinned to a section.
fn text_substr_cond(value: &str, section: Option<&str>) -> Condition {
    Condition::Text(TextQuery {
        encoding: None,
        length_min: None,
        length_max: None,
        exclude_html_comments: false,
        exact: None,
        substr: Some(value.to_string()),
        regex: None,
        word: None,
        case_insensitive: false,
        is_check: None,
        not: None,
        platforms: None,
        section: section.map(str::to_string),
        offset: None,
        offset_range: None,
        section_offset: None,
        section_offset_range: None,
    })
}

fn create_test_trait(
    id: &str,
    condition: Condition,
    for_types: Vec<FileType>,
    file_path: &str,
) -> TraitDefinition {
    create_test_trait_with_conf_crit(
        id,
        condition,
        for_types,
        file_path,
        1.0,
        crate::types::Criticality::Notable,
    )
}

/// Create a trait definition with specific confidence and criticality
fn create_test_trait_with_conf_crit(
    id: &str,
    condition: Condition,
    for_types: Vec<FileType>,
    file_path: &str,
    conf: f32,
    crit: crate::types::Criticality,
) -> TraitDefinition {
    TraitDefinition {
        id: id.to_string(),
        desc: "test trait".to_string(),
        conf,
        crit,
        mbc: None,
        attack: None,
        r#if: condition,
        size_min: None,
        size_max: None,
        count_min: None,
        count_max: None,
        per_kb_min: None,
        per_kb_max: None,
        entropy_min: None,
        entropy_max: None,
        r#for: for_types,
        for_from_groups: false,
        platforms: vec![Platform::All],
        arch: vec![Arch::All],
        not: None,
        unless: None,
        downgrade: None,
        defined_in: PathBuf::from(file_path),
        precision: None,
        ..Default::default()
    }
}

/// Create a string exact trait (backed by `Condition::Raw` so the duplicate
/// detectors scoped to Raw/Symbol see the fixture).
fn create_string_exact(
    id: &str,
    pattern: &str,
    case_insensitive: bool,
    for_types: Vec<FileType>,
    file_path: &str,
) -> TraitDefinition {
    create_test_trait(
        id,
        Condition::Raw(RawQuery {
            length_min: None,
            length_max: None,
            exact: Some(pattern.to_string()),
            substr: None,
            regex: None,
            word: None,
            case_insensitive,
            is_check: None,
            not: None,
            section: None,
            offset: None,
            offset_range: None,
            section_offset: None,
            section_offset_range: None,
        }),
        for_types,
        file_path,
    )
}

/// Create a text exact trait.
fn create_text_exact(
    id: &str,
    pattern: &str,
    case_insensitive: bool,
    for_types: Vec<FileType>,
    file_path: &str,
) -> TraitDefinition {
    create_test_trait(
        id,
        Condition::Text(TextQuery {
            encoding: None,
            length_min: None,
            length_max: None,
            exclude_html_comments: false,
            exact: Some(pattern.to_string()),
            substr: None,
            regex: None,
            word: None,
            case_insensitive,
            is_check: None,
            not: None,
            platforms: None,
            section: None,
            offset: None,
            offset_range: None,
            section_offset: None,
            section_offset_range: None,
        }),
        for_types,
        file_path,
    )
}

/// Create a string-literal exact trait.
fn create_string_literal_exact(
    id: &str,
    pattern: &str,
    case_insensitive: bool,
    for_types: Vec<FileType>,
    file_path: &str,
) -> TraitDefinition {
    create_test_trait(
        id,
        Condition::Literal(LiteralQuery {
            kind: None,
            exact: Some(pattern.to_string()),
            substr: None,
            regex: None,
            word: None,
            value: None,
            radix: None,
            case_insensitive,
            exclude_docstrings: false,
            is_check: None,
            not: None,
            platforms: None,
            section: None,
            offset: None,
            offset_range: None,
            section_offset: None,
            section_offset_range: None,
        }),
        for_types,
        file_path,
    )
}

/// Create a string substr trait
fn create_string_substr(
    id: &str,
    pattern: &str,
    case_insensitive: bool,
    for_types: Vec<FileType>,
    file_path: &str,
) -> TraitDefinition {
    create_test_trait(
        id,
        Condition::Raw(RawQuery {
            length_min: None,
            length_max: None,
            exact: None,
            substr: Some(pattern.to_string()),
            regex: None,
            word: None,
            case_insensitive,
            is_check: None,
            not: None,
            section: None,
            offset: None,
            offset_range: None,
            section_offset: None,
            section_offset_range: None,
        }),
        for_types,
        file_path,
    )
}

/// Create an encoded substr trait.
fn create_encoded_substr(
    id: &str,
    pattern: &str,
    for_types: Vec<FileType>,
    file_path: &str,
) -> TraitDefinition {
    create_test_trait(
        id,
        Condition::Encoded(EncodedQuery {
            exact: None,
            substr: Some(pattern.to_string()),
            regex: None,
            word: None,
            case_insensitive: false,
            encoding: Some(EncodingSpec::Single("base64".to_string())),
            is_check: None,
            not: None,
            section: None,
            offset: None,
            offset_range: None,
            section_offset: None,
            section_offset_range: None,
        }),
        for_types,
        file_path,
    )
}

/// Create a string regex trait
fn create_string_regex(
    id: &str,
    pattern: &str,
    case_insensitive: bool,
    for_types: Vec<FileType>,
    file_path: &str,
) -> TraitDefinition {
    create_test_trait(
        id,
        Condition::Raw(RawQuery {
            length_min: None,
            length_max: None,
            exact: None,
            substr: None,
            regex: Some(pattern.to_string()),
            word: None,
            case_insensitive,
            is_check: None,
            not: None,
            section: None,
            offset: None,
            offset_range: None,
            section_offset: None,
            section_offset_range: None,
        }),
        for_types,
        file_path,
    )
}

/// Create a symbol exact trait
fn create_symbol_exact(
    id: &str,
    pattern: &str,
    for_types: Vec<FileType>,
    file_path: &str,
) -> TraitDefinition {
    create_test_trait(
        id,
        Condition::Symbol(SymbolQuery {
            exact: Some(pattern.to_string()),
            substr: None,
            regex: None,
            platforms: None,
            is_check: None,
            kind: None,
            arg: None,
            args: None,
            alias: None,
            not: None,
            module_level: false,
            receiver: None,
        }),
        for_types,
        file_path,
    )
}

fn create_symbol_exact_with_kind(
    id: &str,
    pattern: &str,
    kind: SymbolKind,
    for_types: Vec<FileType>,
    file_path: &str,
) -> TraitDefinition {
    create_test_trait(
        id,
        Condition::Symbol(SymbolQuery {
            exact: Some(pattern.to_string()),
            substr: None,
            regex: None,
            platforms: None,
            is_check: None,
            kind: Some(kind),
            arg: None,
            args: None,
            alias: None,
            not: None,
            module_level: false,
            receiver: None,
        }),
        for_types,
        file_path,
    )
}

fn create_symbol_exact_with_arg(
    id: &str,
    pattern: &str,
    arg: &str,
    for_types: Vec<FileType>,
    file_path: &str,
) -> TraitDefinition {
    create_test_trait(
        id,
        Condition::Symbol(SymbolQuery {
            exact: Some(pattern.to_string()),
            substr: None,
            regex: None,
            platforms: None,
            is_check: None,
            kind: Some(SymbolKind::Call),
            arg: Some(ArgFilter {
                exact: Some(arg.to_string()),
                ..Default::default()
            }),
            args: None,
            alias: None,
            not: None,
            module_level: false,
            receiver: None,
        }),
        for_types,
        file_path,
    )
}

fn create_text_regex_trait(
    id: &str,
    pattern: &str,
    for_types: Vec<FileType>,
    file_path: &str,
) -> TraitDefinition {
    create_test_trait(
        id,
        Condition::Text(TextQuery {
            regex: Some(pattern.to_string()),
            ..Default::default()
        }),
        for_types,
        file_path,
    )
}

fn create_string_literal_regex(
    id: &str,
    pattern: &str,
    for_types: Vec<FileType>,
    file_path: &str,
) -> TraitDefinition {
    create_test_trait(
        id,
        Condition::Literal(LiteralQuery {
            regex: Some(pattern.to_string()),
            ..Default::default()
        }),
        for_types,
        file_path,
    )
}

fn create_text_word(
    id: &str,
    pattern: &str,
    for_types: Vec<FileType>,
    file_path: &str,
) -> TraitDefinition {
    create_test_trait(
        id,
        Condition::Text(TextQuery {
            word: Some(pattern.to_string()),
            ..Default::default()
        }),
        for_types,
        file_path,
    )
}

fn create_text_substr(
    id: &str,
    pattern: &str,
    for_types: Vec<FileType>,
    file_path: &str,
) -> TraitDefinition {
    create_test_trait(
        id,
        Condition::Text(TextQuery {
            substr: Some(pattern.to_string()),
            ..Default::default()
        }),
        for_types,
        file_path,
    )
}

/// Create a raw regex trait
fn create_raw_regex(
    id: &str,
    pattern: &str,
    case_insensitive: bool,
    for_types: Vec<FileType>,
    file_path: &str,
) -> TraitDefinition {
    create_test_trait(
        id,
        Condition::Raw(RawQuery {
            length_min: None,
            length_max: None,
            exact: None,
            substr: None,
            regex: Some(pattern.to_string()),
            word: None,
            case_insensitive,
            is_check: None,
            section: None,
            offset: None,
            offset_range: None,
            section_offset: None,
            section_offset_range: None,
            not: None,
        }),
        for_types,
        file_path,
    )
}

fn create_raw_regex_in_section(
    id: &str,
    pattern: &str,
    section: Option<&str>,
    for_types: Vec<FileType>,
    file_path: &str,
) -> TraitDefinition {
    create_test_trait(
        id,
        Condition::Raw(RawQuery {
            length_min: None,
            length_max: None,
            exact: None,
            substr: None,
            regex: Some(pattern.to_string()),
            word: None,
            case_insensitive: false,
            is_check: None,
            section: section.map(str::to_string),
            offset: None,
            offset_range: None,
            section_offset: None,
            section_offset_range: None,
            not: None,
        }),
        for_types,
        file_path,
    )
}

fn create_basename_regex(
    id: &str,
    pattern: &str,
    for_types: Vec<FileType>,
    file_path: &str,
) -> TraitDefinition {
    create_test_trait(
        id,
        Condition::Path(PathQuery {
            exact: None,
            substr: None,
            regex: Some(pattern.to_string()),
            case_insensitive: false,
            is_check: None,
            basename: true,
            dirname: false,
        }),
        for_types,
        file_path,
    )
}

// ========================================================================
// Phase 1: Hex Escape Normalization Tests
// ========================================================================

/// A whole-file content matcher inlined in `unless:` while the identical
/// matcher already exists as a named trait must be reported — it is invisible
/// to every other duplicate check, so the two copies silently drift apart.
#[test]
fn test_inline_content_matcher_duplicating_named_trait_is_flagged() {
    let owner = create_test_trait(
        "pack/detect::enigma-protector",
        text_substr_cond("Enigma Protector", None),
        vec![FileType::Pe],
        "pack.yaml",
    );
    let mut borrower = create_test_trait(
        "hardening/memory::wx-section",
        text_substr_cond("writable executable", None),
        vec![FileType::Pe],
        "wx.yaml",
    );
    borrower.unless = Some(vec![text_substr_cond("Enigma Protector", None)]);

    let found = find_inline_content_duplicates(&[owner, borrower], &[]);
    assert_eq!(found.len(), 1, "expected one finding, got {found:?}");
    assert_eq!(found[0].0, "hardening/memory::wx-section");
    assert_eq!(found[0].1, "unless");
    assert!(
        found[0].3.contains("pack/detect::enigma-protector"),
        "advice should name the trait to reference: {}",
        found[0].3
    );
}

/// A matcher pinned to a section is not the same assertion as the same
/// pattern searched file-wide, so it must not be reported as a duplicate.
#[test]
fn test_section_pinned_inline_is_not_a_content_duplicate() {
    let owner = create_test_trait(
        "a::file-wide",
        text_substr_cond("Enigma Protector", None),
        vec![FileType::Pe],
        "a.yaml",
    );
    let mut borrower = create_test_trait(
        "b::section-pinned",
        text_substr_cond("something else", None),
        vec![FileType::Pe],
        "b.yaml",
    );
    borrower.unless = Some(vec![text_substr_cond("Enigma Protector", Some(".rsrc"))]);
    assert!(
        find_inline_content_duplicates(&[owner, borrower], &[]).is_empty(),
        "a section-pinned inline is a different assertion"
    );
}

#[test]
fn test_hex_escape_single_byte() {
    assert_eq!(decode_hex_escapes("\\x27"), "'");
    assert_eq!(decode_hex_escapes("\\x00"), "\0");
    assert_eq!(decode_hex_escapes("\\x41"), "A");
    assert_eq!(decode_hex_escapes("\\x7f"), "\x7f");
}

#[test]
fn test_hex_escape_in_string() {
    assert_eq!(decode_hex_escapes("test\\x27string"), "test'string");
    assert_eq!(decode_hex_escapes("\\x48ello"), "Hello");
    assert_eq!(decode_hex_escapes("foo\\x20bar"), "foo bar");
}

#[test]
fn test_hex_escape_multiple() {
    assert_eq!(decode_hex_escapes("\\x41\\x42\\x43"), "ABC");
    assert_eq!(decode_hex_escapes("\\x27\\x22"), "'\"");
}

#[test]
fn test_hex_escape_invalid_kept_as_is() {
    // Invalid hex (only 1 digit)
    assert_eq!(decode_hex_escapes("\\x2"), "\\x2");
    // Invalid hex (non-hex chars)
    assert_eq!(decode_hex_escapes("\\xZZ"), "\\xZZ");
    // Other escape sequences preserved
    assert_eq!(decode_hex_escapes("\\n"), "\\n");
    assert_eq!(decode_hex_escapes("\\t"), "\\t");
}

#[test]
fn test_hex_escape_duplicate_detection() {
    let trait1 = create_string_exact("test::a", "\\x27", false, vec![FileType::All], "file1.yaml");
    let trait2 = create_string_exact("test::b", "'", false, vec![FileType::All], "file2.yaml");

    let mut warnings = Vec::new();
    find_string_pattern_duplicates(&ExtractedPatterns::of(&[trait1, trait2]), &mut warnings);

    assert_eq!(warnings.len(), 1);
    assert!(warnings[0].contains("Duplicate"));
    assert!(warnings[0].contains("test::a"));
    assert!(warnings[0].contains("test::b"));
}

#[test]
fn test_hex_escape_real_example() {
    // Hex escape vs literal - exact patterns that normalize the same
    let trait1 = create_string_exact(
        "test::a",
        "\\x27", // \x27 is hex for single quote '
        false,
        vec![FileType::All],
        "file1.yaml",
    );
    let trait2 = create_string_exact(
        "test::b",
        "'", // Literal single quote
        false,
        vec![FileType::All],
        "file2.yaml",
    );

    let mut warnings = Vec::new();
    find_string_pattern_duplicates(&ExtractedPatterns::of(&[trait1, trait2]), &mut warnings);

    // Should detect as duplicate - \x27 normalizes to '
    assert_eq!(warnings.len(), 1);
    assert!(warnings[0].contains("Duplicate"));
}

// ========================================================================
// Phase 2: Containment Detection Tests
// ========================================================================

#[test]
fn test_exact_contained_by_substr() {
    let exact = create_string_exact(
        "test::exact",
        "/dev/kmem",
        false,
        vec![FileType::Elf],
        "file1.yaml",
    );
    let substr = create_string_substr(
        "test::substr",
        "/dev/kmem",
        false,
        vec![FileType::Elf],
        "file2.yaml",
    );

    let mut warnings = Vec::new();
    check_exact_contained_by_substr(&ExtractedPatterns::of(&[exact, substr]), &mut warnings);

    assert_eq!(warnings.len(), 1);
    assert!(warnings[0].contains("Exact pattern"));
    assert!(warnings[0].contains("substr pattern"));
    assert!(warnings[0].contains("/dev/kmem"));
}

#[test]
fn test_redundant_skips_low_value_same_tier_token_across_dirs() {
    let exact = create_string_exact(
        "objectives/a::client",
        "client",
        false,
        vec![FileType::Python],
        "objectives/a/traits.yaml",
    );
    let substr = create_string_substr(
        "objectives/b::client",
        "client",
        false,
        vec![FileType::Python],
        "objectives/b/traits.yaml",
    );

    let mut warnings = Vec::new();
    check_exact_contained_by_substr(&ExtractedPatterns::of(&[exact, substr]), &mut warnings);

    assert_eq!(warnings.len(), 0);
}

#[test]
fn test_redundant_skips_same_tier_across_dirs() {
    let exact = create_string_exact(
        "objectives/anti-static/obfuscation/string/runtime-decrypt::ntdll-wide-string",
        "ntdll.dll",
        false,
        vec![FileType::Pe],
        "objectives/anti-static/obfuscation/string/runtime-decrypt/pe.yaml",
    );
    let substr = create_string_substr(
        "objectives/evasion/anti-av/platform/defender::ntdll-dll-str",
        "ntdll.dll",
        false,
        vec![FileType::Pe],
        "objectives/evasion/anti-av/platform/defender/windows.yaml",
    );

    let mut warnings = Vec::new();
    check_exact_contained_by_substr(&ExtractedPatterns::of(&[exact, substr]), &mut warnings);

    assert_eq!(warnings.len(), 0);
}

#[test]
fn test_redundant_keeps_same_dir_duplicate() {
    let exact = create_string_exact(
        "objectives/evasion/anti-av/platform/defender::amsi-bypass-init-flag",
        "amsiInitFailed",
        false,
        vec![FileType::PowerShell],
        "objectives/evasion/anti-av/platform/defender/windows.yaml",
    );
    let substr = create_string_substr(
        "objectives/evasion/anti-av/platform/defender::amsi-init-failed-substr",
        "amsiInitFailed",
        false,
        vec![FileType::PowerShell],
        "objectives/evasion/anti-av/platform/defender/windows.yaml",
    );

    let mut warnings = Vec::new();
    check_exact_contained_by_substr(&ExtractedPatterns::of(&[exact, substr]), &mut warnings);

    assert_eq!(warnings.len(), 1);
}

#[test]
fn test_redundant_keeps_reusable_cross_tier_token() {
    let exact = create_string_exact(
        "micro-behaviors/data/decode/base64::atob",
        "atob",
        false,
        vec![FileType::JavaScript],
        "micro-behaviors/data/decode/base64/javascript.yaml",
    );
    let substr = create_string_substr(
        "objectives/anti-static/obfuscation/string::atob",
        "atob",
        false,
        vec![FileType::JavaScript],
        "objectives/anti-static/obfuscation/string/traits.yaml",
    );

    let mut warnings = Vec::new();
    check_exact_contained_by_substr(&ExtractedPatterns::of(&[exact, substr]), &mut warnings);

    assert_eq!(warnings.len(), 1);
    assert!(warnings[0].contains("atob"));
}

#[test]
fn test_redundant_skips_low_signal_lexicon_token() {
    let exact = create_string_exact(
        "objectives/command-and-control/backdoor/tasking/filesystem::task-command-field",
        "command",
        false,
        vec![FileType::Go],
        "objectives/command-and-control/backdoor/tasking/filesystem/macos-go.yaml",
    );
    let substr = create_string_substr(
        "micro-behaviors/data/text/keywords/lexicon::command-dup",
        "command",
        false,
        vec![FileType::Go],
        "micro-behaviors/data/text/keywords/lexicon/traits.yaml",
    );

    let mut warnings = Vec::new();
    check_exact_contained_by_substr(&ExtractedPatterns::of(&[exact, substr]), &mut warnings);

    assert_eq!(warnings.len(), 0);
}

#[test]
fn test_redundant_skips_text_vs_encoded_context() {
    let exact = create_string_exact(
        "micro-behaviors/process/create/shell/invoke::bin-sh",
        "/bin/sh",
        false,
        vec![FileType::Elf],
        "micro-behaviors/process/create/shell/invoke/generic.yaml",
    );
    let encoded = create_encoded_substr(
        "objectives/anti-static/obfuscation/encoding/content::encoded-bin-sh",
        "/bin/sh",
        vec![FileType::Elf],
        "objectives/anti-static/obfuscation/encoding/content/malware.yaml",
    );

    let mut warnings = Vec::new();
    check_exact_contained_by_substr(&ExtractedPatterns::of(&[exact, encoded]), &mut warnings);

    assert_eq!(warnings.len(), 0);
}

#[test]
fn test_cross_type_keeps_same_file_text_string_literal_duplicate() {
    let text = create_text_exact(
        "well-known/malware/ransomware/jigsaw::game-message",
        "I want to play a game with you.",
        false,
        vec![FileType::CSharp],
        "well-known/malware/ransomware/jigsaw/traits.yaml",
    );
    let literal = create_string_literal_exact(
        "well-known/malware/ransomware/jigsaw::game-message-source",
        "I want to play a game with you.",
        false,
        vec![FileType::CSharp],
        "well-known/malware/ransomware/jigsaw/traits.yaml",
    );

    let mut warnings = Vec::new();
    check_same_string_different_types(&ExtractedPatterns::of(&[text, literal]), &mut warnings);

    assert_eq!(warnings.len(), 1);
    assert!(warnings[0].contains("I want to play a game"));
}

/// A kinded symbol and a text matcher for the same API name are the same
/// evidence read off two surfaces. Keying the symbol as
/// `<literal>#kind:Call` used to file it in a bucket no text matcher could
/// reach, so this pair -- by far the most common duplicate shape in the
/// tree -- went unreported.
#[test]
fn test_cross_type_flags_kinded_symbol_against_text_word() {
    let symbol = create_symbol_exact_with_kind(
        "micro-behaviors/fs/write/file/direct::php-file-put-contents",
        "file_put_contents",
        SymbolKind::Call,
        vec![FileType::Php],
        "micro-behaviors/fs/write/file/direct/write-php.yaml",
    );
    let text = create_text_word(
        "micro-behaviors/fs/write/file/direct::file-put-contents",
        "file_put_contents",
        vec![FileType::Php],
        "micro-behaviors/fs/write/file/direct/php.yaml",
    );

    let mut warnings = Vec::new();
    check_same_string_different_types(&ExtractedPatterns::of(&[symbol, text]), &mut warnings);

    assert_eq!(warnings.len(), 1);
    assert!(warnings[0].contains("file_put_contents"));
    // The advice must preserve both surfaces: a stripped binary keeps the
    // string and loses the symbol, and a source file does the reverse.
    assert!(warnings[0].contains("`any:` composite"));
}

/// `word` and `exact` both demand the whole token, so they are the same
/// question asked on two surfaces even though they are spelled differently.
#[test]
fn test_cross_type_flags_word_against_exact() {
    let symbol = create_symbol_exact(
        "micro-behaviors/communications/http/client/winhttp::winhttp-connect",
        "WinHttpConnect",
        vec![FileType::Pe],
        "micro-behaviors/communications/http/client/winhttp/traits.yaml",
    );
    let text = create_text_word(
        "micro-behaviors/communications/http/client/winhttp::winhttp-connect-api-name",
        "WinHttpConnect",
        vec![FileType::Pe],
        "micro-behaviors/communications/http/client/winhttp/traits.yaml",
    );

    let mut warnings = Vec::new();
    check_same_string_different_types(&ExtractedPatterns::of(&[symbol, text]), &mut warnings);

    assert_eq!(warnings.len(), 1);
}

/// Exporting an API is the opposite of calling it: the file implements the
/// Windows surface rather than abusing it, which is exactly what
/// metadata/binary/vendor distinguishes. Pairing an export with a text
/// reference would call a discriminator a duplicate of what it discriminates.
#[test]
fn test_cross_type_keeps_export_against_text_reference() {
    let export = create_symbol_exact_with_kind(
        "metadata/binary/vendor::exports-mem-map-inject-api--virtualallocex",
        "VirtualAllocEx",
        SymbolKind::Export,
        vec![FileType::Pe],
        "metadata/binary/vendor/wine.yaml",
    );
    let text = create_text_word(
        "micro-behaviors/mem/alloc/remote::virtual-alloc-ex-text",
        "VirtualAllocEx",
        vec![FileType::Pe],
        "micro-behaviors/mem/alloc/remote/traits.yaml",
    );

    let mut warnings = Vec::new();
    check_same_string_different_types(&ExtractedPatterns::of(&[export, text]), &mut warnings);

    assert_eq!(warnings.len(), 0);
}

#[test]
fn test_cross_type_keeps_function_definition_distinct_from_call_and_text() {
    let definition = create_symbol_exact_with_kind(
        "micro-behaviors/data/source/function/names::curl-definition",
        "curl",
        SymbolKind::Function,
        vec![FileType::Shell],
        "definitions.yaml",
    );
    let call = create_symbol_exact_with_kind(
        "micro-behaviors/communications/http/client::curl-call",
        "curl",
        SymbolKind::Call,
        vec![FileType::Shell],
        "calls.yaml",
    );
    let text = create_text_word(
        "micro-behaviors/communications/http/client::curl-word",
        "curl",
        vec![FileType::Shell],
        "words.yaml",
    );
    let mut warnings = Vec::new();
    check_same_string_different_types(
        &ExtractedPatterns::of(&[definition.clone(), text.clone()]),
        &mut warnings,
    );
    assert!(warnings.is_empty());

    check_same_string_different_types(
        &ExtractedPatterns::of(&[definition, call, text]),
        &mut warnings,
    );
    assert_eq!(warnings.len(), 1);
    assert!(warnings[0].contains("calls.yaml"));
    assert!(!warnings[0].contains("definitions.yaml"));
}

/// Four same-context, same-tier regexes matching one literal phrase is the
/// shape this reports: the phrase is covered several times over.
#[test]
fn test_literal_covered_by_four_regexes() {
    let mut defs = vec![create_text_word(
        "micro-behaviors/os/module/load::get-proc-address-reference",
        "GetProcAddress",
        vec![FileType::Pe],
        "micro-behaviors/os/module/load/windows-loader.yaml",
    )];
    for (i, pat) in [
        r"(?m)^GetProcAddress$",
        r"(?i)getprocaddress",
        r"\bGetProcAddress\b",
        r"Get(Proc|Module)Address",
    ]
    .iter()
    .enumerate()
    {
        defs.push(create_text_regex_trait(
            &format!("objectives/evasion/dynamic::resolver-{i}"),
            pat,
            vec![FileType::Pe],
            "objectives/evasion/dynamic/traits.yaml",
        ));
    }

    let mut warnings = Vec::new();
    find_literals_covered_by_regexes(&ExtractedPatterns::of(&defs), &mut warnings);

    assert_eq!(warnings.len(), 1, "{warnings:?}");
    assert!(warnings[0].contains("GetProcAddress"));
    assert!(warnings[0].contains("consolidate"));
}

/// Literal coverage served from stored facts reports exactly what a run
/// without them does, and a one-byte edit to either side -- a regex, its
/// flag, or the literal -- is recomputed rather than served stale.
#[test]
fn test_literal_coverage_with_stored_facts_matches_a_cold_run() {
    use crate::capabilities::validation::facts_cache;
    let dir = tempfile::tempdir().expect("tempdir");
    let store = dir.path().join("facts.bin");
    let tree = |literal: &str, patterns: &[&str]| {
        let mut defs = vec![create_text_word(
            "micro-behaviors/os/module/load::get-proc-address-reference",
            literal,
            vec![FileType::Pe],
            "micro-behaviors/os/module/load/windows-loader.yaml",
        )];
        for (i, pat) in patterns.iter().enumerate() {
            defs.push(create_text_regex_trait(
                &format!("objectives/evasion/dynamic::resolver-{i}"),
                pat,
                vec![FileType::Pe],
                "objectives/evasion/dynamic/traits.yaml",
            ));
        }
        defs
    };
    let run = |defs: &[TraitDefinition], with_facts: bool| {
        let _session = with_facts.then(|| facts_cache::begin_at(&store));
        let mut warnings = Vec::new();
        find_literals_covered_by_regexes(&ExtractedPatterns::of(defs), &mut warnings);
        warnings
    };
    let patterns = [
        r"(?m)^GetProcAddress$",
        r"(?i)getprocaddress",
        r"\bGetProcAddress\b",
        r"Get(Proc|Module)Address",
    ];

    let base = tree("GetProcAddress", &patterns);
    let cold = run(&base, false);
    assert_eq!(cold.len(), 1, "{cold:?}");
    assert_eq!(run(&base, true), cold);
    assert!(facts_cache::stored_entries(&store) > 0);
    assert_eq!(run(&base, true), cold);

    for edited in [
        // One byte of one regex: it stops covering the literal.
        tree(
            "GetProcAddress",
            &[patterns[0], patterns[1], r"\bGetProcAddresz\b", patterns[3]],
        ),
        // A flag: without (?i) the lowercase regex no longer matches.
        tree(
            "GetProcAddress",
            &[patterns[0], "getprocaddress", patterns[2], patterns[3]],
        ),
        // The literal side: no regex covers the new phrase.
        tree("GetProcAddresz", &patterns),
    ] {
        let expected = run(&edited, false);
        assert!(expected.is_empty(), "{expected:?}");
        assert_eq!(run(&edited, true), expected);
    }
    // The original tree is still served correctly after the edits.
    assert_eq!(run(&base, true), cold);
}

/// Three is under the threshold: a couple of rules sharing a token is
/// ordinary, and reporting it would bury the real cases.
#[test]
fn test_literal_covered_by_three_regexes_is_quiet() {
    let mut defs = vec![create_text_word(
        "micro-behaviors/os/module/load::get-proc-address-reference",
        "GetProcAddress",
        vec![FileType::Pe],
        "micro-behaviors/os/module/load/windows-loader.yaml",
    )];
    for (i, pat) in [
        r"GetProcAddress\s*\(",
        r"(?i)getprocaddress",
        r"\bGetProcAddress\b",
    ]
    .iter()
    .enumerate()
    {
        defs.push(create_text_regex_trait(
            &format!("objectives/evasion/dynamic::resolver-{i}"),
            pat,
            vec![FileType::Pe],
            "objectives/evasion/dynamic/traits.yaml",
        ));
    }

    let mut warnings = Vec::new();
    find_literals_covered_by_regexes(&ExtractedPatterns::of(&defs), &mut warnings);

    assert!(warnings.is_empty(), "{warnings:?}");
}

/// A regex that needs context the phrase does not carry is not counted, even
/// though both rules fire on a real file. Counting it would mean guessing at
/// what surrounds the phrase.
#[test]
fn test_literal_coverage_ignores_regexes_needing_context() {
    let mut defs = vec![create_text_word(
        "micro-behaviors/os/module/load::get-proc-address-reference",
        "GetProcAddress",
        vec![FileType::Pe],
        "micro-behaviors/os/module/load/windows-loader.yaml",
    )];
    for (i, pat) in [
        r"GetProcAddress\s*\(",
        r"GetProcAddress[^\n]{0,80}LoadLibrary",
        r"LoadLibrary[^\n]{0,80}GetProcAddress",
        r"\bGetProcAddress\b\s*=\s*\w+",
    ]
    .iter()
    .enumerate()
    {
        defs.push(create_text_regex_trait(
            &format!("objectives/evasion/dynamic::resolver-{i}"),
            pat,
            vec![FileType::Pe],
            "objectives/evasion/dynamic/traits.yaml",
        ));
    }

    let mut warnings = Vec::new();
    find_literals_covered_by_regexes(&ExtractedPatterns::of(&defs), &mut warnings);

    assert!(warnings.is_empty(), "{warnings:?}");
}

/// A literal `#` inside a pattern is not a symbol discriminator. Splitting
/// on the first one truncated these regexes to a shared `[?&]\w{1,24}=[^&`
/// prefix and filed four unrelated injection patterns in one bucket.
#[test]
fn test_cross_type_keeps_regexes_sharing_only_a_prefix() {
    let text = create_text_regex_trait(
        "objectives/execution/exploit/http-command-injection::url-pipe-interpreter-raw",
        r#"(?i)[?&]\w{1,24}=[^&#\r\n"]{0,48}\| *(sh|bash)\b"#,
        vec![FileType::Python],
        "objectives/execution/exploit/http-command-injection/remote-query.yaml",
    );
    let literal = create_string_literal_regex(
        "objectives/execution/exploit/http-command-injection::url-pipe-command-encoded",
        r#"(?i)[?&]\w{1,24}=[^&#]{0,48}%7c(%20|\+)*(id|whoami)\b"#,
        vec![FileType::Python],
        "objectives/execution/exploit/http-command-injection/remote-query.yaml",
    );

    let mut warnings = Vec::new();
    check_same_string_different_types(&ExtractedPatterns::of(&[text, literal]), &mut warnings);

    assert_eq!(warnings.len(), 0);
}

/// A text matcher that stands down wherever the symbol matcher fires is the
/// runtime-resolution case: the API name is present as a string but the
/// binary does not import it. That is distinct evidence, not a second
/// reading of the same fact.
#[test]
fn test_cross_type_keeps_pair_where_one_suppresses_the_other() {
    let symbol = create_symbol_exact(
        "micro-behaviors/communications/http/client/winhttp::winhttp-connect",
        "WinHttpConnect",
        vec![FileType::Pe],
        "micro-behaviors/communications/http/client/winhttp/traits.yaml",
    );
    let mut text = create_text_word(
        "micro-behaviors/communications/http/client/winhttp::winhttp-connect-api-name",
        "WinHttpConnect",
        vec![FileType::Pe],
        "micro-behaviors/communications/http/client/winhttp/traits.yaml",
    );
    text.unless = Some(vec![Condition::Trait {
        id: "winhttp-connect".to_string(),
    }]);

    let mut warnings = Vec::new();
    check_same_string_different_types(&ExtractedPatterns::of(&[symbol, text]), &mut warnings);

    assert_eq!(warnings.len(), 0);
}

/// `substr` reaches inside longer tokens (`WriteFile` inside
/// `WriteFileEx`), so pairing it with a whole-token matcher would call two
/// different reaches a duplicate and invite the author to drop the broader
/// one -- a loss of detection, which is the opposite of the point.
#[test]
fn test_cross_type_keeps_substr_against_whole_token_match() {
    let symbol = create_symbol_exact(
        "micro-behaviors/fs/write/file/direct::write-file",
        "WriteFile",
        vec![FileType::Pe],
        "micro-behaviors/fs/write/file/direct/file-write.yaml",
    );
    let text = create_text_substr(
        "micro-behaviors/fs/write/file/direct::native-binary-write-file-text",
        "WriteFile",
        vec![FileType::Pe],
        "micro-behaviors/fs/write/file/direct/go-binary.yaml",
    );

    let mut warnings = Vec::new();
    check_same_string_different_types(&ExtractedPatterns::of(&[symbol, text]), &mut warnings);

    assert_eq!(warnings.len(), 0);
}

/// An `arg:` filter changes which fact the token names: `require('fs')` is
/// not `require('dns')`, and a text matcher for the bare token is neither
/// of them. A call/reference kind may be dropped across surfaces, but
/// definitions and argument discriminators change the observed fact.
#[test]
fn test_cross_type_keeps_arg_discriminated_symbol_against_text() {
    let symbol = create_symbol_exact_with_arg(
        "micro-behaviors/process/create/spawn::require-child-process",
        "require",
        "child_process",
        vec![FileType::JavaScript],
        "micro-behaviors/process/create/spawn/javascript.yaml",
    );
    let text = create_text_word(
        "metadata/lang/scripted::js-require-keyword",
        "require",
        vec![FileType::JavaScript],
        "metadata/lang/scripted/javascript.yaml",
    );

    let mut warnings = Vec::new();
    check_same_string_different_types(&ExtractedPatterns::of(&[symbol, text]), &mut warnings);

    assert_eq!(warnings.len(), 0);
}

#[test]
fn test_cross_type_flags_symbol_raw_api_duplicate() {
    // The same literal searched as both `symbol` and `raw` with
    // overlapping file types is a duplicate to collapse, even in the
    // same file.
    let symbol = create_symbol_exact(
        "micro-behaviors/fs/memory/mmap::create-file-mapping-w",
        "CreateFileMappingW",
        vec![FileType::Pe],
        "micro-behaviors/fs/memory/mmap/windows.yaml",
    );
    let raw = create_string_exact(
        "micro-behaviors/fs/memory/mmap::create-file-mapping-w-import",
        "CreateFileMappingW",
        false,
        vec![FileType::Pe],
        "micro-behaviors/fs/memory/mmap/windows.yaml",
    );

    let mut warnings = Vec::new();
    check_same_string_different_types(&ExtractedPatterns::of(&[symbol, raw]), &mut warnings);

    assert_eq!(warnings.len(), 1);
    assert!(warnings[0].contains("CreateFileMappingW"));
}

#[test]
fn test_cross_type_flags_cross_dir_api_duplicate() {
    // Cross-type duplicates are flagged regardless of which directory
    // each trait lives in.
    let symbol = create_symbol_exact(
        "micro-behaviors/fs/memory/mmap::create-file-mapping-w",
        "CreateFileMappingW",
        vec![FileType::Pe],
        "micro-behaviors/fs/memory/mmap/windows.yaml",
    );
    let raw = create_string_exact(
        "well-known/malware/example::create-file-mapping-w",
        "CreateFileMappingW",
        false,
        vec![FileType::Pe],
        "well-known/malware/example/traits.yaml",
    );

    let mut warnings = Vec::new();
    check_same_string_different_types(&ExtractedPatterns::of(&[symbol, raw]), &mut warnings);

    assert_eq!(warnings.len(), 1);
    assert!(warnings[0].contains("CreateFileMappingW"));
}

#[test]
fn test_cross_type_flags_same_dir_different_file_duplicate() {
    // Cross-type duplicates are flagged regardless of which file each
    // trait lives in.
    let symbol = create_symbol_exact(
        "micro-behaviors/communications/http/get::internet-open",
        "InternetOpen",
        vec![FileType::Pe],
        "micro-behaviors/communications/http/get/wininet.yaml",
    );
    let raw = create_string_exact(
        "micro-behaviors/communications/http/get::internet-open-str",
        "InternetOpen",
        false,
        vec![FileType::Pe],
        "micro-behaviors/communications/http/get/wininet-dynamic.yaml",
    );

    let mut warnings = Vec::new();
    check_same_string_different_types(&ExtractedPatterns::of(&[symbol, raw]), &mut warnings);

    assert_eq!(warnings.len(), 1);
    assert!(warnings[0].contains("InternetOpen"));
}

#[test]
fn test_cross_type_skips_encoded_context() {
    let raw = create_string_exact(
        "objectives/evasion/indicator-removal/logs::utmp-cleanup-status",
        "utmp logs cleaned up.",
        false,
        vec![FileType::Elf],
        "objectives/evasion/indicator-removal/logs/unix-accounting.yaml",
    );
    let encoded = create_encoded_substr(
        "objectives/evasion/indicator-removal/logs::utmp-cleanup-status-xor",
        "utmp logs cleaned up.",
        vec![FileType::Elf],
        "objectives/evasion/indicator-removal/logs/unix-accounting.yaml",
    );

    let mut warnings = Vec::new();
    check_same_string_different_types(&ExtractedPatterns::of(&[raw, encoded]), &mut warnings);

    assert_eq!(warnings.len(), 0);
}

#[test]
fn test_exact_not_contained_different_strings() {
    let exact = create_string_exact(
        "test::exact",
        "os.rename",
        false,
        vec![FileType::All],
        "file1.yaml",
    );
    let substr = create_string_substr(
        "test::substr",
        "os.rename ", // trailing space
        false,
        vec![FileType::All],
        "file2.yaml",
    );

    let mut warnings = Vec::new();
    check_exact_contained_by_substr(&ExtractedPatterns::of(&[exact, substr]), &mut warnings);

    // No redundancy because strings differ (trailing space)
    assert_eq!(warnings.len(), 0);
}

// ========================================================================
// Phase 3: Case-Insensitive Overlap Tests
// ========================================================================

#[test]
fn test_case_insensitive_subsumes_case_sensitive() {
    let case_sensitive = create_string_exact(
        "test::sensitive",
        "PASSWORD",
        false,
        vec![FileType::All],
        "file1.yaml",
    );
    let case_insensitive = create_string_exact(
        "test::insensitive",
        "password",
        true,
        vec![FileType::All],
        "file2.yaml",
    );

    let mut warnings = Vec::new();
    check_case_insensitive_overlaps(&[case_sensitive, case_insensitive], &mut warnings);

    assert_eq!(warnings.len(), 1);
    assert!(warnings[0].contains("CASE SUBSUMPTION"));
}

#[test]
fn test_both_case_insensitive_differ_in_case() {
    let trait1 = create_string_exact(
        "test::a",
        "GetProcAddress",
        true,
        vec![FileType::All],
        "file1.yaml",
    );
    let trait2 = create_string_exact(
        "test::b",
        "getprocaddress",
        true,
        vec![FileType::All],
        "file2.yaml",
    );

    let mut warnings = Vec::new();
    check_case_insensitive_overlaps(&[trait1, trait2], &mut warnings);

    assert_eq!(warnings.len(), 1);
    assert!(warnings[0].contains("DUPLICATE (case only)"));
}

#[test]
fn test_both_case_sensitive_different_case_ok() {
    let trait1 = create_string_exact(
        "test::a",
        "GetProcAddress",
        false,
        vec![FileType::All],
        "file1.yaml",
    );
    let trait2 = create_string_exact(
        "test::b",
        "GETPROCADDRESS",
        false,
        vec![FileType::All],
        "file2.yaml",
    );

    let mut warnings = Vec::new();
    check_case_insensitive_overlaps(&[trait1, trait2], &mut warnings);

    // No warning - both case-sensitive, different case = different patterns
    assert_eq!(warnings.len(), 0);
}

// ========================================================================
// Phase 4: Regex Containment Tests
// ========================================================================

#[test]
fn test_regex_exact_match_cross_type() {
    let symbol_exact = create_symbol_exact(
        "test::symbol",
        "GetProcAddress",
        vec![FileType::Pe],
        "file1.yaml",
    );
    let raw_regex = create_raw_regex(
        "test::raw",
        "GetProcAddress",
        false,
        vec![FileType::Pe],
        "file2.yaml",
    );

    let mut warnings = Vec::new();
    check_regex_contains_literal(&[symbol_exact, raw_regex], &mut warnings);

    assert_eq!(warnings.len(), 1);
    assert!(warnings[0].contains("Same pattern, different match types"));
    assert!(warnings[0].contains("cross-type"));
}

#[test]
fn regex_literal_symbol_overlap_respects_explicit_kinds() {
    let import = create_test_trait(
        "metadata/demo::import",
        Condition::Symbol(SymbolQuery {
            regex: Some("createRootShell$".to_string()),
            kind: Some(SymbolKind::Import),
            ..Default::default()
        }),
        vec![FileType::All],
        "import.yaml",
    );
    let mut call = create_symbol_exact_with_kind(
        "micro-behaviors/demo::call",
        "createRootShell",
        SymbolKind::Call,
        vec![FileType::All],
        "call.yaml",
    );
    let mut warnings = Vec::new();
    check_regex_contains_literal(&[import.clone(), call.clone()], &mut warnings);
    assert!(warnings.is_empty());
    if let Condition::Symbol(query) = &mut call.r#if {
        query.kind = Some(SymbolKind::Import);
    }
    check_regex_contains_literal(&[import.clone(), call.clone()], &mut warnings);
    assert_eq!(warnings.len(), 1);
    warnings.clear();
    if let Condition::Symbol(query) = &mut call.r#if {
        query.kind = None;
    }
    check_regex_contains_literal(&[import, call], &mut warnings);
    assert_eq!(warnings.len(), 1);
}

#[test]
fn test_regex_contains_literal() {
    let exact = create_string_exact(
        "test::exact",
        "foo",
        false,
        vec![FileType::All],
        "file1.yaml",
    );
    let regex = create_string_regex(
        "test::regex",
        "foo.*",
        false,
        vec![FileType::All],
        "file2.yaml",
    );

    let mut warnings = Vec::new();
    check_regex_contains_literal(&[exact, regex], &mut warnings);

    assert_eq!(warnings.len(), 1);
    assert!(warnings[0].contains("Regex pattern matches literal"));
}

#[test]
fn regex_literal_overlap_respects_call_arguments() {
    let generic = create_symbol_exact_with_kind(
        "micro-behaviors/test::open",
        "fopen",
        SymbolKind::Call,
        vec![FileType::Php],
        "open.yaml",
    );
    let append = create_symbol_exact_with_arg(
        "micro-behaviors/test::append",
        "fopen",
        "a",
        vec![FileType::Php],
        "append.yaml",
    );
    let mut qualified_append = append.clone();
    qualified_append.id = "micro-behaviors/test::qualified-append".into();
    qualified_append.defined_in = "qualified.yaml".into();
    if let Condition::Symbol(query) = &mut qualified_append.r#if {
        query.exact = None;
        query.regex = Some(r"^\\?fopen$".into());
    }
    assert!(find_regex_literal_overlap_issues(&[generic, qualified_append.clone()]).is_empty());
    let mut write = append.clone();
    if let Condition::Symbol(query) = &mut write.r#if {
        query.arg.as_mut().unwrap().exact = Some("w".into());
    }
    assert!(find_regex_literal_overlap_issues(&[write, qualified_append.clone()]).is_empty());
    // Equivalent filters still represent overlap; do not silence the
    // duplicate merely because both conditions carry an arg predicate.
    assert_eq!(
        find_regex_literal_overlap_issues(&[append, qualified_append]).len(),
        1
    );
}

#[test]
fn test_broad_regex_matching_literal_no_warning() {
    let exact = create_string_exact(
        "test::exact",
        "COMPUTERNAME",
        false,
        vec![FileType::All],
        "file1.yaml",
    );
    let regex = create_string_regex(
        "test::regex",
        "^[A-Z]{8,12}$",
        false,
        vec![FileType::All],
        "file2.yaml",
    );

    let mut warnings = Vec::new();
    check_regex_contains_literal(&[exact, regex], &mut warnings);

    assert_eq!(warnings.len(), 0);
}

#[test]
fn test_regex_doesnt_match_no_warning() {
    let exact = create_string_exact(
        "test::exact",
        "bar",
        false,
        vec![FileType::All],
        "file1.yaml",
    );
    let regex = create_string_regex(
        "test::regex",
        "foo.*",
        false,
        vec![FileType::All],
        "file2.yaml",
    );

    let mut warnings = Vec::new();
    check_regex_contains_literal(&[exact, regex], &mut warnings);

    // No warning - regex doesn't match literal
    assert_eq!(warnings.len(), 0);
}

#[test]
fn test_regex_contains_literal_after_leading_metacharacters() {
    let exact = create_string_exact(
        "test::exact",
        ".exe",
        false,
        vec![FileType::All],
        "file1.yaml",
    );
    let regex = create_string_regex(
        "test::regex",
        r".*\.exe",
        false,
        vec![FileType::All],
        "file2.yaml",
    );

    let mut warnings = Vec::new();
    check_regex_contains_literal(&[exact, regex], &mut warnings);

    assert_eq!(warnings.len(), 1);
}

/// Every pair the regex-vs-literal check can report must be among the
/// candidates its index proposes, or the report silently loses it.
#[test]
fn test_regex_literal_candidates_cover_every_reportable_pair() {
    use std::collections::HashMap;

    let regexes = [
        "foo.*", ".*foo", "^foo$", r".*\.exe", r"7z\.exe", "foo", "a.b", r"\.\*", ".*", "",
        "x+foo?", "foo.*bar", r"\\", "^.*", "fo.o", "foo.*foo", "..foo..",
    ];
    let literals = [
        "foo", ".exe", "exe", "7z.exe", "", "a.b", ".*", r"\", "bar", "FOO", "fo.o", "foo.*bar",
        "..", "o",
    ];
    let normalized: Vec<String> = literals
        .iter()
        .map(|literal| normalize_pattern_for_comparison(literal, false))
        .collect();
    let mut by_normalized: HashMap<&str, Vec<usize>> = HashMap::new();
    let mut by_escaped: HashMap<String, Vec<usize>> = HashMap::new();
    for (idx, literal) in literals.iter().enumerate() {
        by_normalized
            .entry(normalized[idx].as_str())
            .or_default()
            .push(idx);
        by_escaped
            .entry(regex::escape(literal))
            .or_default()
            .push(idx);
    }

    for pattern in regexes {
        let pattern_normalized = normalize_pattern_for_comparison(pattern, true);
        let candidates =
            regex_literal_candidates(pattern, &pattern_normalized, &by_normalized, &by_escaped);
        for (idx, literal) in literals.iter().enumerate() {
            let reportable = pattern_normalized == normalized[idx]
                || trivially_extends(pattern, &regex::escape(literal));
            assert!(
                !reportable || candidates.contains(&idx),
                "{pattern:?} vs {literal:?} is reportable but not a candidate"
            );
        }
    }
}

// ========================================================================
// Phase 5: Regex Alternative Subset Tests
// ========================================================================

#[test]
fn test_regex_alternative_subset() {
    let regex1 = create_string_regex(
        "test::subset",
        "(read|write)",
        false,
        vec![FileType::All],
        "file1.yaml",
    );
    let regex2 = create_string_regex(
        "test::superset",
        "(read|write|execute)",
        false,
        vec![FileType::All],
        "file2.yaml",
    );

    let mut warnings = Vec::new();
    check_regex_alternative_subsets(&[regex1, regex2], &mut warnings);

    assert_eq!(warnings.len(), 1);
    assert!(warnings[0].contains("REGEX ALTERNATIVE SUBSET"));
}

#[test]
fn test_regex_case_insensitive_subsumption() {
    let case_sensitive = create_string_regex(
        "test::sensitive",
        "(password|secret)",
        false,
        vec![FileType::All],
        "file1.yaml",
    );
    let case_insensitive = create_string_regex(
        "test::insensitive",
        "(PASSWORD|SECRET)",
        true,
        vec![FileType::All],
        "file2.yaml",
    );

    let mut warnings = Vec::new();
    check_regex_alternative_subsets(&[case_sensitive, case_insensitive], &mut warnings);

    assert_eq!(warnings.len(), 1);
    assert!(warnings[0].contains("REGEX CASE SUBSUMPTION"));
}

#[test]
fn test_regex_alternative_subsets_pair_only_shared_alternatives() {
    let regex = |id: &str, pattern: &str, case_insensitive: bool, file: &str| {
        create_string_regex(id, pattern, case_insensitive, vec![FileType::All], file)
    };
    let traits = [
        regex("a::subset", "read|write", false, "a.yaml"),
        regex("b::unrelated", "alpha|beta", false, "b.yaml"),
        regex("c::superset", "read|write|exec", false, "c.yaml"),
        regex("d::upper", "READ|WRITE", true, "d.yaml"),
        // The same alternatives in a group are a different shape.
        regex("e::grouped", "x(read|write|exec)", false, "e.yaml"),
        regex("f::grouped-upper", "X(READ|WRITE|EXEC)", true, "f.yaml"),
    ];

    let mut warnings = Vec::new();
    check_regex_alternative_subsets(&traits, &mut warnings);

    // In pair order: a ⊂ c, a's case variant d, e's case variant f.
    assert_eq!(warnings.len(), 3, "{warnings:#?}");
    assert!(warnings[0].starts_with("REGEX ALTERNATIVE SUBSET"));
    assert!(warnings[0].contains("a::subset") && warnings[0].contains("c::superset"));
    assert!(warnings[1].starts_with("REGEX CASE SUBSUMPTION"));
    assert!(warnings[1].contains("d::upper") && warnings[1].contains("a::subset"));
    assert!(warnings[2].starts_with("REGEX CASE SUBSUMPTION"));
    assert!(warnings[2].contains("f::grouped-upper") && warnings[2].contains("e::grouped"));
}

// ========================================================================
// Phase 6: Tier Violation Tests
// ========================================================================

#[test]
fn test_tier_violation_detection() {
    let micro = create_symbol_exact(
        "micro-behaviors/fs/file/delete::unlink",
        "unlink",
        vec![FileType::Elf],
        "traits/micro-behaviors/fs/file/delete.yaml",
    );
    let objective = create_symbol_exact(
        "objectives/anti-forensics/cleanup::artifact",
        "unlink",
        vec![FileType::Elf],
        "traits/objectives/anti-forensics/cleanup.yaml",
    );

    let mut warnings = Vec::new();
    find_string_pattern_duplicates(&ExtractedPatterns::of(&[micro, objective]), &mut warnings);

    assert_eq!(warnings.len(), 1);
    assert!(warnings[0].contains("Duplicate reusable atom"));
    assert!(warnings[0].contains("Reference reusable atom"));
}

#[test]
fn test_no_tier_violation_same_tier() {
    let trait1 = create_symbol_exact(
        "micro-behaviors/fs/file/delete::unlink",
        "unlink",
        vec![FileType::Elf],
        "traits/micro-behaviors/fs/file/delete.yaml",
    );
    let trait2 = create_symbol_exact(
        "micro-behaviors/fs/file/remove::rm",
        "unlink",
        vec![FileType::Elf],
        "traits/micro-behaviors/fs/file/remove.yaml",
    );

    let mut warnings = Vec::new();
    find_string_pattern_duplicates(&ExtractedPatterns::of(&[trait1, trait2]), &mut warnings);

    assert_eq!(warnings.len(), 1);
    // Should NOT contain TIER VIOLATION (both in micro-behaviors)
    assert!(!warnings[0].contains("TIER VIOLATION"));
}

// ========================================================================
// File Type Overlap Tests
// ========================================================================

#[test]
fn test_filetype_overlap_all_vs_specific() {
    let trait1 = create_string_exact("test::a", "test", false, vec![FileType::All], "file1.yaml");
    let trait2 = create_string_exact("test::b", "test", false, vec![FileType::Elf], "file2.yaml");

    let mut warnings = Vec::new();
    find_string_pattern_duplicates(&ExtractedPatterns::of(&[trait1, trait2]), &mut warnings);

    // Should detect overlap (All overlaps with everything)
    assert_eq!(warnings.len(), 1);
}

#[test]
fn test_filetype_no_overlap_disjoint() {
    let trait1 = create_string_exact("test::a", "test", false, vec![FileType::Elf], "file1.yaml");
    let trait2 = create_string_exact("test::b", "test", false, vec![FileType::Pe], "file2.yaml");

    let mut warnings = Vec::new();
    find_string_pattern_duplicates(&ExtractedPatterns::of(&[trait1, trait2]), &mut warnings);

    // No overlap - disjoint file types
    assert_eq!(warnings.len(), 0);
}

#[test]
fn test_dup_pattern_ignores_match_all_basename_carrier() {
    let trait1 = create_basename_regex(
        "metadata/binary/metrics/size::large-file",
        ".",
        vec![FileType::Pe],
        "metadata/binary/metrics/size.yaml",
    );
    let trait2 = create_basename_regex(
        "well-known/malware/test::tiny-file",
        ".",
        vec![FileType::Pe],
        "well-known/malware/test/traits.yaml",
    );

    let mut warnings = Vec::new();
    find_string_pattern_duplicates(&ExtractedPatterns::of(&[trait1, trait2]), &mut warnings);

    assert_eq!(warnings.len(), 0);
}

#[test]
fn test_dup_pattern_requires_same_section_scope() {
    let unscoped = create_raw_regex_in_section(
        "metadata/binary/anomaly/content::sha256",
        "^[a-f0-9]{64}$",
        None,
        vec![FileType::Pe],
        "metadata/binary/anomaly/content/hash.yaml",
    );
    let scoped = create_raw_regex_in_section(
        "metadata/binary/anomaly/format::sha256-rdata",
        "^[a-f0-9]{64}$",
        Some(".rdata"),
        vec![FileType::Pe],
        "metadata/binary/anomaly/format/pe.yaml",
    );

    let mut warnings = Vec::new();
    find_string_pattern_duplicates(&ExtractedPatterns::of(&[unscoped, scoped]), &mut warnings);

    assert_eq!(warnings.len(), 0);
}

// ========================================================================
// Carveout Exception Tests (>2 char diff + conf/crit differs)
// ========================================================================

#[test]
fn test_decode_hex_for_carveout() {
    // Verify hex decoding works as expected
    assert_eq!(decode_hex_escapes("AB"), "AB");
    assert_eq!(decode_hex_escapes("\\x41B"), "AB");
    assert_eq!(decode_hex_escapes("test"), "test");
    assert_eq!(decode_hex_escapes("\\x74est"), "test");
}

#[test]
fn test_simple_duplicate_without_carveout() {
    // Same exact pattern without any carveout -> should warn
    let trait1 = create_test_trait_with_conf_crit(
        "test::a",
        Condition::Raw(RawQuery {
            length_min: None,
            length_max: None,
            exact: Some("duplicate".to_string()),
            substr: None,
            regex: None,
            word: None,
            case_insensitive: false,
            is_check: None,
            section: None,
            offset: None,
            offset_range: None,
            section_offset: None,
            section_offset_range: None,
            not: None,
        }),
        vec![FileType::All],
        "file1.yaml",
        0.8,
        crate::types::Criticality::Notable,
    );

    let trait2 = create_test_trait_with_conf_crit(
        "test::b",
        Condition::Raw(RawQuery {
            length_min: None,
            length_max: None,
            exact: Some("duplicate".to_string()),
            substr: None,
            regex: None,
            word: None,
            case_insensitive: false,
            is_check: None,
            section: None,
            offset: None,
            offset_range: None,
            section_offset: None,
            section_offset_range: None,
            not: None,
        }),
        vec![FileType::All],
        "file2.yaml",
        0.9,
        crate::types::Criticality::Notable,
    );

    let mut warnings = Vec::new();
    find_string_pattern_duplicates(&ExtractedPatterns::of(&[trait1, trait2]), &mut warnings);

    // Should warn - exact duplicate, carveout doesn't apply (len diff = 0)
    assert_eq!(warnings.len(), 1);
    assert!(warnings[0].contains("Duplicate"));
}

#[test]
fn test_hex_duplicate_without_carveout() {
    // Hex-encoded duplicate with same conf/crit -> should warn
    let trait1 = create_test_trait_with_conf_crit(
        "test::a",
        Condition::Raw(RawQuery {
            length_min: None,
            length_max: None,
            exact: Some("AB".to_string()),
            substr: None,
            regex: None,
            word: None,
            case_insensitive: false,
            is_check: None,
            section: None,
            offset: None,
            offset_range: None,
            section_offset: None,
            section_offset_range: None,
            not: None,
        }),
        vec![FileType::All],
        "file1.yaml",
        0.8,
        crate::types::Criticality::Notable,
    );

    let trait2 = create_test_trait_with_conf_crit(
        "test::b",
        Condition::Raw(RawQuery {
            length_min: None,
            length_max: None,
            exact: Some("\\x41B".to_string()), // Normalizes to "AB"
            substr: None,
            regex: None,
            word: None,
            case_insensitive: false,
            is_check: None,
            section: None,
            offset: None,
            offset_range: None,
            section_offset: None,
            section_offset_range: None,
            not: None,
        }),
        vec![FileType::All],
        "file2.yaml",
        0.8,
        crate::types::Criticality::Notable,
    );

    let mut warnings = Vec::new();
    find_string_pattern_duplicates(&ExtractedPatterns::of(&[trait1, trait2]), &mut warnings);

    // Should warn - normalizes to same pattern, carveout doesn't apply (same conf/crit)
    assert_eq!(warnings.len(), 1);
    assert!(warnings[0].contains("Duplicate"));
}

#[test]
fn test_carveout_large_pattern_diff_with_conf_diff() {
    // Same normalized pattern "test", but original values differ by >2 chars AND confidence differs by >=0.2 -> NO warning
    let trait1 = create_test_trait_with_conf_crit(
        "test::a",
        Condition::Raw(RawQuery {
            length_min: None,
            length_max: None,
            exact: Some("test".to_string()), // 4 chars
            substr: None,
            regex: None,
            word: None,
            case_insensitive: false,
            is_check: None,
            section: None,
            offset: None,
            offset_range: None,
            section_offset: None,
            section_offset_range: None,
            not: None,
        }),
        vec![FileType::All],
        "file1.yaml",
        0.5, // conf = 0.5
        crate::types::Criticality::Notable,
    );

    let trait2 = create_test_trait_with_conf_crit(
        "test::b",
        Condition::Raw(RawQuery {
            length_min: None,
            length_max: None,
            exact: Some("\\x74\\x65\\x73\\x74".to_string()), // 16 chars hex-encoded "test" (diff = 12 > 2)
            substr: None,
            regex: None,
            word: None,
            case_insensitive: false,
            is_check: None,
            section: None,
            offset: None,
            offset_range: None,
            section_offset: None,
            section_offset_range: None,
            not: None,
        }),
        vec![FileType::All],
        "file2.yaml",
        0.9, // conf = 0.9 (diff = 0.4 >= 0.2)
        crate::types::Criticality::Notable,
    );

    let mut warnings = Vec::new();
    find_string_pattern_duplicates(&ExtractedPatterns::of(&[trait1, trait2]), &mut warnings);

    // Should NOT warn - carveout applies (same normalized "test", but original differs by >2 and conf differs)
    assert_eq!(warnings.len(), 0);
}

#[test]
fn test_carveout_large_pattern_diff_with_crit_diff() {
    // Same normalized "data", but original differs by >2 chars AND criticality differs -> NO warning
    let trait1 = create_test_trait_with_conf_crit(
        "test::a",
        Condition::Raw(RawQuery {
            length_min: None,
            length_max: None,
            exact: Some("data".to_string()), // 4 chars
            substr: None,
            regex: None,
            word: None,
            case_insensitive: false,
            is_check: None,
            section: None,
            offset: None,
            offset_range: None,
            section_offset: None,
            section_offset_range: None,
            not: None,
        }),
        vec![FileType::All],
        "file1.yaml",
        0.8,
        crate::types::Criticality::Notable,
    );

    let trait2 = create_test_trait_with_conf_crit(
        "test::b",
        Condition::Raw(RawQuery {
            length_min: None,
            length_max: None,
            exact: Some("\\x64ata".to_string()), // 7 chars hex-encoded first char (diff = 3 > 2)
            substr: None,
            regex: None,
            word: None,
            case_insensitive: false,
            is_check: None,
            section: None,
            offset: None,
            offset_range: None,
            section_offset: None,
            section_offset_range: None,
            not: None,
        }),
        vec![FileType::All],
        "file2.yaml",
        0.8,
        crate::types::Criticality::Hostile, // Different criticality
    );

    let mut warnings = Vec::new();
    find_string_pattern_duplicates(&ExtractedPatterns::of(&[trait1, trait2]), &mut warnings);

    // Should NOT warn - carveout applies
    assert_eq!(warnings.len(), 0);
}

#[test]
fn test_carveout_fails_small_pattern_diff() {
    // Identical patterns (0-char diff) with different conf/crit -> should warn
    // Carveout requires BOTH >2 char diff AND conf/crit difference
    let trait1 = create_test_trait_with_conf_crit(
        "test::a",
        Condition::Raw(RawQuery {
            length_min: None,
            length_max: None,
            exact: Some("pattern".to_string()), // 7 chars
            substr: None,
            regex: None,
            word: None,
            case_insensitive: false,
            is_check: None,
            section: None,
            offset: None,
            offset_range: None,
            section_offset: None,
            section_offset_range: None,
            not: None,
        }),
        vec![FileType::All],
        "file1.yaml",
        0.5,
        crate::types::Criticality::Notable,
    );

    let trait2 = create_test_trait_with_conf_crit(
        "test::b",
        Condition::Raw(RawQuery {
            length_min: None,
            length_max: None,
            exact: Some("pattern".to_string()), // 7 chars (diff = 0, not >2)
            substr: None,
            regex: None,
            word: None,
            case_insensitive: false,
            is_check: None,
            section: None,
            offset: None,
            offset_range: None,
            section_offset: None,
            section_offset_range: None,
            not: None,
        }),
        vec![FileType::All],
        "file2.yaml",
        0.9, // conf diff = 0.4 >= 0.2 (but pattern diff = 0, so carveout doesn't apply)
        crate::types::Criticality::Notable,
    );

    let mut warnings = Vec::new();
    find_string_pattern_duplicates(&ExtractedPatterns::of(&[trait1, trait2]), &mut warnings);

    // Should WARN - carveout does NOT apply (pattern diff = 0, not >2)
    assert_eq!(warnings.len(), 1);
    assert!(warnings[0].contains("Duplicate"));
}

#[test]
fn test_carveout_fails_small_conf_diff() {
    // Same normalized "value", original differs by >2 chars BUT confidence diff <0.2 and crit same -> should warn
    let trait1 = create_test_trait_with_conf_crit(
        "test::a",
        Condition::Raw(RawQuery {
            length_min: None,
            length_max: None,
            exact: Some("value".to_string()), // 5 chars
            substr: None,
            regex: None,
            word: None,
            case_insensitive: false,
            is_check: None,
            section: None,
            offset: None,
            offset_range: None,
            section_offset: None,
            section_offset_range: None,
            not: None,
        }),
        vec![FileType::All],
        "file1.yaml",
        0.8,
        crate::types::Criticality::Notable,
    );

    let trait2 = create_test_trait_with_conf_crit(
        "test::b",
        Condition::Raw(RawQuery {
            length_min: None,
            length_max: None,
            exact: Some("\\x76\\x61lue".to_string()), // 11 chars, first 2 chars hex-encoded (diff = 6 > 2)
            substr: None,
            regex: None,
            word: None,
            case_insensitive: false,
            is_check: None,
            section: None,
            offset: None,
            offset_range: None,
            section_offset: None,
            section_offset_range: None,
            not: None,
        }),
        vec![FileType::All],
        "file2.yaml",
        0.9,                                // conf diff = 0.1 < 0.2
        crate::types::Criticality::Notable, // Same criticality
    );

    let mut warnings = Vec::new();
    find_string_pattern_duplicates(&ExtractedPatterns::of(&[trait1, trait2]), &mut warnings);

    // Should WARN - carveout does NOT apply (conf diff <0.2 AND crit same)
    assert_eq!(warnings.len(), 1);
    assert!(warnings[0].contains("Duplicate"));
}

#[test]
fn test_carveout_multiple_pairs_all_pass() {
    // Three traits, all normalize to "name", all pairs meet carveout criteria -> NO warnings
    let trait1 = create_test_trait_with_conf_crit(
        "test::a",
        Condition::Raw(RawQuery {
            length_min: None,
            length_max: None,
            exact: Some("name".to_string()), // 4 chars
            substr: None,
            regex: None,
            word: None,
            case_insensitive: false,
            is_check: None,
            section: None,
            offset: None,
            offset_range: None,
            section_offset: None,
            section_offset_range: None,
            not: None,
        }),
        vec![FileType::All],
        "file1.yaml",
        0.5,
        crate::types::Criticality::Notable,
    );

    let trait2 = create_test_trait_with_conf_crit(
        "test::b",
        Condition::Raw(RawQuery {
            length_min: None,
            length_max: None,
            exact: Some("\\x6e\\x61me".to_string()), // 11 chars (diff from trait1 = 7 > 2)
            substr: None,
            regex: None,
            word: None,
            case_insensitive: false,
            is_check: None,
            section: None,
            offset: None,
            offset_range: None,
            section_offset: None,
            section_offset_range: None,
            not: None,
        }),
        vec![FileType::All],
        "file2.yaml",
        0.9, // conf diff from trait1 = 0.4 >= 0.2
        crate::types::Criticality::Notable,
    );

    let trait3 = create_test_trait_with_conf_crit(
        "test::c",
        Condition::Raw(RawQuery {
            length_min: None,
            length_max: None,
            exact: Some("\\x6e\\x61\\x6d\\x65".to_string()), // 16 chars, all hex-encoded (diff from trait1 = 12, from trait2 = 5 > 2)
            substr: None,
            regex: None,
            word: None,
            case_insensitive: false,
            is_check: None,
            section: None,
            offset: None,
            offset_range: None,
            section_offset: None,
            section_offset_range: None,
            not: None,
        }),
        vec![FileType::All],
        "file3.yaml",
        0.5,
        crate::types::Criticality::Hostile, // Different from traits 1 and 2
    );

    let mut warnings = Vec::new();
    find_string_pattern_duplicates(
        &ExtractedPatterns::of(&[trait1, trait2, trait3]),
        &mut warnings,
    );

    // Should NOT warn - all pairs meet carveout criteria
    assert_eq!(warnings.len(), 0);
}

#[test]
fn test_carveout_multiple_pairs_one_fails() {
    // Three traits, all normalize to "code", one pair doesn't meet carveout -> should warn
    let trait1 = create_test_trait_with_conf_crit(
        "test::a",
        Condition::Raw(RawQuery {
            length_min: None,
            length_max: None,
            exact: Some("code".to_string()), // 4 chars
            substr: None,
            regex: None,
            word: None,
            case_insensitive: false,
            is_check: None,
            section: None,
            offset: None,
            offset_range: None,
            section_offset: None,
            section_offset_range: None,
            not: None,
        }),
        vec![FileType::All],
        "file1.yaml",
        0.8,
        crate::types::Criticality::Notable,
    );

    let trait2 = create_test_trait_with_conf_crit(
        "test::b",
        Condition::Raw(RawQuery {
            length_min: None,
            length_max: None,
            exact: Some("\\x63\\x6fde".to_string()), // 11 chars (diff = 7 > 2)
            substr: None,
            regex: None,
            word: None,
            case_insensitive: false,
            is_check: None,
            section: None,
            offset: None,
            offset_range: None,
            section_offset: None,
            section_offset_range: None,
            not: None,
        }),
        vec![FileType::All],
        "file2.yaml",
        0.9,                                // conf diff from trait1 = 0.1 < 0.2
        crate::types::Criticality::Notable, // Same as trait1 - FAILS carveout
    );

    let trait3 = create_test_trait_with_conf_crit(
        "test::c",
        Condition::Raw(RawQuery {
            length_min: None,
            length_max: None,
            exact: Some("\\x63\\x6f\\x64\\x65".to_string()), // 16 chars (diff from trait1 = 12 > 2)
            substr: None,
            regex: None,
            word: None,
            case_insensitive: false,
            is_check: None,
            section: None,
            offset: None,
            offset_range: None,
            section_offset: None,
            section_offset_range: None,
            not: None,
        }),
        vec![FileType::All],
        "file3.yaml",
        0.5,
        crate::types::Criticality::Hostile, // Different from trait1 - PASSES carveout with trait1
    );

    let mut warnings = Vec::new();
    find_string_pattern_duplicates(
        &ExtractedPatterns::of(&[trait1, trait2, trait3]),
        &mut warnings,
    );

    // Should WARN - trait1 and trait2 don't meet carveout criteria (conf diff <0.2 and same crit)
    assert_eq!(warnings.len(), 1);
    assert!(warnings[0].contains("Duplicate"));
}

// ========================================================================
// Helper Function Tests
// ========================================================================

#[test]
fn test_extract_tier() {
    assert_eq!(
        extract_tier("micro-behaviors/fs/file/delete::unlink"),
        Some("micro-behaviors")
    );
    assert_eq!(
        extract_tier("objectives/collection/metadata::home-env"),
        Some("objectives")
    );
    assert_eq!(
        extract_tier("well-known/malware/rat::geacon"),
        Some("well-known")
    );
    assert_eq!(
        extract_tier("metadata/format/extension::exe"),
        Some("metadata")
    );

    // Invalid formats
    assert_eq!(extract_tier("invalid-id"), None);
    assert_eq!(extract_tier(""), None);
}

// ========================================================================
// Basename Pattern Duplicate Tests
// ========================================================================

#[test]
fn test_basename_exact_duplicate() {
    let traits = vec![
        create_test_trait(
            "test1",
            Condition::Path(PathQuery {
                exact: Some("setup.py".to_string()),
                substr: None,
                regex: None,
                case_insensitive: false,
                is_check: None,
                basename: true,
                dirname: false,
            }),
            vec![FileType::Python],
            "file1.yaml",
        ),
        create_test_trait(
            "test2",
            Condition::Path(PathQuery {
                exact: Some("setup.py".to_string()),
                substr: None,
                regex: None,
                case_insensitive: false,
                is_check: None,
                basename: true,
                dirname: false,
            }),
            vec![FileType::Python],
            "file2.yaml",
        ),
    ];

    let mut warnings = Vec::new();
    check_basename_pattern_duplicates(&traits, &mut warnings);

    assert_eq!(warnings.len(), 1);
    assert!(warnings[0].contains("Duplicate basename exact pattern 'setup.py'"));
    assert!(warnings[0].contains("test1"));
    assert!(warnings[0].contains("test2"));
}

#[test]
fn test_basename_substr_duplicate() {
    let traits = vec![
        create_test_trait(
            "test1",
            Condition::Path(PathQuery {
                exact: None,
                substr: Some("chrome".to_string()),
                regex: None,
                case_insensitive: false,
                is_check: None,
                basename: true,
                dirname: false,
            }),
            vec![FileType::All],
            "file1.yaml",
        ),
        create_test_trait(
            "test2",
            Condition::Path(PathQuery {
                exact: None,
                substr: Some("chrome".to_string()),
                regex: None,
                case_insensitive: false,
                is_check: None,
                basename: true,
                dirname: false,
            }),
            vec![FileType::All],
            "file2.yaml",
        ),
    ];

    let mut warnings = Vec::new();
    check_basename_pattern_duplicates(&traits, &mut warnings);

    assert_eq!(warnings.len(), 1);
    assert!(warnings[0].contains("Duplicate basename substr pattern 'chrome'"));
}

#[test]
fn test_basename_regex_duplicate() {
    let traits = vec![
        create_test_trait(
            "test1",
            Condition::Path(PathQuery {
                exact: None,
                substr: None,
                regex: Some("\\.pyc$".to_string()),
                case_insensitive: false,
                is_check: None,
                basename: true,
                dirname: false,
            }),
            vec![FileType::Python],
            "file1.yaml",
        ),
        create_test_trait(
            "test2",
            Condition::Path(PathQuery {
                exact: None,
                substr: None,
                regex: Some("\\.pyc$".to_string()),
                case_insensitive: false,
                is_check: None,
                basename: true,
                dirname: false,
            }),
            vec![FileType::Python],
            "file2.yaml",
        ),
    ];

    let mut warnings = Vec::new();
    check_basename_pattern_duplicates(&traits, &mut warnings);

    assert_eq!(warnings.len(), 1);
    assert!(warnings[0].contains("Duplicate basename regex pattern '\\.pyc$'"));
}

#[test]
fn test_basename_regex_should_be_exact() {
    let traits = vec![
        create_test_trait(
            "test1",
            Condition::Path(PathQuery {
                exact: None,
                substr: None,
                regex: Some("^Makefile$".to_string()),
                case_insensitive: false,
                is_check: None,
                basename: true,
                dirname: false,
            }),
            vec![FileType::All],
            "file1.yaml",
        ),
        create_test_trait(
            "test2",
            Condition::Path(PathQuery {
                exact: None,
                substr: None,
                regex: Some("^setup\\.py$".to_string()),
                case_insensitive: false,
                is_check: None,
                basename: true,
                dirname: false,
            }),
            vec![FileType::Python],
            "file2.yaml",
        ),
    ];

    let mut warnings = Vec::new();
    check_basename_pattern_duplicates(&traits, &mut warnings);

    assert_eq!(warnings.len(), 2);
    assert!(warnings[0].contains("is just ^literal$ and should use exact: 'Makefile'"));
    assert!(warnings[1].contains("is just ^literal$ and should use exact: 'setup.py'"));
}

#[test]
fn test_basename_regex_should_be_exact_case_insensitive() {
    let traits = vec![create_test_trait(
        "test1",
        Condition::Path(PathQuery {
            exact: None,
            substr: None,
            regex: Some("(?i)^setup\\.py$".to_string()),
            case_insensitive: false,
            is_check: None,
            basename: true,
            dirname: false,
        }),
        vec![FileType::Python],
        "file1.yaml",
    )];

    let mut warnings = Vec::new();
    check_basename_pattern_duplicates(&traits, &mut warnings);

    assert_eq!(warnings.len(), 1);
    assert!(warnings[0].contains("should use exact: 'setup.py', case_insensitive: true"));
}

#[test]
fn test_basename_regex_with_metacharacters_not_flagged() {
    let traits = vec![
        create_test_trait(
            "test1",
            Condition::Path(PathQuery {
                exact: None,
                substr: None,
                regex: Some("^(setup|install)\\.py$".to_string()),
                case_insensitive: false,
                is_check: None,
                basename: true,
                dirname: false,
            }),
            vec![FileType::Python],
            "file1.yaml",
        ),
        create_test_trait(
            "test2",
            Condition::Path(PathQuery {
                exact: None,
                substr: None,
                regex: Some(".*\\.exe$".to_string()),
                case_insensitive: false,
                is_check: None,
                basename: true,
                dirname: false,
            }),
            vec![FileType::Pe],
            "file2.yaml",
        ),
    ];

    let mut warnings = Vec::new();
    check_basename_pattern_duplicates(&traits, &mut warnings);

    // Should not flag these as "should be exact" because they have regex metacharacters
    for warning in &warnings {
        assert!(!warning.contains("should use exact"));
    }
}

#[test]
fn test_basename_empty_pattern_skipped() {
    let traits = vec![create_test_trait(
        "test1",
        Condition::Path(PathQuery {
            exact: None,
            substr: None,
            regex: None,
            case_insensitive: false,
            is_check: None,
            basename: true,
            dirname: false,
        }),
        vec![FileType::All],
        "file1.yaml",
    )];

    let mut warnings = Vec::new();
    check_basename_pattern_duplicates(&traits, &mut warnings);

    // Empty basename pattern should be skipped
    assert_eq!(warnings.len(), 0);
}

#[test]
fn test_basename_bogus_dot_pattern_skipped() {
    let traits = vec![create_test_trait(
        "test1",
        Condition::Path(PathQuery {
            exact: None,
            substr: None,
            regex: Some(".".to_string()),
            case_insensitive: false,
            is_check: None,
            basename: true,
            dirname: false,
        }),
        vec![FileType::All],
        "file1.yaml",
    )];

    let mut warnings = Vec::new();
    check_basename_pattern_duplicates(&traits, &mut warnings);

    // Bogus "." pattern should be skipped
    assert_eq!(warnings.len(), 0);
}

#[test]
fn test_basename_non_basename_conditions_ignored() {
    let traits = vec![
        create_test_trait(
            "test1",
            Condition::Raw(RawQuery {
                length_min: None,
                length_max: None,
                exact: Some("setup.py".to_string()),
                substr: None,
                word: None,
                regex: None,
                case_insensitive: false,
                is_check: None,
                section: None,
                offset: None,
                offset_range: None,
                section_offset: None,
                section_offset_range: None,
                not: None,
            }),
            vec![FileType::Python],
            "file1.yaml",
        ),
        create_test_trait(
            "test2",
            Condition::Symbol(SymbolQuery {
                exact: Some("setup".to_string()),
                substr: None,
                regex: None,
                platforms: None,
                is_check: None,
                kind: None,
                arg: None,
                args: None,
                alias: None,
                not: None,
                module_level: false,
                receiver: None,
            }),
            vec![FileType::Python],
            "file2.yaml",
        ),
    ];

    let mut warnings = Vec::new();
    check_basename_pattern_duplicates(&traits, &mut warnings);

    // Non-basename conditions should be ignored
    assert_eq!(warnings.len(), 0);
}

// ========================================================================
// Regex Overlap Tests
// ========================================================================

#[test]
fn test_regex_literal_overlap_same_length_blocked() {
    use crate::capabilities::validation::duplicates::validate_regex_overlap_with_literal;

    let traits = vec![
        create_string_exact(
            "exact_trait",
            "chrome.exe",
            false,
            vec![FileType::Pe],
            "file1.yaml",
        ),
        create_string_regex(
            "regex_trait",
            "chrome\\.exe",
            false,
            vec![FileType::Pe],
            "file2.yaml",
        ),
    ];

    let mut warnings = Vec::new();
    validate_regex_overlap_with_literal(&traits, &mut warnings);

    // Same length patterns should trigger warning
    assert_eq!(warnings.len(), 1);
    assert!(warnings[0].contains("Ambiguous regex overlap"));
}

#[test]
fn test_regex_literal_overlap_33_percent_diff_allowed() {
    use crate::capabilities::validation::duplicates::validate_regex_overlap_with_literal;

    let traits = vec![
        // ".exe" = 4 chars, "7z.exe" = 6 chars
        // Diff: 2/6 = 33.33% -> should be allowed
        create_string_substr(
            "substr_trait",
            ".exe",
            false,
            vec![FileType::Pe],
            "file1.yaml",
        ),
        create_string_regex(
            "regex_trait",
            "7z\\.exe",
            false,
            vec![FileType::Pe],
            "file2.yaml",
        ),
    ];

    let mut warnings = Vec::new();
    validate_regex_overlap_with_literal(&traits, &mut warnings);

    // 33% or more difference should be allowed
    assert_eq!(warnings.len(), 0);
}

#[test]
fn test_regex_literal_overlap_with_alternation_blocked() {
    use crate::capabilities::validation::duplicates::validate_regex_overlap_with_literal;

    let traits = vec![
        // Even with length difference, alternation should block the exemption
        create_string_exact(
            "exact_trait",
            "chrome.exe",
            false,
            vec![FileType::Pe],
            "file1.yaml",
        ),
        create_string_regex(
            "regex_trait",
            "(chrome\\.exe|firefox\\.exe)",
            false,
            vec![FileType::Pe],
            "file2.yaml",
        ),
    ];

    let mut warnings = Vec::new();
    validate_regex_overlap_with_literal(&traits, &mut warnings);

    // Alternation present means no exemption
    assert_eq!(warnings.len(), 1);
    assert!(warnings[0].contains("Ambiguous regex overlap"));
}

#[test]
fn test_regex_literal_overlap_prefix_blocked() {
    use crate::capabilities::validation::duplicates::validate_regex_overlap_with_literal;

    let traits = vec![
        // "foo" (3 chars) vs "foo.*" (5 chars) = 40% difference
        // BUT "foo" is a prefix of "foo.*", so should still be blocked
        create_string_exact(
            "exact_trait",
            "foo",
            false,
            vec![FileType::All],
            "file1.yaml",
        ),
        create_string_regex(
            "regex_trait",
            "foo.*",
            false,
            vec![FileType::All],
            "file2.yaml",
        ),
    ];

    let mut warnings = Vec::new();
    validate_regex_overlap_with_literal(&traits, &mut warnings);

    // Prefix match should be blocked even with >33% length difference
    assert_eq!(warnings.len(), 1);
    assert!(warnings[0].contains("Ambiguous regex overlap"));
}

#[test]
fn test_regex_literal_overlap_suffix_blocked() {
    use crate::capabilities::validation::duplicates::validate_regex_overlap_with_literal;

    let traits = vec![
        // ".exe" is a suffix of ".*\.exe", should be blocked
        create_string_substr(
            "substr_trait",
            ".exe",
            false,
            vec![FileType::Pe],
            "file1.yaml",
        ),
        create_string_regex(
            "regex_trait",
            ".*\\.exe",
            false,
            vec![FileType::Pe],
            "file2.yaml",
        ),
    ];

    let mut warnings = Vec::new();
    validate_regex_overlap_with_literal(&traits, &mut warnings);

    // Suffix match should be blocked
    assert_eq!(warnings.len(), 1);
    assert!(warnings[0].contains("Ambiguous regex overlap"));
}

#[test]
fn test_basename_regex_literal_overlap_blocked() {
    use crate::capabilities::validation::duplicates::validate_regex_overlap_with_literal;

    let traits = vec![
        create_test_trait(
            "basename_exact",
            Condition::Path(PathQuery {
                exact: Some("sshd".to_string()),
                substr: None,
                regex: None,
                case_insensitive: false,
                is_check: None,
                basename: true,
                dirname: false,
            }),
            vec![FileType::Shell],
            "file1.yaml",
        ),
        create_test_trait(
            "basename_regex",
            Condition::Path(PathQuery {
                exact: None,
                substr: None,
                regex: Some("^(ssh|sshd|ssh_config)$".to_string()),
                case_insensitive: false,
                is_check: None,
                basename: true,
                dirname: false,
            }),
            vec![FileType::Shell],
            "file2.yaml",
        ),
    ];

    let mut warnings = Vec::new();
    validate_regex_overlap_with_literal(&traits, &mut warnings);

    assert!(!warnings.is_empty());
    assert!(warnings.iter().any(|w| w.contains("sshd")));
}

#[test]
fn test_regex_literal_overlap_different_criticality_allowed() {
    use crate::capabilities::validation::duplicates::validate_regex_overlap_with_literal;

    let traits = vec![
        create_test_trait_with_conf_crit(
            "exact_notable",
            Condition::Raw(RawQuery {
                length_min: None,
                length_max: None,
                exact: Some("malware.exe".to_string()),
                substr: None,
                regex: None,
                word: None,
                case_insensitive: false,
                is_check: None,
                section: None,
                offset: None,
                offset_range: None,
                section_offset: None,
                section_offset_range: None,
                not: None,
            }),
            vec![FileType::Pe],
            "file1.yaml",
            1.0,
            crate::types::Criticality::Notable,
        ),
        create_test_trait_with_conf_crit(
            "regex_hostile",
            Condition::Raw(RawQuery {
                length_min: None,
                length_max: None,
                exact: None,
                substr: None,
                regex: Some("malware\\.exe".to_string()),
                word: None,
                case_insensitive: false,
                is_check: None,
                section: None,
                offset: None,
                offset_range: None,
                section_offset: None,
                section_offset_range: None,
                not: None,
            }),
            vec![FileType::Pe],
            "file2.yaml",
            1.0,
            crate::types::Criticality::Hostile,
        ),
    ];

    let mut warnings = Vec::new();
    validate_regex_overlap_with_literal(&traits, &mut warnings);

    // Different criticality should be allowed
    assert_eq!(warnings.len(), 0);
}

#[test]
fn test_basename_regex_alternative_subset_detected() {
    use crate::capabilities::validation::duplicates::check_regex_alternative_subsets;

    let traits = vec![
        create_test_trait(
            "subset",
            Condition::Path(PathQuery {
                exact: None,
                substr: None,
                regex: Some("\\.(test|spec)\\.[cm]?[jt]sx?$".to_string()),
                case_insensitive: false,
                is_check: None,
                basename: true,
                dirname: false,
            }),
            vec![FileType::JavaScript, FileType::TypeScript],
            "file1.yaml",
        ),
        create_test_trait(
            "superset",
            Condition::Path(PathQuery {
                exact: None,
                substr: None,
                regex: Some("\\.(test|spec|bench)\\.[cm]?[jt]sx?$".to_string()),
                case_insensitive: false,
                is_check: None,
                basename: true,
                dirname: false,
            }),
            vec![FileType::JavaScript, FileType::TypeScript],
            "file2.yaml",
        ),
    ];

    let mut warnings = Vec::new();
    check_regex_alternative_subsets(&traits, &mut warnings);

    assert!(!warnings.is_empty());
    assert!(warnings[0].contains("REGEX ALTERNATIVE SUBSET"));
    assert!(warnings[0].contains("\\.(test|spec)\\.[cm]?[jt]sx?$"));
}

#[test]
fn test_regex_regex_overlap_with_length_diff_allowed() {
    use crate::capabilities::validation::duplicates::check_overlapping_regex_patterns;

    let traits = vec![
        // Both regexes, >33% length difference, one has no alternation
        create_string_regex(
            "regex_short",
            "\\.exe$",
            false,
            vec![FileType::Pe],
            "file1.yaml",
        ),
        create_string_regex(
            "regex_long",
            "7z\\.exe$",
            false,
            vec![FileType::Pe],
            "file2.yaml",
        ),
    ];

    let mut warnings = Vec::new();
    check_overlapping_regex_patterns(&ExtractedPatterns::of(&traits), &mut warnings);

    // Should be allowed due to length difference and no alternation
    assert_eq!(warnings.len(), 0);
}

#[test]
fn test_regex_regex_overlap_both_alternation_checked() {
    use crate::capabilities::validation::duplicates::check_overlapping_regex_patterns;

    let traits = vec![
        // Both have alternation and share alternatives
        create_string_regex(
            "regex_a",
            "(chrome\\.exe|firefox\\.exe)",
            false,
            vec![FileType::Pe],
            "file1.yaml",
        ),
        create_string_regex(
            "regex_b",
            "(firefox\\.exe|safari\\.exe)",
            false,
            vec![FileType::Pe],
            "file2.yaml",
        ),
    ];

    let mut warnings = Vec::new();
    check_overlapping_regex_patterns(&ExtractedPatterns::of(&traits), &mut warnings);

    // Should warn about shared alternative "firefox.exe"
    assert_eq!(warnings.len(), 1);
    assert!(warnings[0].contains("Overlapping regex patterns"));
}

#[test]
fn test_regex_regex_one_alternation_length_diff_allowed() {
    use crate::capabilities::validation::duplicates::check_overlapping_regex_patterns;

    let traits = vec![
        // One has alternation, but >33% length difference
        create_string_regex(
            "regex_simple",
            "\\.exe",
            false,
            vec![FileType::Pe],
            "file1.yaml",
        ),
        create_string_regex(
            "regex_alternation",
            "(chrome\\.exe|firefox\\.exe|safari\\.exe)",
            false,
            vec![FileType::Pe],
            "file2.yaml",
        ),
    ];

    let mut warnings = Vec::new();
    check_overlapping_regex_patterns(&ExtractedPatterns::of(&traits), &mut warnings);

    // Should be allowed: >33% diff and one has no alternation
    assert_eq!(warnings.len(), 0);
}

#[test]
fn test_regex_regex_structurally_identical_shorthand_vs_class() {
    use crate::capabilities::validation::duplicates::check_overlapping_regex_patterns;

    // `\d{3}` and `[0-9]{3}` are the same language written two ways. The HIR
    // canonicalization must flag them even though they differ in length by
    // >33% with no alternation (the heuristic that allowed `\.exe$` vs
    // `7z\.exe$` must not suppress a genuine duplicate).
    let traits = vec![
        create_string_regex(
            "digits_shorthand",
            r"\d{3}",
            false,
            vec![FileType::Pe],
            "a.yaml",
        ),
        create_string_regex(
            "digits_class",
            r"[0-9]{3}",
            false,
            vec![FileType::Pe],
            "b.yaml",
        ),
    ];

    let mut warnings = Vec::new();
    check_overlapping_regex_patterns(&ExtractedPatterns::of(&traits), &mut warnings);

    assert_eq!(warnings.len(), 1, "expected one duplicate: {warnings:?}");
    assert!(warnings[0].contains("Structurally identical regex patterns"));
    assert!(warnings[0].contains("canonical form"));
}

#[test]
fn test_regex_regex_structurally_identical_class_order() {
    use crate::capabilities::validation::duplicates::check_overlapping_regex_patterns;

    // Character-class member order is not semantic: `gr[ae]y` ≡ `gr[ea]y`.
    let traits = vec![
        create_string_regex("grey_ae", r"gr[ae]y", false, vec![FileType::Pe], "a.yaml"),
        create_string_regex("grey_ea", r"gr[ea]y", false, vec![FileType::Pe], "b.yaml"),
    ];

    let mut warnings = Vec::new();
    check_overlapping_regex_patterns(&ExtractedPatterns::of(&traits), &mut warnings);

    assert_eq!(warnings.len(), 1, "expected one duplicate: {warnings:?}");
    assert!(warnings[0].contains("Structurally identical regex patterns"));
}

#[test]
fn test_regex_regex_word_boundary_not_identical_to_substring() {
    use crate::capabilities::validation::duplicates::check_overlapping_regex_patterns;

    // `\bfoobar\b` (whole word) and `foobar` (substring) describe different
    // languages — the look-around boundaries change the match, so this must
    // NOT be reported as structurally identical.
    let traits = vec![
        create_string_regex("word", r"\bfoobar\b", false, vec![FileType::Pe], "a.yaml"),
        create_string_regex("substr", r"foobar", false, vec![FileType::Pe], "b.yaml"),
    ];

    let mut warnings = Vec::new();
    check_overlapping_regex_patterns(&ExtractedPatterns::of(&traits), &mut warnings);

    assert!(
        !warnings
            .iter()
            .any(|w| w.contains("Structurally identical")),
        "word-boundary vs substring must not be called identical: {warnings:?}"
    );
}

// ========================================================================
// Criticality Equivalence Tests
// ========================================================================

#[test]
fn test_criticalities_equivalent_inert_levels() {
    use crate::capabilities::validation::duplicates::criticalities_equivalent;
    use crate::types::Criticality;

    // Component, Baseline, and Filtered should all be equivalent
    assert!(criticalities_equivalent(
        Criticality::Component,
        Criticality::Baseline
    ));
    assert!(criticalities_equivalent(
        Criticality::Baseline,
        Criticality::Component
    ));
    assert!(criticalities_equivalent(
        Criticality::Filtered,
        Criticality::Baseline
    ));
    assert!(criticalities_equivalent(
        Criticality::Filtered,
        Criticality::Component
    ));
    assert!(criticalities_equivalent(
        Criticality::Component,
        Criticality::Filtered
    ));

    // Same level is always equivalent
    assert!(criticalities_equivalent(
        Criticality::Component,
        Criticality::Component
    ));
    assert!(criticalities_equivalent(
        Criticality::Baseline,
        Criticality::Baseline
    ));
    assert!(criticalities_equivalent(
        Criticality::Filtered,
        Criticality::Filtered
    ));
}

#[test]
fn test_criticalities_equivalent_distinct_levels() {
    use crate::capabilities::validation::duplicates::criticalities_equivalent;
    use crate::types::Criticality;

    // Notable, Suspicious, Hostile should be distinct from each other and from inert levels
    assert!(!criticalities_equivalent(
        Criticality::Notable,
        Criticality::Baseline
    ));
    assert!(!criticalities_equivalent(
        Criticality::Notable,
        Criticality::Component
    ));
    assert!(!criticalities_equivalent(
        Criticality::Suspicious,
        Criticality::Baseline
    ));
    assert!(!criticalities_equivalent(
        Criticality::Hostile,
        Criticality::Baseline
    ));

    assert!(!criticalities_equivalent(
        Criticality::Notable,
        Criticality::Suspicious
    ));
    assert!(!criticalities_equivalent(
        Criticality::Notable,
        Criticality::Hostile
    ));
    assert!(!criticalities_equivalent(
        Criticality::Suspicious,
        Criticality::Hostile
    ));

    // Same level is equivalent
    assert!(criticalities_equivalent(
        Criticality::Notable,
        Criticality::Notable
    ));
    assert!(criticalities_equivalent(
        Criticality::Suspicious,
        Criticality::Suspicious
    ));
    assert!(criticalities_equivalent(
        Criticality::Hostile,
        Criticality::Hostile
    ));
}

// ========================================================================
// Atomic Logic Duplicates Tests
// ========================================================================

#[test]
fn test_atomic_logic_duplicates_same_logic_different_crit() {
    use crate::capabilities::validation::duplicates::find_atomic_logic_duplicates;

    let traits = vec![
        create_test_trait_with_conf_crit(
            "trait_notable",
            Condition::Raw(RawQuery {
                length_min: None,
                length_max: None,
                exact: Some("malicious_pattern".to_string()),
                substr: None,
                regex: None,
                word: None,
                case_insensitive: false,
                is_check: None,
                section: None,
                offset: None,
                offset_range: None,
                section_offset: None,
                section_offset_range: None,
                not: None,
            }),
            vec![FileType::Elf],
            "file1.yaml",
            1.0,
            crate::types::Criticality::Notable,
        ),
        create_test_trait_with_conf_crit(
            "trait_hostile",
            Condition::Raw(RawQuery {
                length_min: None,
                length_max: None,
                exact: Some("malicious_pattern".to_string()),
                substr: None,
                regex: None,
                word: None,
                case_insensitive: false,
                is_check: None,
                section: None,
                offset: None,
                offset_range: None,
                section_offset: None,
                section_offset_range: None,
                not: None,
            }),
            vec![FileType::Elf],
            "file2.yaml",
            1.0,
            crate::types::Criticality::Hostile,
        ),
    ];

    let duplicates = find_atomic_logic_duplicates(&traits);
    assert_eq!(duplicates.len(), 1);
    assert!(duplicates[0].2.contains("crit:"));
}

/// `not:` is a carve-out, not the assertion — two traits that match the same
/// thing at the same criticality are one detection however their exclusions
/// are spelled, so the pair must still be reported.
#[test]
fn test_atomic_logic_duplicates_not_differs_at_same_crit_is_reported() {
    use crate::capabilities::validation::duplicates::find_atomic_logic_duplicates;
    use crate::composite_rules::condition::NotException;

    let matcher = || {
        Condition::Raw(RawQuery {
            length_min: None,
            length_max: None,
            exact: Some("shared_pattern".to_string()),
            substr: None,
            regex: None,
            word: None,
            case_insensitive: false,
            is_check: None,
            section: None,
            offset: None,
            offset_range: None,
            section_offset: None,
            section_offset_range: None,
            not: None,
        })
    };
    let mut a = create_test_trait_with_conf_crit(
        "a",
        matcher(),
        vec![FileType::Elf],
        "a.yaml",
        1.0,
        crate::types::Criticality::Notable,
    );
    let mut b = create_test_trait_with_conf_crit(
        "b",
        matcher(),
        vec![FileType::Elf],
        "b.yaml",
        1.0,
        crate::types::Criticality::Notable,
    );
    a.not = Some(vec![NotException::Shorthand("carve_out_one".to_string())]);
    b.not = Some(vec![NotException::Shorthand("carve_out_two".to_string())]);

    let duplicates = find_atomic_logic_duplicates(&[a, b]);
    assert_eq!(
        duplicates.len(),
        1,
        "same matcher + same crit is one detection"
    );
    assert!(
        duplicates[0].2.contains("not: differs"),
        "the report must say what differs: {}",
        duplicates[0].2
    );
}

/// The opposite case: a generic matcher beside one narrowed by `not:` that
/// says something stronger is a deliberate specialization, and the differing
/// `crit:` is what marks it as intentional. Reporting it would be noise.
#[test]
fn test_atomic_logic_duplicates_not_differs_at_different_crit_is_quiet() {
    use crate::capabilities::validation::duplicates::find_atomic_logic_duplicates;
    use crate::composite_rules::condition::NotException;

    let matcher = || {
        Condition::Raw(RawQuery {
            length_min: None,
            length_max: None,
            exact: Some("ip_pattern".to_string()),
            substr: None,
            regex: None,
            word: None,
            case_insensitive: false,
            is_check: None,
            section: None,
            offset: None,
            offset_range: None,
            section_offset: None,
            section_offset_range: None,
            not: None,
        })
    };
    let generic = create_test_trait_with_conf_crit(
        "any-ip",
        matcher(),
        vec![FileType::Elf],
        "generic.yaml",
        1.0,
        crate::types::Criticality::Baseline,
    );
    let mut external_only = create_test_trait_with_conf_crit(
        "external-ip",
        matcher(),
        vec![FileType::Elf],
        "external.yaml",
        1.0,
        crate::types::Criticality::Notable,
    );
    external_only.not = Some(vec![NotException::Shorthand("10.".to_string())]);

    let duplicates = find_atomic_logic_duplicates(&[generic, external_only]);
    assert!(
        duplicates.is_empty(),
        "a narrowed matcher at a higher crit is a specialization, not a duplicate: {duplicates:?}"
    );
}

#[test]
fn test_atomic_logic_duplicates_same_logic_different_conf() {
    use crate::capabilities::validation::duplicates::find_atomic_logic_duplicates;

    let traits = vec![
        create_test_trait_with_conf_crit(
            "trait_low_conf",
            Condition::Raw(RawQuery {
                length_min: None,
                length_max: None,
                exact: Some("test_pattern".to_string()),
                substr: None,
                regex: None,
                word: None,
                case_insensitive: false,
                is_check: None,
                section: None,
                offset: None,
                offset_range: None,
                section_offset: None,
                section_offset_range: None,
                not: None,
            }),
            vec![FileType::Shell],
            "file1.yaml",
            0.5,
            crate::types::Criticality::Notable,
        ),
        create_test_trait_with_conf_crit(
            "trait_high_conf",
            Condition::Raw(RawQuery {
                length_min: None,
                length_max: None,
                exact: Some("test_pattern".to_string()),
                substr: None,
                regex: None,
                word: None,
                case_insensitive: false,
                is_check: None,
                section: None,
                offset: None,
                offset_range: None,
                section_offset: None,
                section_offset_range: None,
                not: None,
            }),
            vec![FileType::Shell],
            "file2.yaml",
            0.9,
            crate::types::Criticality::Notable,
        ),
    ];

    let duplicates = find_atomic_logic_duplicates(&traits);
    assert_eq!(duplicates.len(), 1);
    assert!(duplicates[0].2.contains("conf:"));
}

#[test]
fn test_atomic_logic_duplicates_differ_only_in_unless() {
    use crate::capabilities::validation::duplicates::find_atomic_logic_duplicates;

    // Same matcher, same crit/conf/platforms — they differ only in `unless:`.
    // The matcher signature ignores `unless`, so the pair is flagged and the
    // recommendation is to collapse it into one trait with a downgrade.
    let matcher = || {
        Condition::Raw(RawQuery {
            exact: Some("shared_matcher".to_string()),
            ..Default::default()
        })
    };
    let mut guarded = create_test_trait_with_conf_crit(
        "trait_guarded",
        matcher(),
        vec![FileType::Shell],
        "a.yaml",
        0.9,
        crate::types::Criticality::Suspicious,
    );
    guarded.unless = Some(vec![Condition::Trait {
        id: "some/benign::context".to_string(),
    }]);
    let unguarded = create_test_trait_with_conf_crit(
        "trait_unguarded",
        matcher(),
        vec![FileType::Shell],
        "b.yaml",
        0.9,
        crate::types::Criticality::Suspicious,
    );

    let duplicates = find_atomic_logic_duplicates(&[guarded, unguarded]);
    assert_eq!(
        duplicates.len(),
        1,
        "same matcher differing only in unless must be flagged"
    );
    assert!(duplicates[0].2.contains("unless: differs"));
    assert!(
        duplicates[0].2.contains("downgrade:"),
        "should recommend merging via a downgrade"
    );
}

/// Build two `metadata/` traits sharing a matcher, with the given ids and `unless:`.
fn metadata_unless_pair(
    id_a: &str,
    id_b: &str,
    unless_a: &str,
    unless_b: &str,
) -> Vec<TraitDefinition> {
    let matcher = || {
        Condition::Raw(RawQuery {
            exact: Some("gate_matcher".to_string()),
            ..Default::default()
        })
    };
    let mut a = create_test_trait_with_conf_crit(
        id_a,
        matcher(),
        vec![FileType::Shell],
        "a.yaml",
        0.7,
        crate::types::Criticality::Component,
    );
    a.unless = Some(vec![Condition::Trait {
        id: unless_a.to_string(),
    }]);
    let mut b = create_test_trait_with_conf_crit(
        id_b,
        matcher(),
        vec![FileType::Shell],
        "b.yaml",
        0.7,
        crate::types::Criticality::Component,
    );
    b.unless = Some(vec![Condition::Trait {
        id: unless_b.to_string(),
    }]);
    vec![a, b]
}

// The metadata field-presence idiom: two metadata traits sharing a gate matcher,
// distinct ids, differing only in `unless:` — distinct detections, NOT flagged.
#[test]
fn test_atomic_logic_duplicates_metadata_unless_idiom_skipped() {
    use crate::capabilities::validation::duplicates::find_atomic_logic_duplicates;
    let traits = metadata_unless_pair(
        "metadata/package/manifest::pkginfo-no-author",
        "metadata/package/manifest::pkginfo-no-author-email",
        "field-author-present",
        "field-author-email-present",
    );
    assert!(
        find_atomic_logic_duplicates(&traits).is_empty(),
        "metadata gate+unless idiom must not be flagged"
    );
}

// The same local id duplicated across two metadata directories is a copy-paste —
// flagged even though it differs only in unless and lives under metadata/.
#[test]
fn test_atomic_logic_duplicates_metadata_same_local_id_flagged() {
    use crate::capabilities::validation::duplicates::find_atomic_logic_duplicates;
    let traits = metadata_unless_pair(
        "metadata/binary/metrics/structural::text-dominates-cstring",
        "metadata/binary/anomaly/format::text-dominates-cstring",
        "guard-apple",
        "guard-funcs",
    );
    assert_eq!(
        find_atomic_logic_duplicates(&traits).len(),
        1,
        "same local id across metadata dirs is a copy-paste dupe"
    );
}

// A crit mismatch is a real inconsistency — flagged even within metadata/.
#[test]
fn test_atomic_logic_duplicates_metadata_crit_diff_flagged() {
    use crate::capabilities::validation::duplicates::find_atomic_logic_duplicates;
    let mut traits = metadata_unless_pair(
        "metadata/hardening/mitigation::textrel",
        "metadata/hardening/mitigation::text-relocations",
        "guard-a",
        "guard-b",
    );
    traits[1].crit = crate::types::Criticality::Suspicious; // a is Component
    assert_eq!(
        find_atomic_logic_duplicates(&traits).len(),
        1,
        "crit mismatch must flag even under metadata/"
    );
}

// When the shared matcher is a bare existence gate, crit may legitimately vary per
// field (missing description = notable, missing author = component). Not flagged.
#[test]
fn test_atomic_logic_duplicates_metadata_gate_crit_diff_skipped() {
    use crate::capabilities::validation::duplicates::find_atomic_logic_duplicates;
    let gate = || {
        Condition::Kv(crate::composite_rules::KvQuery {
            path: "metadata-version".to_string(),
            ..Default::default()
        })
    };
    let mut a = create_test_trait_with_conf_crit(
        "metadata/package/manifest::pkginfo-missing-description",
        gate(),
        vec![FileType::Shell],
        "a.yaml",
        0.7,
        crate::types::Criticality::Notable,
    );
    a.unless = Some(vec![Condition::Trait {
        id: "field-description-present".to_string(),
    }]);
    let mut b = create_test_trait_with_conf_crit(
        "metadata/package/manifest::pkginfo-no-author",
        gate(),
        vec![FileType::Shell],
        "b.yaml",
        0.7,
        crate::types::Criticality::Component,
    );
    b.unless = Some(vec![Condition::Trait {
        id: "field-author-present".to_string(),
    }]);
    assert!(
        find_atomic_logic_duplicates(&[a, b]).is_empty(),
        "gate matcher: per-field crit variation is legitimate, not a dupe"
    );
}

#[test]
fn test_atomic_logic_duplicates_overlapping_for_types() {
    use crate::capabilities::validation::duplicates::find_atomic_logic_duplicates;

    // Same pattern, overlapping file types (both include Elf), different crit
    let traits = vec![
        create_test_trait_with_conf_crit(
            "trait_elf_macho",
            Condition::Raw(RawQuery {
                length_min: None,
                length_max: None,
                exact: Some("shared_pattern".to_string()),
                substr: None,
                regex: None,
                word: None,
                case_insensitive: false,
                is_check: None,
                section: None,
                offset: None,
                offset_range: None,
                section_offset: None,
                section_offset_range: None,
                not: None,
            }),
            vec![FileType::Elf, FileType::Macho],
            "file1.yaml",
            1.0,
            crate::types::Criticality::Notable,
        ),
        create_test_trait_with_conf_crit(
            "trait_elf_pe",
            Condition::Raw(RawQuery {
                length_min: None,
                length_max: None,
                exact: Some("shared_pattern".to_string()),
                substr: None,
                regex: None,
                word: None,
                case_insensitive: false,
                is_check: None,
                section: None,
                offset: None,
                offset_range: None,
                section_offset: None,
                section_offset_range: None,
                not: None,
            }),
            vec![FileType::Elf, FileType::Pe],
            "file2.yaml",
            1.0,
            crate::types::Criticality::Hostile,
        ),
    ];

    let duplicates = find_atomic_logic_duplicates(&traits);
    // Should flag: same logic, overlapping types (Elf), different crit
    assert_eq!(duplicates.len(), 1);
}

#[test]
fn test_atomic_logic_duplicates_no_overlap_no_warning() {
    use crate::capabilities::validation::duplicates::find_atomic_logic_duplicates;

    // Same pattern but disjoint file types - no warning
    let traits = vec![
        create_test_trait_with_conf_crit(
            "trait_macho",
            Condition::Raw(RawQuery {
                length_min: None,
                length_max: None,
                exact: Some("platform_pattern".to_string()),
                substr: None,
                regex: None,
                word: None,
                case_insensitive: false,
                is_check: None,
                section: None,
                offset: None,
                offset_range: None,
                section_offset: None,
                section_offset_range: None,
                not: None,
            }),
            vec![FileType::Macho],
            "file1.yaml",
            1.0,
            crate::types::Criticality::Notable,
        ),
        create_test_trait_with_conf_crit(
            "trait_pe",
            Condition::Raw(RawQuery {
                length_min: None,
                length_max: None,
                exact: Some("platform_pattern".to_string()),
                substr: None,
                regex: None,
                word: None,
                case_insensitive: false,
                is_check: None,
                section: None,
                offset: None,
                offset_range: None,
                section_offset: None,
                section_offset_range: None,
                not: None,
            }),
            vec![FileType::Pe],
            "file2.yaml",
            1.0,
            crate::types::Criticality::Hostile,
        ),
    ];

    let duplicates = find_atomic_logic_duplicates(&traits);
    // No overlap in file types, so no warning even with different crit
    assert_eq!(duplicates.len(), 0);
}

#[test]
fn test_atomic_logic_duplicates_inert_crit_equivalent() {
    use crate::capabilities::validation::duplicates::find_atomic_logic_duplicates;

    // Component vs Baseline should NOT trigger a warning (they're equivalent)
    let traits = vec![
        create_test_trait_with_conf_crit(
            "trait_component",
            Condition::Raw(RawQuery {
                length_min: None,
                length_max: None,
                exact: Some("building_block".to_string()),
                substr: None,
                regex: None,
                word: None,
                case_insensitive: false,
                is_check: None,
                section: None,
                offset: None,
                offset_range: None,
                section_offset: None,
                section_offset_range: None,
                not: None,
            }),
            vec![FileType::All],
            "file1.yaml",
            1.0,
            crate::types::Criticality::Component,
        ),
        create_test_trait_with_conf_crit(
            "trait_baseline",
            Condition::Raw(RawQuery {
                length_min: None,
                length_max: None,
                exact: Some("building_block".to_string()),
                substr: None,
                regex: None,
                word: None,
                case_insensitive: false,
                is_check: None,
                section: None,
                offset: None,
                offset_range: None,
                section_offset: None,
                section_offset_range: None,
                not: None,
            }),
            vec![FileType::All],
            "file2.yaml",
            1.0,
            crate::types::Criticality::Baseline,
        ),
    ];

    let duplicates = find_atomic_logic_duplicates(&traits);
    // Component and Baseline are equivalent, same conf, so no warning
    assert_eq!(duplicates.len(), 0);
}

#[test]
fn test_atomic_logic_duplicates_different_logic_no_warning() {
    use crate::capabilities::validation::duplicates::find_atomic_logic_duplicates;

    // Different patterns - no warning even with same metadata
    let traits = vec![
        create_test_trait_with_conf_crit(
            "trait_a",
            Condition::Raw(RawQuery {
                length_min: None,
                length_max: None,
                exact: Some("pattern_a".to_string()),
                substr: None,
                regex: None,
                word: None,
                case_insensitive: false,
                is_check: None,
                section: None,
                offset: None,
                offset_range: None,
                section_offset: None,
                section_offset_range: None,
                not: None,
            }),
            vec![FileType::All],
            "file1.yaml",
            1.0,
            crate::types::Criticality::Notable,
        ),
        create_test_trait_with_conf_crit(
            "trait_b",
            Condition::Raw(RawQuery {
                length_min: None,
                length_max: None,
                exact: Some("pattern_b".to_string()),
                substr: None,
                regex: None,
                word: None,
                case_insensitive: false,
                is_check: None,
                section: None,
                offset: None,
                offset_range: None,
                section_offset: None,
                section_offset_range: None,
                not: None,
            }),
            vec![FileType::All],
            "file2.yaml",
            1.0,
            crate::types::Criticality::Hostile,
        ),
    ];

    let duplicates = find_atomic_logic_duplicates(&traits);
    // Different logic, so no warning
    assert_eq!(duplicates.len(), 0);
}

// ========================================================================
// Structural Regex Duplicate Tests
// ========================================================================

#[test]
fn test_structural_regex_duplicate_char_class_diff() {
    // Two regexes that differ only inside a character class collapse to
    // the same shape and should be flagged.
    let a = create_string_regex(
        "test::a",
        r"(^|[^\w$])eval\s*\(",
        false,
        vec![FileType::JavaScript],
        "file_a.yaml",
    );
    let b = create_string_regex(
        "test::b",
        r"(^|[^\w$.])eval\s*\(",
        false,
        vec![FileType::JavaScript],
        "file_b.yaml",
    );

    let mut warnings = Vec::new();
    find_structural_regex_duplicates(&[a, b], &mut warnings);

    assert_eq!(warnings.len(), 1, "expected one duplicate warning");
    assert!(warnings[0].contains("Structurally duplicate"));
}

#[test]
fn test_structural_regex_duplicate_skipped_when_baseline() {
    // Component/Baseline tier traits are intentional building blocks.
    let a = create_test_trait_with_conf_crit(
        "test::comp_a",
        Condition::Raw(RawQuery {
            length_min: None,
            length_max: None,
            exact: None,
            substr: None,
            regex: Some(r"eval\s*\([a-z]+\)".to_string()),
            word: None,
            case_insensitive: false,
            is_check: None,
            section: None,
            offset: None,
            offset_range: None,
            section_offset: None,
            section_offset_range: None,
            not: None,
        }),
        vec![FileType::JavaScript],
        "file_a.yaml",
        1.0,
        crate::types::Criticality::Component,
    );
    let b = create_test_trait_with_conf_crit(
        "test::comp_b",
        Condition::Raw(RawQuery {
            length_min: None,
            length_max: None,
            exact: None,
            substr: None,
            regex: Some(r"eval\s*\([A-Z]+\)".to_string()),
            word: None,
            case_insensitive: false,
            is_check: None,
            section: None,
            offset: None,
            offset_range: None,
            section_offset: None,
            section_offset_range: None,
            not: None,
        }),
        vec![FileType::JavaScript],
        "file_b.yaml",
        1.0,
        crate::types::Criticality::Component,
    );

    let mut warnings = Vec::new();
    find_structural_regex_duplicates(&[a, b], &mut warnings);
    assert_eq!(warnings.len(), 0, "component-tier should be ignored");
}

#[test]
fn test_structural_regex_duplicate_no_overlap_when_filetypes_disjoint() {
    let a = create_string_regex(
        "test::a",
        r"\bnft\s+flush\s+ruleset\b",
        false,
        vec![FileType::Elf],
        "file_a.yaml",
    );
    let b = create_string_regex(
        "test::b",
        r"nft\s+flush\s+ruleset",
        false,
        vec![FileType::Pe],
        "file_b.yaml",
    );

    let mut warnings = Vec::new();
    find_structural_regex_duplicates(&[a, b], &mut warnings);
    assert_eq!(warnings.len(), 0, "disjoint file types should not collide");
}

#[test]
fn test_structural_regex_duplicate_no_overlap_across_tiers() {
    // notable vs suspicious — different active tiers shouldn't collide,
    // since a graduated severity ladder is intentional.
    let a = create_test_trait_with_conf_crit(
        "test::a",
        Condition::Raw(RawQuery {
            length_min: None,
            length_max: None,
            exact: None,
            substr: None,
            regex: Some(r"eval\s*\(\s*[a-z]+\s*\)".to_string()),
            word: None,
            case_insensitive: false,
            is_check: None,
            section: None,
            offset: None,
            offset_range: None,
            section_offset: None,
            section_offset_range: None,
            not: None,
        }),
        vec![FileType::JavaScript],
        "file_a.yaml",
        1.0,
        crate::types::Criticality::Notable,
    );
    let b = create_test_trait_with_conf_crit(
        "test::b",
        Condition::Raw(RawQuery {
            length_min: None,
            length_max: None,
            exact: None,
            substr: None,
            regex: Some(r"eval\s*\(\s*[A-Z]+\s*\)".to_string()),
            word: None,
            case_insensitive: false,
            is_check: None,
            section: None,
            offset: None,
            offset_range: None,
            section_offset: None,
            section_offset_range: None,
            not: None,
        }),
        vec![FileType::JavaScript],
        "file_b.yaml",
        1.0,
        crate::types::Criticality::Suspicious,
    );

    let mut warnings = Vec::new();
    find_structural_regex_duplicates(&[a, b], &mut warnings);
    assert_eq!(warnings.len(), 0);
}

#[test]
fn test_structural_regex_duplicate_short_shape_ignored() {
    // Only 3 literal bytes; too generic to bucket.
    let a = create_string_regex(
        "test::a",
        r"a[CC]b",
        false,
        vec![FileType::All],
        "file_a.yaml",
    );
    let b = create_string_regex(
        "test::b",
        r"a[A-Z]b",
        false,
        vec![FileType::All],
        "file_b.yaml",
    );

    let mut warnings = Vec::new();
    find_structural_regex_duplicates(&[a, b], &mut warnings);
    assert_eq!(warnings.len(), 0);
}
