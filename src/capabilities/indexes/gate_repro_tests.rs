use super::*;
use crate::composite_rules::condition::TextQuery;
use crate::composite_rules::{Arch, Platform};

#[test]
fn text_regex_atom_gates_correctly_for_js() {
    let trait_def = TraitDefinition {
        id: "node-readdir-sync-call".to_string(),
        desc: "x".to_string(),
        platforms: vec![Platform::All],
        arch: vec![Arch::All],
        r#for: vec![RuleFileType::JavaScript],
        r#if: Condition::Text(TextQuery {
            regex: Some(r"\bfs[\w$]{0,3}\.readdirSync\s*\(".to_string()),
            ..Default::default()
        }),
        ..Default::default()
    };
    let index = RawContentRegexIndex::build(&[trait_def]);
    assert!(index.is_indexed_trait(0), "trait should be atom-indexed");
    let hits = index.find_matches(b"const e = fs.readdirSync(dir);", &RuleFileType::JavaScript);
    assert!(
        hits.contains(&0),
        "atom present in content must produce a match"
    );
    let miss = index.find_matches(b"nothing relevant here", &RuleFileType::JavaScript);
    assert!(!miss.contains(&0));
}

/// Source-file CSS gate lives on `RawContentRegexIndex`, not the PE
/// extracted-string index (that path caused the Zencoder FN).
#[test]
fn css_font_family_raw_index_gates() {
    let trait_def = TraitDefinition {
        id: "css-font-family".to_string(),
        desc: "x".to_string(),
        platforms: vec![Platform::All],
        arch: vec![Arch::All],
        r#for: vec![RuleFileType::All],
        r#if: Condition::Text(TextQuery {
            regex: Some(r"(?i)(^|})[^@{}]{0,80}\{[^}]{0,160}font-family\s*:".to_string()),
            ..Default::default()
        }),
        ..Default::default()
    };
    let index = RawContentRegexIndex::build(&[trait_def]);
    assert!(index.is_indexed_trait(0));
    assert!(
        !index
            .find_matches(b"no css here", &RuleFileType::JavaScript)
            .contains(&0)
    );
    assert!(
        index
            .find_matches(b"h1 { font-family: serif }", &RuleFileType::JavaScript)
            .contains(&0)
    );
    assert!(
        index
            .find_matches(b"h1 { FONT-FAMILY: serif }", &RuleFileType::JavaScript)
            .contains(&0)
    );
}

#[test]
fn css_font_family_records_atom_offset_on_source() {
    let trait_def = TraitDefinition {
        id: "css-font-family".to_string(),
        desc: "x".to_string(),
        platforms: vec![Platform::All],
        arch: vec![Arch::All],
        r#for: vec![RuleFileType::All],
        r#if: Condition::Text(TextQuery {
            regex: Some(r"(?i)(^|})[^@{}]{0,80}\{[^}]{0,160}font-family\s*:".to_string()),
            ..Default::default()
        }),
        ..Default::default()
    };
    let index = RawContentRegexIndex::build(&[trait_def]);
    let mut content = vec![b'x'; 16 * 1024];
    let atom_at = content.len();
    // `(^|})` cannot see `{` across 16 KiB of padding; a preceding `}`
    // is a real match, not an atom-only candidate.
    content.extend_from_slice(b"}h1 { font-family: serif }");
    let hits = index.find_matches_detailed(&content, &RuleFileType::JavaScript, true);
    assert!(hits.traits.contains(&0));
    #[allow(clippy::expect_used)]
    let offs = hits
        .atom_offsets
        .get(&0)
        .expect("source gate records offset");
    assert_eq!(offs.len(), 1);
    let start = offs[0] as usize;
    assert_eq!(&content[start..start + 11], b"font-family");
    assert_eq!(start, atom_at + 6);
    let miss = index.find_matches_detailed(b"no css here", &RuleFileType::JavaScript, true);
    assert!(!miss.traits.contains(&0));
    assert!(!miss.atom_offsets.contains_key(&0));
}

fn css_font_family_index() -> RawContentRegexIndex {
    RawContentRegexIndex::build(&[TraitDefinition {
        id: "css-font-family".to_string(),
        desc: "x".to_string(),
        platforms: vec![Platform::All],
        arch: vec![Arch::All],
        r#for: vec![RuleFileType::All],
        r#if: Condition::Text(TextQuery {
            regex: Some(r"(?i)(^|})[^@{}]{0,80}\{[^}]{0,160}font-family\s*:".to_string()),
            ..Default::default()
        }),
        ..Default::default()
    }])
}

/// 400 B sits above the 256 B window floor: offsets must be recorded
/// so `eval_raw` can window.
#[test]
fn records_atom_offsets_above_window_floor() {
    let index = css_font_family_index();
    let mut content = vec![b'x'; 2 * 1024];
    let atom_at = content.len();
    content.extend_from_slice(b"}h1 { font-family: serif }");
    let hits = index.find_matches_detailed(&content, &RuleFileType::JavaScript, true);
    assert!(hits.traits.contains(&0));
    #[allow(clippy::expect_used)]
    let offs = hits
        .atom_offsets
        .get(&0)
        .expect("400 B+ source must record offsets");
    let start = offs[0] as usize;
    assert_eq!(&content[start..start + 11], b"font-family");
    assert_eq!(start, atom_at + 6);
}

/// `(?i)font-family` must still see mixed-case `FONT-FAMILY` on a small
/// source member (CI gate via the case-insensitive automaton).
#[test]
fn small_file_ci_literal_gate_finds_mixed_case() {
    let index = css_font_family_index();
    let mut content = vec![b'x'; 2 * 1024];
    let atom_at = content.len();
    content.extend_from_slice(b"}h1 { FONT-FAMILY: serif }");
    let hits = index.find_matches_detailed(&content, &RuleFileType::JavaScript, true);
    assert!(hits.traits.contains(&0), "CI atom must match FONT-FAMILY");
    #[allow(clippy::expect_used)]
    let offs = hits
        .atom_offsets
        .get(&0)
        .expect("2 KiB source must record offsets");
    let start = offs[0] as usize;
    assert_eq!(&content[start..start + 11], b"FONT-FAMILY");
    assert_eq!(start, atom_at + 6);
}

/// Sub-floor stubs still gate on presence, but skip offset recording.
#[test]
fn does_not_record_atom_offsets_below_window_floor() {
    let index = css_font_family_index();
    let mut content = vec![b'x'; 200];
    content.extend_from_slice(b"}h1 { font-family: serif }");
    assert!(content.len() < super::MIN_HAYSTACK_TO_WINDOW);
    let hits = index.find_matches_detailed(&content, &RuleFileType::JavaScript, true);
    assert!(hits.traits.contains(&0), "presence still gates");
    assert!(
        hits.atom_offsets.is_empty(),
        "sub-floor stubs must not record offsets"
    );
}
