use super::{best_mandatory_atom, bounded_consumed_bytes, mandatory_atom_set};

fn set(pattern: &str) -> Option<Vec<(String, bool)>> {
    mandatory_atom_set(pattern).map(|mut s| {
        s.sort();
        s
    })
}

/// The five consumer-webmail traits were the top aggregate CPU consumers
/// on JS-heavy archives precisely because none of them had an extractable
/// single atom. Each must now gate on its provider-domain any-of set.
#[test]
fn email_provider_family_extracts() {
    assert_eq!(
        set(r"(?i).{0,64}\b[\w.%+-]{1,64}@(gmail|googlemail)\.com\b"),
        Some(vec![("gmail".into(), true), ("googlemail".into(), true)])
    );
    assert_eq!(
        set(r".{0,64}[\w.%+-]{1,64}@(proton\.me|protonmail\.com|pm\.me|tuta\.io)\b"),
        Some(vec![
            ("pm.me".into(), false),
            ("proton.me".into(), false),
            ("protonmail.com".into(), false),
            ("tuta.io".into(), false)
        ])
    );
    // (ru|com) has a 2-byte branch, so the *second* alternation is
    // unusable; the first still gates.
    assert_eq!(
        set(r".{0,64}[\w.%+-]{1,64}@(yandex|mail)\.(ru|com)\b"),
        Some(vec![("mail".into(), false), ("yandex".into(), false)])
    );
    assert_eq!(
        set(r".{0,64}[\w.%+-]{1,64}@(outlook|hotmail|live|msn)\.com\b"),
        Some(vec![
            ("hotmail".into(), false),
            ("live".into(), false),
            ("msn".into(), false),
            ("outlook".into(), false)
        ])
    );
}

/// Single-literal extraction must not regress relative to
/// `best_mandatory_atom` on its own cases.
#[test]
fn single_literal_parity() {
    for pat in [
        r"\s*token.*",
        r"fs\.readdirSync\(",
        r"^import\s+os$",
        r"(?:prefix)?CreateRemoteThread",
    ] {
        let old = best_mandatory_atom(pat);
        let new = set(pat);
        assert!(
            new.is_some() || old.is_none(),
            "{pat}: old extracted {old:?} but new returned None"
        );
    }
}

/// `(?i)` literals parse as case-pair classes; the run coalescer must
/// reassemble them into one CI atom.
#[test]
fn case_insensitive_literal_runs() {
    assert_eq!(
        set(r"(?i)powershell"),
        Some(vec![("powershell".into(), true)])
    );
    // Mixed letters and non-letters stay one run.
    assert_eq!(set(r"(?i)\.com\b"), Some(vec![(".com".into(), true)]));
}

/// Baseline CSS `font-family` rule: the only long mandatory literal sits
/// after `(^|})` and bounded `[^}]` runs, so a prefix extractor leaves it
/// ungated. The any-of walk must still recover the CI `font-family` atom.
#[test]
fn css_font_family_rule_extracts_ci_atom() {
    assert_eq!(
        set(r"(?i)(^|})[^@{}]{0,80}\{[^}]{0,160}font-family\s*:"),
        Some(vec![("font-family".into(), true)])
    );
}

/// Non-ASCII patterns get the unicode engine (E7b), whose case folding
/// covers non-ASCII letters — so a byte-mode-extracted atom carrying raw
/// `ç` bytes is NOT mandatory (`Için` matches the engine, misses the
/// atom). Extraction must parse such patterns in unicode mode, where the
/// fold class at `ç` breaks the run: `için`/`você` branches die and the
/// alternation (or whole pattern) stays ungated. Caught as the
/// `lang-turkish` loss on the VSCodium corpus.
#[test]
fn non_ascii_ci_patterns_do_not_emit_byte_atoms() {
    assert_eq!(set(r"(?i)\b(için|olarak|gibi)\b"), None);
    // The pure-ASCII run before the fold class is still mandatory (every
    // match carries some ASCII case of `voc`), so it may gate; the raw
    // `ê` bytes must not appear in any atom.
    assert_eq!(set(r"(?i)\bvocê\b.{0,2}"), Some(vec![("voc".into(), true)]));
    // Case-sensitive non-ASCII literals are exact bytes in every engine
    // mode; they may still gate.
    assert_eq!(
        set(r"执行任意系统命令"),
        Some(vec![("执行任意系统命令".into(), false)])
    );
}

/// The corpus probe's catch: the HIR factors the shared `[Pp]` out of
/// `PING…PONG|PONG…PING`, and naive prefix composition glued it onto
/// branch atoms that sit mid-branch, gating on nonexistent
/// "pping"/"ppong". Composition must require branch-anchored atoms.
#[test]
fn unanchored_branch_atoms_do_not_compose() {
    let got = set(r"(?i)PING.{0,120}PONG|PONG.{0,120}PING").unwrap();
    assert_eq!(got, vec![("ping".into(), true), ("pong".into(), true)]);
}

/// Sets that cannot be guaranteed (or gate poorly) stay inextractable.
#[test]
fn rejects_unguaranteed_sets() {
    // Every branch short.
    assert_eq!(set(r"@(ru|com)"), None);
    // One uncovered branch voids the alternation.
    assert_eq!(set(r"(gmail|[a-z]{5})"), None);
    // Pure classes / no literal.
    assert_eq!(set(r"(?i)[ąćęłńśźż]"), None);
    assert_eq!(set(r"[\w.%+-]{1,64}"), None);
    // Optional literal is not mandatory.
    assert_eq!(set(r"(?:gmail)?[0-9]{4}"), None);
}

/// Any-of guarantee spot check: strings matching the pattern must contain
/// at least one atom (case-folded when flagged CI).
#[test]
fn atoms_are_mandatory_in_matches() {
    let pat = r"(?i).{0,64}\b[\w.%+-]{1,64}@(gmail|googlemail)\.com\b";
    let atoms = mandatory_atom_set(pat).unwrap();
    let re = regex::Regex::new(pat).unwrap();
    for hay in [
        "contact me at Bob.Smith@GMail.com today",
        "x@googlemail.com",
        "prefix junk drop@gmail.com",
    ] {
        let m = re.find(hay).expect("test string must match");
        let matched = m.as_str().to_ascii_lowercase();
        assert!(
            atoms.iter().any(|(a, ci)| if *ci {
                matched.contains(&a.to_ascii_lowercase())
            } else {
                m.as_str().contains(a.as_str())
            }),
            "match {matched:?} contains no atom from {atoms:?}"
        );
    }
}

#[test]
fn bounded_consumed_bytes_examples() {
    assert_eq!(bounded_consumed_bytes(r"PING.{0,120}PONG"), Some(128));
    assert_eq!(bounded_consumed_bytes(r"foo"), Some(3));
    assert_eq!(bounded_consumed_bytes(r"foo.*bar"), None);
    assert_eq!(bounded_consumed_bytes(r"[^\n]*foo"), None);
    assert_eq!(bounded_consumed_bytes(r"(?s)foo.*bar"), None);
    // Trailing `\s*` is capped so CSS can window; `.*` stays unbounded.
    assert_eq!(bounded_consumed_bytes(r"foo\s*bar"), Some(3 + 256 + 3));
    let css = bounded_consumed_bytes(r"(?i)(^|})[^@{}]{0,80}\{[^}]{0,160}font-family\s*:");
    assert!(css.is_some() && css.unwrap() <= 8192);
}
