//! Offline soundness screen, not part of the suite: verifies over a real
//! corpus that every pattern the any-of extractor newly gates cannot match
//! a file its atoms are absent from. Run with:
//! `PROBE_PATTERNS=… PROBE_CORPUS=… cargo test --release -p cleave --lib \
//!    mandatory_atom_set_probe -- --ignored --nocapture`
use super::{best_mandatory_atom, mandatory_atom_set};

#[test]
#[ignore = "offline probe: set PROBE_PATTERNS and PROBE_CORPUS"]
fn newly_gated_atoms_are_mandatory_on_corpus() {
    let patterns_path = std::env::var("PROBE_PATTERNS").expect("PROBE_PATTERNS");
    let corpus_dir = std::env::var("PROBE_CORPUS").expect("PROBE_CORPUS");
    let pats: Vec<String> = serde_json::from_slice(&std::fs::read(patterns_path).unwrap()).unwrap();

    let mut newly: Vec<(String, Vec<(String, bool)>)> = Vec::new();
    for p in &pats {
        let old = best_mandatory_atom(p);
        let new = mandatory_atom_set(p);
        if old.is_none()
            && let Some(set) = new
        {
            newly.push((p.clone(), set));
        }
    }
    println!("patterns: {}, newly gated: {}", pats.len(), newly.len());

    // Compile byte-mode first, unicode fallback — engine parity.
    let compiled: Vec<(usize, regex::bytes::Regex)> = newly
        .iter()
        .enumerate()
        .filter_map(|(i, (p, _))| {
            regex::bytes::RegexBuilder::new(p)
                .unicode(false)
                .multi_line(true)
                .size_limit(super::REGEX_SIZE_LIMIT)
                .build()
                .or_else(|_| {
                    regex::bytes::RegexBuilder::new(p)
                        .multi_line(true)
                        .size_limit(super::REGEX_SIZE_LIMIT)
                        .build()
                })
                .ok()
                .map(|re| (i, re))
        })
        .collect();

    let mut files = 0usize;
    let mut violations = 0usize;
    for entry in walkdir::WalkDir::new(&corpus_dir)
        .into_iter()
        .filter_map(Result::ok)
        .filter(|e| e.file_type().is_file())
    {
        let Ok(content) = std::fs::read(entry.path()) else {
            continue;
        };
        if content.len() > 300 << 10 {
            continue;
        }
        files += 1;
        let lower: Vec<u8> = content.to_ascii_lowercase();
        for (i, re) in &compiled {
            if !re.is_match(&content) {
                continue;
            }
            let (p, atoms) = &newly[*i];
            let present = atoms.iter().any(|(a, ci)| {
                if *ci {
                    memchr::memmem::find(&lower, a.to_ascii_lowercase().as_bytes()).is_some()
                } else {
                    memchr::memmem::find(&content, a.as_bytes()).is_some()
                }
            });
            if !present {
                violations += 1;
                println!(
                    "VIOLATION file={} pattern={:?} atoms={:?}",
                    entry.path().display(),
                    p,
                    atoms
                );
            }
        }
    }
    println!(
        "checked {} files x {} patterns: {} violations",
        files,
        compiled.len(),
        violations
    );
    assert_eq!(violations, 0, "gate would cause false negatives");
}
