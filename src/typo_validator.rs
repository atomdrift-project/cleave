//! Typosquat check: is a name one slip of the keyboard from a well-known one?
//!
//! `is: {typo_of: <dataset>}` holds when the name, normalized, is one edit --
//! an insertion, deletion, substitution or swap of two adjacent characters
//! -- from a dataset entry without being an entry itself, and is not one of
//! the dataset's `lookalikes` (established names that happen to sit that
//! close). Counting a swap as one edit catches `raect` and `aysnc`, which
//! plain edit distance puts two away.
//!
//! Names are compared lowercased with `_` and `.` read as `-` (PEP 503's
//! normal form), so `Py_Yaml` and `py-yaml` are the same name.

use crate::datasets::Dataset;

/// Whether `name` is a near miss of an entry in `dataset`.
#[must_use]
pub(crate) fn is_typo_of(name: &str, dataset: Dataset) -> bool {
    let name = normalize(name);
    if name.is_empty() {
        return false;
    }
    let contents = dataset.contents();
    let known = |set: &std::collections::HashSet<String>| set.iter().any(|e| normalize(e) == name);
    if known(&contents.entries) || known(&contents.lookalikes) {
        return false;
    }
    contents
        .entries
        .iter()
        .any(|entry| within_one_edit(&name, &normalize(entry)))
}

fn normalize(name: &str) -> String {
    name.trim().to_ascii_lowercase().replace(['_', '.'], "-")
}

/// Whether `a` and `b` are at most one insertion, deletion, substitution or
/// adjacent transposition apart.
fn within_one_edit(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len().abs_diff(b.len()) > 1 {
        return false;
    }
    let prefix = a.iter().zip(b).take_while(|(x, y)| x == y).count();
    let (a, b) = (&a[prefix..], &b[prefix..]);
    match (a.len(), b.len()) {
        (0, 0) => true,
        (la, lb) if la == lb => {
            // One substitution, or one swap of the first two differing bytes.
            a[1..] == b[1..] || (la >= 2 && a[0] == b[1] && a[1] == b[0] && a[2..] == b[2..])
        }
        (la, lb) if la > lb => a[1..] == *b,
        _ => *a == b[1..],
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn npm() -> Dataset {
        Dataset::named("top-npm-packages").expect("dataset")
    }

    #[test]
    fn near_misses_of_popular_names() {
        for name in [
            "lodas",
            "lodsh",
            "loadash",
            "lod-ash",
            "expres",
            "reac",
            "raect",
            "axois",
            "axio",
            "chlak",
            "aysnc",
            "requets",
            "wepback",
            "tyepscript",
            "commmander",
        ] {
            assert!(is_typo_of(name, npm()), "{name}");
        }
    }

    #[test]
    fn real_names_are_not_typos() {
        for name in [
            "lodash",
            "react",
            "colors",
            "gaxios",
            "preact",
            "tslint",
            "lodash3",
            "colour",
            "axios-cookiejar-support",
            "@types/react",
            "",
        ] {
            assert!(!is_typo_of(name, npm()), "{name}");
        }
    }

    #[test]
    fn pypi_names_compare_in_normal_form() {
        let pypi = Dataset::named("top-pypi-packages").expect("dataset");
        assert!(is_typo_of("reqests", pypi));
        assert!(is_typo_of("Python_Dateutill", pypi));
        assert!(!is_typo_of("Typing_Extensions", pypi));
        assert!(!is_typo_of("pyaml", pypi));
    }

    #[test]
    fn cli_spellings_parse() {
        use crate::composite_rules::condition::StringValidator;
        assert_eq!("external-ip".parse(), Ok(StringValidator::ExternalIp));
        assert_eq!("external_ip".parse(), Ok(StringValidator::ExternalIp));
        for spelling in ["typo_of:top-npm-packages", "typo-of:top-npm-packages"] {
            assert_eq!(spelling.parse(), Ok(StringValidator::TypoOf(npm())));
        }
        assert!("typo_of:top-crates".parse::<StringValidator>().is_err());
    }

    #[test]
    fn edit_distance() {
        assert!(within_one_edit("abc", "abc"));
        assert!(within_one_edit("abc", "abd"));
        assert!(within_one_edit("abc", "bac"));
        assert!(within_one_edit("abc", "abcd"));
        assert!(within_one_edit("abc", "ac"));
        assert!(!within_one_edit("abc", "cab"));
        assert!(!within_one_edit("abc", "abcde"));
    }
}
