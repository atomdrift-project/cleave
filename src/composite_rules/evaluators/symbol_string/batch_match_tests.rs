use super::*;

#[test]
fn batched_regex_preserves_spans_bounds_and_input_boundaries() {
    let values = [
        "",
        "a",
        "abc",
        "ab abcdef 123",
        "prefix suffix",
        "é",
        "αβ abc",
        "12345",
        "a\nb",
        "suffix",
        "prefix",
    ];
    for pattern in [
        "[a-z]+",
        "^abc$",
        "^$",
        "a*",
        "\\b[a-z]+\\b",
        "prefix.*suffix",
        "[0-9]+",
        ".",
        "\\p{Greek}+",
    ] {
        let matcher = StringMatcher::Regex(
            crate::composite_rules::condition::lazy_regex(Some(pattern), false).unwrap(),
        );
        for bounds in [
            (None, None),
            (Some(0), Some(0)),
            (Some(3), None),
            (None, Some(2)),
            (Some(4), Some(6)),
        ] {
            let expected: Vec<_> = values
                .iter()
                .map(|value| matcher.match_value_bounded(value, bounds))
                .collect();
            for count in [0, 1, values.len()] {
                matcher.with_batch(count, |batch| {
                    for _ in 0..32 {
                        for (value, expected) in values.iter().zip(&expected) {
                            let actual = batch.match_value_bounded(value, bounds);
                            assert_eq!(actual, *expected, "{pattern:?}, {bounds:?}, {value:?}");
                            assert_eq!(actual.map(str::as_ptr), expected.map(str::as_ptr));
                        }
                    }
                });
            }
        }
    }
}

#[test]
#[allow(clippy::panic)] // Exercise the scratch reservation unwind path.
fn batched_regex_allows_nested_exclusion_searches_and_unwinding() {
    let re = crate::composite_rules::condition::lazy_regex(Some("[a-z]+"), false).unwrap();
    let other = crate::composite_rules::condition::lazy_regex(Some("[0-9]+"), false).unwrap();
    let matcher = StringMatcher::Regex(re.clone());
    matcher.with_batch(2, |batch| {
        assert_eq!(batch.match_value_bounded("abc", (None, None)), Some("abc"));
        assert_eq!(re.find_str("nested"), Some("nested"));
        assert_eq!(other.find_str("123"), Some("123"));
        assert_eq!(batch.match_value_bounded("def", (None, None)), Some("def"));
    });
    let failed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        matcher.with_batch(2, |_batch| panic!("intentional batch unwind"));
    }));
    assert!(failed.is_err());
    assert_eq!(re.find_str("after"), Some("after"));
}
