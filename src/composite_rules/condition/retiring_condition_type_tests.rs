use super::*;

#[test]
fn counts_each_retiring_spelling_once_per_condition() {
    let yaml = b"traits:\n  - if:\n      type: string_literal\n  - if:\n      type: literal\n  - type: 'basename'\n    exact: x\n  # type: import\n";
    assert_eq!(
        count_retiring_condition_types([yaml.as_slice()]),
        [1, 0, 0, 0, 1]
    );
}
