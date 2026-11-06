use super::find_parent_duplicate_segments;

fn dirs(v: &[&str]) -> Vec<String> {
    v.iter().map(ToString::to_string).collect()
}

#[test]
fn flags_exact_plural_and_short_abbreviation_duplicates() {
    let input = dirs(&[
        "micro-behaviors/execution/execution",
        "objectives/credential/credentials",
        "micro-behaviors/process/exec/execution",
    ]);
    assert_eq!(find_parent_duplicate_segments(&input).len(), 3);
}

#[test]
fn allows_full_category_word_in_specific_product_name() {
    let input = dirs(&[
        "well-known/app/browser/browserstack",
        "well-known/app/network/networkmanager",
        "well-known/app/data/dataease",
        "well-known/lib/data/datalevin",
        "well-known/app/media/mediaforge",
    ]);
    assert!(find_parent_duplicate_segments(&input).is_empty());
}
