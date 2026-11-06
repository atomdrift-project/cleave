use super::find_metadata_content_dirs;

fn dirs(v: &[&str]) -> Vec<String> {
    v.iter().map(ToString::to_string).collect()
}

#[test]
fn flags_content_dirs_under_metadata_only() {
    let input = dirs(&[
        "metadata/binary/anomaly/content",
        "metadata/binary/section/content",
        "metadata/binary/section/metrics",
        // content/ outside metadata/ is legitimate and must not be flagged.
        "objectives/anti-static/obfuscation/encoding/content",
        "micro-behaviors/data/embedded/hash-table",
    ]);
    let mut got = find_metadata_content_dirs(&input);
    got.sort();
    assert_eq!(
        got,
        vec![
            "metadata/binary/anomaly/content".to_string(),
            "metadata/binary/section/content".to_string(),
        ]
    );
}

#[test]
fn clean_metadata_tree_has_no_violations() {
    let input = dirs(&[
        "metadata/binary/anomaly/format",
        "metadata/binary/section/metrics",
        "metadata/vendor",
    ]);
    assert!(find_metadata_content_dirs(&input).is_empty());
}
