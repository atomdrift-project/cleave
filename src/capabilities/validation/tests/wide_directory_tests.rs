use crate::capabilities::validation::{
    MAX_SUBDIRECTORIES_PER_DIRECTORY, find_wide_trait_directories,
};

/// Leaf directories under `parent`, one per child: `parent/child-<n>`.
fn leaves(parent: &str, count: usize) -> Vec<String> {
    (0..count).map(|n| format!("{parent}/child-{n}")).collect()
}

#[test]
fn narrow_directory_is_clean() {
    let dirs = leaves("well-known/app", MAX_SUBDIRECTORIES_PER_DIRECTORY);
    assert!(find_wide_trait_directories(&dirs).is_empty());
}

#[test]
fn wide_directory_is_flagged() {
    let dirs = leaves("well-known/app", MAX_SUBDIRECTORIES_PER_DIRECTORY + 1);
    assert_eq!(
        find_wide_trait_directories(&dirs),
        vec![(
            "well-known/app".to_string(),
            MAX_SUBDIRECTORIES_PER_DIRECTORY + 1
        )]
    );
}

#[test]
fn counts_immediate_children_not_descendants() {
    // One child holding many grandchildren keeps the parent narrow.
    let dirs = leaves(
        "well-known/app/chrome",
        MAX_SUBDIRECTORIES_PER_DIRECTORY + 1,
    );
    let violations = find_wide_trait_directories(&dirs);
    assert_eq!(
        violations,
        vec![(
            "well-known/app/chrome".to_string(),
            MAX_SUBDIRECTORIES_PER_DIRECTORY + 1
        )],
        "only the level that fans out should be reported"
    );
}

#[test]
fn child_seen_through_many_leaves_counts_once() {
    // Deeper leaves under the same child must not inflate the parent's width.
    let mut dirs = leaves("well-known/app", MAX_SUBDIRECTORIES_PER_DIRECTORY);
    dirs.extend((0..50).map(|n| format!("well-known/app/child-0/deep-{n}")));
    assert!(find_wide_trait_directories(&dirs).is_empty());
}

#[test]
fn violations_are_widest_first_then_lexicographic() {
    let mut dirs = leaves("well-known/app", MAX_SUBDIRECTORIES_PER_DIRECTORY + 9);
    dirs.extend(leaves(
        "well-known/lib",
        MAX_SUBDIRECTORIES_PER_DIRECTORY + 1,
    ));
    dirs.extend(leaves(
        "well-known/game",
        MAX_SUBDIRECTORIES_PER_DIRECTORY + 1,
    ));
    let violations = find_wide_trait_directories(&dirs);
    let order: Vec<&str> = violations.iter().map(|(dir, _)| dir.as_str()).collect();
    assert_eq!(
        order,
        ["well-known/app", "well-known/game", "well-known/lib"]
    );
}
