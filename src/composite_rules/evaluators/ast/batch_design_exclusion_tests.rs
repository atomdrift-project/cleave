use super::batch_leaves_out_by_design;

#[test]
fn multi_wildcard_and_comment_view_queries_stay_off_the_heavy_tail() {
    assert!(batch_leaves_out_by_design(
        "(call_expression arguments: (arguments (_)* @a (_)* @b))"
    ));
    assert!(batch_leaves_out_by_design(
        "((call_expression) @c (#set! cleave.ignore-comments \"true\"))"
    ));
    assert!(!batch_leaves_out_by_design(
        "(binary_expression left: (_) @l operator: \"-\")"
    ));
}
