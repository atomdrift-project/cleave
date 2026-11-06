#[test]
fn rebases_temporary_children_without_touching_unrelated_names() {
    let temp = std::path::Path::new("/tmp/.tmp123");
    let decoded = "/sample.gif##media-base64-pe@42";
    for input in ["/tmp/.tmp123!!embedded.dll", ".tmp123!!embedded.dll"] {
        assert_eq!(
            super::rebase_decoded_child_path(input, temp, decoded),
            format!("{decoded}!!embedded.dll")
        );
    }
    assert_eq!(
        super::rebase_decoded_child_path(".tmp123-other!!file", temp, decoded),
        ".tmp123-other!!file"
    );
}
