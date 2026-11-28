#[test]
fn rebases_temporary_children_without_touching_unrelated_names() {
    let temp = std::path::Path::new("/tmp/.tmp123");
    let decoded = "/sample.gif##media-base64-pe@42";
    for input in ["/tmp/.tmp123!!embedded.dll", ".tmp123!!embedded.dll"] {
        assert_eq!(
            super::rebase_decoded_child_path(input, temp, decoded, decoded),
            format!("{decoded}!!embedded.dll")
        );
    }
    assert_eq!(
        super::rebase_decoded_child_path(".tmp123-other!!file", temp, decoded, decoded),
        ".tmp123-other!!file"
    );
}

/// A compressed layer's one member, which the decompressor names after the
/// temporary file, gets a name of its own instead of its parent's.
#[test]
fn a_compressed_layer_member_is_not_named_like_its_parent() {
    let temp = std::path::Path::new("/tmp/.tmp123");
    let decoded = "/m.gguf##gguf-trailing-data@8736";
    let member = super::decoded_member_root(decoded, filefacts::FileType::Deflate);
    assert_eq!(member, format!("{decoded}!!gguf-trailing-data@8736"));
    assert_eq!(
        super::rebase_decoded_child_path(".tmp123", temp, decoded, &member),
        member
    );
    assert_eq!(
        super::rebase_decoded_child_path(".tmp123!!embedded:pe@0x10", temp, decoded, &member),
        format!("{member}!!embedded:pe@0x10")
    );
    // Absolute temporary paths still name the layer itself.
    assert_eq!(
        super::rebase_decoded_child_path("/tmp/.tmp123", temp, decoded, &member),
        decoded
    );
    // Layers that are not one compressed stream keep their own name.
    assert_eq!(
        super::decoded_member_root(decoded, filefacts::FileType::Pe),
        decoded
    );
}
