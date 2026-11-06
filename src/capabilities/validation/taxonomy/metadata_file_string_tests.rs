use super::find_new_metadata_file_string_ids;

fn ids(v: &[&str]) -> Vec<String> {
    v.iter().map(ToString::to_string).collect()
}

#[test]
fn rejects_former_legacy_definitions() {
    let input = ids(&[
        "metadata/file/string/account::account-id-field",
        "metadata/file/string/account::account-last-seen-field",
        "metadata/file/string/application-name::chrome-browser-name-literal",
        "micro-behaviors/communications/http/string::header-reference",
    ]);
    let mut expected = input[..3].to_vec();
    expected.sort();
    assert_eq!(find_new_metadata_file_string_ids(&input), expected);
}

#[test]
fn rejects_retired_legacy_ids() {
    let input = ids(&[
        "metadata/file/string/account::first-name-field",
        "metadata/file/string/account::last-name-field",
        "metadata/file/string/artifact::process-word-token",
        "metadata/file/string/attribution::author-banner",
        "metadata/file/string/container::poststart-str",
        "metadata/file/string/container::poststop-str",
        "metadata/file/string/container::prestart-str",
        "metadata/file/string/count::binary-strings-at-most-50",
        "metadata/file/string/count::binary-strings-one-to-five",
        "metadata/file/string/count::few-high-entropy-strings-20",
        "metadata/file/string/count::few-string-literals",
        "metadata/file/string/count::fifty-plus-url-strings",
        "metadata/file/string/count::high-entropy-strings-20",
        "metadata/file/string/count::high-entropy-strings-200",
        "metadata/file/string/count::high-entropy-strings-450-plus",
        "metadata/file/string/count::large-macho-high-entropy-string-profile",
        "metadata/file/string/count::large-macho-strings-at-most-50",
        "metadata/file/string/count::large-pe-strings-at-most-128",
        "metadata/file/string/count::string-concealment",
        "metadata/file/string/count::string-count-over-10000",
        "metadata/file/string/count::ten-plus-ip-address-strings",
        "metadata/file/string/count::twenty-plus-shell-command-strings",
        "metadata/file/string/count::vbs-many-long-tokens",
        "metadata/file/string/file::credential-file-extension--kdbx",
        "metadata/file/string/identity::jfif-or-jpeg-media-marker",
        "metadata/file/string/process-name::calc-exe-name",
        "metadata/file/string/process-name::iexplore-exe-name",
        "metadata/file/string/process-name::notepad-exe-name",
        "metadata/file/string/telemetry::device-id-field",
    ]);
    assert_eq!(find_new_metadata_file_string_ids(&input), input);
}

#[test]
fn rejects_new_ids_inside_legacy_leaves_and_new_leaves() {
    let input = ids(&[
        // Adding a rule to an established source leaf is still forbidden.
        "metadata/file/string/account::new-account-string",
        // Creating a new taxonomy leaf is forbidden too.
        "metadata/file/string/software::new-software-name",
        "metadata/file/string/account/credentials::new-secret-label",
        "micro-behaviors/data/string/replace",
        "objectives/credential-access/theft/keywords",
    ]);
    assert_eq!(
        find_new_metadata_file_string_ids(&input),
        vec![
            "metadata/file/string/account/credentials::new-secret-label".to_string(),
            "metadata/file/string/account::new-account-string".to_string(),
            "metadata/file/string/software::new-software-name".to_string(),
        ]
    );
}
