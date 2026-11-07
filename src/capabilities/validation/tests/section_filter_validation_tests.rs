use crate::capabilities::validation::taxonomy::{
    find_meta_missing_section_filter, find_wellknown_missing_section_filter,
    find_wellknown_missing_size_filter,
};
use crate::composite_rules::{Arch, Condition, FileType, Platform, TextQuery, TraitDefinition};
use std::collections::HashMap;
use std::path::PathBuf;

fn text_trait(id: &str, for_types: Vec<FileType>) -> TraitDefinition {
    TraitDefinition {
        id: id.to_string(),
        desc: "test".to_string(),
        conf: 0.8,
        crit: crate::types::Criticality::Notable,
        mbc: None,
        attack: None,
        r#if: Condition::Text(TextQuery {
            encoding: None,
            length_min: None,
            length_max: None,
            exclude_html_comments: false,
            exclude_comments: false,
            exact: None,
            substr: Some("ProjectDiscovery".to_string()),
            regex: None,
            word: None,
            case_insensitive: false,
            is_check: None,
            not: None,
            platforms: None,
            section: None,
            offset: None,
            offset_range: None,
            section_offset: None,
            section_offset_range: None,
        }),
        size_min: None,
        size_max: None,
        count_min: None,
        count_max: None,
        per_kb_min: None,
        per_kb_max: None,
        entropy_min: None,
        entropy_max: None,
        r#for: for_types,
        for_from_groups: false,
        platforms: vec![Platform::All],
        arch: vec![Arch::All],
        not: None,
        unless: None,
        downgrade: None,
        defined_in: PathBuf::from("test.yml"),
        precision: None,
        ..Default::default()
    }
}

#[test]
fn wellknown_section_filter_skips_mixed_binary_and_script_targets() {
    let traits = vec![text_trait(
        "well-known/tool/test::mixed",
        vec![FileType::Pe, FileType::Shell],
    )];
    let mut sources = HashMap::new();
    sources.insert(
        "well-known/tool/test::mixed".to_string(),
        "./well-known/tool/test/traits.yaml".to_string(),
    );
    let result = find_wellknown_missing_section_filter(&traits, &sources);
    assert!(result.is_empty());
}

#[test]
fn wellknown_section_filter_flags_binary_only_targets() {
    let traits = vec![text_trait(
        "well-known/tool/test::binary",
        vec![FileType::Pe],
    )];
    let mut sources = HashMap::new();
    sources.insert(
        "well-known/tool/test::binary".to_string(),
        "./well-known/tool/test/traits.yaml".to_string(),
    );
    let result = find_wellknown_missing_section_filter(&traits, &sources);
    assert_eq!(result.len(), 1);
    assert_eq!(result[0].0, "well-known/tool/test::binary");
}

#[test]
fn only_reviewed_adobe_marker_keeps_whole_file_scope() {
    let traits = vec![
        text_trait(
            "well-known/app/system/adobe-acrobat-updater::adobe-acrobat-updater-text",
            vec![FileType::Pe],
        ),
        text_trait(
            "well-known/app/productivity/adobe-reader::other",
            vec![FileType::Pe],
        ),
    ];
    let result = find_wellknown_missing_section_filter(&traits, &HashMap::new());
    assert_eq!(result.len(), 1);
    assert_eq!(
        result[0].0,
        "well-known/app/productivity/adobe-reader::other"
    );
}

#[test]
fn reviewed_oep_banner_keeps_whole_file_scope_and_no_size_bound() {
    let marker = text_trait(
        "well-known/tool/reverse-engineering/oep-finder::geta-oep-banner-marker",
        vec![FileType::Pe],
    );
    let other = text_trait(
        "well-known/tool/reverse-engineering/oep-finder::other-banner",
        vec![FileType::Pe],
    );
    let traits = vec![marker, other];
    let sizes = find_wellknown_missing_size_filter(&traits, &HashMap::new());
    let sections = find_wellknown_missing_section_filter(&traits, &HashMap::new());
    assert_eq!(sizes.len(), 1);
    assert_eq!(sections.len(), 1);
    assert!(sizes[0].0.ends_with("::other-banner"));
    assert!(sections[0].0.ends_with("::other-banner"));
}

#[test]
fn advanced_installer_size_exceptions_match_reviewed_strings() {
    for (id, query) in [
        (
            "external-ui-started-marker",
            "type: text\nsubstr: Advanced Installer External UI started.\nsection: .rdata\n",
        ),
        (
            "bootstrapper-flag",
            "type: text\nexact: AI_BOOTSTRAPPER\nsection: .rdata\n",
        ),
        (
            "caphyon-registry-root",
            "type: text\nexact: 'Software\\Caphyon\\Advanced Installer\\'\nsection: .rdata\n",
        ),
        (
            "prerequisite-install-marker",
            "type: text\nsubstr: AI_InstallPrerequisite\nsection: .rdata\n",
        ),
    ] {
        let mut fact = text_trait(
            &format!("well-known/lib/platform/advanced-installer::{id}"),
            vec![FileType::Pe],
        );
        fact.crit = crate::types::Criticality::Notable;
        fact.r#if = crate::yaml::from_str(query).unwrap();
        assert!(find_wellknown_missing_size_filter(&[fact.clone()], &HashMap::new()).is_empty());
        fact.id.push_str("-changed");
        assert_eq!(
            find_wellknown_missing_size_filter(&[fact], &HashMap::new()).len(),
            1
        );
    }
}

#[test]
fn inetc_user_agent_size_exception_is_matcher_specific() {
    let mut fact = text_trait(
        "well-known/tool/packaging/nsis-inetc::inetc-user-agent",
        vec![FileType::Pe],
    );
    fact.crit = crate::types::Criticality::Notable;
    fact.r#if =
        crate::yaml::from_str("type: text\nexact: NSIS_Inetc (Mozilla)\nsection: rdata\n").unwrap();
    assert!(find_wellknown_missing_size_filter(&[fact.clone()], &HashMap::new()).is_empty());
    fact.r#if =
        crate::yaml::from_str("type: text\nexact: NSIS_Inetc (Mozilla)\nsection: .text\n").unwrap();
    assert_eq!(
        find_wellknown_missing_size_filter(&[fact], &HashMap::new()).len(),
        1
    );
}

#[test]
fn izpack_path_size_exception_is_matcher_specific() {
    let mut fact = text_trait(
        "well-known/tool/packaging/izpack::izpack-package-path",
        vec![FileType::Pe],
    );
    fact.crit = crate::types::Criticality::Notable;
    fact.r#if = crate::yaml::from_str(
        r"type: path
regex: 'com[/\\]izforge[/\\]izpack'
",
    )
    .unwrap();
    assert!(find_wellknown_missing_size_filter(&[fact.clone()], &HashMap::new()).is_empty());
    fact.r#if = crate::yaml::from_str("type: path\nregex: changed\n").unwrap();
    assert_eq!(
        find_wellknown_missing_size_filter(&[fact], &HashMap::new()).len(),
        1
    );
}

#[test]
fn inno_runtime_size_exceptions_are_matcher_specific() {
    for (id, query) in [
        (
            "inno-setup-550-data-marker",
            "type: text\nexact: 'Inno Setup Setup Data (5.5.0)'\nsection: rdata\n",
        ),
        (
            "inno-password-canary",
            "type: text\nexact: sccPasswordTest\nsection: rdata\n",
        ),
        (
            "inno-setup-header-670",
            "type: hex\npattern: '49 6E 6E 6F 20 53 65 74 75 70 20 53 65 74 75 70 20 44 61 74 61 20 28 36 2E 37 2E 30 29'\noffset_range: [800000, null]\n",
        ),
    ] {
        let mut fact = text_trait(
            &format!("well-known/tool/packaging/inno-setup-runtime::{id}"),
            vec![FileType::Pe],
        );
        fact.crit = crate::types::Criticality::Notable;
        fact.r#if = crate::yaml::from_str(query).unwrap();
        assert!(find_wellknown_missing_size_filter(&[fact.clone()], &HashMap::new()).is_empty());
        fact.id.push_str("-changed");
        assert_eq!(
            find_wellknown_missing_size_filter(&[fact], &HashMap::new()).len(),
            1
        );
    }
}

#[test]
fn nsis_size_exceptions_are_matcher_specific() {
    for (id, query) in [
        (
            "nsis-manifest-identity",
            "type: value\npath: pe.manifest.description\nregex: '(?i)^Nullsoft Install System'\n",
        ),
        (
            "nullsoft-install-system-text",
            "type: text\nsubstr: Nullsoft Install System\nsection: .text\n",
        ),
        (
            "nullsoft-install-system-rdata",
            "type: text\nsubstr: Nullsoft Install System\nsection: .rdata\n",
        ),
        (
            "nsis-error-title-rdata",
            "type: text\nexact: NSIS Error\nsection: .rdata\n",
        ),
        (
            "nsis-error-title-data",
            "type: text\nexact: NSIS Error\nsection: .data\n",
        ),
        (
            "nsis-error-url-rdata",
            "type: text\nsubstr: nsis.sf.net/NSIS_Error\nsection: .rdata\n",
        ),
        (
            "nsis-error-url-data",
            "type: text\nsubstr: nsis.sf.net/NSIS_Error\nsection: .data\n",
        ),
        (
            "nsis-uac-ipc",
            "type: text\nexact: NSISUACIPC\nsection: .rdata\n",
        ),
        (
            "nullsoftinst-marker",
            "type: text\nexact: NullsoftInst\nsection: .rdata\n",
        ),
    ] {
        let mut fact = text_trait(
            &format!("well-known/tool/packaging/nsis::{id}"),
            vec![FileType::Pe],
        );
        fact.crit = crate::types::Criticality::Notable;
        fact.r#if = crate::yaml::from_str(query).unwrap();
        assert!(find_wellknown_missing_size_filter(&[fact.clone()], &HashMap::new()).is_empty());
        fact.id.push_str("-changed");
        assert_eq!(
            find_wellknown_missing_size_filter(&[fact], &HashMap::new()).len(),
            // Manifest descriptions also have a general size exemption.
            usize::from(id != "nsis-manifest-identity")
        );
    }
}

#[test]
fn installer_reference_size_exceptions_are_matcher_specific() {
    for (id, query) in [
        (
            "well-known/app/development/code-forge/github::github-web-raw-msi-url",
            r###"type: text
regex: 'https://github\.com/.{1,40}/.{1,40}/raw/.{1,40}/.{1,80}\.msi'
"###,
        ),
        (
            "well-known/app/development/code-forge/github::github-web-raw-url",
            r###"type: text
regex: 'https?://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/raw/(refs/heads/)?'
"###,
        ),
        (
            "well-known/app/development/code-forge/github::raw-githubusercontent-web-file",
            r###"type: text
regex: 'raw\.githubusercontent\.com/.{1,100}\.(html|txt|php)'
"###,
        ),
        (
            "well-known/app/development/code-forge/github::raw-githubusercontent-script-file",
            r###"type: text
regex: 'raw\.githubusercontent\.com/.{1,100}\.(sh|py|ps1|cmd)\b'
"###,
        ),
        (
            "well-known/app/development/code-forge/github::raw-githubusercontent-scripting-lang",
            r###"type: text
regex: 'raw\.githubusercontent\.com/.{1,100}\.(rb|pl|js)\b'
"###,
        ),
        (
            "well-known/app/development/code-forge/github::raw-githubusercontent-actions-url",
            r###"type: text
regex: '(?i)raw\.githubusercontent\.com/actions/'
"###,
        ),
        (
            "well-known/app/development/code-forge/github::raw-githubusercontent-native-library",
            r###"type: text
regex: 'raw\.githubusercontent\.com/.{1,140}\.(so(\.[0-9.]+)?|dylib|dll)\b'
"###,
        ),
        (
            "well-known/app/development/code-forge/github::raw-githubusercontent-msbuild-project",
            r###"type: text
regex: 'raw\.githubusercontent\.com/.{1,160}\.(csproj|vbproj|fsproj|sln)\b'
"###,
        ),
        (
            "well-known/app/development/code-forge/github::raw-githubusercontent-image-suffix",
            r###"type: text
regex: '(?i)raw\.githubusercontent\.com/[^\s"''`]{1,120}\.(png|jpe?g|gif)\b'
"###,
        ),
        (
            "well-known/app/development/code-forge/github::raw-githubusercontent-any",
            r###"type: text
regex: 'raw\.githubusercontent\.com/[a-zA-Z0-9._-]+/[a-zA-Z0-9._-]+/'
"###,
        ),
        (
            "well-known/app/development/code-forge/github::raw-githubusercontent-refs",
            r###"type: text
regex: 'raw\.githubusercontent\.com/.{1,80}/refs/heads/'
"###,
        ),
        (
            "well-known/app/development/code-forge/github::raw-githubusercontent-host-string",
            r###"type: text
exact: 'raw.githubusercontent.com'
"###,
        ),
        (
            "well-known/app/development/code-forge/github::gist-githubusercontent-raw-binary-url",
            r###"type: text
regex: 'gist\.githubusercontent\.com/[^\s/]{1,80}/[^\s/]{1,80}/raw/'
"###,
        ),
        (
            "well-known/lib/ai/tesseract::tesseract-upstream-model-url",
            "type: text\nsubstr: github.com/tesseract-ocr/tessdata\n",
        ),
        (
            "well-known/app/storage/mediafire::mediafire-download-url",
            r###"type: text
regex: 'mediafire\.com/(file|download)/[a-zA-Z0-9_-]{10,}'
"###,
        ),
        (
            "well-known/app/productivity/zoho::zoho-service-url",
            r###"type: text
regex: 'https?://(www\.)?(zohoapis|workdrive\.zoho|accounts\.zoho)\.[a-z]{2,3}(\.[a-z]{2})?/'
"###,
        ),
        (
            "well-known/app/productivity/zoho::zoho-service-host-reference",
            r###"type: text
regex: '(?i)(^|[^\w.-])(zohoapis|(workdrive|accounts)\.zoho)\.[a-z]{2,3}(\.[a-z]{2})?([^\w.-]|$)'
"###,
        ),
        (
            "well-known/app/productivity/zoho::zoho-oauth-token-url",
            r###"type: text
regex: '(?i)(^|[^\w.-])accounts\.zoho\.[a-z]{2,3}(\.[a-z]{2})?/oauth/v2/token\b'
"###,
        ),
        (
            "well-known/app/productivity/zoho::workdrive-zoho-host-url",
            r###"type: text
regex: 'https?://workdrive\.zoho\.(com|eu|in|jp|ca|sa|com\.[a-z]{2})/'
"###,
        ),
        (
            "well-known/app/productivity/zoho::workdrive-zoho-api-url",
            r###"type: text
regex: 'https?://([a-z0-9-]+\.)?zohoapis\.(com|eu|in|jp|ca|sa|com\.[a-z]{2})/workdrive/'
"###,
        ),
        (
            "well-known/app/storage/dropbox::dropbox-direct-share-url",
            r###"type: text
regex: '(dl\.dropbox\.com|dl\.dropboxusercontent\.com)/s(cl)?/fi/[a-zA-Z0-9_-]{10,}'
"###,
        ),
        (
            "well-known/app/storage/dropbox::dropbox-web-share-url",
            r###"type: text
regex: '(www\.dropbox\.com)/s(cl)?/fi/[a-zA-Z0-9_-]{10,}'
"###,
        ),
        (
            "well-known/app/storage/dropbox::dropboxusercontent-executable-url",
            r###"type: text
regex: 'dl\.dropboxusercontent\.com/[^\s"''<>]{1,240}\.(exe|dll|bat|ps1|msi)\b'
"###,
        ),
        (
            "well-known/app/storage/dropbox::dropbox-share-executable-url",
            r###"type: text
regex: 'www\.dropbox\.com/s(cl)?/fi/[A-Za-z0-9_-]{10,}[^\s"''<>]{0,240}\.(exe|dll|bat|ps1|msi)\b'
"###,
        ),
        (
            "well-known/app/storage/dropbox::dropbox-direct-executable-url",
            r###"type: text
regex: 'dl\.dropbox\.com/s(cl)?/fi/[A-Za-z0-9_-]{10,}[^\s"''<>]{0,240}\.(exe|dll|bat|ps1|msi)\b'
"###,
        ),
        (
            "well-known/app/storage/dropbox::dropbox-share-url-bytecode",
            r###"type: text
regex: '(dl\.dropbox|www\.dropbox)\.com/s(cl)?/fi/[a-zA-Z0-9_-]{10,}'
"###,
        ),
        (
            "well-known/app/storage/google-drive::gdrive-export-download-url",
            r###"type: text
regex: '(drive|docs)\.google\.com/uc\?export=download&id=[a-zA-Z0-9_-]{20,}'
"###,
        ),
        (
            "well-known/app/storage/google-drive::gdrive-usercontent-download-reference",
            r###"type: text
substr: 'drive.usercontent.google.com/download'
"###,
        ),
        (
            "well-known/app/storage/google-drive::gdrive-usercontent-host",
            r###"type: text
exact: 'drive.usercontent.google.com'
"###,
        ),
        (
            "well-known/app/storage/google-drive::gdrive-pe-file-url",
            r###"type: text
regex: '(drive|docs)\.google\.com/(uc|file/d)/[a-zA-Z0-9_-]{20,}[^\s,"''<>]{0,200}\.(exe|dll)\b'
"###,
        ),
        (
            "well-known/app/storage/google-drive::gdrive-script-file-url",
            r###"type: text
regex: '(drive|docs)\.google\.com/(uc|file/d)/[a-zA-Z0-9_-]{20,}[^\s,"''<>]{0,200}\.(bat|ps1)\b'
"###,
        ),
        (
            "well-known/app/storage/alibaba-oss::oss-service-host-reference",
            r###"type: text
regex: '(?i)([A-Za-z0-9-]{1,64}\.oss-(cn|ap|us|eu|me)-[A-Za-z0-9-]{1,32}|oss)\.aliyuncs\.com'
"###,
        ),
        (
            "well-known/app/storage/alibaba-oss::oss-bucket-host-cn-ap",
            r###"type: text
regex: '[a-z0-9-]{1,64}\.oss-(cn|ap)-[a-z0-9-]{1,32}\.aliyuncs\.com'
"###,
        ),
        (
            "well-known/app/storage/alibaba-oss::oss-bucket-host-us-eu",
            r###"type: text
regex: '[a-z0-9-]{1,64}\.oss-(us|eu)-[a-z0-9-]{1,32}\.aliyuncs\.com'
"###,
        ),
        (
            "well-known/app/storage/alibaba-oss::oss-bucket-host-me",
            r###"type: text
regex: '[a-z0-9-]{1,64}\.oss-(me)-[a-z0-9-]{1,32}\.aliyuncs\.com'
"###,
        ),
        (
            "well-known/app/storage/alibaba-oss::oss-executable-url-cn-ap",
            r###"type: text
regex: '\.oss-(cn|ap)-[a-z0-9-]{1,32}\.aliyuncs\.com/.{1,200}\.(exe|dll)\b'
"###,
        ),
        (
            "well-known/app/storage/alibaba-oss::oss-script-url-cn-ap",
            r###"type: text
regex: '\.oss-(cn|ap)-[a-z0-9-]{1,32}\.aliyuncs\.com/.{1,200}\.(bat|ps1)\b'
"###,
        ),
        (
            "well-known/app/storage/alibaba-oss::oss-executable-url-us-eu",
            r###"type: text
regex: '\.oss-(us|eu)-[a-z0-9-]{1,32}\.aliyuncs\.com/.{1,200}\.(exe|dll)\b'
"###,
        ),
        (
            "well-known/app/storage/alibaba-oss::oss-script-url-us-eu",
            r###"type: text
regex: '\.oss-(us|eu)-[a-z0-9-]{1,32}\.aliyuncs\.com/.{1,200}\.(bat|ps1)\b'
"###,
        ),
        (
            "well-known/app/storage/alibaba-oss::oss-executable-url-me",
            r###"type: text
regex: '\.oss-(me)-[a-z0-9-]{1,32}\.aliyuncs\.com/.{1,200}\.(exe|dll|bat|ps1)\b'
"###,
        ),
        (
            "well-known/app/storage/tencent-cos::myqcloud-domain-reference",
            r###"type: text
regex: '(?i)myqcloud\.com'
"###,
        ),
        (
            "well-known/app/storage/tencent-cos::tencent-cos-url",
            r###"type: text
regex: '[a-z0-9-]{1,64}\.cos\.ap-[a-z0-9-]{1,32}\.myqcloud\.com'
"###,
        ),
        (
            "well-known/app/storage/tencent-cos::cos-pe-url",
            r###"type: text
regex: '\.cos\.ap-[a-z0-9-]{1,32}\.myqcloud\.com/.{1,200}\.(exe|dll)\b'
"###,
        ),
        (
            "well-known/app/storage/tencent-cos::cos-installer-batch-url",
            r###"type: text
regex: '\.cos\.ap-[a-z0-9-]{1,32}\.myqcloud\.com/.{1,200}\.(msi|bat)\b'
"###,
        ),
        (
            "well-known/app/storage/tencent-cos::cos-powershell-url",
            r###"type: text
regex: '\.cos\.ap-[a-z0-9-]{1,32}\.myqcloud\.com/.{1,200}\.(ps1)\b'
"###,
        ),
        (
            "well-known/app/storage/tencent-cos::tencent-cos-archive-url",
            r###"type: text
regex: '\.cos\.ap-[a-z0-9-]{1,32}\.myqcloud\.com/.{1,200}\.(zip|7z|rar)\b'
"###,
        ),
        (
            "well-known/app/storage/digitalocean-spaces::spaces-domain-reference",
            r###"type: text
regex: '(?i)digitaloceanspaces\.com'
"###,
        ),
        (
            "well-known/app/storage/filen::filen-domain-reference",
            r###"type: text
regex: '(?i)\bfilen\.(io|net)\b'
"###,
        ),
        (
            "well-known/app/storage/koofr::koofr-domain-reference",
            r###"type: text
regex: '(?i)\bkoofr\.(eu|com)\b'
"###,
        ),
        (
            "well-known/app/storage/amazon-s3::aws-s3-url",
            r###"type: text
regex: '(?i)https?://([a-z0-9-]+\.)?s3([.-][a-z0-9-]+)?\.amazonaws\.com/'
"###,
        ),
        (
            "well-known/app/storage/amazon-s3::s3-bucket-uri",
            r###"type: text
regex: '(?i)\bs3://[a-z0-9][a-z0-9.-]{1,62}(/|$)'
"###,
        ),
        (
            "well-known/app/storage/google-cloud-storage::gcs-url",
            r###"type: text
regex: 'https?://storage\.googleapis\.com/[a-z0-9-_]+(/|["'']|$)'
"###,
        ),
        (
            "well-known/app/storage/cloudflare-r2::r2-object-endpoint",
            r###"type: text
regex: '(?i)(^|[^A-Za-z0-9.-])([a-z0-9-]+\.)?r2\.cloudflarestorage\.com([^A-Za-z0-9.-]|$)'
"###,
        ),
        (
            "well-known/app/storage/cloudflare-r2::cloudflare-r2-url",
            r###"type: text
regex: 'https?://[a-z0-9-]+\.r2\.cloudflarestorage\.com(/|["'']|$)'
"###,
        ),
        (
            "well-known/app/storage/cloudflare-r2::cloudflare-r2-pub-url",
            r###"type: text
regex: 'https?://pub-[a-f0-9]+\.r2\.dev/'
"###,
        ),
        (
            "well-known/app/storage/digitalocean-spaces::do-spaces-url",
            r###"type: text
regex: 'https?://[a-z0-9-]+\.[a-z0-9-]+\.digitaloceanspaces\.com/'
"###,
        ),
        (
            "well-known/app/storage/vultr-object-storage::vultr-object-storage-url",
            r###"type: text
regex: 'https?://[a-z0-9-]+\.[a-z0-9-]+\.vultrobjects\.com/'
"###,
        ),
        (
            "well-known/app/storage/backblaze-b2::backblaze-b2-url",
            r###"type: text
regex: 'https?://[a-z0-9-]+\.backblazeb2\.com/'
"###,
        ),
        (
            "well-known/app/communication/discord::discord-cdn-shell-script-url",
            r##"type: text
regex: 'cdn\.discordapp\.com/attachments/\d+/\d+/[^\s"''<>]{1,80}\.sh\b'
"##,
        ),
        (
            "well-known/app/communication/discord::discord-cdn-download-url",
            r##"type: text
regex: '(cdn|media)\.discordapp\.(com|net)/attachments/\d+/\d+/'
"##,
        ),
        (
            "well-known/app/communication/discord::discord-cdn-windows-executable-url",
            r##"type: text
regex: 'discordapp\.com/attachments/[0-9]{15,}/[0-9]{15,}/.{1,80}\.(exe|dll|bat|ps1)\b'
"##,
        ),
        (
            "well-known/app/communication/discord::discord-cdn-archive-url",
            r##"type: text
regex: 'discordapp\.com/attachments/[0-9]{15,}/[0-9]{15,}/.{1,80}\.(zip|7z|rar)\b'
"##,
        ),
        (
            "well-known/app/storage/mega::mega-file-share-url",
            r##"type: text
regex: 'mega\.nz/(file/[a-zA-Z0-9_-]{8,}|#![a-zA-Z0-9_-]{8,})'
"##,
        ),
        (
            "well-known/app/infrastructure/content-delivery/jsdelivr::jsdelivr-npm-script-url",
            r#"type: text
regex: 'cdn\.jsdelivr\.net/npm/[^"''\s]{0,160}\.js([?#"''`\s<>)\]}]|$)'
"#,
        ),
        (
            "well-known/lib/platform/windows-base-api::microsoft-kernel32-version-identity",
            "type: value\npath: pe.version.internal_name\nexact: kernel32\n",
        ),
        (
            "well-known/lib/platform/windows-base-api::microsoft-kernelbase-version-identity",
            "type: value\npath: pe.version.internal_name\nregex: '(?i)^kernelbase(\\.dll)?$'\n",
        ),
        (
            "well-known/app/system/microsoft/sync-center::syncmgr-registry-cluster",
            "type: text\nsubstr: 'SyncMgr\\Handlers'\nsection: rdata\n",
        ),
        (
            "well-known/app/system/microsoft/sync-center::syncmgr-handler-clsid",
            "type: text\nexact: '{F897AA24-BDC3-11d1-B85B-00C04FB93981}'\nsection: rdata\n",
        ),
        (
            "well-known/app/system/microsoft/sync-center::mobsync-pdb-path",
            "type: value\npath: pe.debug.pdb.path\nregex: '(?i)(^|[\\\\/])mobsync\\.pdb$'\n",
        ),
        (
            "well-known/app/system/microsoft/sync-center::mobsync-version-name",
            "type: text\nexact: mobsync.exe\nsection: rdata\n",
        ),
        (
            "well-known/app/security/microsoft-security-essentials::msse-product-name",
            "type: text\nexact: Microsoft Security Essentials\nsection: rdata\n",
        ),
        (
            "well-known/lib/native/madexcept::mad-except",
            "type: text\nsubstr: madExcept\nsection: CODE\n",
        ),
        (
            "well-known/lib/development/halide::halide-hexagon-remote-profiler-symbol",
            "type: export\nexact: halide_hexagon_remote_profiler_get_global_instance\n",
        ),
        (
            "well-known/lib/development/halide::halide-library-loader-symbol",
            "type: export\nexact: halide_load_library\n",
        ),
        (
            "well-known/lib/runtime/native-platform/qualcomm-hexagon::qdsp6-start-symbol",
            "type: export\nexact: qdsp6_start_main\n",
        ),
        (
            "well-known/lib/runtime/native-platform/qualcomm-hexagon::hexagon-hvx-lock-symbol",
            "type: export\nexact: qurt_hvx_lock\n",
        ),
        (
            "well-known/app/system/drivers/nvidia::nvidia-nvapi-internal-name",
            "type: value\npath: pe.version.internal_name\nexact: nvapi.dll\n",
        ),
        (
            "well-known/app/system/firmware/qualcomm-xbl::qcom-xbl-bootloader-marker",
            "type: raw\nsubstr: XBL_SC_MINI_CTX\noffset_range: [0, null]\n",
        ),
        (
            "well-known/lib/platform/wine::wine-debug-channel-symbol",
            "type: symbol\nregex: '^__wine_dbg_[a-z_]{3,30}$'\n",
        ),
        (
            "well-known/lib/platform/wine::wine-builtin-header-text",
            "type: text\nexact: Wine builtin DLL\noffset: 64\n",
        ),
        (
            "well-known/tool/development/toolchain/edg::edg-modules-path-env",
            "type: text\nword: EDG_MODULES_PATH\nsection: rodata\n",
        ),
        (
            "well-known/tool/development/toolchain/edg::edg-front-end-daemon",
            "type: text\nword: EDG_FRONT_END_DAEMON\nsection: rodata\n",
        ),
        (
            "well-known/tool/development/toolchain/dotnet-sdk::dotnet-ilasm-coreclr-binary",
            "type: text\nregex: 'src[/\\\\]runtime[/\\\\]src[/\\\\]coreclr[/\\\\]ilasm[/\\\\]main\\.cpp|\\.NET IL Assembler version'\nsection: .rodata\n",
        ),
        (
            "well-known/lib/platform/atl::atl-module-rtti",
            "type: text\nregex: 'C(AtlModule|ComModule|AtlException)@ATL@@'\nsection: .data\n",
        ),
        (
            "well-known/lib/platform/wtl::wtl-frame-rtti",
            "type: text\nregex: 'C(FrameWindowImpl|AppModule|AboutDlg|MainFrame).{0,50}WTL@@'\nsection: .data\n",
        ),
        (
            "well-known/lib/platform/mfc::mfc-ccmdtarget",
            "type: text\nexact: CCmdTarget\nsection: .rdata\n",
        ),
        (
            "well-known/lib/platform/mfc::mfc-cwinapp",
            "type: text\nexact: CWinApp\nsection: .rdata\n",
        ),
        (
            "well-known/lib/platform/mfc::mfc-afx-window-classes",
            "type: text\nregex: 'Afx(ControlBar|MDIFrame|FrameOrView|OleControl)'\nsection: .rdata\n",
        ),
        (
            "well-known/lib/platform/mfc::mfc-symbols",
            "type: symbol\nsubstr: AfxWinMain\n",
        ),
        (
            "well-known/lib/ui/qt::qt-core-runtime-dll",
            "type: text\nregex: 'Qt\\dCore\\.dll'\nsection: rdata\n",
        ),
        (
            "well-known/lib/runtime/managed/dotnet-process::dotnet-system-diagnostics-process-resource",
            "type: text\nsubstr: FxResources.System.Diagnostics.Process\nsection: rdata\n",
        ),
        (
            "well-known/lib/runtime/managed/dotnet-process::dotnet-system-diagnostics-process-pdb",
            "type: value\npath: pe.debug.pdb.path\nregex: '(?i)(^|[\\\\/])System\\.Diagnostics\\.Process\\.ni\\.pdb$'\n",
        ),
        (
            "well-known/lib/runtime/managed/jvm::jli-launch",
            "type: symbol\nexact: JLI_Launch\n",
        ),
        (
            "well-known/lib/runtime/managed/jvm::jli-cmd-to-args",
            "type: symbol\nexact: JLI_CmdToArgs\n",
        ),
        (
            "well-known/lib/runtime/managed/jvm::jli-get-std-args",
            "type: symbol\nexact: JLI_GetStdArgs\n",
        ),
        (
            "well-known/lib/runtime/managed/jvm::jli-init-arg-processing",
            "type: symbol\nexact: JLI_InitArgProcessing\n",
        ),
        (
            "well-known/lib/runtime/managed/jvm::jli-mem-alloc",
            "type: symbol\nexact: JLI_MemAlloc\n",
        ),
        (
            "well-known/lib/runtime/managed/jvm::jli-report-error",
            "type: symbol\nexact: JLI_ReportErrorMessage\n",
        ),
        (
            "well-known/tool/packaging/jsmooth::jsmooth-vm-search-order-string",
            "type: text\nsubstr: 'JSmooth will now try to use the VM in the following order:'\n",
        ),
        (
            "well-known/tool/packaging/jsmooth::jsmooth-native-class-string",
            "type: text\nsubstr: jsmooth.Native\n",
        ),
        (
            "well-known/lib/ui/flutter::flutter-windows-dll",
            "type: text\nexact: flutter_windows.dll\nsection: rdata\n",
        ),
        (
            "well-known/lib/ui/flutter::flutter-assets-path",
            "type: text\nexact: '\\flutter_assets'\nsection: rdata\n",
        ),
        (
            "well-known/lib/ui/flutter::flutter-desktop-engine-symbols",
            "type: symbol\nregex: '^FlutterDesktop(Engine|ViewController)'\n",
        ),
        (
            "well-known/lib/ui/flutter::flutter-linux-desktop-runner",
            "type: symbol\nregex: '^fl_(dart_project_new|view_new|plugin_registry_get_type)$'\n",
        ),
        (
            "well-known/app/system/microsoft/core-utilities::bits-service-name-reference",
            "type: text\nsubstr: 'Background Intelligent Transfer Service'\nsection: rdata\n",
        ),
        (
            "well-known/app/media/windows-media-player::windows-media-player-name-reference",
            "type: text\nsubstr: 'Microsoft Windows Media Player'\nsection: rdata\n",
        ),
        (
            "well-known/app/system/huawei-pc-manager::pc-manager-uninstall-guide-reference",
            "type: text\nsubstr: 'C:\\Program Files\\Huawei\\PCManager\\UninstallGuide.exe.FriendlyAppName'\nsection: rdata\n",
        ),
        (
            "well-known/game/steam::steam-drivers-archive-title",
            "type: text\nexact: Steam Drivers Archive\nsection: rdata\n",
        ),
        (
            "well-known/game/steam::steam-driver-archive-path",
            "type: text\nsubstr: drivers/Windows10/x64/Steam\nsection: rdata\n",
        ),
        (
            "well-known/app/system/mobile/tencent-mobilegamepc::tencent-mobilegamepc-registry",
            "type: text\nexact: 'SOFTWARE\\Tencent\\MobileGamePC'\nsection: rdata\n",
        ),
        (
            "well-known/app/system/mobile/tencent-mobilegamepc::tencent-tmarketinst-version",
            "type: text\nexact: TMarketInst\nsection: rdata\n",
        ),
        (
            "well-known/app/system/mobile/tencent-mobilegamepc::tencent-txmobilegamepc-marker",
            "type: text\nexact: TXMobileGamePC\nsection: rdata\n",
        ),
        (
            "well-known/app/system/mobile/tencent-mobilegamepc::tencent-tgbdownloader-marker",
            "type: text\nexact: TGBDownloader\nsection: rdata\n",
        ),
        (
            "well-known/tool/packaging/qt-installer-framework::qt-installer-framework",
            "type: text\nsubstr: 'Built with Qt Installer Framework'\nsection: .rdata\n",
        ),
        (
            "well-known/tool/packaging/installshield::installshield-setup-runtime-marker",
            "type: text\nsubstr: 'InstallShield setup.exe (Unicode) started'\nsection: .rdata\n",
        ),
        (
            "well-known/tool/packaging/squirrel-windows::squirrel-windows-setup-marker",
            "type: text\nexact: SquirrelInstall\nsection: rdata\n",
        ),
        (
            "well-known/tool/packaging/squirrel-windows::squirrel-temp-marker",
            "type: text\nexact: SQUIRREL_TEMP\nsection: rdata\n",
        ),
        (
            "well-known/tool/packaging/smart-install-maker::smart-install-maker-description",
            "type: text\nsubstr: 'Smart Install Maker'\n",
        ),
        (
            "well-known/tool/packaging/nsis::nsis-first-header-specific-build-sizes",
            "type: hex\nsection: overlay\npattern: 'EF BE AD DE 4E 75 6C 6C 73 6F 66 74 49 6E 73 74 75 11 00 00 18 27 00 00 5D 00 00 80'\n",
        ),
    ] {
        let mut fact = text_trait(id, vec![FileType::Pe]);
        fact.crit = crate::types::Criticality::Notable;
        fact.r#if = crate::yaml::from_str(query).unwrap();
        assert!(find_wellknown_missing_size_filter(&[fact.clone()], &HashMap::new()).is_empty());
        assert!(find_wellknown_missing_section_filter(&[fact.clone()], &HashMap::new()).is_empty());
        fact.id.push_str("-changed");
        assert_eq!(
            find_wellknown_missing_size_filter(&[fact], &HashMap::new()).len(),
            1
        );
    }
}

#[test]
fn security_product_path_references_keep_reviewed_whole_file_scope() {
    for (id, query) in [
        (
            "well-known/app/security/eset::eset-update-manifest-path",
            "type: text\nregex: '/eset_upd/[\\w./-]{0,64}update\\.ver\\b'\n",
        ),
        (
            "well-known/app/security/globalprotect::globalprotect-sslvpn-login-esp",
            "type: text\nsubstr: /ssl-vpn/login.esp\n",
        ),
    ] {
        let mut fact = text_trait(id, vec![FileType::Pe]);
        fact.crit = crate::types::Criticality::Notable;
        fact.r#if = crate::yaml::from_str(query).unwrap();
        assert!(find_wellknown_missing_size_filter(&[fact.clone()], &HashMap::new()).is_empty());
        // GlobalProtect normally targets mixed scripts and binaries;
        // only ESET's binary-only rule needs the section allowance.
        if id.contains("eset::") {
            assert!(
                find_wellknown_missing_section_filter(&[fact.clone()], &HashMap::new()).is_empty()
            );
        }
        let mut altered = fact.clone();
        altered.r#if = crate::yaml::from_str("type: text\nsubstr: unrelated\n").unwrap();
        assert_eq!(
            find_wellknown_missing_size_filter(&[altered], &HashMap::new()).len(),
            1
        );
        fact.crit = crate::types::Criticality::Suspicious;
        assert_eq!(
            find_wellknown_missing_size_filter(&[fact.clone()], &HashMap::new()).len(),
            1
        );
        fact.crit = crate::types::Criticality::Notable;
        fact.id.push_str("-changed");
        assert_eq!(
            find_wellknown_missing_size_filter(&[fact], &HashMap::new()).len(),
            1
        );
    }
}

#[test]
fn embala_banner_size_exception_is_matcher_specific() {
    let mut fact = text_trait(
        "well-known/tool/packaging/embala::embala-banner-token",
        vec![FileType::Pe],
    );
    fact.crit = crate::types::Criticality::Notable;
    fact.r#if = crate::yaml::from_str(
        "type: hex\npattern: '45 4D 42 41 4C 41 5F 42 41 4E 4E 45 52'\nsection: .rdata\n",
    )
    .unwrap();
    assert!(find_wellknown_missing_size_filter(&[fact.clone()], &HashMap::new()).is_empty());
    fact.id.push_str("-changed");
    assert_eq!(
        find_wellknown_missing_size_filter(&[fact], &HashMap::new()).len(),
        1
    );
}

#[test]
fn inno_loader_size_exceptions_are_matcher_specific() {
    for (id, query) in [
        (
            "inno-manifest-description",
            r#"type: value
path: pe.manifest.description
regex: '(?i)^Inno Setup\s*$'
"#,
        ),
        (
            "inno-setup-data-marker",
            r#"type: text
substr: 'Inno Setup Setup Data ('
section: rdata
"#,
        ),
        (
            "inno-setup-data-marker-overlay",
            r#"type: text
substr: 'Inno Setup Setup Data ('
section: overlay
"#,
        ),
        (
            "inno-setup-installer-marker",
            r#"type: text
substr: 'This installation was built with Inno Setup.'
section: rdata
"#,
        ),
        (
            "inno-setup-installer-text",
            r#"type: text
substr: 'Inno Setup Setup Data ('
section: .text
"#,
        ),
        (
            "inno-setup-installer-data",
            r#"type: text
substr: 'Inno Setup Setup Data ('
section: .data
"#,
        ),
        (
            "inno-setup-built-with-comment",
            r#"type: text
substr: 'This installation was built with Inno Setup'
section: rdata
"#,
        ),
        (
            "inno-uninstaller-marker",
            r#"type: text
exact: 'ISUNINSTALLER'
section: .text
"#,
        ),
        (
            "inno-loader-magic-legacy-120",
            "type: hex\npattern: '72 44 6C 50 74 53 30 32 87 65 56 78'\nsection: .rsrc\n",
        ),
        (
            "inno-loader-magic-legacy-400",
            "type: hex\npattern: '72 44 6C 50 74 53 30 34 87 65 56 78'\nsection: .rsrc\n",
        ),
        (
            "inno-loader-magic-legacy-403",
            "type: hex\npattern: '72 44 6C 50 74 53 30 35 87 65 56 78'\nsection: .rsrc\n",
        ),
        (
            "inno-loader-magic-legacy-410",
            "type: hex\npattern: '72 44 6C 50 74 53 30 36 87 65 56 78'\nsection: .rsrc\n",
        ),
        (
            "inno-loader-magic-legacy-416",
            "type: hex\npattern: '72 44 6C 50 74 53 30 37 87 65 56 78'\nsection: .rsrc\n",
        ),
        (
            "inno-loader-magic-515",
            "type: hex\npattern: '72 44 6C 50 74 53 CD E6 D7 7B 0B 2A'\nsection: .rsrc\n",
        ),
    ] {
        let mut fact = text_trait(
            &format!("well-known/tool/packaging/inno-setup-loader::{id}"),
            vec![FileType::Pe],
        );
        fact.crit = crate::types::Criticality::Notable;
        fact.r#if = crate::yaml::from_str(query).unwrap();
        assert!(find_wellknown_missing_size_filter(&[fact.clone()], &HashMap::new()).is_empty());
        fact.id.push_str("-changed");
        assert_eq!(
            find_wellknown_missing_size_filter(&[fact], &HashMap::new()).len(),
            // Manifest descriptions also have a general size exemption.
            usize::from(id != "inno-manifest-description")
        );
    }
}

#[test]
fn signed_sfx_product_size_exceptions_are_matcher_specific() {
    for (id, query) in [
        (
            "well-known/tool/packaging/installaware::installaware-version-comment",
            r#"type: value
path: pe.version.comments
regex: '(?i)\bInstallAware\b'
"#,
        ),
        (
            "well-known/tool/packaging/installaware::installaware-sfx-builder-pdb",
            r#"type: value
path: pe.debug.pdb.path
regex: '(?i)\\InstallAware\\.*\\SFXSetup\.pdb$'
"#,
        ),
        (
            "well-known/tool/packaging/qsetup::qsetup-extraction-banner",
            r#"type: text
exact: 'QSetup will extract files to your Temp Drive (<DRIVE>)<P>'
section: CODE
"#,
        ),
    ] {
        let mut fact = text_trait(id, vec![FileType::Pe]);
        fact.crit = crate::types::Criticality::Notable;
        fact.r#if = crate::yaml::from_str(query).unwrap();
        assert!(find_wellknown_missing_size_filter(&[fact.clone()], &HashMap::new()).is_empty());
        fact.id.push_str("-changed");
        assert_eq!(
            find_wellknown_missing_size_filter(&[fact], &HashMap::new()).len(),
            1
        );
    }
}

#[test]
fn iexpress_size_exceptions_are_matcher_specific() {
    for (id, query) in [
        (
            "wextract-assembly-name",
            r#"type: text
substr: Microsoft.Windows.Wextract
section: rsrc
"#,
        ),
        (
            "wextract-manifest-description",
            r#"type: text
substr: '<description>IExpress extraction tool</description>'
section: rsrc
"#,
        ),
        (
            "wextract-product-description",
            r#"type: text
exact: Win32 Cabinet Self-Extractor
section: rsrc
"#,
        ),
        (
            "wextract-pdb-path",
            r#"type: text
exact: wextract.pdb
section: .rdata
"#,
        ),
        (
            "wextract-cleanup-string",
            r#"type: text
substr: wextract_cleanup%
"#,
        ),
        (
            "wextract-internal-name",
            r#"type: value
path: pe.version.internal_name
regex: '(?i)^wextract(\.exe)?$'
"#,
        ),
    ] {
        let mut fact = text_trait(
            &format!("well-known/tool/packaging/iexpress::{id}"),
            vec![FileType::Pe],
        );
        fact.crit = crate::types::Criticality::Notable;
        fact.r#if = crate::yaml::from_str(query).unwrap();
        assert!(find_wellknown_missing_size_filter(&[fact.clone()], &HashMap::new()).is_empty());
        if id == "wextract-cleanup-string" {
            assert!(
                find_wellknown_missing_section_filter(&[fact.clone()], &HashMap::new()).is_empty()
            );
        }
        fact.id.push_str("-changed");
        assert_eq!(
            find_wellknown_missing_size_filter(&[fact.clone()], &HashMap::new()).len(),
            1
        );
        if id == "wextract-cleanup-string" {
            assert_eq!(
                find_wellknown_missing_section_filter(&[fact], &HashMap::new()).len(),
                1
            );
        }
    }
}

#[test]
fn winrar_registry_text_size_exception_is_matcher_specific() {
    let mut fact = text_trait(
        "well-known/tool/sysadmin/winrar-sfx::winrar-sfx-registry-text",
        vec![FileType::Pe],
    );
    fact.crit = crate::types::Criticality::Notable;
    fact.r#if = crate::yaml::from_str(
        r#"type: text
exact: 'Software\WinRAR SFX'
section: .rdata
"#,
    )
    .unwrap();
    assert!(find_wellknown_missing_size_filter(&[fact.clone()], &HashMap::new()).is_empty());
    fact.r#if = crate::yaml::from_str("type: text\nexact: changed\nsection: .rdata\n").unwrap();
    assert_eq!(
        find_wellknown_missing_size_filter(&[fact], &HashMap::new()).len(),
        1
    );
}

#[test]
fn sevenzip_sfx_size_exceptions_are_matcher_specific() {
    for (id, query) in [
        (
            "7zip-fm-app-path",
            r#"type: text
exact: 'Software\Microsoft\Windows\CurrentVersion\App Paths\7zFM.exe'
section: .rdata
offset_range: [6291456, null]
"#,
        ),
        (
            "7zip-installer-setup-banner",
            r#"type: text
regex: '7-Zip [0-9]{1,2}\.[0-9]{2}( \(x(64|86)\))? Setup'
section: .rdata
"#,
        ),
        (
            "7zip-registry-key",
            r#"type: text
exact: 'Software\7-Zip'
section: .rdata
"#,
        ),
        (
            "7zip-shell-extension-clsid",
            r#"type: text
exact: 'CLSID\{23170F69-40C1-278A-1000-000100020000}'
section: .rdata
"#,
        ),
        (
            "7zip-uninstall-registry-path",
            r#"type: text
exact: 'Software\Microsoft\Windows\CurrentVersion\Uninstall\7-Zip'
section: .rdata
"#,
        ),
        (
            "7zip32-runtime-dll",
            r#"type: text
exact: '7-zip32.dll'
section: .rdata
offset_range: [6291456, null]
"#,
        ),
        (
            "7zsfx-runtime-stub",
            r#"type: text
exact: '7zS.sfx.exe'
section: .rdata
offset_range: [6291456, null]
"#,
        ),
    ] {
        let mut fact = text_trait(
            &format!("well-known/tool/sysadmin/7zip::{id}"),
            vec![FileType::Pe],
        );
        fact.crit = crate::types::Criticality::Notable;
        fact.r#if = crate::yaml::from_str(query).unwrap();
        assert!(find_wellknown_missing_size_filter(&[fact.clone()], &HashMap::new()).is_empty());
        fact.id.push_str("-changed");
        assert_eq!(
            find_wellknown_missing_size_filter(&[fact], &HashMap::new()).len(),
            1
        );
    }
}

#[test]
fn installer_tool_size_exception_is_scoped_to_reviewed_matcher() {
    let mut fact = text_trait(
        "well-known/tool/sysadmin/alzip::alzip-zipsfx-marker",
        vec![FileType::Pe],
    );
    fact.crit = crate::types::Criticality::Notable;
    fact.r#if = crate::yaml::from_str("type: text\nexact: ZIPSFX\nsection: UPX1\n").unwrap();
    assert!(find_wellknown_missing_size_filter(&[fact.clone()], &HashMap::new()).is_empty());
    let mut changed = fact.clone();
    changed.id.push_str("-other");
    assert_eq!(
        find_wellknown_missing_size_filter(&[changed], &HashMap::new()).len(),
        1
    );
    let mut changed = fact.clone();
    changed.crit = crate::types::Criticality::Suspicious;
    assert_eq!(
        find_wellknown_missing_size_filter(&[changed], &HashMap::new()).len(),
        1
    );
    let mut changed = fact.clone();
    changed.r#if =
        crate::yaml::from_str("type: text\nexact: ZIPSFX\nsection: UPX1\ncase_insensitive: true\n")
            .unwrap();
    assert_eq!(
        find_wellknown_missing_size_filter(&[changed], &HashMap::new()).len(),
        1
    );
    fact.r#if = crate::yaml::from_str("type: text\nexact: ZIPSFX\nsection: rdata\n").unwrap();
    assert_eq!(
        find_wellknown_missing_size_filter(&[fact], &HashMap::new()).len(),
        1
    );
}

#[test]
fn reviewed_stagecomp_size_exceptions_require_exact_id_matcher_and_severity() {
    for (id, pattern) in [
        ("stagecomp-moonzonet-domain", r"(?i)\bmoonzonet\.com\b"),
        (
            "stagecomp-visualwincomp-output",
            r"(?i)\bvisualwincomp\.txt\b",
        ),
    ] {
        let mut fact = text_trait(
            &format!("well-known/malware/backdoor/muddywater-darkcomp::{id}"),
            vec![FileType::Pe],
        );
        fact.crit = crate::types::Criticality::Notable;
        fact.r#if = crate::yaml::from_str(&format!("type: text\nregex: '{pattern}'\n")).unwrap();
        assert!(find_wellknown_missing_size_filter(&[fact.clone()], &HashMap::new()).is_empty());
        let mut wrong_id = fact.clone();
        wrong_id.id.push_str("-other");
        assert_eq!(
            find_wellknown_missing_size_filter(&[wrong_id], &HashMap::new()).len(),
            1
        );
        let mut wrong_crit = fact.clone();
        wrong_crit.crit = crate::types::Criticality::Suspicious;
        assert_eq!(
            find_wellknown_missing_size_filter(&[wrong_crit], &HashMap::new()).len(),
            1
        );
        fact.r#if = crate::yaml::from_str("type: text\nregex: changed\n").unwrap();
        assert_eq!(
            find_wellknown_missing_size_filter(&[fact], &HashMap::new()).len(),
            1
        );
    }
}

#[test]
fn utility_section_exceptions_require_exact_reviewed_markers() {
    for (id, crit, kind, marker) in [
        (
            "well-known/app/utility/hwinfo::hwinfo-name-reference",
            crate::types::Criticality::Component,
            "regex",
            r"(?i)HWiNFO",
        ),
        (
            "well-known/app/network/filezilla::filezilla-name-reference",
            crate::types::Criticality::Component,
            "regex",
            r"(?i)FileZilla",
        ),
        (
            "well-known/tool/detection/wireshark::wireshark-name-reference",
            crate::types::Criticality::Component,
            "regex",
            r"(?i)Wireshark",
        ),
        (
            "well-known/app/productivity/notepad-plus-plus::notepad-plus-plus-name-reference",
            crate::types::Criticality::Component,
            "regex",
            r"(?i)Notepad\+\+",
        ),
        (
            "well-known/tool/sysadmin/7zip::sevenzip-setup-label-reference",
            crate::types::Criticality::Notable,
            "regex",
            r"(?i)7-Zip\s+(Setup|Installer)",
        ),
        (
            "well-known/tool/sysadmin/7zip::sevenzip-file-manager-label-reference",
            crate::types::Criticality::Notable,
            "regex",
            r"(?i)7-Zip\s+(File Manager|Standalone)",
        ),
        (
            "well-known/tool/sysadmin/7zip::sevenzip-console-label-reference",
            crate::types::Criticality::Notable,
            "regex",
            r"(?i)7-Zip\s+(Console|Archiver)",
        ),
        (
            "well-known/tool/sysadmin/7zip::sevenzip-extension-label-reference",
            crate::types::Criticality::Component,
            "regex",
            r"(?i)7-Zip\s+(Extension)",
        ),
        (
            "well-known/lib/data/sevenzipjbinding::sevenzipjbinding-package-path-reference",
            crate::types::Criticality::Notable,
            "substr",
            r"net/sf/sevenzipjbinding",
        ),
    ] {
        let mut fact = text_trait(id, vec![FileType::Pe]);
        fact.crit = crit;
        fact.r#if = crate::yaml::from_str(&format!("type: text\n{kind}: '{marker}'\n")).unwrap();
        assert!(
            find_wellknown_missing_section_filter(&[fact.clone()], &HashMap::new()).is_empty(),
            "{id}"
        );
        let mut wrong_id = fact.clone();
        wrong_id.id.push_str("-other");
        assert_eq!(
            find_wellknown_missing_section_filter(&[wrong_id], &HashMap::new()).len(),
            1,
            "{id}"
        );
        let mut wrong_crit = fact.clone();
        wrong_crit.crit = crate::types::Criticality::Suspicious;
        assert_eq!(
            find_wellknown_missing_section_filter(&[wrong_crit], &HashMap::new()).len(),
            1,
            "{id}"
        );
        fact.r#if = crate::yaml::from_str("type: text\nsubstr: changed\n").unwrap();
        assert_eq!(
            find_wellknown_missing_section_filter(&[fact], &HashMap::new()).len(),
            1,
            "{id}"
        );
    }
}

#[test]
fn star_section_exceptions_require_exact_markers() {
    for (id, marker) in [
        (
            "star-archive-format-marker",
            "Extended standard tar (star 1994)",
        ),
        ("star-default-config-marker", "/etc/default/star"),
    ] {
        let mut fact = text_trait(
            &format!("well-known/tool/sysadmin/star::{id}"),
            vec![FileType::Elf],
        );
        fact.crit = crate::types::Criticality::Notable;
        fact.r#if = crate::yaml::from_str(&format!("type: text\nexact: '{marker}'\n")).unwrap();
        assert!(find_wellknown_missing_section_filter(&[fact.clone()], &HashMap::new()).is_empty());
        let mut wrong_id = fact.clone();
        wrong_id.id.push_str("-other");
        assert_eq!(
            find_wellknown_missing_section_filter(&[wrong_id], &HashMap::new()).len(),
            1
        );
        let mut wrong_crit = fact.clone();
        wrong_crit.crit = crate::types::Criticality::Suspicious;
        assert_eq!(
            find_wellknown_missing_section_filter(&[wrong_crit], &HashMap::new()).len(),
            1
        );
        fact.r#if = crate::yaml::from_str("type: text\nexact: changed\n").unwrap();
        assert_eq!(
            find_wellknown_missing_section_filter(&[fact], &HashMap::new()).len(),
            1
        );
    }
}

#[test]
fn edge_name_section_exception_requires_exact_marker() {
    let mut fact = text_trait(
        "well-known/app/browser/microsoft-edge::microsoft-edge-name",
        vec![FileType::Pe],
    );
    fact.crit = crate::types::Criticality::Notable;
    fact.r#if = crate::yaml::from_str("type: text\nsubstr: Microsoft Edge\n").unwrap();
    assert!(find_wellknown_missing_section_filter(&[fact.clone()], &HashMap::new()).is_empty());
    let mut wrong_id = fact.clone();
    wrong_id.id.push_str("-other");
    assert_eq!(
        find_wellknown_missing_section_filter(&[wrong_id], &HashMap::new()).len(),
        1
    );
    let mut wrong_crit = fact.clone();
    wrong_crit.crit = crate::types::Criticality::Suspicious;
    assert_eq!(
        find_wellknown_missing_section_filter(&[wrong_crit], &HashMap::new()).len(),
        1
    );
    fact.r#if = crate::yaml::from_str("type: text\nsubstr: changed\n").unwrap();
    assert_eq!(
        find_wellknown_missing_section_filter(&[fact], &HashMap::new()).len(),
        1
    );
}

#[test]
fn dotnet_component_section_exception_requires_exact_marker() {
    let mut fact = text_trait(
        "well-known/lib/runtime/managed/dotnet-runtime::mscorsvc-dll-filename",
        vec![FileType::Pe],
    );
    fact.crit = crate::types::Criticality::Notable;
    fact.r#if = crate::yaml::from_str("type: text\nsubstr: mscorsvc.dll\n").unwrap();
    assert!(find_wellknown_missing_section_filter(&[fact.clone()], &HashMap::new()).is_empty());
    let mut wrong_id = fact.clone();
    wrong_id.id.push_str("-other");
    assert_eq!(
        find_wellknown_missing_section_filter(&[wrong_id], &HashMap::new()).len(),
        1
    );
    let mut wrong_crit = fact.clone();
    wrong_crit.crit = crate::types::Criticality::Suspicious;
    assert_eq!(
        find_wellknown_missing_section_filter(&[wrong_crit], &HashMap::new()).len(),
        1
    );
    fact.r#if = crate::yaml::from_str("type: text\nsubstr: changed\n").unwrap();
    assert_eq!(
        find_wellknown_missing_section_filter(&[fact], &HashMap::new()).len(),
        1
    );
}

#[test]
fn shellobject_section_exceptions_require_exact_identity_and_matcher() {
    for (id, marker) in [
        (
            "encoded-kvic-jpg-payload-url",
            "9/Pz76m8vPT09L349fYAvfnvvAP8APC8+AWvp7357wSf",
        ),
        ("encoded-kvic-probe-path", "vAP8APC87/H8AQK97/fvnw=="),
        ("encoded-temp-res-file-template", "0u3+8evyy8Lenw=="),
    ] {
        let mut fact = text_trait(
            &format!("well-known/malware/trojan/shellobject/hijack::{id}"),
            vec![FileType::Pe],
        );
        fact.crit = crate::types::Criticality::Notable;
        fact.r#if = crate::yaml::from_str(&format!("type: text\nexact: {marker}\n")).unwrap();
        assert!(find_wellknown_missing_section_filter(&[fact.clone()], &HashMap::new()).is_empty());
        let mut wrong_id = fact.clone();
        wrong_id.id.push_str("-other");
        assert_eq!(
            find_wellknown_missing_section_filter(&[wrong_id], &HashMap::new()).len(),
            1
        );
        let mut wrong_crit = fact.clone();
        wrong_crit.crit = crate::types::Criticality::Suspicious;
        assert_eq!(
            find_wellknown_missing_section_filter(&[wrong_crit], &HashMap::new()).len(),
            1
        );
        fact.r#if = crate::yaml::from_str("type: text\nexact: changed\n").unwrap();
        assert_eq!(
            find_wellknown_missing_section_filter(&[fact], &HashMap::new()).len(),
            1
        );
    }
}

#[test]
fn reviewed_redshell_injection_menu_exception_is_matcher_scoped() {
    let mut fact = text_trait(
        "well-known/malware/backdoor/redc2::redshell-injection-menu",
        vec![FileType::Elf],
    );
    fact.r#if = crate::yaml::from_str(
        "type: text\nregex: '/redshell bin -inject <proc> <file\\.bin>[\\s\\S]{0,220}/redshell elf -inject <pid> <file>'\n",
    )
    .unwrap();
    assert!(find_wellknown_missing_size_filter(&[fact.clone()], &HashMap::new()).is_empty());
    assert!(find_wellknown_missing_section_filter(&[fact.clone()], &HashMap::new()).is_empty());
    let mut wrong_id = fact.clone();
    wrong_id.id.push_str("-other");
    assert_eq!(
        find_wellknown_missing_size_filter(&[wrong_id.clone()], &HashMap::new()).len(),
        1
    );
    assert_eq!(
        find_wellknown_missing_section_filter(&[wrong_id], &HashMap::new()).len(),
        1
    );
    let mut wrong_case = fact.clone();
    if let Condition::Text(query) = &mut wrong_case.r#if {
        query.case_insensitive = true;
    }
    assert_eq!(
        find_wellknown_missing_size_filter(&[wrong_case.clone()], &HashMap::new()).len(),
        1
    );
    assert_eq!(
        find_wellknown_missing_section_filter(&[wrong_case], &HashMap::new()).len(),
        1
    );
    let mut wrong_crit = fact.clone();
    wrong_crit.crit = crate::types::Criticality::Suspicious;
    assert_eq!(
        find_wellknown_missing_size_filter(&[wrong_crit.clone()], &HashMap::new()).len(),
        1
    );
    assert_eq!(
        find_wellknown_missing_section_filter(&[wrong_crit], &HashMap::new()).len(),
        1
    );
    fact.r#if = crate::yaml::from_str("type: text\nregex: changed\n").unwrap();
    assert_eq!(
        find_wellknown_missing_size_filter(&[fact.clone()], &HashMap::new()).len(),
        1
    );
    assert_eq!(
        find_wellknown_missing_section_filter(&[fact], &HashMap::new()).len(),
        1
    );
}

#[test]
fn gitlab_registry_reference_size_exception_is_exact() {
    let mut fact = text_trait(
        "well-known/app/development/code-forge/gitlab::gitlab-generic-package-upload",
        vec![FileType::Elf],
    );
    fact.crit = crate::types::Criticality::Notable;
    fact.r#if =
        crate::yaml::from_str("type: text\nregex: '/api/v4/projects/.{0,160}/packages/generic/'\n")
            .unwrap();
    assert!(find_wellknown_missing_size_filter(&[fact.clone()], &HashMap::new()).is_empty());
    let mut wrong_id = fact.clone();
    wrong_id.id.push_str("-other");
    assert_eq!(
        find_wellknown_missing_size_filter(&[wrong_id], &HashMap::new()).len(),
        1
    );
    let mut wrong_crit = fact.clone();
    wrong_crit.crit = crate::types::Criticality::Suspicious;
    assert_eq!(
        find_wellknown_missing_size_filter(&[wrong_crit], &HashMap::new()).len(),
        1
    );
    fact.r#if = crate::yaml::from_str("type: text\nregex: '/api/v4/projects/.*'\n").unwrap();
    assert_eq!(
        find_wellknown_missing_size_filter(&[fact], &HashMap::new()).len(),
        1
    );
}

#[test]
fn go_socks5_references_keep_whole_file_scope_only_for_exact_matches() {
    for (id, marker) in [
        ("armon-go-socks5", "github.com/armon/go-socks5"),
        (
            "armon-go-socks5-listen-and-serve",
            "github.com/armon/go-socks5.(*Server).ListenAndServe",
        ),
        (
            "armon-go-socks5-serve-conn",
            "github.com/armon/go-socks5.(*Server).ServeConn",
        ),
    ] {
        let mut fact = text_trait(
            &format!("well-known/lib/network/proxy/go-socks5::{id}"),
            vec![FileType::Elf],
        );
        fact.crit = crate::types::Criticality::Notable;
        fact.r#if = crate::yaml::from_str(&format!("type: text\nsubstr: '{marker}'\n")).unwrap();
        assert!(find_wellknown_missing_size_filter(&[fact.clone()], &HashMap::new()).is_empty());
        assert!(find_wellknown_missing_section_filter(&[fact.clone()], &HashMap::new()).is_empty());
        let mut other = fact.clone();
        other.id.push_str("-other");
        assert_eq!(
            find_wellknown_missing_size_filter(&[other.clone()], &HashMap::new()).len(),
            1
        );
        assert_eq!(
            find_wellknown_missing_section_filter(&[other], &HashMap::new()).len(),
            1
        );
        fact.r#if = crate::yaml::from_str("type: text\nsubstr: 'github.com/armon'\n").unwrap();
        assert_eq!(
            find_wellknown_missing_size_filter(&[fact.clone()], &HashMap::new()).len(),
            1
        );
        assert_eq!(
            find_wellknown_missing_section_filter(&[fact], &HashMap::new()).len(),
            1
        );
    }
}

#[test]
fn reviewed_linfeng_markers_keep_whole_file_scope_only_for_exact_matches() {
    for (id, marker, crit) in [
        (
            "linfeng-adb-bot-marker",
            ".linfengadbbotmasterchina",
            crate::types::Criticality::Notable,
        ),
        (
            "linfeng-bot-telegram-handle",
            "t.me/mrrobot764linfengsudoopsec",
            crate::types::Criticality::Component,
        ),
    ] {
        let mut fact = text_trait(
            &format!("well-known/malware/botnet/linfeng::{id}"),
            vec![FileType::Elf],
        );
        fact.crit = crit;
        fact.r#if = crate::yaml::from_str(&format!("type: text\nsubstr: {marker}\n")).unwrap();
        assert!(find_wellknown_missing_size_filter(&[fact.clone()], &HashMap::new()).is_empty());
        assert!(find_wellknown_missing_section_filter(&[fact.clone()], &HashMap::new()).is_empty());

        let mut wrong_id = fact.clone();
        wrong_id.id.push_str("-other");
        assert_eq!(
            find_wellknown_missing_size_filter(&[wrong_id.clone()], &HashMap::new()).len(),
            1
        );
        assert_eq!(
            find_wellknown_missing_section_filter(&[wrong_id], &HashMap::new()).len(),
            1
        );
        let mut wrong_crit = fact.clone();
        wrong_crit.crit = crate::types::Criticality::Suspicious;
        assert_eq!(
            find_wellknown_missing_size_filter(&[wrong_crit.clone()], &HashMap::new()).len(),
            1
        );
        assert_eq!(
            find_wellknown_missing_section_filter(&[wrong_crit], &HashMap::new()).len(),
            1
        );
        fact.r#if = crate::yaml::from_str("type: text\nsubstr: changed\n").unwrap();
        assert_eq!(
            find_wellknown_missing_size_filter(&[fact.clone()], &HashMap::new()).len(),
            1
        );
        assert_eq!(
            find_wellknown_missing_section_filter(&[fact], &HashMap::new()).len(),
            1
        );
    }
}

#[test]
fn metadata_section_filter_requires_a_location_claim() {
    let traits = vec![
        text_trait(
            "metadata/file/string/command::vocabulary",
            vec![FileType::Pe],
        ),
        text_trait("metadata/binary/debug::pdb-name", vec![FileType::Pe]),
        text_trait(
            "metadata/binary/section/data::section-name",
            vec![FileType::Pe],
        ),
    ];
    let result = find_meta_missing_section_filter(&traits, &HashMap::new());
    assert_eq!(result.len(), 1);
    assert_eq!(result[0].0, "metadata/binary/section/data::section-name");
}

#[test]
fn metadata_section_filter_skips_mixed_binary_and_script_targets() {
    let traits = vec![text_trait(
        "metadata/binary/test::mixed",
        vec![FileType::Pe, FileType::Shell],
    )];
    let mut sources = HashMap::new();
    sources.insert(
        "metadata/binary/test::mixed".to_string(),
        "./metadata/binary/test/traits.yaml".to_string(),
    );
    let result = find_meta_missing_section_filter(&traits, &sources);
    assert!(result.is_empty());
}
