use super::{TraitDefinition, find_broad_filetype_traits};
use std::collections::HashMap;
use std::path::Path;

#[test]
fn gif_header_allowance_is_exact_file_and_hex_only() -> anyhow::Result<()> {
    let hex: TraitDefinition = crate::yaml::from_str(
        "id: gif-header\ndesc: GIF signature\ncrit: baseline\nconf: 0.99\nfor: [gif, php, asp, data, javascript, python]\nif:\n  type: hex\n  pattern: 47 49 46 38 (37|39) 61\n  offset: 0\n",
    )?;
    for (path, permitted) in [
        ("/traits/metadata/file/magic/identity/gif.yaml", true),
        ("/traits/metadata/file/magic/identity/gif.yaml-extra", false),
        ("/traits/other/metadata/file/magic/identity/gif.yaml", false),
        ("/traits/metadata/file/magic/identity/traits.yaml", false),
    ] {
        let sources = HashMap::from([(hex.id.clone(), path.to_string())]);
        assert_eq!(
            find_broad_filetype_traits(std::slice::from_ref(&hex), &sources, Path::new("/traits"))
                .is_empty(),
            permitted,
            "{path}"
        );
    }
    Ok(())
}

#[test]
fn media_fact_scope_follows_the_producer_and_rejects_other_carriers() -> anyhow::Result<()> {
    use crate::composite_rules::FileType;

    let mut rule: TraitDefinition = crate::yaml::from_str(
        "id: carrier\ndesc: Container signature\ncrit: baseline\nconf: 0.9\nif: {type: value, path: media.container}\n",
    )?;
    rule.r#for = FileType::MEDIA_FAMILY.to_vec();
    let sources = HashMap::new();
    let root = Path::new("/traits");
    let violations = |rule: &TraitDefinition| {
        find_broad_filetype_traits(std::slice::from_ref(rule), &sources, root)
    };

    assert!(violations(&rule).is_empty());
    rule.r#for.push(FileType::Elf);
    assert_eq!(violations(&rule).len(), 1);
    rule.r#for.pop();
    rule.r#if = crate::yaml::from_str("type: value\npath: arbitrary.key")?;
    assert_eq!(violations(&rule).len(), 1);
    Ok(())
}
