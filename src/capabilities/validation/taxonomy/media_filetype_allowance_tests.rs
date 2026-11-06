use super::{TraitDefinition, find_broad_filetype_traits};
use std::collections::HashMap;

#[test]
fn gif_header_allowance_is_exact_file_and_hex_only() -> anyhow::Result<()> {
    let hex: TraitDefinition = crate::yaml::from_str(
        "id: gif-header\ndesc: GIF signature\ncrit: baseline\nconf: 0.99\nfor: [gif, php, asp, data, javascript, python]\nif:\n  type: hex\n  pattern: 47 49 46 38 (37|39) 61\n  offset: 0\n",
    )?;
    for (path, permitted) in [
        ("/traits/metadata/file/magic/identity/gif.yaml", true),
        ("/traits/metadata/file/magic/identity/gif.yaml-extra", false),
        ("/traits/metadata/file/magic/identity/traits.yaml", false),
    ] {
        let sources = HashMap::from([(hex.id.clone(), path.to_string())]);
        assert_eq!(
            find_broad_filetype_traits(std::slice::from_ref(&hex), &sources).is_empty(),
            permitted,
            "{path}"
        );
    }
    Ok(())
}

#[test]
fn embedded_php_allowance_is_exact_file_and_value_only() -> anyhow::Result<()> {
    let value: TraitDefinition = crate::yaml::from_str(
        "id: request-call\ndesc: Parsed request call\ncrit: suspicious\nconf: 0.99\nfor: [jpeg, png, gif, wav, aiff, mp3, mp4, ico, webp, font]\nif:\n  type: value\n  path: media.php.request_calls[*]\n  exact: system\n",
    )?;
    for (path, permitted) in [
        (
            "/traits/micro-behaviors/data/embedded/payload/media/php-command-input.yaml",
            true,
        ),
        (
            "/traits/micro-behaviors/data/embedded/payload/media/php.yaml",
            false,
        ),
        (
            "/traits/micro-behaviors/data/embedded/payload/media/php-command-input.yaml-extra",
            false,
        ),
    ] {
        let sources = HashMap::from([(value.id.clone(), path.to_string())]);
        assert_eq!(
            find_broad_filetype_traits(std::slice::from_ref(&value), &sources).is_empty(),
            permitted,
            "{path}"
        );
    }
    let mut raw = value.clone();
    raw.r#if = crate::yaml::from_str("type: raw\nsubstr: system\n")?;
    let sources = HashMap::from([(
        raw.id.clone(),
        "/traits/micro-behaviors/data/embedded/payload/media/php-command-input.yaml".to_string(),
    )]);
    assert_eq!(find_broad_filetype_traits(&[raw], &sources).len(), 1);
    Ok(())
}

#[test]
fn relocated_media_allowance_stays_matcher_and_directory_scoped() -> anyhow::Result<()> {
    let value: TraitDefinition = crate::yaml::from_str(
        "id: carrier\ndesc: Container signature\ncrit: baseline\nconf: 0.9\nfor: [jpeg, png, svg, wav, aiff, mp3, mp4, ico, gif, bmp, webp, font]\nif:\n  type: value\n  path: media.container\n",
    )?;
    assert_eq!(value.r#for.len(), 12);
    for (path, permitted) in [
        ("/traits/metadata/file/format/media/container.yaml", true),
        (
            "/traits/metadata/file/format/media-extra/container.yaml",
            false,
        ),
        ("/traits/metadata/file/format/structured/traits.yaml", false),
    ] {
        let sources = HashMap::from([(value.id.clone(), path.to_string())]);
        assert_eq!(
            find_broad_filetype_traits(std::slice::from_ref(&value), &sources).is_empty(),
            permitted,
            "{path}"
        );
    }
    let mut raw = value.clone();
    raw.r#if = crate::yaml::from_str("type: raw\nsubstr: RIFF\n")?;
    let sources = HashMap::from([(
        raw.id.clone(),
        "/traits/metadata/file/format/media/container.yaml".to_string(),
    )]);
    assert_eq!(find_broad_filetype_traits(&[raw], &sources).len(), 1);
    Ok(())
}
