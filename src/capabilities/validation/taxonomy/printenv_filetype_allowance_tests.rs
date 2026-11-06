use super::{TraitDefinition, find_broad_filetype_traits};
use std::collections::HashMap;

#[test]
fn named_call_scope_preserves_script_frontends_without_licensing_other_matchers()
-> anyhow::Result<()> {
    let symbol: TraitDefinition = crate::yaml::from_str(
        "id: printenv\ndesc: Named call reference\ncrit: notable\nconf: 0.6\nfor: [shell, batch, python, javascript, ruby, php, lua, perl, powershell, applescript, vbs, mirc, ircii]\nif:\n  type: symbol\n  kind: call\n  exact: printenv\n",
    )?;
    assert_eq!(symbol.r#for.len(), 13);
    for (path, permitted) in [
        (
            "/traits/micro-behaviors/os/env/enumerate/enumeration-query.yaml",
            true,
        ),
        (
            "/traits/micro-behaviors/os/env/enumerate/enumeration-query-extra.yaml",
            false,
        ),
        (
            "/traits/micro-behaviors/os/env/enumerate-extra/enumeration-query.yaml",
            false,
        ),
    ] {
        let sources = HashMap::from([(symbol.id.clone(), path.to_string())]);
        assert_eq!(
            find_broad_filetype_traits(std::slice::from_ref(&symbol), &sources).is_empty(),
            permitted,
            "{path}"
        );
    }
    for condition in [
        "type: raw\nsubstr: printenv\n",
        "type: value\npath: example.value\n",
    ] {
        let mut other = symbol.clone();
        other.r#if = crate::yaml::from_str(condition)?;
        let sources = HashMap::from([(
            other.id.clone(),
            "/traits/micro-behaviors/os/env/enumerate/enumeration-query.yaml".to_string(),
        )]);
        assert_eq!(find_broad_filetype_traits(&[other], &sources).len(), 1);
    }
    Ok(())
}

#[test]
fn named_call_file_allowance_rejects_path_substring_collisions() -> anyhow::Result<()> {
    let symbol: TraitDefinition = crate::yaml::from_str(
        "id: printenv\ndesc: Named call reference\ncrit: notable\nconf: 0.6\nfor: [shell, batch, python, javascript, ruby, php, lua, perl]\nif:\n  type: symbol\n  kind: call\n  exact: printenv\n",
    )?;
    for path in [
        "/traits/micro-behaviors/os/env/enumerate/enumeration-query.yaml.backup.yaml",
        "/traits/xmicro-behaviors/os/env/enumerate/enumeration-query.yaml",
        "/traits/micro-behaviors/os/env/enumerate/enumeration-query.yaml/child.yaml",
    ] {
        let sources = HashMap::from([(symbol.id.clone(), path.to_string())]);
        assert_eq!(
            find_broad_filetype_traits(std::slice::from_ref(&symbol), &sources).len(),
            1,
            "{path}"
        );
    }
    Ok(())
}
