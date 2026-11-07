use super::*;

#[test]
fn test_validate_location_no_constraints() {
    let result = validate_location_constraints(&None, None, None, None, None, "text");
    assert!(result.is_ok());
}

#[test]
fn test_validate_location_section_only() {
    let result =
        validate_location_constraints(&Some(".text".to_string()), None, None, None, None, "text");
    assert!(result.is_ok());
}

#[test]
fn test_validate_location_offset_only() {
    let result = validate_location_constraints(&None, Some(0x1000), None, None, None, "text");
    assert!(result.is_ok());
}

#[test]
fn test_validate_location_offset_range_only() {
    let result =
        validate_location_constraints(&None, None, Some((0, Some(0x1000))), None, None, "text");
    assert!(result.is_ok());
}

#[test]
fn test_validate_location_offset_and_offset_range_fails() {
    let result = validate_location_constraints(
        &None,
        Some(0x100),
        Some((0, Some(0x1000))),
        None,
        None,
        "text",
    );
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("offset"));
}

#[test]
fn test_validate_location_section_offset_without_section_fails() {
    let result = validate_location_constraints(&None, None, None, Some(0x100), None, "content");
    assert!(result.is_err());
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("requires 'section'")
    );
}

#[test]
fn test_validate_location_section_offset_range_without_section_fails() {
    let result =
        validate_location_constraints(&None, None, None, None, Some((0, Some(0x100))), "base64");
    assert!(result.is_err());
}

#[test]
fn test_validate_location_section_with_section_offset() {
    let result = validate_location_constraints(
        &Some(".data".to_string()),
        None,
        None,
        Some(0x100),
        None,
        "xor",
    );
    assert!(result.is_ok());
}

#[test]
fn test_validate_location_section_offset_and_range_fails() {
    let result = validate_location_constraints(
        &Some(".text".to_string()),
        None,
        None,
        Some(0x100),
        Some((0, Some(0x200))),
        "text",
    );
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("section_offset"));
}

#[test]
fn test_validate_location_invalid_offset_range() {
    // start > end should fail
    let result = validate_location_constraints(
        &None,
        None,
        Some((0x1000, Some(0x100))), // 0x1000 > 0x100
        None,
        None,
        "text",
    );
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("start"));
}

#[test]
fn test_validate_location_negative_offsets_allowed() {
    // Negative offsets are allowed (means from end)
    let result =
        validate_location_constraints(&None, None, Some((-1024, None)), None, None, "content");
    assert!(result.is_ok());
}

#[test]
fn test_validate_location_open_ended_range() {
    // Open-ended range (start, None) is allowed
    let result =
        validate_location_constraints(&None, None, Some((0x1000, None)), None, None, "text");
    assert!(result.is_ok());
}

#[test]
fn test_condition_validate_string_location() {
    // Test that Condition::Text validates location constraints
    let condition = Condition::Text(TextQuery {
        encoding: None,
        length_min: None,
        length_max: None,
        exclude_html_comments: false,
        exclude_comments: false,
        exact: Some("test".to_string()),
        substr: None,
        regex: None,
        word: None,
        case_insensitive: false,
        is_check: None,
        not: None,
        section: None,
        offset: Some(0x100),
        offset_range: Some((0, Some(0x1000))), // Mutually exclusive with offset
        section_offset: None,
        section_offset_range: None,
        platforms: None,
    });
    assert!(condition.validate().is_err());
}

#[test]
fn test_condition_validate_content_location() {
    // Valid content condition with section constraint
    let condition = Condition::Raw(RawQuery {
        length_min: None,
        length_max: None,
        exact: Some("test".to_string()),
        substr: None,
        regex: None,
        word: None,
        case_insensitive: false,
        is_check: None,
        not: None,
        section: Some(".text".to_string()),
        offset: None,
        offset_range: Some((0, Some(0x1000))),
        section_offset: None,
        section_offset_range: None,
    });
    assert!(condition.validate().is_ok());
}

#[test]
fn test_offset_range_deser_closed_range() {
    // Test [start, end] format - deserialize as a tuple
    let yaml = "[100, 200]";
    let result: Result<Option<(i64, Option<i64>)>, _> = crate::yaml::from_str(yaml);
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), Some((100, Some(200))));
}

#[test]
fn kv_length_bounds_accept_both_spellings() {
    // Canonical `length_min`/`length_max` and the deprecated `size_min`/
    // `size_max` aliases parse to the same fields.
    for yaml in [
        "type: value\npath: maintainers\nlength_min: 2\nlength_max: 5",
        "type: value\npath: maintainers\nsize_min: 2\nsize_max: 5",
    ] {
        let result: Result<Condition, _> = crate::yaml::from_str(yaml);
        assert!(result.is_ok(), "failed to parse: {yaml}");
        assert!(matches!(
            result.unwrap(),
            Condition::Kv(KvQuery {
                length_min: Some(2),
                length_max: Some(5),
                ..
            })
        ));
    }
}

#[test]
fn text_length_bounds_parse() {
    let result: Result<Condition, _> =
        crate::yaml::from_str("type: text\nregex: '[A-Za-z0-9]+'\nlength_min: 4000");
    assert!(result.is_ok());
    assert!(matches!(
        result.unwrap(),
        Condition::Text(TextQuery {
            length_min: Some(4000),
            length_max: None,
            ..
        })
    ));
}

#[test]
fn text_yaml_parses_html_comment_exclusion() {
    let cond: Condition =
        crate::yaml::from_str("type: text\nregex: 'Server\\.MapPath'\nexclude_html_comments: true")
            .expect("parse text comment option");
    assert!(matches!(
        cond,
        Condition::Text(TextQuery {
            exclude_html_comments: true,
            exclude_comments: false,
            ..
        })
    ));
}

#[test]
fn test_offset_range_deser_open_end() {
    // Test [start,] format - open-ended to end of file
    #[derive(Debug, serde::Deserialize, PartialEq)]
    struct TestStruct {
        #[serde(deserialize_with = "offset_range_serde::deserialize")]
        offset_range: Option<(i64, Option<i64>)>,
    }

    let yaml = "offset_range: [-1024,]";
    let result: Result<TestStruct, _> = crate::yaml::from_str(yaml);
    assert!(result.is_ok());
    let parsed = result.unwrap();
    assert_eq!(parsed.offset_range, Some((-1024, None)));
}

#[test]
fn test_offset_range_deser_open_start() {
    // Test [~, end] format - open-ended from beginning (YAML null syntax)
    #[derive(Debug, serde::Deserialize, PartialEq)]
    struct TestStruct {
        #[serde(deserialize_with = "offset_range_serde::deserialize")]
        offset_range: Option<(i64, Option<i64>)>,
    }

    let yaml = "offset_range: [~, 1024]";
    let result: Result<TestStruct, _> = crate::yaml::from_str(yaml);
    if let Err(ref e) = result {
        eprintln!("Deserialization error: {}", e);
    }
    assert!(result.is_ok());
    let parsed = result.unwrap();
    assert_eq!(parsed.offset_range, Some((0, Some(1024))));
}

#[test]
fn test_offset_range_deser_null_end() {
    // Test [start, null] format - compatibility with explicit null
    #[derive(Debug, serde::Deserialize, PartialEq)]
    struct TestStruct {
        #[serde(deserialize_with = "offset_range_serde::deserialize")]
        offset_range: Option<(i64, Option<i64>)>,
    }

    let yaml = "offset_range: [100, null]";
    let result: Result<TestStruct, _> = crate::yaml::from_str(yaml);
    assert!(result.is_ok());
    let parsed = result.unwrap();
    assert_eq!(parsed.offset_range, Some((100, None)));
}

#[test]
fn test_offset_range_deser_tilde_end() {
    // Test [start, ~] format - YAML null syntax (most ergonomic)
    #[derive(Debug, serde::Deserialize, PartialEq)]
    struct TestStruct {
        #[serde(deserialize_with = "offset_range_serde::deserialize")]
        offset_range: Option<(i64, Option<i64>)>,
    }

    let yaml = "offset_range: [100, ~]";
    let result: Result<TestStruct, _> = crate::yaml::from_str(yaml);
    assert!(result.is_ok());
    let parsed = result.unwrap();
    assert_eq!(parsed.offset_range, Some((100, None)));
}

#[test]
fn test_offset_range_deser_null_start() {
    // Test [null, end] format - compatibility with explicit null
    #[derive(Debug, serde::Deserialize, PartialEq)]
    struct TestStruct {
        #[serde(deserialize_with = "offset_range_serde::deserialize")]
        offset_range: Option<(i64, Option<i64>)>,
    }

    let yaml = "offset_range: [null, 1024]";
    let result: Result<TestStruct, _> = crate::yaml::from_str(yaml);
    assert!(result.is_ok());
    let parsed = result.unwrap();
    assert_eq!(parsed.offset_range, Some((0, Some(1024))));
}

#[test]
fn test_offset_range_deser_negative_offset() {
    // Test negative offsets (from end of file)
    #[derive(Debug, serde::Deserialize, PartialEq)]
    struct TestStruct {
        #[serde(deserialize_with = "offset_range_serde::deserialize")]
        offset_range: Option<(i64, Option<i64>)>,
    }

    let yaml = "offset_range: [-1024, -512]";
    let result: Result<TestStruct, _> = crate::yaml::from_str(yaml);
    assert!(result.is_ok());
    let parsed = result.unwrap();
    assert_eq!(parsed.offset_range, Some((-1024, Some(-512))));
}

#[test]
fn test_section_offset_range_deser() {
    // Test section_offset_range with same formats
    #[derive(Debug, serde::Deserialize, PartialEq)]
    struct TestStruct {
        #[serde(deserialize_with = "offset_range_serde::deserialize")]
        section_offset_range: Option<(i64, Option<i64>)>,
    }

    let yaml = "section_offset_range: [100,]";
    let result: Result<TestStruct, _> = crate::yaml::from_str(yaml);
    assert!(result.is_ok());
    let parsed = result.unwrap();
    assert_eq!(parsed.section_offset_range, Some((100, None)));
}
