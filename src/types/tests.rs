//! Test module.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! Tests for types module

use super::*;

#[test]
fn test_criticality_enum() {
    assert!(Criticality::Baseline < Criticality::Notable);
    assert!(Criticality::Notable < Criticality::Suspicious);
    assert!(Criticality::Suspicious < Criticality::Hostile);
}

#[test]
fn test_criticality_default() {
    assert_eq!(Criticality::default(), Criticality::Baseline);
}

#[test]
fn test_criticality_serialization() {
    let crit = Criticality::Hostile;
    let json = serde_json::to_string(&crit).unwrap();
    assert_eq!(json, "\"hostile\"");

    let deserialized: Criticality = serde_json::from_str(&json).unwrap();
    assert_eq!(deserialized, Criticality::Hostile);
}

#[test]
fn test_path_type_enum_variants() {
    let types = [PathType::Absolute, PathType::Relative, PathType::Dynamic];
    assert_eq!(types.len(), 3);
}

#[test]
fn test_path_category_enum_variants() {
    let categories = vec![
        PathCategory::System,
        PathCategory::Config,
        PathCategory::Temp,
        PathCategory::Log,
        PathCategory::Home,
        PathCategory::Device,
        PathCategory::Runtime,
        PathCategory::Hidden,
        PathCategory::Network,
        PathCategory::Other,
    ];
    assert_eq!(categories.len(), 10);
}

#[test]
fn test_path_access_type_enum() {
    let access_types = [
        PathAccessType::Read,
        PathAccessType::Write,
        PathAccessType::Execute,
        PathAccessType::Delete,
        PathAccessType::Create,
        PathAccessType::Unknown,
    ];
    assert_eq!(access_types.len(), 6);
}

#[test]
fn test_string_type_enum_variants() {
    let types = vec![
        StringType::Url,
        StringType::IP,
        StringType::Path,
        StringType::Email,
        StringType::Base64,
        StringType::Import,
        StringType::Export,
        StringType::FuncName,
        StringType::ShellCmd,
    ];
    assert_eq!(types.len(), 9);
}

#[test]
fn test_env_var_access_type_enum() {
    let access_types = [
        EnvVarAccessType::Read,
        EnvVarAccessType::Write,
        EnvVarAccessType::Delete,
        EnvVarAccessType::Unknown,
    ];
    assert_eq!(access_types.len(), 4);
}

#[test]
fn test_env_var_category_enum() {
    let categories = vec![
        EnvVarCategory::Path,
        EnvVarCategory::User,
        EnvVarCategory::System,
        EnvVarCategory::Temp,
        EnvVarCategory::Display,
        EnvVarCategory::Credential,
        EnvVarCategory::Runtime,
        EnvVarCategory::Platform,
        EnvVarCategory::Injection,
        EnvVarCategory::Locale,
        EnvVarCategory::Network,
        EnvVarCategory::Other,
    ];
    assert_eq!(categories.len(), 12);
}

#[test]
fn test_directory_access_pattern_enum() {
    let _pattern1 = DirectoryAccessPattern::SingleFile;
    let _pattern2 = DirectoryAccessPattern::MultipleSpecific { count: 3 };
    let _pattern3 = DirectoryAccessPattern::Enumeration {
        pattern: Some("*.txt".to_string()),
    };
    let _pattern4 = DirectoryAccessPattern::BatchOperation {
        operation: "delete".to_string(),
        count: 5,
    };
    let _pattern5 = DirectoryAccessPattern::UserEnumeration;
}

#[test]
fn test_target_info_creation() {
    let target = TargetInfo {
        path: "/bin/ls".to_string(),
        file_type: "elf".to_string(),
        size_bytes: 12345,
        sha256: "abc123".to_string(),
        architectures: Some(vec!["x86_64".to_string()]),
    };

    assert_eq!(target.path, "/bin/ls");
    assert_eq!(target.file_type, "elf");
    assert_eq!(target.size_bytes, 12345);
    assert!(target.architectures.is_some());
}

#[test]
fn test_analysis_report_new() {
    let target = TargetInfo {
        path: "/test".to_string(),
        file_type: "elf".to_string(),
        size_bytes: 100,
        sha256: "test".to_string(),
        architectures: None,
    };

    let report = AnalysisReport::new(target);

    assert_eq!(report.version, "3.0");
    assert_eq!(report.target.path, "/test");
    assert!(report.findings.is_empty());
    assert!(report.strings.is_empty());
    assert!(report.files.is_empty());
    assert!(report.summary.is_none());
}

#[test]
fn test_analysis_report_new_with_timestamp() {
    let target = TargetInfo {
        path: "/test".to_string(),
        file_type: "elf".to_string(),
        size_bytes: 100,
        sha256: "test".to_string(),
        architectures: None,
    };

    let timestamp = chrono::DateTime::parse_from_rfc3339("2024-01-01T00:00:00Z")
        .unwrap()
        .with_timezone(&chrono::Utc);

    let report = AnalysisReport::new_with_timestamp(target, timestamp);

    assert_eq!(report.version, "3.0");
    assert_eq!(report.target.path, "/test");
    assert_eq!(report.analysis_timestamp, Some(timestamp));
    assert!(report.findings.is_empty());
    assert!(report.files.is_empty());
}

#[test]
fn test_trait_new_constructor() {
    let trait_obj = Trait {
        kind: TraitKind::String,
        value: "test_value".to_string(),
        source: "test_source".to_string(),
        offset: None,
        encoding: None,
        section: None,
    };

    assert_eq!(trait_obj.kind, TraitKind::String);
    assert_eq!(trait_obj.value, "test_value");
}

#[test]
fn test_finding_constructor() {
    let evidence = vec![Evidence {
        method: "symbol".to_string(),
        source: "goblin".to_string(),
        value: "socket".to_string(),
        location: Some("0x1000".to_string()),
        ..Default::default()
    }];

    let finding = Finding {
        precomputed_spans: None,
        src: None,
        id: "net/socket".to_string().into(),
        kind: FindingKind::Capability,
        desc: "Network socket".to_string().into(),
        conf: 1.0,
        crit: Criticality::Baseline,
        mbc: None,
        attack: None,
        trait_refs: vec![],
        evidence,
        match_count: 1,
        source_file: None,
    };

    assert_eq!(finding.id, "net/socket");
    assert_eq!(finding.conf, 1.0);
    assert!(finding.evidence.len() == 1);
}

#[test]
fn test_evidence_creation() {
    let evidence = Evidence {
        method: "symbol".to_string(),
        source: "goblin".to_string(),
        value: "socket".to_string(),
        location: Some("0x1000".to_string()),
        ..Default::default()
    };

    assert_eq!(evidence.method, "symbol");
    assert_eq!(evidence.value, "socket");
    assert_eq!(evidence.location, Some("0x1000".to_string()));
}

#[test]
fn test_path_info_creation() {
    let path = PathInfo {
        path: "/etc/passwd".to_string(),
        path_type: PathType::Absolute,
        category: PathCategory::Config,
        access_type: Some(PathAccessType::Read),
        source: "strings".to_string(),
        evidence: vec![],
        referenced_by_traits: vec![],
    };

    assert_eq!(path.path, "/etc/passwd");
    assert_eq!(path.path_type, PathType::Absolute);
    assert_eq!(path.category, PathCategory::Config);
    assert_eq!(path.access_type, Some(PathAccessType::Read));
}

#[test]
fn test_env_var_info_creation() {
    let env_var = EnvVarInfo {
        name: "USER".to_string(),
        category: EnvVarCategory::User,
        access_type: EnvVarAccessType::Read,
        source: "tree-sitter".to_string(),
        evidence: vec![],
        referenced_by_traits: vec![],
    };

    assert_eq!(env_var.name, "USER");
    assert_eq!(env_var.category, EnvVarCategory::User);
    assert_eq!(env_var.access_type, EnvVarAccessType::Read);
}

#[test]
fn test_function_creation() {
    let func = Function {
        name: "main".to_string(),
        offset: Some("0x1000".to_string()),
        size: Some(256),
        complexity: Some(5),
        calls: vec!["printf".to_string()],
        control_flow: None,
        register_usage: None,
        constants: vec![],
        signature: None,
        nesting: None,
        call_patterns: None,
    };

    assert_eq!(func.name, "main");
    assert_eq!(func.size, Some(256));
    assert_eq!(func.calls.len(), 1);
}

#[test]
fn test_string_info_creation() {
    let string = StringInfo {
        value: ("http://example.com".to_string()).into(),
        offset: Some(0x2000),
        encoding: "utf8".to_string(),
        string_type: Some(StringType::Url),
        section: Some(".rodata".to_string()),
        encoding_chain: Vec::new(),
        fragments: None,
    };

    assert_eq!(string.value, "http://example.com");
    assert_eq!(string.string_type, Some(StringType::Url));
    assert_eq!(string.encoding, "utf8");
}

#[test]
fn test_section_creation() {
    let section = Section {
        name: ".text".to_string(),
        address: None,
        offset: None,
        size: 4096,
        entropy: 6.5,
        permissions: Some("r-x".to_string()),
        flags: Vec::new(),
    };

    assert_eq!(section.name, ".text");
    assert_eq!(section.size, 4096);
    assert_eq!(section.entropy, 6.5);
}

#[test]
fn test_import_creation() {
    let import = Import {
        symbol: "printf".to_string(),
        library: Some("libc.so.6".to_string()),
        offset: None,
        alias: None,
    };

    assert_eq!(import.symbol, "printf");
    assert_eq!(import.library, Some("libc.so.6".to_string()));
}

#[test]
fn test_export_creation() {
    let export = Export {
        symbol: "my_function".to_string(),
        offset: Some("0x1500".to_string()),
        forward_to: None,
    };

    assert_eq!(export.symbol, "my_function");
    assert_eq!(export.offset, Some("0x1500".to_string()));
}

#[test]
fn test_yara_match_creation() {
    let yara_match = YaraMatch {
        rule: "malware_rule".to_string(),
        namespace: "malware".to_string(),
        crit: "hostile".to_string(),
        desc: "Malware detected".to_string(),
        matched_strings: vec![],
        is_capability: false,
        mbc: None,
        attack: None,
        trait_id: None,
        arch_context: None,
    };

    assert_eq!(yara_match.rule, "malware_rule");
    assert_eq!(yara_match.namespace, "malware");
    assert_eq!(yara_match.crit, "hostile");
}

#[test]
fn test_analysis_metadata_default() {
    let metadata = AnalysisMetadata::default();

    assert!(metadata.tools_used.is_empty());
    assert_eq!(metadata.analysis_duration_ms, 0);
    assert!(metadata.errors.is_empty());
}

#[test]
fn test_structural_feature_serialization() {
    let feature = StructuralFeature {
        id: "binary/stripped".to_string(),
        desc: "Binary is stripped".to_string(),
        evidence: vec![],
    };

    let json = serde_json::to_string(&feature).unwrap();
    let deserialized: StructuralFeature = serde_json::from_str(&json).unwrap();

    assert_eq!(deserialized.id, "binary/stripped");
    assert_eq!(deserialized.desc, "Binary is stripped");
}

#[test]
fn test_target_info_serialization() {
    let target = TargetInfo {
        path: "/bin/test".to_string(),
        file_type: "elf".to_string(),
        size_bytes: 1024,
        sha256: "abc123".to_string(),
        architectures: Some(vec!["arm64".to_string()]),
    };

    let json = serde_json::to_string(&target).unwrap();
    let deserialized: TargetInfo = serde_json::from_str(&json).unwrap();

    assert_eq!(deserialized.path, "/bin/test");
    assert_eq!(deserialized.size_bytes, 1024);
}

#[test]
fn test_directory_access_creation() {
    let dir_access = DirectoryAccess {
        directory: "/tmp".to_string(),
        files: vec!["file1.txt".to_string(), "file2.txt".to_string()],
        file_count: 2,
        access_pattern: DirectoryAccessPattern::MultipleSpecific { count: 2 },
        categories: vec![PathCategory::Temp],
        enumerated: false,
        generated_traits: vec![],
    };

    assert_eq!(dir_access.directory, "/tmp");
    assert_eq!(dir_access.file_count, 2);
    assert_eq!(dir_access.files.len(), 2);
    assert!(!dir_access.enumerated);
}
