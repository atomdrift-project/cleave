//! Python pickle analyzer for malicious deserialization detection
//!
//! Pickle files can contain arbitrary code execution via `__reduce__`:
//! - `GLOBAL`/`STACK_GLOBAL` opcodes reference Python modules and callables
//! - `REDUCE` opcode calls those callables with arguments
//!
//! This analyzer extracts all module.attr references as symbols and
//! exposes them for trait rule matching.

use super::{AnalysisInput, Analyzer};
use crate::capabilities::CapabilityMapper;
use crate::types::{AnalysisReport, TargetInfo};
use anyhow::Result;
use sha2::{Digest, Sha256};
use std::path::Path;
use std::sync::Arc;

/// Pickle analyzer for deserialization attack detection
#[derive(Debug)]
pub(crate) struct PickleAnalyzer {
    capability_mapper: Arc<CapabilityMapper>,
}

impl PickleAnalyzer {
    #[must_use]
    pub(crate) fn new() -> Self {
        Self {
            capability_mapper: Arc::new(CapabilityMapper::empty()),
        }
    }

    #[must_use]
    pub(crate) fn with_capability_mapper(mut self, mapper: CapabilityMapper) -> Self {
        self.capability_mapper = Arc::new(mapper);
        self
    }

    #[must_use]
    pub(crate) fn with_capability_mapper_arc(mut self, mapper: Arc<CapabilityMapper>) -> Self {
        self.capability_mapper = mapper;
        self
    }

    fn analyze_pickle(&self, file_path: &Path, data: &[u8]) -> AnalysisReport {
        let mut hasher = Sha256::new();
        hasher.update(data);
        let sha256 = format!("{:x}", hasher.finalize());

        let target = TargetInfo {
            path: file_path.display().to_string(),
            file_type: "pickle".to_string(),
            size_bytes: data.len() as u64,
            sha256,
            architectures: None,
        };

        let mut report = AnalysisReport::new(target);
        report
            .metadata
            .tools_used
            .push("pickle-analyzer".to_string());

        // Extract globals (module.attr references) as import symbols
        let globals = extract_pickle_globals(data);
        for global_ref in &globals {
            report.imports.push(crate::types::Import::new(
                global_ref.as_str(),
                Some("pickle-global".to_string()),
                "pickle-analyzer",
            ));
        }

        // Extract readable strings from pickle data
        let strings = extract_pickle_strings(data);
        for s in &strings {
            report.strings.push(crate::types::StringInfo {
                value: s.clone(),
                string_type: None,
                offset: None,
                encoding: String::new(),
                section: None,
                encoding_chain: Vec::new(),
                fragments: None,
            });
        }

        // Structural kv subtree (`pickle.*`) — protocol + modules +
        // distinct opcode set. Cheap; complementary to the
        // import/string extraction above.
        if let Some(kv) = super::pickle_kv::extract(data) {
            attach_pickle_kv(&mut report, kv);
        }

        // Evaluate trait rules
        self.capability_mapper
            .evaluate_and_merge_findings(&mut report, data, None, None);

        report
    }
}

/// Attach the synthesized `pickle.*` subtree to `report.kv_tree`,
/// preserving any pre-existing tree.
fn attach_pickle_kv(report: &mut AnalysisReport, pickle_value: serde_json::Value) {
    use serde_json::{Map, Value};
    let mut root = match report.kv_tree.take().map(|b| *b) {
        Some(Value::Object(m)) => m,
        Some(other) => {
            let mut m = Map::new();
            m.insert("_legacy".into(), other);
            m
        }
        None => Map::new(),
    };
    root.insert("pickle".into(), pickle_value);
    report.kv_tree = Some(Box::new(Value::Object(root)));
}

impl Default for PickleAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl Analyzer for PickleAnalyzer {
    fn analyze_input(&self, input: &AnalysisInput<'_>) -> Result<AnalysisReport> {
        Ok(self.analyze_pickle(input.path, input.data))
    }

    fn analyze(&self, file_path: &Path) -> Result<AnalysisReport> {
        let data = std::fs::read(file_path)?;
        Ok(self.analyze_pickle(file_path, &data))
    }

    fn can_analyze(&self, file_path: &Path) -> bool {
        if let Some(ext) = file_path.extension() {
            matches!(
                ext.to_string_lossy().to_lowercase().as_str(),
                "pkl" | "pickle" | "joblib"
            )
        } else {
            false
        }
    }
}

/// Extract all STACK_GLOBAL (0x93) and GLOBAL (opcode 'c') references from pickle data.
/// Returns deduplicated "module.attr" strings.
fn extract_pickle_globals(data: &[u8]) -> Vec<String> {
    let mut globals = Vec::new();
    let mut seen = std::collections::HashSet::new();

    // Track recent SHORT_BINUNICODE strings for STACK_GLOBAL pairing.
    // Bounded to prevent memory exhaustion on crafted pickle streams.
    let mut recent_strings: Vec<String> = Vec::new();
    let mut i = 0;
    const MAX_PICKLE_STRINGS: usize = 10_000;

    while i < data.len() && recent_strings.len() < MAX_PICKLE_STRINGS {
        match data[i] {
            // SHORT_BINUNICODE (protocol 4+): 1-byte length
            0x8c => {
                if i + 1 >= data.len() {
                    break;
                }
                let length = data[i + 1] as usize;
                if i + 2 + length > data.len() {
                    break;
                }
                if let Ok(s) = std::str::from_utf8(&data[i + 2..i + 2 + length]) {
                    if s.is_ascii() && s.len() > 1 {
                        recent_strings.push(s.to_string());
                    }
                }
                i += 2 + length;
            }
            // STACK_GLOBAL: pairs the top two stack items as module.attr
            0x93 => {
                if recent_strings.len() >= 2 {
                    let attr = &recent_strings[recent_strings.len() - 1];
                    let module = &recent_strings[recent_strings.len() - 2];
                    // Only keep if both look like Python identifiers
                    if is_python_identifier(module) && is_python_identifier(attr) {
                        let global_ref = format!("{module}.{attr}");
                        if seen.insert(global_ref.clone()) {
                            globals.push(global_ref);
                        }
                    }
                }
                i += 1;
            }
            // GLOBAL (protocol 0-2): "module\nattr\n"
            b'c' => {
                if let Some(end) = data[i + 1..].iter().position(|&b| b == b'\n') {
                    let module_end = i + 1 + end;
                    if let Ok(module) = std::str::from_utf8(&data[i + 1..module_end]) {
                        if let Some(end2) = data[module_end + 1..].iter().position(|&b| b == b'\n')
                        {
                            let attr_end = module_end + 1 + end2;
                            if let Ok(attr) = std::str::from_utf8(&data[module_end + 1..attr_end]) {
                                if is_python_identifier(module) && is_python_identifier(attr) {
                                    let global_ref = format!("{module}.{attr}");
                                    if seen.insert(global_ref.clone()) {
                                        globals.push(global_ref);
                                    }
                                }
                            }
                            i = attr_end + 1;
                            continue;
                        }
                    }
                }
                i += 1;
            }
            // MEMOIZE, REDUCE, etc. — skip
            _ => {
                i += 1;
            }
        }
    }

    globals
}

/// Extract readable ASCII strings from pickle SHORT_BINUNICODE fields.
fn extract_pickle_strings(data: &[u8]) -> Vec<String> {
    let mut strings = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let mut i = 0;

    while i < data.len() {
        if data[i] == 0x8c {
            if i + 1 >= data.len() {
                break;
            }
            let length = data[i + 1] as usize;
            if i + 2 + length > data.len() {
                break;
            }
            if let Ok(s) = std::str::from_utf8(&data[i + 2..i + 2 + length]) {
                if s.is_ascii() && s.len() > 2 && seen.insert(s.to_string()) {
                    strings.push(s.to_string());
                }
            }
            i += 2 + length;
        } else {
            i += 1;
        }
    }

    strings
}

fn is_python_identifier(s: &str) -> bool {
    !s.is_empty()
        && s.is_ascii()
        && s.chars()
            .all(|c| c.is_alphanumeric() || c == '_' || c == '.')
        && s.starts_with(|c: char| c.is_alphabetic() || c == '_')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[allow(clippy::expect_used)]
    fn test_is_python_identifier() {
        assert!(is_python_identifier("os"));
        assert!(is_python_identifier("os.system"));
        assert!(is_python_identifier("builtins.exec"));
        assert!(is_python_identifier("_io.BytesIO"));
        assert!(!is_python_identifier(""));
        assert!(!is_python_identifier("123"));
        assert!(!is_python_identifier("hello world"));
    }

    #[test]
    fn test_extract_stack_global() {
        // Minimal pickle with STACK_GLOBAL: builtins.exec
        let data: Vec<u8> = vec![
            0x80, 0x04, // PROTO 4
            0x8c, 0x08, b'b', b'u', b'i', b'l', b't', b'i', b'n',
            b's', // SHORT_BINUNICODE "builtins"
            0x94, // MEMOIZE
            0x8c, 0x04, b'e', b'x', b'e', b'c', // SHORT_BINUNICODE "exec"
            0x94, // MEMOIZE
            0x93, // STACK_GLOBAL
        ];
        let globals = extract_pickle_globals(&data);
        assert_eq!(globals, vec!["builtins.exec"]);
    }

    #[test]
    fn test_extract_global_opcode_protocol0() {
        // Protocol 0/1 GLOBAL opcode: c<module>\n<attr>\n
        let data = b"cbuiltins\nexec\n";
        let globals = extract_pickle_globals(data);
        assert_eq!(globals, vec!["builtins.exec"]);
    }

    #[test]
    fn test_extract_global_os_system() {
        // Protocol 0 GLOBAL for os.system — classic pickle RCE
        let data = b"cos\nsystem\n";
        let globals = extract_pickle_globals(data);
        assert_eq!(globals, vec!["os.system"]);
    }

    #[test]
    fn test_extract_multiple_globals_protocol0() {
        // Two GLOBAL references in sequence
        let data = b"cos\nsystem\ncbuiltins\nexec\n";
        let globals = extract_pickle_globals(data);
        assert_eq!(globals, vec!["os.system", "builtins.exec"]);
    }

    #[test]
    fn test_extract_multiple_stack_globals() {
        // Two STACK_GLOBAL references
        let mut data: Vec<u8> = vec![
            0x80, 0x04, // PROTO 4
            0x8c, 0x02, b'o', b's', // SHORT_BINUNICODE "os"
            0x8c, 0x06, b's', b'y', b's', b't', b'e', b'm', // SHORT_BINUNICODE "system"
            0x93, // STACK_GLOBAL
            0x8c, 0x08, b'b', b'u', b'i', b'l', b't', b'i', b'n',
            b's', // SHORT_BINUNICODE "builtins"
            0x8c, 0x04, b'e', b'x', b'e', b'c', // SHORT_BINUNICODE "exec"
            0x93, // STACK_GLOBAL
        ];
        // Add a STOP opcode for completeness
        data.push(0x2e);
        let globals = extract_pickle_globals(&data);
        assert_eq!(globals, vec!["os.system", "builtins.exec"]);
    }

    #[test]
    fn test_globals_deduplicated() {
        // Same GLOBAL reference repeated should appear only once
        let data = b"cos\nsystem\ncos\nsystem\n";
        let globals = extract_pickle_globals(data);
        assert_eq!(globals, vec!["os.system"]);
    }

    #[test]
    fn test_extract_globals_empty_data() {
        let globals = extract_pickle_globals(&[]);
        assert!(globals.is_empty());
    }

    #[test]
    fn test_extract_globals_no_opcodes() {
        // Random bytes with no pickle opcodes
        let data = &[0x00, 0x01, 0x02, 0x03, 0xFF, 0xFE];
        let globals = extract_pickle_globals(data);
        assert!(globals.is_empty());
    }

    #[test]
    fn test_extract_globals_truncated_short_binunicode() {
        // SHORT_BINUNICODE with length extending past end of data
        let data: Vec<u8> = vec![0x8c, 0x20, b'o', b's']; // claims 32 bytes, only 2 available
        let globals = extract_pickle_globals(&data);
        assert!(globals.is_empty());
    }

    #[test]
    fn test_extract_globals_truncated_global_opcode() {
        // GLOBAL opcode with no trailing newline
        let data = b"cbuiltins";
        let globals = extract_pickle_globals(data);
        assert!(globals.is_empty());
    }

    #[test]
    fn test_extract_globals_rejects_non_identifier() {
        // GLOBAL with non-identifier module name
        let data = b"c123\nsystem\n";
        let globals = extract_pickle_globals(data);
        assert!(globals.is_empty());
    }

    #[test]
    fn test_extract_pickle_strings() {
        let data: Vec<u8> = vec![
            0x8c, 0x05, b'h', b'e', b'l', b'l', b'o', // "hello"
            0x8c, 0x05, b'w', b'o', b'r', b'l', b'd', // "world"
        ];
        let strings = extract_pickle_strings(&data);
        assert_eq!(strings, vec!["hello", "world"]);
    }

    #[test]
    fn test_extract_strings_deduplication() {
        let data: Vec<u8> = vec![
            0x8c, 0x05, b'h', b'e', b'l', b'l', b'o', // "hello"
            0x8c, 0x05, b'h', b'e', b'l', b'l', b'o', // "hello" again
        ];
        let strings = extract_pickle_strings(&data);
        assert_eq!(strings, vec!["hello"]);
    }

    #[test]
    fn test_extract_strings_skips_short() {
        // Strings <= 2 chars are filtered out
        let data: Vec<u8> = vec![
            0x8c, 0x02, b'o', b's', // "os" — too short (len 2)
            0x8c, 0x01, b'x', // "x" — too short (len 1)
            0x8c, 0x03, b'f', b'o', b'o', // "foo" — kept
        ];
        let strings = extract_pickle_strings(&data);
        assert_eq!(strings, vec!["foo"]);
    }

    #[test]
    fn test_extract_strings_empty_data() {
        let strings = extract_pickle_strings(&[]);
        assert!(strings.is_empty());
    }

    #[test]
    fn test_extract_strings_truncated() {
        // SHORT_BINUNICODE claiming more bytes than available
        let data: Vec<u8> = vec![0x8c, 0x10, b'a', b'b'];
        let strings = extract_pickle_strings(&data);
        assert!(strings.is_empty());
    }

    #[test]
    fn test_can_analyze_extensions() {
        let analyzer = PickleAnalyzer::new();
        assert!(analyzer.can_analyze(Path::new("model.pkl")));
        assert!(analyzer.can_analyze(Path::new("data.pickle")));
        assert!(analyzer.can_analyze(Path::new("pipeline.joblib")));
        assert!(analyzer.can_analyze(Path::new("MODEL.PKL")));
        assert!(!analyzer.can_analyze(Path::new("model.pt")));
        assert!(!analyzer.can_analyze(Path::new("model.pth")));
        assert!(!analyzer.can_analyze(Path::new("script.py")));
        assert!(!analyzer.can_analyze(Path::new("noext")));
    }

    #[test]
    fn test_analyze_pickle_report_structure() {
        let analyzer = PickleAnalyzer::new();
        // Construct a pickle with os.system via GLOBAL opcode
        let data = b"\x80\x02cos\nsystem\nq\x00X\x02\x00\x00\x00ls\x85R.";
        let report = analyzer.analyze_pickle(Path::new("evil.pkl"), data);

        assert_eq!(report.target.file_type, "pickle");
        assert_eq!(report.target.size_bytes, data.len() as u64);
        assert!(!report.target.sha256.is_empty());
        assert!(report
            .metadata
            .tools_used
            .contains(&"pickle-analyzer".to_string()));
        // Should find the os.system global import
        assert!(report.imports.iter().any(|i| i.symbol == "os.system"));
    }

    #[test]
    fn test_analyze_pickle_malicious_exec() {
        // Protocol 4 pickle calling builtins.exec
        let analyzer = PickleAnalyzer::new();
        let data: Vec<u8> = vec![
            0x80, 0x04, // PROTO 4
            0x8c, 0x08, b'b', b'u', b'i', b'l', b't', b'i', b'n', b's', 0x8c, 0x04, b'e', b'x',
            b'e', b'c', 0x93, // STACK_GLOBAL
            0x8c, 0x11, b'p', b'r', b'i', b'n', b't', b'(', b'"', b'p', b'w', b'n', b'e', b'd',
            b'"', b')', b' ', b' ', b' ', 0x85, // TUPLE1
            0x52, // REDUCE
            0x2e, // STOP
        ];
        let report = analyzer.analyze_pickle(Path::new("payload.pkl"), &data);

        assert!(report.imports.iter().any(|i| i.symbol == "builtins.exec"));
        assert!(report.imports.iter().all(|i| i.source == "pickle-analyzer"));
    }

    #[test]
    fn test_analyze_pickle_benign_empty() {
        let analyzer = PickleAnalyzer::new();
        // Minimal valid pickle: PROTO 4, EMPTY_DICT, STOP
        let data: Vec<u8> = vec![0x80, 0x04, 0x7d, 0x2e];
        let report = analyzer.analyze_pickle(Path::new("empty.pkl"), &data);

        assert!(report.imports.is_empty());
        assert_eq!(report.target.file_type, "pickle");
    }

    #[test]
    fn test_mixed_protocol0_and_stack_global() {
        // GLOBAL opcode followed by STACK_GLOBAL in same stream
        let mut data: Vec<u8> = Vec::new();
        // Protocol 0 GLOBAL: posix.system
        data.extend_from_slice(b"cposix\nsystem\n");
        // Then a SHORT_BINUNICODE pair + STACK_GLOBAL
        data.extend_from_slice(&[
            0x8c, 0x08, b'b', b'u', b'i', b'l', b't', b'i', b'n', b's', 0x8c, 0x04, b'e', b'x',
            b'e', b'c', 0x93,
        ]);
        let globals = extract_pickle_globals(&data);
        assert_eq!(globals, vec!["posix.system", "builtins.exec"]);
    }

    #[test]
    fn test_stack_global_needs_two_strings() {
        // STACK_GLOBAL with only one preceding string should not produce a global
        let data: Vec<u8> = vec![
            0x8c, 0x02, b'o', b's', // only one SHORT_BINUNICODE
            0x93, // STACK_GLOBAL — needs two strings
        ];
        let globals = extract_pickle_globals(&data);
        assert!(globals.is_empty());
    }
}
