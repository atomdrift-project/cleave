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

        // Open the filefacts parse once: it resolves the `module.attr`
        // callable references (`pickle.globals`) and the `pickle.*` opcode
        // facts, and is reused for trait evaluation below.
        let filefacts_ctx = crate::analysis_context::AnalysisContext::open(file_path, data).ok();

        // Project filefacts' resolved `module.attr` globals (the RCE targets)
        // as import symbols for trait matching.
        if let Some(ctx) = filefacts_ctx.as_ref()
            && let Some(globals) = ctx
                .parsed
                .values()
                .get("pickle.globals")
                .and_then(|v| v.as_array())
        {
            for global_ref in globals.iter().filter_map(|v| v.as_str()) {
                report.imports.push(crate::types::Import::new(
                    global_ref,
                    Some("pickle-global".to_string()),
                ));
            }
        }

        // Extract readable strings from pickle data. (This SHORT_BINUNICODE
        // scan folds into the filefacts string-extraction track alongside the
        // other analyzers.)
        let strings = extract_pickle_strings(data);
        for s in &strings {
            report.strings.push(crate::types::StringInfo {
                value: s.clone().into(),
                string_type: None,
                offset: None,
                encoding: String::new(),
                section: None,
                encoding_chain: Vec::new(),
                fragments: None,
            });
        }

        // `pickle.*` kv comes from filefacts's dual emission in the
        // capability mapper — no synthesis needed here.

        // Evaluate trait rules
        self.capability_mapper
            .evaluate_and_merge_findings_with_precomputed(
                &mut report,
                data,
                crate::capabilities::AnalysisBorrow::with_filefacts(None, filefacts_ctx.as_ref()),
                None,
                None,
                None,
                None,
            );

        report
    }
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
            if let Ok(s) = std::str::from_utf8(&data[i + 2..i + 2 + length])
                && s.is_ascii()
                && s.len() > 2
                && seen.insert(s.to_string())
            {
                strings.push(s.to_string());
            }
            i += 2 + length;
        } else {
            i += 1;
        }
    }

    strings
}

#[cfg(test)]
mod tests {
    use super::*;

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
        assert!(
            report
                .metadata
                .tools_used
                .contains(&"pickle-analyzer".to_string())
        );
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
        // GLOBAL opcode followed by STACK_GLOBAL in same stream — both
        // module.attr callables surface as imports via filefacts pickle.globals.
        let analyzer = PickleAnalyzer::new();
        let mut data: Vec<u8> = Vec::new();
        // Protocol 0 GLOBAL: posix.system
        data.extend_from_slice(b"cposix\nsystem\n");
        // Then a SHORT_BINUNICODE pair + STACK_GLOBAL
        data.extend_from_slice(&[
            0x8c, 0x08, b'b', b'u', b'i', b'l', b't', b'i', b'n', b's', 0x8c, 0x04, b'e', b'x',
            b'e', b'c', 0x93,
        ]);
        let report = analyzer.analyze_pickle(Path::new("mixed.pkl"), &data);
        assert!(report.imports.iter().any(|i| i.symbol == "posix.system"));
        assert!(report.imports.iter().any(|i| i.symbol == "builtins.exec"));
    }
}
