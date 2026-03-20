//! LNK (Windows Shell Link) file analyzer for cleave
//!
//! Parses Windows shortcut files (.lnk) to extract target paths, arguments,
//! working directory, and other metadata. Detects obfuscation techniques like
//! excessive whitespace padding (ZDI-CAN-25373).
use super::{AnalysisInput, Analyzer};
use crate::capabilities::CapabilityMapper;
use crate::types::{AnalysisReport, TargetInfo};
use anyhow::Result;
use sha2::{Digest, Sha256};
use std::path::Path;
use std::sync::Arc;

/// LNK file magic bytes: 4C 00 00 00 (header size)
/// followed by CLSID: 01 14 02 00 00 00 00 00 C0 00 00 00 00 00 00 46
const LNK_MAGIC: &[u8] = &[
    0x4C, 0x00, 0x00, 0x00, // HeaderSize (76 bytes in little-endian)
    0x01, 0x14, 0x02, 0x00, // LinkCLSID start
    0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46, // LinkCLSID end
];

/// Threshold for "excessive" whitespace padding (ZDI-CAN-25373)
const EXCESSIVE_WHITESPACE_THRESHOLD: usize = 50;

/// Extracted LNK file data for analysis
#[derive(Debug, Clone)]
pub(crate) struct LnkData {
    /// Target file path (e.g., "C:\Windows\System32\cmd.exe")
    pub target_path: Option<String>,
    /// Command-line arguments
    pub arguments: Option<String>,
    /// Working directory
    pub working_dir: Option<String>,
    /// Icon file location
    pub icon_location: Option<String>,
    /// ShowCommand value (0=SW_HIDE, 1=SW_NORMAL, 3=SW_MAXIMIZE, 7=SW_MINIMIZE)
    pub show_command: u32,
    /// Hotkey value
    pub hotkey: u16,
    /// Whether file has link target ID list
    pub has_link_target_id_list: bool,
    /// Whether file has link info
    pub has_link_info: bool,
    /// Whether file has arguments
    pub has_arguments: bool,
    /// Whether file has working directory
    pub has_working_dir: bool,
    /// Whether file has icon location
    pub has_icon_location: bool,
    /// Whitespace analysis results
    pub whitespace_analysis: WhitespaceAnalysis,
}

/// Whitespace analysis for detecting obfuscation
#[derive(Debug, Clone, Default)]
pub(crate) struct WhitespaceAnalysis {
    /// Number of leading spaces in arguments
    pub leading_spaces: usize,
    /// Number of leading tabs in arguments
    pub leading_tabs: usize,
    /// Total whitespace characters in arguments
    pub total_whitespace: usize,
    /// Longest consecutive whitespace run in arguments
    pub max_consecutive_whitespace: usize,
    /// Whether arguments have excessive padding (>50 consecutive whitespace chars)
    pub has_excessive_padding: bool,
}

/// Check if data looks like a LNK file
#[must_use]
pub(crate) fn is_lnk(data: &[u8]) -> bool {
    data.len() >= LNK_MAGIC.len() && data.starts_with(LNK_MAGIC)
}

/// Extract LNK data from file content
#[must_use]
pub(crate) fn extract_lnk_data(data: &[u8]) -> Option<LnkData> {
    // Write data to a temporary file since lnk crate requires a path
    let temp_file = tempfile::NamedTempFile::new().ok()?;
    std::fs::write(temp_file.path(), data).ok()?;

    // Parse using lnk crate with Windows-1252 encoding (default for LNK files)
    let shell_link =
        ::lnk::ShellLink::open(temp_file.path(), ::lnk::encoding::WINDOWS_1252).ok()?;

    // Extract target path from link info
    let target_path = shell_link
        .link_info()
        .as_ref()
        .and_then(|info| info.local_base_path())
        .map(String::from);

    // Extract string data using string_data accessor
    let string_data = shell_link.string_data();
    let arguments = string_data
        .command_line_arguments()
        .as_ref()
        .map(std::string::ToString::to_string);
    let working_dir = string_data
        .working_dir()
        .as_ref()
        .map(std::string::ToString::to_string);
    let icon_location = string_data
        .icon_location()
        .as_ref()
        .map(std::string::ToString::to_string);

    // Analyze whitespace in arguments
    let whitespace_analysis = analyze_whitespace(arguments.as_deref());

    // Get header flags and show command
    let header = shell_link.header();
    let link_flags = header.link_flags();

    // Convert ShowCommand enum to u32
    let show_command = match header.show_command() {
        ::lnk::ShowCommand::ShowNormal => 1,
        ::lnk::ShowCommand::ShowMaximized => 3,
        ::lnk::ShowCommand::ShowMinNoActive => 7,
    };

    // Hotkey is rarely important for malware detection - use 0 as placeholder
    let hotkey = 0u16;

    Some(LnkData {
        target_path,
        arguments,
        working_dir,
        icon_location,
        show_command,
        hotkey,
        has_link_target_id_list: link_flags.contains(::lnk::LinkFlags::HAS_LINK_TARGET_ID_LIST),
        has_link_info: link_flags.contains(::lnk::LinkFlags::HAS_LINK_INFO),
        has_arguments: link_flags.contains(::lnk::LinkFlags::HAS_ARGUMENTS),
        has_working_dir: link_flags.contains(::lnk::LinkFlags::HAS_WORKING_DIR),
        has_icon_location: link_flags.contains(::lnk::LinkFlags::HAS_ICON_LOCATION),
        whitespace_analysis,
    })
}

/// Analyze whitespace in arguments string for obfuscation detection
fn analyze_whitespace(arguments: Option<&str>) -> WhitespaceAnalysis {
    let Some(args) = arguments else {
        return WhitespaceAnalysis::default();
    };

    let mut leading_spaces = 0usize;
    let mut leading_tabs = 0usize;
    let mut total_whitespace = 0usize;
    let mut current_run = 0usize;
    let mut max_consecutive_whitespace = 0usize;
    let mut in_leading = true;

    for c in args.chars() {
        if c.is_whitespace() {
            total_whitespace += 1;
            current_run += 1;
            if in_leading {
                if c == ' ' {
                    leading_spaces += 1;
                } else if c == '\t' {
                    leading_tabs += 1;
                }
            }
        } else {
            in_leading = false;
            if current_run > max_consecutive_whitespace {
                max_consecutive_whitespace = current_run;
            }
            current_run = 0;
        }
    }

    // Check final run
    if current_run > max_consecutive_whitespace {
        max_consecutive_whitespace = current_run;
    }

    // Excessive padding is detected by either leading or consecutive whitespace
    let has_excessive = max_consecutive_whitespace >= EXCESSIVE_WHITESPACE_THRESHOLD;

    WhitespaceAnalysis {
        leading_spaces,
        leading_tabs,
        total_whitespace,
        max_consecutive_whitespace,
        has_excessive_padding: has_excessive,
    }
}

/// LNK file analyzer
#[derive(Debug)]
pub(crate) struct LnkAnalyzer {
    capability_mapper: Arc<CapabilityMapper>,
}

impl LnkAnalyzer {
    /// Create a new LNK analyzer with an empty capability mapper
    #[must_use]
    pub(crate) fn new() -> Self {
        Self {
            capability_mapper: Arc::new(CapabilityMapper::empty()),
        }
    }

    /// Create analyzer with pre-existing capability mapper (wraps in Arc)
    #[must_use]
    pub(crate) fn with_capability_mapper(mut self, mapper: CapabilityMapper) -> Self {
        self.capability_mapper = Arc::new(mapper);
        self
    }

    /// Create analyzer with shared capability mapper (avoids cloning)
    #[must_use]
    pub(crate) fn with_capability_mapper_arc(mut self, mapper: Arc<CapabilityMapper>) -> Self {
        self.capability_mapper = mapper;
        self
    }

    fn analyze_lnk(&self, file_path: &Path, data: &[u8]) -> AnalysisReport {
        // Calculate hash
        let mut hasher = Sha256::new();
        hasher.update(data);
        let sha256 = format!("{:x}", hasher.finalize());

        // Create target info
        let target = TargetInfo {
            path: file_path.display().to_string(),
            file_type: "lnk".to_string(),
            size_bytes: data.len() as u64,
            sha256,
            architectures: None,
        };

        let mut report = AnalysisReport::new(target);
        report.metadata.tools_used.push("lnk-parser".to_string());

        // Parse LNK file
        if let Some(lnk_data) = extract_lnk_data(data) {
            // Add extracted data to strings for trait evaluation
            if let Some(ref path) = lnk_data.target_path {
                report.strings.push(crate::types::StringInfo {
                    value: path.clone(),
                    offset: None,
                    encoding: "utf-16le".to_string(),
                    string_type: crate::types::binary::StringType::Const,
                    section: Some("lnk:target_path".to_string()),
                    encoding_chain: Vec::new(),
                    fragments: None,
                });
            }
            if let Some(ref args) = lnk_data.arguments {
                report.strings.push(crate::types::StringInfo {
                    value: args.clone(),
                    offset: None,
                    encoding: "utf-16le".to_string(),
                    string_type: crate::types::binary::StringType::Const,
                    section: Some("lnk:arguments".to_string()),
                    encoding_chain: Vec::new(),
                    fragments: None,
                });
            }
            if let Some(ref wd) = lnk_data.working_dir {
                report.strings.push(crate::types::StringInfo {
                    value: wd.clone(),
                    offset: None,
                    encoding: "utf-16le".to_string(),
                    string_type: crate::types::binary::StringType::Const,
                    section: Some("lnk:working_dir".to_string()),
                    encoding_chain: Vec::new(),
                    fragments: None,
                });
            }
            if let Some(ref icon) = lnk_data.icon_location {
                report.strings.push(crate::types::StringInfo {
                    value: icon.clone(),
                    offset: None,
                    encoding: "utf-16le".to_string(),
                    string_type: crate::types::binary::StringType::Const,
                    section: Some("lnk:icon_location".to_string()),
                    encoding_chain: Vec::new(),
                    fragments: None,
                });
            }
            // LNK data is parsed directly by the KV evaluator from raw bytes
            // when evaluating traits, so no need to store it in the report
            drop(lnk_data);
        }

        // Evaluate YAML traits against the file content
        self.capability_mapper
            .evaluate_and_merge_findings(&mut report, data, None, None);

        report
    }
}

impl Default for LnkAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl Analyzer for LnkAnalyzer {
    fn analyze_input(&self, input: &AnalysisInput<'_>) -> Result<AnalysisReport> {
        Ok(self.analyze_lnk(input.path, input.data))
    }

    fn analyze(&self, file_path: &Path) -> Result<AnalysisReport> {
        let data = std::fs::read(file_path)?;
        Ok(self.analyze_lnk(file_path, &data))
    }

    fn can_analyze(&self, file_path: &Path) -> bool {
        if let Some(ext) = file_path.extension() {
            ext.to_string_lossy().to_lowercase() == "lnk"
        } else {
            false
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_lnk_magic_detection() {
        // Valid LNK header
        let valid = [
            0x4C, 0x00, 0x00, 0x00, 0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x46,
        ];
        assert!(is_lnk(&valid));

        // Invalid - too short
        assert!(!is_lnk(&[0x4C, 0x00, 0x00]));

        // Invalid - wrong magic
        assert!(!is_lnk(&[0x00; 20]));
    }

    #[test]
    fn test_whitespace_analysis() {
        // Normal arguments
        let normal = analyze_whitespace(Some("/c dir"));
        assert_eq!(normal.leading_spaces, 0);
        assert_eq!(normal.max_consecutive_whitespace, 1);
        assert!(!normal.has_excessive_padding);

        // Excessive leading spaces (obfuscation)
        let spaces = " ".repeat(60) + "cmd.exe";
        let padded = analyze_whitespace(Some(&spaces));
        assert_eq!(padded.leading_spaces, 60);
        assert_eq!(padded.max_consecutive_whitespace, 60);
        assert!(padded.has_excessive_padding);

        // Tabs
        let tabs = "\t".repeat(55) + "cmd.exe";
        let tabbed = analyze_whitespace(Some(&tabs));
        assert_eq!(tabbed.leading_tabs, 55);
        assert_eq!(tabbed.max_consecutive_whitespace, 55);
        assert!(tabbed.has_excessive_padding);

        // Whitespace AFTER command switch (ZDI-CAN-25373 pattern)
        let after_switch = "/c".to_string() + &" ".repeat(100) + "calc.exe";
        let after_result = analyze_whitespace(Some(&after_switch));
        assert_eq!(after_result.leading_spaces, 0);
        assert_eq!(after_result.max_consecutive_whitespace, 100);
        assert!(after_result.has_excessive_padding);

        // Mixed but under threshold
        let mixed = " ".repeat(20) + "\t".repeat(20).as_str() + "cmd.exe";
        let mixed_result = analyze_whitespace(Some(&mixed));
        assert_eq!(mixed_result.leading_spaces, 20);
        assert_eq!(mixed_result.leading_tabs, 20);
        assert_eq!(mixed_result.max_consecutive_whitespace, 40);
        assert!(!mixed_result.has_excessive_padding);

        // None
        let none = analyze_whitespace(None);
        assert_eq!(none.leading_spaces, 0);
        assert_eq!(none.max_consecutive_whitespace, 0);
        assert!(!none.has_excessive_padding);
    }

    #[test]
    fn test_analyzer_basic() {
        let analyzer = LnkAnalyzer::new();
        assert!(analyzer.can_analyze(Path::new("/tmp/test.lnk")));
        assert!(analyzer.can_analyze(Path::new("/tmp/test.LNK")));
        assert!(!analyzer.can_analyze(Path::new("/tmp/test.exe")));
    }

    #[test]
    fn test_parse_whitespace_obfuscated_fixture() {
        // Test parsing of generated LNK fixture
        let fixture_path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/lnk/whitespace_obfuscated.lnk");

        if !fixture_path.exists() {
            eprintln!(
                "Fixture not found: {:?} - run generate.py first",
                fixture_path
            );
            return;
        }

        let data = std::fs::read(&fixture_path).expect("Failed to read fixture");
        assert!(is_lnk(&data), "Should detect LNK magic");

        let lnk_data = extract_lnk_data(&data);
        assert!(lnk_data.is_some(), "Should parse LNK file");

        let lnk = lnk_data.unwrap();

        // pylnk3 uses Minimized (7) since it doesn't support SW_HIDE (0)
        assert_eq!(lnk.show_command, 7, "Should have minimized window");

        // Arguments should exist and have excessive consecutive whitespace
        assert!(lnk.has_arguments, "Should have arguments");
        assert!(
            lnk.whitespace_analysis.max_consecutive_whitespace >= 100,
            "Should have 100+ consecutive whitespace chars, got {}",
            lnk.whitespace_analysis.max_consecutive_whitespace
        );
        assert!(
            lnk.whitespace_analysis.has_excessive_padding,
            "Should detect excessive padding"
        );
    }

    #[test]
    fn test_parse_benign_notepad_fixture() {
        let fixture_path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/lnk/benign_notepad.lnk");

        if !fixture_path.exists() {
            eprintln!(
                "Fixture not found: {:?} - run generate.py first",
                fixture_path
            );
            return;
        }

        let data = std::fs::read(&fixture_path).expect("Failed to read fixture");
        assert!(is_lnk(&data), "Should detect LNK magic");

        let lnk_data = extract_lnk_data(&data);
        assert!(lnk_data.is_some(), "Should parse LNK file");

        let lnk = lnk_data.unwrap();
        // Normal window (1)
        assert_eq!(lnk.show_command, 1, "Should have normal window");
        // No excessive whitespace
        assert!(
            !lnk.whitespace_analysis.has_excessive_padding,
            "Should not have excessive padding"
        );
        // No arguments
        assert!(!lnk.has_arguments, "Should not have arguments");
    }
}
