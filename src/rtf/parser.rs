use crate::rtf::error::{Result, RtfError};
use crate::rtf::hex_decoder::decode_hex_tolerant;
use crate::rtf::ole_extractor;
use crate::rtf::types::{
    ControlWord, DocumentMetadata, OleObject, RtfDocument, RtfHeader, SuspiciousFlag,
};
use regex::Regex;
use std::sync::OnceLock;

/// Cached regex patterns for RTF parsing
fn control_word_regex() -> Option<&'static Regex> {
    static RE: OnceLock<Option<Regex>> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\\([a-zA-Z]+)(-?\d*)").ok())
        .as_ref()
}

fn object_regex() -> Option<&'static Regex> {
    static RE: OnceLock<Option<Regex>> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\{\\object[^}]*\}").ok())
        .as_ref()
}

fn objclass_regex() -> Option<&'static Regex> {
    static RE: OnceLock<Option<Regex>> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r#"\\objclass\s+"([^"]+)"?"#).ok())
        .as_ref()
}

fn objdata_regex() -> Option<&'static Regex> {
    static RE: OnceLock<Option<Regex>> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\\objdata\s+([0-9a-fA-F\s]+)").ok())
        .as_ref()
}

fn unc_path_regex() -> Option<&'static Regex> {
    static RE: OnceLock<Option<Regex>> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\\\\([^\s\\]+)@SSL\\([^\s}]+)").ok())
        .as_ref()
}

/// RTF parser with anti-bomb protections and minimal dependencies
#[derive(Debug)]
pub(crate) struct RtfParser {
    max_depth: usize,
    max_objects: usize,
    max_file_size: usize,
}

impl RtfParser {
    /// Create a new parser with default limits (100 nesting depth, 50 objects, 10MB max size)
    #[must_use]
    pub(crate) fn new() -> Self {
        Self {
            max_depth: 100,
            max_objects: 50,
            max_file_size: 10 * 1024 * 1024, // 10MB
        }
    }

    /// Parse RTF data and extract document structure
    pub(crate) fn parse(&self, data: &[u8]) -> Result<RtfDocument> {
        if data.is_empty() {
            return Err(RtfError::EmptyFile);
        }

        if data.len() > self.max_file_size {
            return Err(RtfError::FileTooLarge {
                size: data.len(),
                max: self.max_file_size,
            });
        }

        // Validate RTF header
        if !data.starts_with(b"{\\rtf") {
            return Err(RtfError::InvalidHeader);
        }

        let text = String::from_utf8_lossy(data);

        // Extract control words
        let control_words = self.extract_control_words(&text);

        // Check for objupdate directive (suspicious)
        let has_objupdate = control_words.iter().any(|cw| cw.name == "objupdate");

        // Extract embedded objects
        let embedded_objects = self.extract_ole_objects(&text);

        if embedded_objects.len() > self.max_objects {
            return Err(RtfError::TooManyObjects {
                count: embedded_objects.len(),
                max: self.max_objects,
            });
        }

        // Calculate nesting depth
        let max_nesting_depth = self.calculate_nesting_depth(&text)?;

        let header = RtfHeader {
            version: self.extract_version(&control_words),
            charset: self.extract_charset(&control_words),
            offset: 0,
        };

        let metadata = DocumentMetadata {
            file_size: data.len(),
            object_count: embedded_objects.len(),
            max_nesting_depth,
            has_objupdate,
            detected_charset: self.extract_charset(&control_words),
        };

        Ok(RtfDocument {
            header,
            control_words,
            embedded_objects,
            metadata,
        })
    }

    /// Extract control words from RTF text
    fn extract_control_words(&self, text: &str) -> Vec<ControlWord> {
        let mut words = Vec::new();
        let Some(re) = control_word_regex() else {
            return words;
        };

        for (i, m) in re.find_iter(text).enumerate() {
            if i > 10000 {
                // Sanity check - prevent excessive parsing
                break;
            }

            if let Some(caps) = re.captures(m.as_str()) {
                if let Some(name_match) = caps.get(1) {
                    let name = name_match.as_str().to_string();
                    let param = caps.get(2).map(|p| p.as_str()).and_then(|s| s.parse().ok());

                    words.push(ControlWord {
                        name,
                        parameter: param,
                        offset: m.start(),
                    });
                }
            }
        }

        words
    }

    /// Extract embedded OLE objects
    fn extract_ole_objects(&self, text: &str) -> Vec<OleObject> {
        let mut objects = Vec::new();

        // Find all \object...{\object directives
        // Look for patterns like: {\object\objemb...{\*\objdata ...}}
        let Some(re) = object_regex() else {
            return objects;
        };

        for m in re.find_iter(text) {
            let object_str = m.as_str();

            // Try to extract objdata (hex-encoded OLE data)
            if let Some((class_name, objdata)) = self.extract_objdata(object_str) {
                let mut flags = Vec::new();

                // Check for OLE header
                let ole_header = if let Ok(header) = ole_extractor::extract_header(&objdata) {
                    flags.push(SuspiciousFlag::ObfuscatedOleHeader);
                    Some(header)
                } else {
                    None
                };

                // Check for obfuscation in hex encoding
                if let Some(hex_start) = object_str.find("objdata") {
                    if detect_hex_obfuscation(&object_str[hex_start..]) {
                        flags.push(SuspiciousFlag::ObfuscatedOleHeader);
                    }
                }

                // Check for UNC paths
                if let Some(unc_path) = extract_unc_path(object_str) {
                    flags.push(SuspiciousFlag::UncPath(unc_path));
                }

                // Check for objupdate
                if object_str.contains("\\objupdate") {
                    flags.push(SuspiciousFlag::ObjUpdateDirective);
                }

                // Check for WebDAV paths
                if object_str.contains("davwwwroot") || object_str.contains("DavWWWRoot") {
                    flags.push(SuspiciousFlag::WebdavPath);
                }

                objects.push(OleObject {
                    class_name,
                    objdata,
                    ole_header,
                    offset: m.start(),
                    suspicious_flags: flags,
                });
            }
        }

        objects
    }

    /// Extract objdata hex string from object directive
    fn extract_objdata(&self, object_str: &str) -> Option<(String, Vec<u8>)> {
        // Extract class name (e.g., "Word.Document.8")
        let class_name = objclass_regex()
            .and_then(|regex| regex.captures(object_str))
            .and_then(|c| c.get(1))
            .map(|m| m.as_str().to_string())
            .unwrap_or_else(|| "Unknown".to_string());

        // Extract hex data from {\*\objdata ...}
        let data_re = objdata_regex()?;

        if let Some(caps) = data_re.captures(object_str) {
            let hex_str = caps.get(1).map(|m| m.as_str())?;
            if let Ok(decoded) = decode_hex_tolerant(hex_str) {
                return Some((class_name, decoded));
            }
        }

        None
    }

    /// Calculate maximum nesting depth to detect zip bombs
    fn calculate_nesting_depth(&self, text: &str) -> Result<usize> {
        let mut max_depth = 0;
        let mut current_depth = 0;

        for ch in text.chars() {
            match ch {
                '{' => {
                    current_depth += 1;
                    if current_depth > max_depth {
                        max_depth = current_depth;
                    }
                    if current_depth > self.max_depth {
                        return Err(RtfError::ExcessiveNesting {
                            depth: current_depth,
                            max: self.max_depth,
                        });
                    }
                }
                '}' => {
                    current_depth = current_depth.saturating_sub(1);
                }
                _ => {}
            }
        }

        Ok(max_depth)
    }

    /// Extract RTF version from control words
    fn extract_version(&self, words: &[ControlWord]) -> u32 {
        words
            .iter()
            .find(|w| w.name == "rtf")
            .and_then(|w| w.parameter)
            .unwrap_or(0) as u32
    }

    /// Extract charset from control words
    fn extract_charset(&self, words: &[ControlWord]) -> Option<String> {
        words.iter().find(|w| w.name == "charset").and_then(|w| {
            w.parameter.map(|p| match p {
                0 => "ANSI".to_string(),
                1 => "Default".to_string(),
                2 => "Symbol".to_string(),
                238 => "Eastern European".to_string(),
                _ => format!("Unknown({})", p),
            })
        })
    }
}

impl Default for RtfParser {
    fn default() -> Self {
        Self::new()
    }
}

/// Extract UNC path from RTF control sequences
fn extract_unc_path(text: &str) -> Option<String> {
    // Look for \\server@SSL\path patterns
    let re = unc_path_regex()?;

    if let Some(caps) = re.captures(text) {
        let server = caps.get(1).map(|m| m.as_str()).unwrap_or("");
        let path = caps.get(2).map(|m| m.as_str()).unwrap_or("");
        return Some(format!("\\\\{}@SSL\\{}", server, path));
    }

    None
}

/// Detect hex obfuscation (whitespace between hex digits)
fn detect_hex_obfuscation(text: &str) -> bool {
    let bytes = text.as_bytes();
    let mut prev_was_hex = false;
    let mut found_spacing = false;

    for &b in bytes {
        let is_hex = b.is_ascii_hexdigit();
        let is_ws = matches!(b, b' ' | b'\t' | b'\n' | b'\r');

        if is_hex {
            if prev_was_hex && found_spacing {
                return true;
            }
            prev_was_hex = true;
            found_spacing = false;
        } else if is_ws && prev_was_hex {
            found_spacing = true;
        } else if !is_ws {
            prev_was_hex = false;
            found_spacing = false;
        }
    }

    false
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_minimal_rtf() {
        let data = b"{\\rtf1\\ansi\\ansicpg1252}";
        let parser = RtfParser::new();
        let doc = parser.parse(data).unwrap();
        assert_eq!(doc.header.version, 1);
    }

    #[test]
    fn test_parse_empty_file() {
        let parser = RtfParser::new();
        assert!(parser.parse(b"").is_err());
    }

    #[test]
    fn test_parse_invalid_header() {
        let parser = RtfParser::new();
        assert!(parser.parse(b"not rtf").is_err());
    }

    #[test]
    fn test_excessive_nesting() {
        let bomb = format!("{{\\rtf1{}", "{".repeat(101));
        let parser = RtfParser::new();
        assert!(matches!(
            parser.parse(bomb.as_bytes()),
            Err(RtfError::ExcessiveNesting { .. })
        ));
    }

    #[test]
    fn test_extract_control_words() {
        let parser = RtfParser::new();
        let words = parser.extract_control_words("{\\rtf1\\ansi\\deff0}");
        assert!(words.iter().any(|w| w.name == "rtf"));
        assert!(words.iter().any(|w| w.name == "ansi"));
    }
}
