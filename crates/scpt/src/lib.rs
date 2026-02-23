//! Parser and symbol extractor for compiled AppleScript (.scpt) files
//!
//! This crate provides functionality to parse Apple's compiled AppleScript format
//! and extract symbols including variable names, function calls, Apple Event codes,
//! and string literals.
//!
//! # Example
//!
//! ```no_run
//! use scpt::ScptParser;
//!
//! let data = std::fs::read("script.scpt").unwrap();
//! let parser = ScptParser::new(&data).unwrap();
//!
//! for symbol in parser.symbols() {
//!     println!("{:?}", symbol);
//! }
//! ```

use std::collections::HashSet;
use thiserror::Error;

/// Magic bytes for compiled AppleScript files
const SCPT_MAGIC: &[u8; 8] = b"FasdUAS ";

/// Footer magic that marks the end of a compiled AppleScript
const SCPT_FOOTER: &[u8; 4] = b"ascr";

/// Terminator bytes
const SCPT_TERMINATOR: [u8; 4] = [0xfa, 0xde, 0xde, 0xad];

/// Errors that can occur during scpt parsing
#[derive(Error, Debug)]
pub enum ScptError {
    /// Invalid magic bytes - not a compiled AppleScript file
    #[error("invalid magic bytes - not a compiled AppleScript file")]
    InvalidMagic,

    /// File too small to be a valid scpt
    #[error("file too small to be a valid scpt")]
    FileTooSmall,

    /// Malformed data at offset
    #[error("malformed data at offset {0}")]
    MalformedData(usize),
}

/// Types of symbols that can be extracted from a compiled AppleScript
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum SymbolKind {
    /// Variable or property name (e.g., "savePath", "sysUpdate")
    Variable,
    /// Apple Event code (e.g., "syso.exec" for do shell script)
    AppleEvent,
    /// Four character code (e.g., "TEXT", "ascr")
    FourCharCode,
    /// Application name from tell blocks
    Application,
    /// String literal
    StringLiteral,
    /// Handler/function name
    Handler,
}

/// A symbol extracted from a compiled AppleScript
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Symbol {
    /// The symbol text
    pub name: String,
    /// What kind of symbol this is
    pub kind: SymbolKind,
    /// Offset in the file where this was found
    pub offset: usize,
}

/// Known Apple Event classes and their meanings
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppleEventClass {
    /// System operations (syso) - do shell script, etc.
    System,
    /// Core Apple Events (aevt) - open, quit, activate
    Core,
    /// Finder/file events (ears)
    Finder,
    /// Miscellaneous events (misc) - activate, select
    Misc,
    /// Core suite (core) - count, create, delete
    CoreSuite,
    /// Unknown class
    Unknown,
}

impl AppleEventClass {
    fn from_code(code: &[u8]) -> Self {
        match code {
            b"syso" => Self::System,
            b"aevt" => Self::Core,
            b"ears" => Self::Finder,
            b"misc" => Self::Misc,
            b"core" => Self::CoreSuite,
            _ => Self::Unknown,
        }
    }
}

/// Known Apple Event IDs and their meanings
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppleEventInfo {
    /// The Apple Event class category
    pub class: AppleEventClass,
    /// The four-character class code (e.g., "syso", "aevt")
    pub class_code: String,
    /// The four-character event code (e.g., "exec", "oapp")
    pub event_code: String,
    /// Human-readable description of the event
    pub desc: &'static str,
}

impl AppleEventInfo {
    fn new(class_code: &[u8], event_code: &[u8]) -> Self {
        let class = AppleEventClass::from_code(class_code);
        let class_str = String::from_utf8_lossy(class_code).to_string();
        let event_str = String::from_utf8_lossy(event_code).to_string();

        let description = match (class_code, event_code) {
            // System operations
            (b"syso", b"exec") => "do shell script",
            (b"syso", b"dela") => "delay",
            (b"syso", b"load") => "load script",
            (b"syso", b"open") => "open location",
            (b"syso", b"surl") => "open URL",
            (b"syso", b"GUrl") => "get URL",
            // Core Apple Events
            (b"aevt", b"oapp") => "run/open application",
            (b"aevt", b"quit") => "quit application",
            (b"aevt", b"odoc") => "open document",
            (b"aevt", b"pdoc") => "print document",
            (b"aevt", b"rapp") => "reopen application",
            // Miscellaneous
            (b"misc", b"actv") => "activate",
            (b"misc", b"dosc") => "do script",
            (b"misc", b"slct") => "select",
            (b"misc", b"mvis") => "make visible",
            // Finder/file operations
            (b"ears", b"ffdr") => "folder/file reference",
            // Core suite
            (b"core", b"cnte") => "count",
            (b"core", b"crel") => "create",
            (b"core", b"dele") => "delete",
            (b"core", b"getd") => "get data",
            (b"core", b"setd") => "set data",
            (b"core", b"move") => "move",
            (b"core", b"clon") => "duplicate",
            _ => "unknown",
        };

        Self {
            class,
            class_code: class_str,
            event_code: event_str,
            desc: description,
        }
    }
}

/// Parser for compiled AppleScript (.scpt) files
#[derive(Debug)]
pub struct ScptParser<'a> {
    data: &'a [u8],
    version: String,
}

impl<'a> ScptParser<'a> {
    /// Create a new parser for the given data
    pub fn new(data: &'a [u8]) -> Result<Self, ScptError> {
        if data.len() < 20 {
            return Err(ScptError::FileTooSmall);
        }

        if !data.starts_with(SCPT_MAGIC) {
            return Err(ScptError::InvalidMagic);
        }

        // Extract version string (bytes 8-16)
        let version_bytes = &data[8..16];
        let version = String::from_utf8_lossy(version_bytes)
            .trim_end_matches('\0')
            .to_string();

        Ok(Self { data, version })
    }

    /// Get the AppleScript version string
    #[must_use]
    pub fn version(&self) -> &str {
        &self.version
    }

    /// Check if this is a valid compiled AppleScript file
    #[must_use]
    pub fn is_valid(&self) -> bool {
        // Check for footer magic ("ascr") and terminator ("fade dead")
        self.find_footer().is_some() && self.find_terminator().is_some()
    }

    fn find_footer(&self) -> Option<usize> {
        // Search backwards from end for "ascr"
        (0..self.data.len().saturating_sub(4))
            .rev()
            .find(|&i| self.data[i..i + 4] == *SCPT_FOOTER)
    }

    fn find_terminator(&self) -> Option<usize> {
        // Search backwards from end for "fade dead"
        if self.data.len() < 4 {
            return None;
        }
        (0..=self.data.len() - 4)
            .rev()
            .find(|&i| self.data[i..i + 4] == SCPT_TERMINATOR)
    }

    /// Extract all symbols from the compiled AppleScript
    #[must_use]
    pub fn symbols(&self) -> Vec<Symbol> {
        let mut symbols = Vec::new();
        let mut seen: HashSet<(String, SymbolKind)> = HashSet::new();

        // Extract variable names (0b prefix entries)
        self.extract_variables(&mut symbols, &mut seen);

        // Extract Apple Event codes (0a prefix entries)
        self.extract_apple_events(&mut symbols, &mut seen);

        // Extract string literals
        self.extract_strings(&mut symbols, &mut seen);

        // Extract application names from tell blocks
        self.extract_applications(&mut symbols, &mut seen);

        symbols
    }

    /// Extract variable names from the symbol table
    fn extract_variables(
        &self,
        symbols: &mut Vec<Symbol>,
        seen: &mut HashSet<(String, SymbolKind)>,
    ) {
        // Pattern: 0b <id:2> 00 <len:1> 30 00 <namelen:1> <name> ...
        // The 0b prefix marks variable name entries
        let mut i = 16; // Skip header

        while i + 10 < self.data.len() {
            // Look for variable entry marker: 0x0b followed by 2-byte id, then 0x00
            if self.data[i] == 0x0b && i + 3 < self.data.len() && self.data[i + 3] == 0x00 {
                if let Some((name, consumed)) = self.parse_variable_entry(i) {
                    if !name.is_empty() && Self::is_valid_identifier(&name) {
                        let key = (name.clone(), SymbolKind::Variable);
                        if !seen.contains(&key) {
                            seen.insert(key);
                            symbols.push(Symbol {
                                name,
                                kind: SymbolKind::Variable,
                                offset: i,
                            });
                        }
                    }
                    i += consumed;
                    continue;
                }
            }
            i += 1;
        }
    }

    fn parse_variable_entry(&self, offset: usize) -> Option<(String, usize)> {
        // Format: 0b <id:2> 00 <total_len:1> 30 00 <name1_len:1> <name1> 00 <name2_len:1> <name2>
        if offset + 8 > self.data.len() {
            return None;
        }

        let total_len = self.data[offset + 4] as usize;
        if total_len < 4 || offset + 5 + total_len > self.data.len() {
            return None;
        }

        // Check for '30' marker (type indicator for variable names)
        if self.data[offset + 5] != 0x30 || self.data[offset + 6] != 0x00 {
            return None;
        }

        let name1_len = self.data[offset + 7] as usize;
        if offset + 8 + name1_len > self.data.len() {
            return None;
        }

        // Extract the first name (usually lowercase)
        let name1_bytes = &self.data[offset + 8..offset + 8 + name1_len];
        let name1 = String::from_utf8_lossy(name1_bytes).to_string();

        // Try to get the second name (camelCase version) if present
        let name2_offset = offset + 8 + name1_len;
        if name2_offset + 2 <= self.data.len() && self.data[name2_offset] == 0x00 {
            let name2_len = self.data[name2_offset + 1] as usize;
            if name2_offset + 2 + name2_len <= self.data.len() {
                let name2_bytes = &self.data[name2_offset + 2..name2_offset + 2 + name2_len];
                let name2 = String::from_utf8_lossy(name2_bytes).to_string();
                // Return the camelCase version if it's valid and different
                if Self::is_valid_identifier(&name2) && name2 != name1 {
                    return Some((name2, 5 + total_len));
                }
            }
        }

        Some((name1, 5 + total_len))
    }

    /// Extract Apple Event codes
    fn extract_apple_events(
        &self,
        symbols: &mut Vec<Symbol>,
        seen: &mut HashSet<(String, SymbolKind)>,
    ) {
        // Pattern: 0a <id:2> 00 18 2e <class:4> <event:4> ...
        // Or: 0a <id:2> 00 04 0a <fourcc:4>
        let mut i = 16;

        while i + 12 < self.data.len() {
            if self.data[i] == 0x0a && i + 3 < self.data.len() && self.data[i + 3] == 0x00 {
                let len = self.data[i + 4] as usize;

                // Full Apple Event entry (0x18 = 24 bytes, starts with '.')
                if len == 0x18 && i + 6 < self.data.len() && self.data[i + 5] == 0x2e {
                    if let Some((info, _)) = self.parse_apple_event_entry(i) {
                        let name = format!("{}.{}", info.class_code, info.event_code);
                        let key = (name.clone(), SymbolKind::AppleEvent);
                        if !seen.contains(&key) {
                            seen.insert(key);
                            symbols.push(Symbol {
                                name,
                                kind: SymbolKind::AppleEvent,
                                offset: i,
                            });
                        }
                    }
                }
                // Four char code entry (0x04 = 4 bytes)
                else if len == 0x04 && i + 10 <= self.data.len() {
                    // Skip the 0x0a marker after length
                    if self.data[i + 5] == 0x0a {
                        let fourcc = &self.data[i + 6..i + 10];
                        if fourcc.iter().all(|&b| b.is_ascii_alphanumeric()) {
                            let name = String::from_utf8_lossy(fourcc).to_string();
                            let key = (name.clone(), SymbolKind::FourCharCode);
                            if !seen.contains(&key) {
                                seen.insert(key);
                                symbols.push(Symbol {
                                    name,
                                    kind: SymbolKind::FourCharCode,
                                    offset: i,
                                });
                            }
                        }
                    }
                }
            }
            i += 1;
        }
    }

    fn parse_apple_event_entry(&self, offset: usize) -> Option<(AppleEventInfo, usize)> {
        // Format: 0a <id:2> 00 18 2e <class:4> <event:4> <type:4> ...
        if offset + 14 > self.data.len() {
            return None;
        }

        let class_code = &self.data[offset + 6..offset + 10];
        let event_code = &self.data[offset + 10..offset + 14];

        // Validate that codes are ASCII
        if !class_code.iter().all(|&b| b.is_ascii_alphanumeric())
            || !event_code.iter().all(|&b| b.is_ascii_alphanumeric())
        {
            return None;
        }

        let info = AppleEventInfo::new(class_code, event_code);
        Some((info, 24)) // Standard entry is 24 bytes
    }

    /// Extract string literals (both ASCII and UTF-16LE)
    fn extract_strings(&self, symbols: &mut Vec<Symbol>, seen: &mut HashSet<(String, SymbolKind)>) {
        // Look for interesting string patterns
        self.extract_ascii_strings(symbols, seen);
        self.extract_utf16_strings(symbols, seen);
    }

    fn extract_ascii_strings(
        &self,
        symbols: &mut Vec<Symbol>,
        seen: &mut HashSet<(String, SymbolKind)>,
    ) {
        // Find ASCII strings that look like paths, URLs, or commands
        let min_len = 6;
        let mut current_start = None;

        for (i, &byte) in self.data.iter().enumerate() {
            if byte.is_ascii_graphic() || byte == b' ' {
                if current_start.is_none() {
                    current_start = Some(i);
                }
            } else {
                if let Some(start) = current_start {
                    let len = i - start;
                    if len >= min_len {
                        let s = String::from_utf8_lossy(&self.data[start..i]).to_string();
                        if Self::is_interesting_string(&s) {
                            let key = (s.clone(), SymbolKind::StringLiteral);
                            if !seen.contains(&key) {
                                seen.insert(key);
                                symbols.push(Symbol {
                                    name: s,
                                    kind: SymbolKind::StringLiteral,
                                    offset: start,
                                });
                            }
                        }
                    }
                }
                current_start = None;
            }
        }
    }

    fn extract_utf16_strings(
        &self,
        symbols: &mut Vec<Symbol>,
        seen: &mut HashSet<(String, SymbolKind)>,
    ) {
        // Look for UTF-16LE strings (common in scpt for display text)
        let mut i = 0;
        while i + 2 < self.data.len() {
            // UTF-16LE: ASCII char followed by 0x00
            if self.data[i].is_ascii_graphic() && self.data[i + 1] == 0x00 {
                let start = i;
                let mut chars = Vec::new();

                while i + 2 <= self.data.len() {
                    let lo = self.data[i];
                    let hi = self.data[i + 1];

                    if hi == 0x00 && (lo.is_ascii_graphic() || lo == b' ' || lo == b'\t') {
                        chars.push(lo as char);
                        i += 2;
                    } else {
                        break;
                    }
                }

                if chars.len() >= 6 {
                    let s: String = chars.iter().collect();
                    if Self::is_interesting_string(&s) {
                        let key = (s.clone(), SymbolKind::StringLiteral);
                        if !seen.contains(&key) {
                            seen.insert(key);
                            symbols.push(Symbol {
                                name: s,
                                kind: SymbolKind::StringLiteral,
                                offset: start,
                            });
                        }
                    }
                }
            } else {
                i += 1;
            }
        }
    }

    /// Extract application names from tell blocks
    fn extract_applications(
        &self,
        symbols: &mut Vec<Symbol>,
        seen: &mut HashSet<(String, SymbolKind)>,
    ) {
        // Look for common application reference patterns
        let app_patterns = [
            b"System Settings".as_slice(),
            b"System Preferences".as_slice(),
            b"Finder".as_slice(),
            b"Terminal".as_slice(),
            b"Safari".as_slice(),
            b"System Events".as_slice(),
        ];

        for pattern in app_patterns {
            for i in 0..self.data.len().saturating_sub(pattern.len()) {
                if &self.data[i..i + pattern.len()] == pattern {
                    let name = String::from_utf8_lossy(pattern).to_string();
                    let key = (name.clone(), SymbolKind::Application);
                    if !seen.contains(&key) {
                        seen.insert(key);
                        symbols.push(Symbol {
                            name,
                            kind: SymbolKind::Application,
                            offset: i,
                        });
                    }
                }
            }
        }
    }

    fn is_valid_identifier(s: &str) -> bool {
        if s.is_empty() || s.len() > 100 {
            return false;
        }

        let Some(first) = s.chars().next() else {
            return false;
        };
        if !first.is_ascii_alphabetic() && first != '_' {
            return false;
        }

        s.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    }

    fn is_interesting_string(s: &str) -> bool {
        // Skip trivial strings
        if s.len() < 4 || s.len() > 500 {
            return false;
        }

        // Skip strings that are just repeated characters
        let Some(first_char) = s.chars().next() else {
            return false;
        };
        if s.chars().all(|c| c == first_char) {
            return false;
        }

        // Skip strings that are mostly whitespace/control chars
        let printable: usize = s.chars().filter(char::is_ascii_graphic).count();
        if printable < s.len() / 2 {
            return false;
        }

        // Look for interesting patterns
        let lower = s.to_lowercase();

        // Paths
        if s.starts_with('/') || s.starts_with('~') || s.contains("Applications") {
            return true;
        }

        // URLs
        if lower.starts_with("http://") || lower.starts_with("https://") {
            return true;
        }

        // Commands
        if lower.contains("shell")
            || lower.contains("script")
            || lower.contains("curl")
            || lower.contains("wget")
            || lower.contains("osascript")
            || lower.contains("open ")
        {
            return true;
        }

        // AppleScript keywords
        if lower.contains("tell application")
            || lower.contains("do shell")
            || lower.contains("delay")
            || lower.contains("activate")
        {
            return true;
        }

        // Suspicious strings
        if lower.contains("password")
            || lower.contains("credential")
            || lower.contains("keychain")
            || lower.contains("tmp")
            || lower.contains("download")
        {
            return true;
        }

        // Check for readable sentences (user-facing text)
        let words: Vec<&str> = s.split_whitespace().collect();
        if words.len() >= 3 {
            return true;
        }

        false
    }

    /// Get Apple Event information for known event codes in this script
    #[must_use]
    pub fn apple_events(&self) -> Vec<AppleEventInfo> {
        let mut events = Vec::new();
        let mut seen = HashSet::new();

        let mut i = 16;
        while i + 14 < self.data.len() {
            if self.data[i] == 0x0a
                && i + 3 < self.data.len()
                && self.data[i + 3] == 0x00
                && self.data[i + 4] == 0x18
                && self.data[i + 5] == 0x2e
            {
                if let Some((info, _)) = self.parse_apple_event_entry(i) {
                    let key = (info.class_code.clone(), info.event_code.clone());
                    if !seen.contains(&key) {
                        seen.insert(key);
                        events.push(info);
                    }
                }
            }
            i += 1;
        }

        events
    }

    /// Get variable names defined in this script
    #[must_use]
    pub fn variables(&self) -> Vec<String> {
        self.symbols()
            .into_iter()
            .filter(|s| s.kind == SymbolKind::Variable)
            .map(|s| s.name)
            .collect()
    }

    /// Check if this script contains a specific Apple Event
    #[must_use]
    pub fn has_apple_event(&self, class: &str, event: &str) -> bool {
        for ae in self.apple_events() {
            if ae.class_code == class && ae.event_code == event {
                return true;
            }
        }
        false
    }

    /// Check if this script uses "do shell script"
    #[must_use]
    pub fn uses_shell_script(&self) -> bool {
        self.has_apple_event("syso", "exec")
    }

    /// Check if this script uses delay
    #[must_use]
    pub fn uses_delay(&self) -> bool {
        self.has_apple_event("syso", "dela")
    }
}

/// Check if a byte slice starts with the scpt magic
#[must_use]
pub fn is_scpt(data: &[u8]) -> bool {
    data.len() >= 8 && data.starts_with(SCPT_MAGIC)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_scpt() {
        assert!(is_scpt(b"FasdUAS 1.101.10"));
        assert!(!is_scpt(b"not a scpt"));
        assert!(!is_scpt(b"Fasd")); // Too short
    }

    #[test]
    fn test_invalid_magic() {
        let data = b"not a scpt file";
        assert!(ScptParser::new(data).is_err());
    }

    #[test]
    fn test_too_small() {
        let data = b"FasdUAS";
        assert!(ScptParser::new(data).is_err());
    }

    #[test]
    fn test_is_valid_identifier() {
        assert!(ScptParser::is_valid_identifier("myVar"));
        assert!(ScptParser::is_valid_identifier("my_var"));
        assert!(ScptParser::is_valid_identifier("_private"));
        assert!(ScptParser::is_valid_identifier("var123"));
        assert!(!ScptParser::is_valid_identifier("123var"));
        assert!(!ScptParser::is_valid_identifier(""));
        assert!(!ScptParser::is_valid_identifier("my var"));
    }

    #[test]
    fn test_is_interesting_string() {
        assert!(ScptParser::is_interesting_string("/usr/bin/curl"));
        assert!(ScptParser::is_interesting_string("https://example.com"));
        assert!(ScptParser::is_interesting_string("do shell script"));
        assert!(ScptParser::is_interesting_string("tell application Finder"));
        assert!(!ScptParser::is_interesting_string("###"));
        assert!(!ScptParser::is_interesting_string("ab"));
    }

    #[test]
    fn test_apple_event_info() {
        let info = AppleEventInfo::new(b"syso", b"exec");
        assert_eq!(info.class, AppleEventClass::System);
        assert_eq!(info.class_code, "syso");
        assert_eq!(info.event_code, "exec");
        assert_eq!(info.desc, "do shell script");
    }
}
