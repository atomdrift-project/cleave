use serde::{Deserialize, Serialize};

/// Represents a parsed RTF document
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct RtfDocument {
    /// Parsed RTF header (version, charset)
    pub header: RtfHeader,
    /// All control words found in the document
    pub control_words: Vec<ControlWord>,
    /// OLE objects embedded in the document
    pub embedded_objects: Vec<OleObject>,
    /// Document-level statistics
    pub metadata: DocumentMetadata,
}

/// RTF header information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct RtfHeader {
    /// RTF specification version number
    pub version: u32,
    /// Character set identifier (e.g., "ansi", "mac")
    pub charset: Option<String>,
    /// Byte offset where the header ends
    pub offset: usize,
}

/// Represents a control word in RTF (e.g., \object, \objdata)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct ControlWord {
    /// Control word name without backslash (e.g., "object", "b")
    pub name: String,
    /// Optional numeric parameter following the control word
    pub parameter: Option<i32>,
    /// Byte offset in the RTF file
    pub offset: usize,
}

/// Represents an embedded OLE object
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct OleObject {
    /// OLE class name (e.g., "Word.Document.8")
    pub class_name: String,
    /// Hex-decoded raw bytes of the object data
    pub objdata: Vec<u8>,
    /// Parsed OLE header if the data begins with a valid OLE magic
    pub ole_header: Option<OleHeader>,
    /// Byte offset of this object in the RTF file
    pub offset: usize,
    /// Suspicious patterns detected in this object
    pub suspicious_flags: Vec<SuspiciousFlag>,
}

/// OLE compound document header
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct OleHeader {
    /// OLE magic bytes (should be D0CF11E0A1B11AE1)
    pub magic: [u8; 8],
    /// Whether whitespace was found interspersed in the hex encoding
    pub is_obfuscated: bool,
}

/// Suspicious patterns found in the document
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub(crate) enum SuspiciousFlag {
    /// UNC path reference to external host (\\host@SSL\path)
    UncPath(String),
    /// Whitespace interspersed in OLE hex encoding (evasion)
    ObfuscatedOleHeader,
    /// \objupdate directive that forces object execution
    ObjUpdateDirective,
    /// RTF header does not match expected format
    MalformedHeader,
    /// Nesting depth unusually high (potential zip-bomb pattern)
    ExcessiveNesting,
    /// WebDAV path reference (davwwwroot)
    WebdavPath,
}

/// Document-level metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct DocumentMetadata {
    /// Total file size in bytes
    pub file_size: usize,
    /// Number of embedded OLE objects found
    pub object_count: usize,
    /// Maximum group nesting depth encountered
    pub max_nesting_depth: usize,
    /// Whether any \objupdate directives were found
    pub has_objupdate: bool,
    /// Character set detected in the header
    pub detected_charset: Option<String>,
}
