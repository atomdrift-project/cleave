use thiserror::Error;

/// Errors that can occur during RTF parsing
#[derive(Debug, Error)]
pub(crate) enum RtfError {
    /// The file does not begin with the required `{\rtf` prefix
    #[error("Invalid RTF header: expected '{{\\rtf' prefix")]
    InvalidHeader,

    /// Group nesting exceeded the configured maximum depth
    #[error("Excessive nesting depth: {depth} (max: {max})")]
    ExcessiveNesting {
        /// Actual nesting depth encountered
        depth: usize,
        /// Maximum allowed depth
        max: usize,
    },

    /// Number of embedded objects exceeded the configured maximum
    #[error("Too many embedded objects: {count} (max: {max})")]
    TooManyObjects {
        /// Actual object count
        count: usize,
        /// Maximum allowed count
        max: usize,
    },

    /// Input file exceeds the configured size limit
    #[error("File too large: {size} bytes (max: {max} bytes)")]
    FileTooLarge {
        /// Actual file size
        size: usize,
        /// Maximum allowed size
        max: usize,
    },

    /// A hex-encoded objdata sequence contained invalid characters
    #[error("Hex decoding failed at position {position}: {reason}")]
    HexDecodeError {
        /// Byte position where decoding failed
        position: usize,
        /// Human-readable failure reason
        reason: String,
    },

    /// The OLE magic bytes were not present or invalid
    #[error("Invalid OLE header")]
    InvalidOleHeader,

    /// An underlying I/O error occurred
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// The decoded bytes were not valid UTF-8
    #[error("Invalid UTF-8: {0}")]
    Utf8Error(#[from] std::string::FromUtf8Error),

    /// The file was empty (zero bytes)
    #[error("Empty file")]
    EmptyFile,
}

/// Convenience alias for `Result<T, RtfError>`
pub(crate) type Result<T> = std::result::Result<T, RtfError>;
