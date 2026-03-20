use crate::rtf::error::{Result, RtfError};
use crate::rtf::types::OleHeader;

/// OLE compound document magic bytes (8 bytes)
const OLE_MAGIC: &[u8; 8] = b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1";

/// Extract and validate an OLE header from binary data
pub(crate) fn extract_header(data: &[u8]) -> Result<OleHeader> {
    if data.len() < 8 {
        return Err(RtfError::InvalidOleHeader);
    }

    let mut magic = [0u8; 8];
    magic.copy_from_slice(&data[0..8]);

    if magic != *OLE_MAGIC {
        return Err(RtfError::InvalidOleHeader);
    }

    Ok(OleHeader {
        magic,
        is_obfuscated: false,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_header() {
        let data = b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1";
        let header = extract_header(data).unwrap();
        assert_eq!(header.magic, *OLE_MAGIC);
        assert!(!header.is_obfuscated);
    }

    #[test]
    fn test_extract_header_short() {
        let data = b"\xD0\xCF";
        assert!(extract_header(data).is_err());
    }
}
