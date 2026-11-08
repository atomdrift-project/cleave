//! Whole executables carried inside another file, as filefacts located them
//! (`binary.embedded[]`), and the bytes cleave carves from those locations
//! to analyze each one as a child.

use std::borrow::Cow;

/// One embedded PE or ELF image in its host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct EmbeddedImage {
    /// Offset in the host; for a base64 payload, where the encoded run starts.
    pub offset: usize,
    /// `pe` or `elf`.
    pub family: String,
    /// Physical size; for base64, the decoded size.
    pub size: usize,
    /// The payload is base64 text and must be decoded first.
    pub base64: bool,
    /// The installer the image is a stub of (`nsis`, `inno`), if any.
    pub format: Option<String>,
}

impl EmbeddedImage {
    /// The images filefacts reported for a file.
    pub(crate) fn from_values(values: &filefacts::Values) -> Vec<Self> {
        values
            .get("binary.embedded")
            .and_then(serde_json::Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|entry| {
                Some(Self {
                    offset: usize::try_from(entry.get("offset")?.as_u64()?).ok()?,
                    family: entry.get("kind")?.as_str()?.to_string(),
                    size: usize::try_from(entry.get("size")?.as_u64()?).ok()?,
                    base64: entry.get("encoding").and_then(serde_json::Value::as_str)
                        == Some("base64"),
                    format: entry
                        .get("format")
                        .and_then(serde_json::Value::as_str)
                        .map(str::to_string),
                })
            })
            .collect()
    }

    /// Name fragment for the child: `pe`, `pe.nsis`, `elf`.
    pub(crate) fn display_kind(&self) -> String {
        match &self.format {
            Some(format) => format!("{}.{format}", self.family),
            None => self.family.clone(),
        }
    }

    /// The image's bytes in `host`: its physical extent, or for a base64
    /// image the decoded run starting at its offset (trimmed to whole
    /// quads). `None` when the offset is past the host or the base64 does
    /// not decode.
    pub(crate) fn bytes<'d>(&self, host: &'d [u8]) -> Option<Cow<'d, [u8]>> {
        let rest = host.get(self.offset..).filter(|rest| !rest.is_empty())?;
        if self.base64 {
            let run = rest
                .iter()
                .take_while(|&&b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'='))
                .count();
            let encoded = rest.get(..run & !3).unwrap_or_default();
            base64::Engine::decode(&base64::engine::general_purpose::STANDARD, encoded)
                .ok()
                .map(Cow::Owned)
        } else {
            rest.get(..self.size.min(rest.len())).map(Cow::Borrowed)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn image(offset: usize, size: usize, base64: bool) -> EmbeddedImage {
        EmbeddedImage {
            offset,
            family: "pe".into(),
            size,
            base64,
            format: Some("nsis".into()),
        }
    }

    #[test]
    fn raw_images_are_their_extent() {
        let host = b"xxxxMZpayloadyyyy";
        let bytes = image(4, 9, false).bytes(host).unwrap_or_default();
        assert_eq!(&*bytes, b"MZpayload");
        assert!(image(100, 9, false).bytes(host).is_none());
        assert_eq!(image(4, 9, false).display_kind(), "pe.nsis");
    }

    #[test]
    fn base64_images_are_decoded() {
        let host = b"--TVqQAA==--";
        let bytes = image(2, 4, true).bytes(host).unwrap_or_default();
        assert_eq!(&*bytes, b"MZ\x90\x00");
    }
}
