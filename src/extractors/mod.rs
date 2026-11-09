//! Extractors for encoded payloads (base64, zlib, AES, etc.)
//!
//! This module extracts encoded payloads from files, decodes them,
//! and writes them to temp files for separate analysis.

pub(crate) mod encoded_payload;

pub(crate) use encoded_payload::extract_encoded_payloads;

use crate::analyzers::{FileType, detect_file_type_from_data};
use crate::types::ExtractedPayload;

/// The file type cleave analyzes a recovered script in.
pub(crate) const fn language_file_type(language: unpack::Language) -> FileType {
    match language {
        unpack::Language::JavaScript => FileType::JavaScript,
        unpack::Language::Python => FileType::Python,
        unpack::Language::Shell => FileType::Shell,
        unpack::Language::PowerShell => FileType::PowerShell,
        unpack::Language::VbScript => FileType::Vbs,
        unpack::Language::Batch => FileType::Batch,
    }
}

/// A PowerShell script with its character tables and literal arithmetic
/// rebuilt.
pub(crate) fn powershell_literal_payload(data: &[u8]) -> Option<ExtractedPayload> {
    let script = unpack::powershell_literals::recover(data)?;
    Some(ExtractedPayload {
        preview: script.chars().take(200).collect(),
        data: script.into_bytes(),
        encoding_chain: vec![
            "powershell-literal-arithmetic".into(),
            "character-table".into(),
        ],
        detected_type: FileType::PowerShell,
        original_offset: 0,
    })
}

/// Payloads a PowerShell script carries as literals: PE images, and source
/// code, by cleave's identification of the decoded bytes.
pub(crate) fn powershell_payloads(content: &[u8]) -> Vec<ExtractedPayload> {
    use std::path::Path;
    unpack::powershell_payloads::extract(content)
        .into_iter()
        .filter_map(|payload| {
            let detected_type = match payload.kind {
                unpack::powershell_payloads::Kind::Pe => {
                    (detect_file_type_from_data(Path::new("decoded.bin"), &payload.data)
                        == FileType::Pe)
                        .then_some(FileType::Pe)?
                }
                unpack::powershell_payloads::Kind::Text => {
                    let file_type = detect_file_type_from_data(Path::new("decoded"), &payload.data);
                    file_type.is_source_code().then_some(file_type)?
                }
            };
            Some(ExtractedPayload {
                encoding_chain: payload.encoding.split('/').map(str::to_string).collect(),
                preview: String::new(),
                detected_type,
                original_offset: payload.offset,
                data: payload.data,
            })
        })
        .collect()
}
