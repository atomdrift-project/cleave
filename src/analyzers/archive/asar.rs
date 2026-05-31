//! Electron ASAR archive header parser.
//!
//! ASAR member contents are stored uncompressed after a Chromium-pickle JSON
//! header, so the archive analyzer can safely slice members in memory without
//! invoking an external extractor.

use anyhow::{Context, Result};
use serde_json::{Map as JsonMap, Value as JsonValue};

#[derive(Debug, Clone)]
pub(super) struct AsarEntry {
    pub(super) path: String,
    pub(super) data_offset: u64,
    pub(super) size: u64,
}

fn read_u32_le(bytes: &[u8], offset: usize) -> Result<u32> {
    let chunk = bytes
        .get(offset..offset + 4)
        .context("truncated ASAR header")?;
    Ok(u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]))
}

fn parse_offset(value: &JsonValue) -> Option<u64> {
    match value {
        JsonValue::String(s) => s.parse::<u64>().ok(),
        JsonValue::Number(n) => n.as_u64(),
        _ => None,
    }
}

fn path_join(prefix: &str, name: &str) -> String {
    if prefix.is_empty() {
        name.to_string()
    } else {
        format!("{prefix}/{name}")
    }
}

fn walk_files(
    prefix: &str,
    files: &JsonMap<String, JsonValue>,
    data_offset: u64,
    entries: &mut Vec<AsarEntry>,
) {
    for (name, node) in files {
        let path = path_join(prefix, name);
        let Some(obj) = node.as_object() else {
            continue;
        };

        if let Some(children) = obj.get("files").and_then(JsonValue::as_object) {
            walk_files(&path, children, data_offset, entries);
            continue;
        }

        let Some(size) = obj.get("size").and_then(JsonValue::as_u64) else {
            continue;
        };
        if obj
            .get("unpacked")
            .and_then(JsonValue::as_bool)
            .unwrap_or(false)
        {
            continue;
        }
        let Some(member_offset) = obj.get("offset").and_then(parse_offset) else {
            continue;
        };
        let Some(start) = data_offset.checked_add(member_offset) else {
            continue;
        };
        entries.push(AsarEntry {
            path,
            data_offset: start,
            size,
        });
    }
}

pub(super) fn collect_entries(bytes: &[u8]) -> Result<Vec<AsarEntry>> {
    if bytes.len() < 16 {
        anyhow::bail!("truncated ASAR header");
    }

    let pickle_field_size = read_u32_le(bytes, 0)?;
    let header_size = read_u32_le(bytes, 4)? as usize;
    let json_size = read_u32_le(bytes, 12)? as usize;
    if pickle_field_size != 4 {
        anyhow::bail!("unexpected ASAR pickle header");
    }

    let header_end = 16usize
        .checked_add(json_size)
        .context("ASAR header size overflow")?;
    let data_offset = 8usize
        .checked_add(header_size)
        .context("ASAR data offset overflow")?;
    if header_end > bytes.len() || data_offset > bytes.len() || data_offset < header_end {
        anyhow::bail!("ASAR header extends past end of file");
    }

    let header: JsonValue =
        serde_json::from_slice(&bytes[16..header_end]).context("invalid ASAR header JSON")?;
    let files = header
        .get("files")
        .and_then(JsonValue::as_object)
        .context("missing ASAR files table")?;

    let mut entries = Vec::with_capacity(files.len());
    walk_files("", files, data_offset as u64, &mut entries);
    Ok(entries)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)] // unwrap is fine in tests — failures are the assertion
    use super::*;

    fn fixture() -> Vec<u8> {
        let header = br#"{"files":{"main.js":{"size":18,"offset":"0"},"lib":{"files":{"inner.js":{"size":3,"offset":"18"}}},"external.node":{"size":10,"unpacked":true}}}"#;
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&4u32.to_le_bytes());
        bytes.extend_from_slice(&((header.len() + 8) as u32).to_le_bytes());
        bytes.extend_from_slice(&(header.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&(header.len() as u32).to_le_bytes());
        bytes.extend_from_slice(header);
        bytes.extend_from_slice(b"console.log('x');abc");
        bytes
    }

    #[test]
    fn collects_addressable_entries() {
        let entries = collect_entries(&fixture()).unwrap();
        assert_eq!(entries.len(), 2);
        assert!(entries.iter().any(|e| e.path == "main.js" && e.size == 18));
        assert!(entries.iter().all(|e| e.path != "external.node"));
    }
}
