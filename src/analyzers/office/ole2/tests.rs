use super::*;

/// Helper: build a CompObj stream payload with the given strings.
/// `clipboard_marker` controls whether the clipboard slot is a
/// registered ID, absent, or a length-prefixed string.
#[derive(Clone, Copy)]
enum ClipboardSlot {
    RegisteredId(u32),
    AnsiString(&'static str),
}

fn build_compobj(user_type: &str, clipboard: ClipboardSlot, app_version: Option<&str>) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(&[0u8; 28]); // header (Reserved1 + Version + Reserved2)

    // AnsiUserType
    let ut_len = (user_type.len() + 1) as u32;
    buf.extend_from_slice(&ut_len.to_le_bytes());
    buf.extend_from_slice(user_type.as_bytes());
    buf.push(0);

    // AnsiClipboardFormat
    match clipboard {
        ClipboardSlot::RegisteredId(id) => {
            buf.extend_from_slice(&id.to_le_bytes());
        }
        ClipboardSlot::AnsiString(s) => {
            let len = (s.len() + 1) as u32;
            buf.extend_from_slice(&len.to_le_bytes());
            buf.extend_from_slice(s.as_bytes());
            buf.push(0);
        }
    }

    // Reserved3 (ProgID)
    if let Some(av) = app_version {
        let len = (av.len() + 1) as u32;
        buf.extend_from_slice(&len.to_le_bytes());
        buf.extend_from_slice(av.as_bytes());
        buf.push(0);
    }

    buf
}

/// Excel CompObj layout — string clipboard slot + ProgID.
#[test]
fn parse_compobj_excel_typical() {
    let payload = build_compobj(
        "Microsoft Office Excel Worksheet",
        ClipboardSlot::AnsiString("Biff8"),
        Some("Excel.Sheet.8"),
    );
    let parsed = parse_compobj(&payload).expect("parses");
    assert_eq!(parsed.user_type, "Microsoft Office Excel Worksheet");
    assert_eq!(parsed.clipboard_format, "Biff8");
    assert_eq!(parsed.app_version, "Excel.Sheet.8");
}

/// Word with a registered clipboard ID — clipboard_format stays empty
/// (no string variant), but user_type and ProgID still parse.
#[test]
fn parse_compobj_registered_clipboard_id() {
    let payload = build_compobj(
        "Microsoft Word Document",
        ClipboardSlot::RegisteredId(0x31),
        Some("Word.Document.8"),
    );
    let parsed = parse_compobj(&payload).expect("parses");
    assert_eq!(parsed.user_type, "Microsoft Word Document");
    assert_eq!(parsed.clipboard_format, "");
    assert_eq!(parsed.app_version, "Word.Document.8");
}

/// Adversarial CompObj that lies about user_type length — parser
/// must refuse the user_type read (returns Some with empty fields)
/// rather than panic on the slice.
#[test]
fn parse_compobj_oversized_user_type_does_not_panic() {
    let mut payload = vec![0u8; 28];
    payload.extend_from_slice(&100u32.to_le_bytes());
    payload.extend_from_slice(b"\x00\x00\x00\x00");
    let parsed = parse_compobj(&payload).expect("returns parsed default");
    assert_eq!(parsed.user_type, "");
}

/// Empty user_type slot still parses (length 0 means absent).
#[test]
fn parse_compobj_empty_user_type() {
    let mut payload = vec![0u8; 28];
    payload.extend_from_slice(&0u32.to_le_bytes()); // user_type len = 0
    payload.extend_from_slice(&0u32.to_le_bytes()); // clipboard marker = 0
    let parsed = parse_compobj(&payload).expect("parses");
    assert_eq!(parsed.user_type, "");
    assert_eq!(parsed.clipboard_format, "");
    assert_eq!(parsed.app_version, "");
}

/// Build a minimal MS-OLEPS property-set stream containing one
/// section with the given (property_id, payload) entries. Every
/// payload byte slice must be a fully formed VT_* value (type
/// dword + value bytes). Returns the assembled stream.
fn build_property_set_stream(entries: &[(u32, &[u8])]) -> Vec<u8> {
    // Outer header (28 bytes): BOM + version + osversion + clsid + num_sections=1
    let mut out = Vec::new();
    out.extend_from_slice(&0xFFFEu16.to_le_bytes()); // BOM
    out.extend_from_slice(&0u16.to_le_bytes()); // version
    out.extend_from_slice(&0u32.to_le_bytes()); // osversion
    out.extend_from_slice(&[0u8; 16]); // clsid
    out.extend_from_slice(&1u32.to_le_bytes()); // num_sections

    // SectionHeader: fmtid (16 bytes) + offset (4 bytes)
    out.extend_from_slice(&[0u8; 16]); // fmtid
    let section_offset_pos = out.len();
    out.extend_from_slice(&0u32.to_le_bytes()); // placeholder offset

    // Pad to ensure section_offset >= 48 (matches the parser's bound).
    while out.len() < 48 {
        out.push(0);
    }
    let section_start = out.len();
    // Patch section_offset.
    let off = (section_start as u32).to_le_bytes();
    out[section_offset_pos..section_offset_pos + 4].copy_from_slice(&off);

    // Section: size (4) + num_props (4), then num_props (id + offset)
    // entries, then payloads.
    let num_props = entries.len() as u32;
    // Section size patched after we know the final size.
    let section_size_pos = out.len();
    out.extend_from_slice(&0u32.to_le_bytes()); // placeholder
    out.extend_from_slice(&num_props.to_le_bytes());

    // Compute payload offsets relative to the section start.
    let table_size = entries.len() * 8; // 4 id + 4 offset per entry
    let mut payload_offset = 8 + table_size; // section header (8) + table

    // Emit id+offset entries first.
    let mut payload_offsets = Vec::with_capacity(entries.len());
    for (id, payload) in entries {
        out.extend_from_slice(&id.to_le_bytes());
        out.extend_from_slice(&(payload_offset as u32).to_le_bytes());
        payload_offsets.push(payload_offset);
        payload_offset += payload.len();
    }
    // Emit payloads in order.
    for (_, payload) in entries {
        out.extend_from_slice(payload);
    }
    // Patch section_size.
    let section_size = (out.len() - section_start) as u32;
    out[section_size_pos..section_size_pos + 4].copy_from_slice(&section_size.to_le_bytes());
    let _ = payload_offsets; // for debugging
    out
}

fn vt_i4(v: i32) -> [u8; 8] {
    let mut b = [0u8; 8];
    b[..4].copy_from_slice(&0x0003u32.to_le_bytes());
    b[4..].copy_from_slice(&v.to_le_bytes());
    b
}

fn vt_filetime(units_100ns: u64) -> [u8; 12] {
    let mut b = [0u8; 12];
    b[..4].copy_from_slice(&0x0040u32.to_le_bytes());
    b[4..].copy_from_slice(&units_100ns.to_le_bytes());
    b
}

fn vt_lpstr(s: &str) -> Vec<u8> {
    let mut b = Vec::with_capacity(8 + s.len() + 1);
    b.extend_from_slice(&0x001Eu32.to_le_bytes());
    let len = (s.len() + 1) as u32;
    b.extend_from_slice(&len.to_le_bytes());
    b.extend_from_slice(s.as_bytes());
    b.push(0);
    b
}

#[test]
fn parse_summary_info_captures_numeric_properties() {
    let page = vt_i4(7);
    let word = vt_i4(123);
    let char_ = vt_i4(800);
    let rev = vt_lpstr("12");
    // 30 minutes = 30 * 60 * 10_000_000 = 18_000_000_000
    let edit = vt_filetime(18_000_000_000);
    let stream = build_property_set_stream(&[
        (0x0E, &page),
        (0x0F, &word),
        (0x10, &char_),
        (0x09, &rev),
        (0x0A, &edit),
    ]);
    let mut meta = DocumentMetadata::default();
    parse_summary_info(&stream, &mut meta);
    assert_eq!(meta.page_count, Some(7));
    assert_eq!(meta.word_count, Some(123));
    assert_eq!(meta.char_count, Some(800));
    assert_eq!(meta.revision_number, Some(12));
    assert_eq!(meta.total_edit_time_minutes, Some(30));
}

#[test]
fn parse_doc_summary_info_captures_security_flag() {
    // Security flag = 2 (recommend read-only).
    let security = vt_i4(2);
    let stream = build_property_set_stream(&[(0x13, &security)]);
    let mut meta = DocumentMetadata::default();
    parse_doc_summary_info(&stream, &mut meta);
    assert_eq!(meta.security_flag, Some(2));
}

#[test]
fn read_property_u32_rejects_wrong_vt_type() {
    // Build VT_LPSTR where VT_I4 is expected.
    let mut buf = vec![0u8; 0];
    buf.extend_from_slice(&0x001Eu32.to_le_bytes()); // wrong type
    buf.extend_from_slice(&0u32.to_le_bytes());
    assert_eq!(read_property_u32(&buf, 0), None);
}

#[test]
fn read_filetime_minutes_zero_for_zero_units() {
    let mut buf = vec![0u8; 0];
    buf.extend_from_slice(&0x0040u32.to_le_bytes());
    buf.extend_from_slice(&0u64.to_le_bytes());
    assert_eq!(read_filetime_minutes(&buf, 0), Some(0));
}

#[test]
fn parse_leading_u32_handles_mixed_input() {
    assert_eq!(parse_leading_u32("12"), Some(12));
    assert_eq!(parse_leading_u32("12.0"), Some(12));
    assert_eq!(parse_leading_u32("abc"), None);
    assert_eq!(parse_leading_u32(""), None);
}

/// LengthPrefixedAnsiString with NUL preserved correctly: trailing
/// NUL stripped, embedded NULs kept.
#[test]
fn read_length_prefixed_ansi_strips_trailing_nul_only() {
    // "ABC\0" = 4 bytes
    let raw = b"\x04\x00\x00\x00ABC\0";
    let (s, advance) = read_length_prefixed_ansi(raw).expect("reads");
    assert_eq!(s, "ABC");
    assert_eq!(advance, 8);
}

#[test]
fn test_detect_subtype() {
    let word_streams = vec!["/WordDocument".to_string(), "/1Table".to_string()];
    assert_eq!(detect_subtype(&word_streams), Ole2Subtype::Word);

    let excel_streams = vec!["/Workbook".to_string()];
    assert_eq!(detect_subtype(&excel_streams), Ole2Subtype::Excel);

    let ppt_streams = vec!["/PowerPoint Document".to_string()];
    assert_eq!(detect_subtype(&ppt_streams), Ole2Subtype::PowerPoint);

    let unknown_streams = vec!["/SomeStream".to_string()];
    assert_eq!(detect_subtype(&unknown_streams), Ole2Subtype::Unknown);

    let msi_streams = vec!["/Binary.123".to_string(), "/_Tables".to_string()];
    assert_eq!(detect_subtype(&msi_streams), Ole2Subtype::Msi);
}

/// Build an in-memory compound file from `(path, body)` streams,
/// creating parent storages on demand.
pub(crate) fn build_cfb(streams: &[(&str, &[u8])]) -> Vec<u8> {
    use std::io::Write;
    let mut comp = cfb::CompoundFile::create(Cursor::new(Vec::new())).unwrap();
    for (path, body) in streams {
        let parts: Vec<&str> = path.trim_start_matches('/').split('/').collect();
        let mut accum = String::new();
        for part in &parts[..parts.len() - 1] {
            accum.push('/');
            accum.push_str(part);
            if !comp.exists(&accum) {
                comp.create_storage(&accum).unwrap();
            }
        }
        comp.create_stream(path).unwrap().write_all(body).unwrap();
    }
    comp.flush().unwrap();
    comp.into_inner().into_inner()
}

pub(crate) fn utf16(s: &str) -> Vec<u8> {
    s.encode_utf16()
        .chain(std::iter::once(0))
        .flat_map(u16::to_le_bytes)
        .collect()
}

const A0: &str = "/__attach_version1.0_#00000000";
const A1: &str = "/__attach_version1.0_#00000001";

#[test]
fn msg_attachments_are_extracted_with_filename() {
    let svg = b"<svg xmlns='http://www.w3.org/2000/svg'><script>x()</script></svg>";
    let cfb = build_cfb(&[
        ("/__substg1.0_0037001F", &utf16("subject")),
        (&format!("{A0}/__substg1.0_37010102"), svg),
        (&format!("{A0}/__substg1.0_3707001F"), &utf16("lure.xhtml")),
        (&format!("{A0}/__substg1.0_3704001F"), &utf16("LURE~1.XHT")),
        (&format!("{A0}/__substg1.0_370E001F"), &utf16("text/html")),
        (&format!("{A1}/__substg1.0_37010102"), b"\x89PNG\r\n\x1a\n"),
        // No long filename: falls back to the 8.3 name.
        (
            &format!("{A1}/__substg1.0_3704001F"),
            &utf16("image001.png"),
        ),
    ]);
    let doc = parse_ole2(&cfb).expect("parses");
    assert_eq!(doc.doc_subtype, Ole2Subtype::Msg);
    assert_eq!(doc.msg_attachments.len(), 2);

    let lure = &doc.msg_attachments[0];
    assert_eq!(lure.filename, "lure.xhtml");
    assert_eq!(lure.kind, MsgAttachmentKind::File);
    assert_eq!(lure.data, svg);
    assert_eq!(lure.storage_path, A0);

    assert_eq!(doc.msg_attachments[1].filename, "image001.png");
}

#[test]
fn non_msg_documents_have_no_attachments() {
    // An attachment-shaped storage in a Word document is not an
    // Outlook attachment.
    let cfb = build_cfb(&[
        ("/WordDocument", b"body"),
        (&format!("{A0}/__substg1.0_37010102"), b"payload"),
    ]);
    let doc = parse_ole2(&cfb).expect("parses");
    assert_eq!(doc.doc_subtype, Ole2Subtype::Word);
    assert!(doc.msg_attachments.is_empty());
}

#[test]
fn executable_attachment_is_left_to_the_pe_path() {
    let mut pe = vec![0u8; 2048];
    pe[..2].copy_from_slice(b"MZ");
    let cfb = build_cfb(&[
        ("/__substg1.0_0037001F", &utf16("subject")),
        (&format!("{A0}/__substg1.0_37010102"), &pe),
        (&format!("{A0}/__substg1.0_3707001F"), &utf16("invoice.exe")),
        (&format!("{A1}/__substg1.0_37010102"), b"<html></html>"),
        (&format!("{A1}/__substg1.0_3707001F"), &utf16("a.html")),
    ]);
    let doc = parse_ole2(&cfb).expect("parses");
    assert_eq!(doc.embedded_executables.len(), 1);
    let names: Vec<&str> = doc
        .msg_attachments
        .iter()
        .map(|a| a.filename.as_str())
        .collect();
    assert_eq!(names, ["a.html"]);
}

#[test]
fn embedded_message_is_rebuilt_as_standalone_msg() {
    let inner = format!("{A0}/__substg1.0_3701000D");
    let cfb = build_cfb(&[
        ("/__substg1.0_0037001F", &utf16("outer")),
        (
            &format!("{A0}/__substg1.0_3001001F"),
            &utf16("Fwd: invoice"),
        ),
        (&format!("{inner}/__substg1.0_0037001F"), &utf16("inner")),
        (
            &format!("{inner}/__attach_version1.0_#00000000/__substg1.0_37010102"),
            b"<html>inner payload</html>",
        ),
        (
            &format!("{inner}/__attach_version1.0_#00000000/__substg1.0_3707001F"),
            &utf16("inner.html"),
        ),
    ]);
    let doc = parse_ole2(&cfb).expect("parses");
    // Only the top-level attachment; the inner one is reached by
    // recursing into the rebuilt message.
    assert_eq!(doc.msg_attachments.len(), 1);
    let att = &doc.msg_attachments[0];
    assert_eq!(att.kind, MsgAttachmentKind::Storage);
    assert_eq!(att.filename, "Fwd: invoice.msg");

    let rebuilt = parse_ole2(&att.data).expect("rebuilt message parses");
    assert_eq!(rebuilt.doc_subtype, Ole2Subtype::Msg);
    assert_eq!(rebuilt.msg_attachments.len(), 1);
    assert_eq!(rebuilt.msg_attachments[0].filename, "inner.html");
    assert_eq!(
        rebuilt.msg_attachments[0].data,
        b"<html>inner payload</html>"
    );
}

#[test]
fn duplicate_attachment_names_get_distinct_members() {
    let cfb = build_cfb(&[
        ("/__substg1.0_0037001F", &utf16("subject")),
        (&format!("{A0}/__substg1.0_37010102"), b"one"),
        (&format!("{A0}/__substg1.0_3707001F"), &utf16("doc.txt")),
        (&format!("{A1}/__substg1.0_37010102"), b"two"),
        (&format!("{A1}/__substg1.0_3707001F"), &utf16("doc.txt")),
    ]);
    let doc = parse_ole2(&cfb).expect("parses");
    let names: Vec<&str> = doc
        .msg_attachments
        .iter()
        .map(|a| a.filename.as_str())
        .collect();
    assert_eq!(names, ["doc.txt", "attachment-1-doc.txt"]);
}

#[test]
fn attachment_filenames_are_sanitized() {
    assert_eq!(sanitize_attachment_filename(Some("a.pdf"), 0), "a.pdf");
    assert_eq!(
        sanitize_attachment_filename(Some("../../etc/passwd"), 0),
        "passwd"
    );
    assert_eq!(
        sanitize_attachment_filename(Some("C:\\Users\\x\\run.lnk"), 0),
        "run.lnk"
    );
    assert_eq!(sanitize_attachment_filename(Some(".."), 3), "attachment-3");
    assert_eq!(
        sanitize_attachment_filename(Some("dir/"), 4),
        "attachment-4"
    );
    assert_eq!(sanitize_attachment_filename(None, 5), "attachment-5");
    assert_eq!(
        sanitize_attachment_filename(Some("a!!b!!!c.js"), 0),
        "a!_b!_!c.js"
    );
    assert_eq!(
        // Control characters go; format characters such as RLO stay,
        // as they do in archive member paths, so rules can see them.
        sanitize_attachment_filename(Some("inv\u{202e}fdp.exe\n"), 0),
        "inv\u{202e}fdp.exe"
    );
    let long = "x".repeat(1000);
    assert_eq!(
        sanitize_attachment_filename(Some(&long), 0).chars().count(),
        MAX_ATTACHMENT_NAME_CHARS
    );
}

#[test]
fn test_ole2_subtype_str() {
    assert_eq!(Ole2Subtype::Word.as_str(), "doc");
    assert_eq!(Ole2Subtype::Excel.as_str(), "xls");
    assert_eq!(Ole2Subtype::PowerPoint.as_str(), "ppt");
    assert_eq!(Ole2Subtype::Msg.as_str(), "msg");
    assert_eq!(Ole2Subtype::Msi.as_str(), "msi");
    assert_eq!(Ole2Subtype::Unknown.as_str(), "ole");
}
