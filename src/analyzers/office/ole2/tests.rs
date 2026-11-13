use super::*;
use std::io::Cursor;

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
    let doc = extract_payloads(&cfb, true, &[]).expect("parses");
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
    let doc = extract_payloads(&cfb, false, &[]).expect("parses");
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
    let doc = extract_payloads(&cfb, true, &[]).expect("parses");
    assert_eq!(doc.executables.len(), 1);
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
    let doc = extract_payloads(&cfb, true, &[]).expect("parses");
    // Only the top-level attachment; the inner one is reached by
    // recursing into the rebuilt message.
    assert_eq!(doc.msg_attachments.len(), 1);
    let att = &doc.msg_attachments[0];
    assert_eq!(att.kind, MsgAttachmentKind::Storage);
    assert_eq!(att.filename, "Fwd: invoice.msg");

    assert!(data_is_msg(&att.data));
    let rebuilt = extract_payloads(&att.data, true, &[]).expect("rebuilt message parses");
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
    let doc = extract_payloads(&cfb, true, &[]).expect("parses");
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

/// A Packager stream: a header, then `payload` at `offset`.
fn packaged(payload: &[u8]) -> (Vec<u8>, u64) {
    let mut stream = vec![0x11; 77];
    let offset = stream.len() as u64;
    stream.extend_from_slice(payload);
    stream.extend_from_slice(b"trailer");
    (stream, offset)
}

fn located(offset: u64, size: u64) -> LocatedPayload {
    LocatedPayload {
        stream: "/ObjectPool/_1/\u{1}Ole10Native".into(),
        filename: "..\\payload.exe".into(),
        offset,
        size,
        kind: EmbeddedExecKind::Pe,
    }
}

#[test]
fn located_payloads_are_carved_beside_their_stream() {
    let mut pe = vec![0u8; 2048];
    pe[..2].copy_from_slice(b"MZ");
    let (stream, offset) = packaged(&pe);
    let cfb = build_cfb(&[
        ("/WordDocument", b"body"),
        ("/ObjectPool/_1/\u{1}Ole10Native", &stream),
    ]);
    let doc = extract_payloads(&cfb, false, &[located(offset, 2048)]).expect("parses");
    assert_eq!(doc.executables.len(), 1);
    let exec = &doc.executables[0];
    assert_eq!(exec.data, pe);
    assert_eq!(exec.kind, EmbeddedExecKind::Pe);
    // Named for the packaged file, its path stripped, beside the stream.
    assert_eq!(exec.stream_path, "/ObjectPool/_1/payload.exe");
}

#[test]
fn a_located_payload_past_its_stream_or_too_small_is_not_carved() {
    let mut pe = vec![0u8; 2048];
    pe[..2].copy_from_slice(b"MZ");
    let (stream, offset) = packaged(&pe);
    let cfb = build_cfb(&[("/ObjectPool/_1/\u{1}Ole10Native", &stream)]);
    for payload in [
        located(offset, 1 << 20),
        located(u64::MAX - 8, 2048),
        located(offset, 16),
    ] {
        let doc = extract_payloads(&cfb, false, &[payload]).expect("parses");
        assert!(doc.executables.is_empty());
    }
}

#[test]
fn an_installer_cabinet_over_50_mib_is_extracted() {
    // MSI installers ship every file in one cabinet stream; 3CXDesktopApp's is
    // ~95 MB. The old 50 MiB cap skipped it, hiding the trojaned DLLs inside.
    let mut cab = vec![0u8; 51 * 1024 * 1024];
    cab[..4].copy_from_slice(b"MSCF");
    let cfb = build_cfb(&[("/Cabinet", &cab)]);
    let doc = extract_payloads(&cfb, false, &[]).expect("parses");
    assert_eq!(doc.executables.len(), 1);
    assert_eq!(doc.executables[0].kind, EmbeddedExecKind::Cab);
    assert_eq!(doc.executables[0].data.len(), cab.len());
}
