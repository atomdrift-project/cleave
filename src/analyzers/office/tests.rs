use super::*;

/// An Outlook attachment is analyzed as a nested member named after its
/// filename, typed from its bytes plus that name, and an attached
/// message recurses one level down.
#[test]
fn msg_attachments_attach_as_named_members() {
    use ole2::tests::{build_cfb, utf16};
    let a0 = "/__attach_version1.0_#00000000";
    let a1 = "/__attach_version1.0_#00000001";
    let inner = format!("{a1}/__substg1.0_3701000D");
    let msg = build_cfb(&[
        ("/__substg1.0_0037001F", &utf16("subject")),
        (
            &format!("{a0}/__substg1.0_37010102"),
            b"<html><body><script>document.write('x')</script></body></html>",
        ),
        (&format!("{a0}/__substg1.0_3707001F"), &utf16("lure.html")),
        (&format!("{a1}/__substg1.0_3001001F"), &utf16("Fwd")),
        (&format!("{inner}/__substg1.0_0037001F"), &utf16("inner")),
        (
            &format!("{inner}/__attach_version1.0_#00000000/__substg1.0_37010102"),
            b"#!/bin/sh\necho hi\n",
        ),
        (
            &format!("{inner}/__attach_version1.0_#00000000/__substg1.0_3707001F"),
            &utf16("run.sh"),
        ),
    ]);

    let report = OfficeAnalyzer::new().analyze_office(
        Path::new("/samples/mail.msg"),
        &msg,
        &FileType::OleDoc,
        0,
        None,
    );
    assert_eq!(report.target.file_type, "msg");
    let files: Vec<(&str, &str, u32)> = report
        .files
        .iter()
        .map(|f| (f.path.as_str(), f.file_type.as_str(), f.depth))
        .collect();
    assert!(
        files.contains(&("mail.msg!!lure.html", "html", 1)),
        "html attachment missing: {files:?}"
    );
    assert!(
        files.contains(&("mail.msg!!Fwd.msg", "msg", 1)),
        "attached message missing: {files:?}"
    );
    assert!(
        files.contains(&("mail.msg!!Fwd.msg!!run.sh", "shell", 2)),
        "attached message's attachment missing: {files:?}"
    );
}

/// An executable an OLE1 Packager object wraps is carved at the offset
/// filefacts reports and analyzed as a member of the document.
#[test]
fn packaged_executables_are_analyzed_as_members() {
    use ole2::tests::build_cfb;
    let mut pe = vec![0u8; 2048];
    pe[..2].copy_from_slice(b"MZ");
    pe[0x3C] = 0x80;
    pe[0x80..0x84].copy_from_slice(b"PE\0\0");
    let mut body = 2_u16.to_le_bytes().to_vec();
    for s in ["payload.exe", "C:\\Users\\Public\\payload.exe"] {
        body.extend_from_slice(s.as_bytes());
        body.push(0);
    }
    body.extend_from_slice(&[0, 0, 3, 0]);
    let temp = b"C:\\Temp\\payload.exe\0";
    body.extend_from_slice(&(temp.len() as u32).to_le_bytes());
    body.extend_from_slice(temp);
    body.extend_from_slice(&(pe.len() as u32).to_le_bytes());
    body.extend_from_slice(&pe);
    let mut native = (body.len() as u32).to_le_bytes().to_vec();
    native.extend_from_slice(&body);
    let doc = build_cfb(&[
        ("/WordDocument", &[0xEC, 0xA5, 0xC1, 0x00]),
        ("/ObjectPool/_1000/\u{1}Ole10Native", &native),
    ]);

    let report = OfficeAnalyzer::new().analyze_office(
        Path::new("/samples/invoice.doc"),
        &doc,
        &FileType::OleDoc,
        0,
        None,
    );
    assert_eq!(report.target.file_type, "doc");
    let files: Vec<(&str, &str)> = report
        .files
        .iter()
        .map(|f| (f.path.as_str(), f.file_type.as_str()))
        .collect();
    assert!(
        files.contains(&("invoice.doc!!ole/ObjectPool__1000_payload.exe", "pe")),
        "packaged payload missing: {files:?}"
    );
}
