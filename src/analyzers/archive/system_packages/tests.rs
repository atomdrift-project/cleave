use super::*;

#[test]
fn seven_zip_technical_listing_keeps_names_intact() {
    let out = "Listing archive: t.7z\n\n--\nPath = t.7z\nType = 7z\n\n----------\n\
            Path = d\nSize = 0\nPacked Size = 0\nAttributes = D drwxr-xr-x\n\n\
            Path = x  y.txt\nSize = 1\nPacked Size = 5\nAttributes = A -rw-r--r--\n";
    let entries = parse_7z_technical_listing(out);
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].entry_type.as_deref(), Some("directory"));
    assert_eq!(entries[1].path, "x  y.txt");
    assert_eq!(entries[1].size_bytes, 1);
    assert_eq!(entries[1].compressed_size, Some(5));
}

fn cpio_fixture(entries: &[(&str, u32, &[u8])]) -> Vec<u8> {
    let mut bytes = Vec::new();
    for (name, mode, body) in entries {
        let mut writer = cpio::newc::Builder::new(name)
            .mode(*mode)
            .write(&mut bytes, body.len() as u32);
        writer.write_all(body).unwrap();
        writer.finish().unwrap();
    }
    cpio::newc::trailer(&mut bytes).unwrap();
    bytes
}

#[test]
fn cpio_entry_padding_preserves_following_files() {
    let bytes = cpio_fixture(&[
        ("one.txt", 0o100644, b"1"),
        ("two.txt", 0o100644, b"22"),
        ("three.txt", 0o100644, b"333"),
        ("four.txt", 0o100644, b"4444"),
    ]);
    let dir = tempfile::tempdir().unwrap();
    extract_cpio(bytes.as_slice(), dir.path(), &ExtractionGuard::new()).unwrap();
    for (name, content) in [
        ("one.txt", "1"),
        ("two.txt", "22"),
        ("three.txt", "333"),
        ("four.txt", "4444"),
    ] {
        assert_eq!(fs::read_to_string(dir.path().join(name)).unwrap(), content);
    }
}

#[test]
fn cpio_malformed_header_is_not_successful_end_of_archive() {
    let dir = tempfile::tempdir().unwrap();
    let invalid = [b'x'; 110];
    assert!(extract_cpio(invalid.as_slice(), dir.path(), &ExtractionGuard::new()).is_err());
    let mut after_file = cpio_fixture(&[("ok.txt", 0o100644, b"okay")]);
    let trailer = after_file
        .windows(6)
        .rposition(|magic| magic == b"070701")
        .unwrap();
    after_file[trailer] = b'x';
    assert!(extract_cpio(after_file.as_slice(), dir.path(), &ExtractionGuard::new()).is_err());
}

#[test]
fn cpio_empty_archive_with_trailer_succeeds() {
    let dir = tempfile::tempdir().unwrap();
    extract_cpio(
        cpio_fixture(&[]).as_slice(),
        dir.path(),
        &ExtractionGuard::new(),
    )
    .unwrap();
    assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 0);
}

#[test]
fn cpio_skipped_names_and_links_do_not_hide_following_files() {
    let bytes = cpio_fixture(&[
        (".", 0o040755, b""),
        ("../escape", 0o100644, b"one"),
        ("./../escape", 0o100644, b"two"),
        ("/absolute", 0o100644, b"three"),
        ("link", 0o120777, b"../outside"),
        ("safe.txt", 0o100644, b"safe"),
    ]);
    let dir = tempfile::tempdir().unwrap();
    let guard = ExtractionGuard::new();
    extract_cpio(bytes.as_slice(), dir.path(), &guard).unwrap();
    assert_eq!(
        fs::read_to_string(dir.path().join("safe.txt")).unwrap(),
        "safe"
    );
    assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
    let reasons = guard.take_reasons();
    assert_eq!(
        reasons
            .iter()
            .filter(|r| matches!(r, HostileArchiveReason::PathTraversal(_)))
            .count(),
        3
    );
    assert!(
        reasons
            .iter()
            .any(|r| matches!(r, HostileArchiveReason::SymlinkEscape(_)))
    );
}

#[test]
fn cpio_truncation_never_reports_complete_extraction() {
    let bytes = cpio_fixture(&[("ok.txt", 0o100644, b"abc")]);
    let dir = tempfile::tempdir().unwrap();
    for len in 0..bytes.len() {
        assert!(
            extract_cpio(&bytes[..len], dir.path(), &ExtractionGuard::new()).is_err(),
            "accepted prefix of {len} bytes"
        );
    }
}

#[test]
fn cpio_duplicate_names_preserve_both_bodies() {
    let bytes = cpio_fixture(&[
        ("same.txt", 0o100644, b"one"),
        ("same.txt", 0o100644, b"two"),
    ]);
    let dir = tempfile::tempdir().unwrap();
    extract_cpio(bytes.as_slice(), dir.path(), &ExtractionGuard::new()).unwrap();
    let mut bodies: Vec<_> = fs::read_dir(dir.path())
        .unwrap()
        .map(|entry| fs::read_to_string(entry.unwrap().path()).unwrap())
        .collect();
    bodies.sort();
    assert_eq!(bodies, ["one", "two"]);
}

#[test]
fn cpio_name_allocation_is_bounded_before_dependency_parser() {
    let mut header = cpio_fixture(&[]);
    header[94..102].copy_from_slice(b"ffffffff");
    let dir = tempfile::tempdir().unwrap();
    let error = extract_cpio(header.as_slice(), dir.path(), &ExtractionGuard::new()).unwrap_err();
    assert!(error.to_string().contains("name size exceeds limit"));
}

#[test]
fn cpio_metadata_cannot_bypass_total_byte_budget() {
    let dir = tempfile::tempdir().unwrap();
    let guard = ExtractionGuard::new();
    assert!(guard.check_bytes(MAX_TOTAL_SIZE - 100, "previous entries"));
    let error = extract_cpio(cpio_fixture(&[]).as_slice(), dir.path(), &guard).unwrap_err();
    assert!(error.to_string().contains("maximum total extraction size"));
}

#[test]
fn cpio_known_unsupported_formats_are_not_called_corrupt() {
    let dir = tempfile::tempdir().unwrap();
    for magic in [b"07070X", b"070707"] {
        let error =
            extract_cpio(magic.as_slice(), dir.path(), &ExtractionGuard::new()).unwrap_err();
        assert!(error.to_string().starts_with("Unsupported"));
    }
}

#[test]
fn cpio_trailer_cannot_silently_discard_claimed_data() {
    let mut bytes = cpio_fixture(&[]);
    bytes[54..62].copy_from_slice(b"00000004");
    bytes.extend_from_slice(b"data");
    let dir = tempfile::tempdir().unwrap();
    assert!(
        extract_cpio(bytes.as_slice(), dir.path(), &ExtractionGuard::new())
            .unwrap_err()
            .to_string()
            .contains("trailer has file data")
    );
}

#[test]
fn cpio_cancellation_interrupts_discarded_member_data() {
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };
    struct CancelReader {
        inner: Cursor<Vec<u8>>,
        flag: Arc<AtomicBool>,
    }
    impl Read for CancelReader {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            let n = self.inner.read(buf)?;
            if self.inner.position() > 128 * 1024 {
                self.flag.store(true, Ordering::Release);
            }
            Ok(n)
        }
    }
    let flag = Arc::new(AtomicBool::new(false));
    // A large ignored link must not bypass cancellation or byte accounting.
    let body = vec![b'x'; 256 * 1024];
    let bytes = cpio_fixture(&[("link", 0o120777, &body)]);
    let reader = CancelReader {
        inner: Cursor::new(bytes),
        flag: Arc::clone(&flag),
    };
    let guard = ExtractionGuard::with_cancellation(Some(flag));
    let dir = tempfile::tempdir().unwrap();
    assert!(
        extract_cpio(reader, dir.path(), &guard)
            .unwrap_err()
            .to_string()
            .contains("cancelled")
    );
    assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 0);
}

/// A UDIF image: [data fork][plist xml][koly], whose only `blkx` partition
/// carries `mish` and whose trailer declares `sectors` sectors.
fn dmg_with_blkx(mish: Vec<u8>, sectors: u64) -> Vec<u8> {
    let mut entry = plist::Dictionary::new();
    entry.insert(
        "Name".into(),
        plist::Value::String("disk image (Apple_APFS : 4)".into()),
    );
    entry.insert("Data".into(), plist::Value::Data(mish));
    let mut rsrc = plist::Dictionary::new();
    rsrc.insert(
        "blkx".into(),
        plist::Value::Array(vec![plist::Value::Dictionary(entry)]),
    );
    let mut root = plist::Dictionary::new();
    root.insert("resource-fork".into(), plist::Value::Dictionary(rsrc));
    let mut xml = Vec::new();
    plist::to_writer_xml(&mut xml, &plist::Value::Dictionary(root)).unwrap();

    // Layout: [data fork][xml][koly]. The data fork must be non-empty or
    // dmgwiz rejects the image before parsing the (panicking) block table.
    let data_fork = vec![0u8; 16];
    let mut bytes = data_fork.clone();
    let xml_offset = bytes.len() as u64;
    bytes.extend_from_slice(&xml);
    let mut koly = vec![0u8; 512];
    koly[0..4].copy_from_slice(b"koly");
    koly[4..8].copy_from_slice(&4u32.to_be_bytes()); // version
    koly[8..12].copy_from_slice(&512u32.to_be_bytes()); // header size
    koly[24..32].copy_from_slice(&0u64.to_be_bytes()); // data fork offset
    koly[32..40].copy_from_slice(&(data_fork.len() as u64).to_be_bytes()); // data fork length
    koly[216..224].copy_from_slice(&xml_offset.to_be_bytes()); // xml offset
    koly[224..232].copy_from_slice(&(xml.len() as u64).to_be_bytes()); // xml length
    koly[492..500].copy_from_slice(&sectors.to_be_bytes()); // sector count
    bytes.extend_from_slice(&koly);
    bytes
}

/// A block table may declare far more output than the trailer's volume size:
/// here a single zero chunk of 1 GiB behind a 4 KiB volume. Reconstruction
/// must stop at the declared size instead of writing the gigabyte.
#[test]
fn reconstruct_dmg_raw_stops_at_declared_volume_size() {
    let mut mish = vec![0u8; 204];
    mish[0..4].copy_from_slice(b"mish");
    mish[200..204].copy_from_slice(&2u32.to_be_bytes()); // num_chunks
    let mut zero = [0u8; 40];
    zero[0..4].copy_from_slice(&0u32.to_be_bytes()); // type: zero fill
    zero[16..24].copy_from_slice(&(1u64 << 21).to_be_bytes()); // sector_count: 1 GiB
    let mut term = [0u8; 40];
    term[0..4].copy_from_slice(&0xffff_ffffu32.to_be_bytes()); // type: terminator
    mish.extend_from_slice(&zero);
    mish.extend_from_slice(&term);
    let bytes = dmg_with_blkx(mish, 8);

    let tmp = tempfile::Builder::new().suffix(".img").tempfile().unwrap();
    let outcome = reconstruct_dmg_raw(&bytes, tmp.path(), 8 * 512).unwrap();
    assert!(matches!(outcome, Reconstruction::OverBudget));
    assert!(std::fs::metadata(tmp.path()).unwrap().len() <= 8 * 512);
}

/// A crafted DMG: valid `koly` trailer + a plist whose only `blkx` carries a
/// `Data` blob too short for the BLKXTable header. dmgwiz navigates the plist
/// fine, then panics in `BLKXTable::from` (bincode `.unwrap()` hits EOF
/// before `sector_number`). `reconstruct_dmg_raw` must catch that and return
/// an error rather than unwinding into the analyzer — so one hostile DMG
/// can't abort a batch scan.
#[test]
fn reconstruct_dmg_raw_isolates_dmgwiz_panic() {
    // A complete 204-byte BLKXTable header (so navigation/parse succeeds)
    // that claims 1000 chunks but supplies none — the chunk-deserialize loop
    // then `.unwrap()`s an EOF error and panics.
    let mut mish = vec![0u8; 204];
    mish[0..4].copy_from_slice(b"mish");
    mish[200..204].copy_from_slice(&1000u32.to_be_bytes()); // num_chunks, no chunk data
    let bytes = dmg_with_blkx(mish, 8);

    let tmp = tempfile::Builder::new().suffix(".img").tempfile().unwrap();
    let err = reconstruct_dmg_raw(&bytes, tmp.path(), MAX_TOTAL_SIZE)
        .expect_err("malformed blkx must not unwind into the caller");
    assert!(
        err.to_string().contains("panicked"),
        "expected the dmgwiz panic to be caught, got: {err}"
    );
}

/// A macOS flat package lists directories before the install scripts.
/// A directory has no heap data; skipping it must not abandon the files
/// that follow.
#[test]
fn pkg_directory_does_not_hide_following_files() {
    let payload = b"echo installed\n";
    let toc = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<xar>
 <toc>
  <creation-time>2020-01-01T00:00:00Z</creation-time>
  <checksum style="none">
   <offset>0</offset>
   <size>0</size>
  </checksum>
  <file id="1">
   <type>directory</type>
   <name>Scripts</name>
  </file>
  <file id="2">
   <data>
    <length>{len}</length>
    <offset>0</offset>
    <size>{len}</size>
    <encoding style="application/octet-stream"/>
    <extracted-checksum style="none">00</extracted-checksum>
    <archived-checksum style="none">00</archived-checksum>
   </data>
   <type>file</type>
   <name>postinstall</name>
  </file>
 </toc>
</xar>
"#,
        len = payload.len()
    );
    let compressed = {
        use std::io::Write as _;
        let mut enc = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        enc.write_all(toc.as_bytes()).unwrap();
        enc.finish().unwrap()
    };
    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"xar!");
    bytes.extend_from_slice(&28u16.to_be_bytes());
    bytes.extend_from_slice(&1u16.to_be_bytes());
    bytes.extend_from_slice(&(compressed.len() as u64).to_be_bytes());
    bytes.extend_from_slice(&(toc.len() as u64).to_be_bytes());
    bytes.extend_from_slice(&0u32.to_be_bytes());
    bytes.extend_from_slice(&compressed);
    bytes.extend_from_slice(payload);

    let dir = tempfile::tempdir().unwrap();
    let data_len = bytes.len() as u64;
    extract_pkg_from_reader(
        std::io::Cursor::new(bytes),
        data_len,
        dir.path(),
        &ExtractionGuard::new(),
    )
    .unwrap();
    assert_eq!(fs::read(dir.path().join("postinstall")).unwrap(), payload);
    assert!(dir.path().join("Scripts").is_dir());
}
