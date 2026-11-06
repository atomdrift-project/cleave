#![allow(clippy::unwrap_used)]
use super::scheduling_size;
use std::io::Write;

#[test]
fn zip_ranks_by_inflated_size() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("tiny.crx");
    let mut zip = zip::ZipWriter::new(std::fs::File::create(&path).unwrap());
    let opts = zip::write::SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated);
    zip.start_file("a.js", opts).unwrap();
    zip.write_all(&vec![b'x'; 1 << 20]).unwrap();
    zip.start_file("b.js", opts).unwrap();
    zip.write_all(&vec![b'y'; 1 << 20]).unwrap();
    zip.finish().unwrap();
    let on_disk = std::fs::metadata(&path).unwrap().len();
    assert!(on_disk < 1 << 16);
    assert_eq!(scheduling_size(&path), 2 << 20);
}

#[test]
fn cab_ranks_by_its_file_table() {
    // MSCF header (36 bytes), one CFFOLDER (8 bytes), then two CFFILE
    // entries; the compressed data itself is never read for the hint.
    let files_offset: u32 = 36 + 8;
    let mut cab = Vec::new();
    cab.extend_from_slice(b"MSCF");
    cab.extend_from_slice(&0u32.to_le_bytes()); // reserved1
    cab.extend_from_slice(&0u32.to_le_bytes()); // cbCabinet (patched below)
    cab.extend_from_slice(&0u32.to_le_bytes()); // reserved2
    cab.extend_from_slice(&files_offset.to_le_bytes()); // coffFiles
    cab.extend_from_slice(&0u32.to_le_bytes()); // reserved3
    cab.extend_from_slice(&[3, 1]); // version
    cab.extend_from_slice(&1u16.to_le_bytes()); // cFolders
    cab.extend_from_slice(&2u16.to_le_bytes()); // cFiles
    cab.extend_from_slice(&0u16.to_le_bytes()); // flags
    cab.extend_from_slice(&0u16.to_le_bytes()); // setID
    cab.extend_from_slice(&0u16.to_le_bytes()); // iCabinet
    cab.extend_from_slice(&[0u8; 8]); // CFFOLDER
    for (size, name) in [(826_355u32, &b"segment.js"[..]), (1_000, &b"b.txt"[..])] {
        cab.extend_from_slice(&size.to_le_bytes());
        cab.extend_from_slice(&[0u8; 12]);
        cab.extend_from_slice(name);
        cab.push(0);
    }
    cab.extend_from_slice(&[0u8; 64]);
    let len = u32::try_from(cab.len()).unwrap();
    cab[8..12].copy_from_slice(&len.to_le_bytes());
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("segment.cab");
    std::fs::write(&path, &cab).unwrap();
    assert_eq!(scheduling_size(&path), 827_355);
}

#[test]
fn plain_file_is_its_length() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("plain.bin");
    std::fs::write(&path, vec![7u8; 4096]).unwrap();
    assert_eq!(scheduling_size(&path), 4096);
}
