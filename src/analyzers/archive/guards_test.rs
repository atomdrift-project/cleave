//! Test module.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! Tests for archive bomb protection guards

use super::guards::*;
use std::io::Read;
use tempfile::TempDir;

// =============================================================================
// Path Traversal Prevention Tests (Zip Slip)
// =============================================================================

#[test]
fn test_sanitize_rejects_absolute_paths() {
    let temp_dir = TempDir::new().unwrap();
    let dest = temp_dir.path();

    // Unix absolute path
    assert!(sanitize_entry_path("/etc/passwd", dest).is_none());

    // Windows absolute path (if on Windows this would be Component::Prefix)
    #[cfg(target_os = "windows")]
    assert!(sanitize_entry_path("C:\\Windows\\System32", dest).is_none());
}

#[test]
fn test_sanitize_rejects_parent_directory_traversal() {
    let temp_dir = TempDir::new().unwrap();
    let dest = temp_dir.path();

    // Direct parent reference
    assert!(sanitize_entry_path("../etc/passwd", dest).is_none());

    // Nested parent reference
    assert!(sanitize_entry_path("foo/../../etc/passwd", dest).is_none());

    // Multiple parent references
    assert!(sanitize_entry_path("../../etc/passwd", dest).is_none());
}

#[test]
fn test_sanitize_allows_safe_relative_paths() {
    let temp_dir = TempDir::new().unwrap();
    let dest = temp_dir.path();

    // Simple filename
    let result = sanitize_entry_path("file.txt", dest).unwrap();
    assert!(result.starts_with(dest));
    assert!(result.ends_with("file.txt"));

    // Nested path
    let result = sanitize_entry_path("foo/bar/baz.txt", dest).unwrap();
    assert!(result.starts_with(dest));
    assert!(result.ends_with("baz.txt"));
}

#[test]
fn test_sanitize_handles_current_directory_references() {
    let temp_dir = TempDir::new().unwrap();
    let dest = temp_dir.path();

    // Current directory reference should be skipped
    let result = sanitize_entry_path("./file.txt", dest).unwrap();
    assert!(result.starts_with(dest));
    assert!(result.ends_with("file.txt"));

    // Multiple current directory references
    let result = sanitize_entry_path("././foo/./bar.txt", dest).unwrap();
    assert!(result.starts_with(dest));
    assert!(result.to_str().unwrap().contains("foo"));
}

#[test]
fn test_sanitize_prevents_symlink_escape() {
    let temp_dir = TempDir::new().unwrap();
    let dest = temp_dir.path();

    // Path that looks safe but would escape if symlinks were followed
    // This test ensures the sanitizer works on the path itself
    let result = sanitize_entry_path("legitimate/../../escape", dest);
    assert!(result.is_none());
}

#[test]
fn test_sanitize_unicode_filenames() {
    let temp_dir = TempDir::new().unwrap();
    let dest = temp_dir.path();

    // Unicode filename
    let result = sanitize_entry_path("文件.txt", dest).unwrap();
    assert!(result.starts_with(dest));

    // Unicode in directory
    let result = sanitize_entry_path("日本語/ファイル.txt", dest).unwrap();
    assert!(result.starts_with(dest));
}

#[test]
fn test_sanitize_empty_components() {
    let temp_dir = TempDir::new().unwrap();
    let dest = temp_dir.path();

    // Double slashes should still result in valid path
    let result = sanitize_entry_path("foo//bar.txt", dest);
    assert!(result.is_some());
}

// =============================================================================
// Decompression Bomb Detection Tests
// =============================================================================

#[test]
fn test_compression_ratio_normal() {
    let guard = ExtractionGuard::new();

    // 10:1 ratio - normal
    assert!(guard.check_compression_ratio(1000, 10_000));

    // 50:1 ratio - still acceptable
    assert!(guard.check_compression_ratio(1000, 50_000));

    let reasons = guard.take_reasons();
    assert_eq!(reasons.len(), 0);
}

#[test]
fn test_compression_ratio_bomb_detected() {
    let guard = ExtractionGuard::new();

    // 200:1 ratio above the minimum material expansion size is suspicious.
    assert!(!guard.check_compression_ratio(1000, 300_000_000));

    let reasons = guard.take_reasons();
    assert_eq!(reasons.len(), 1);
    matches!(reasons[0], HostileArchiveReason::ZipBomb { .. });
}

#[test]
fn test_compression_ratio_extreme_bomb() {
    let guard = ExtractionGuard::new();

    // 10000:1 ratio - extreme zip bomb
    assert!(!guard.check_compression_ratio(100, 1_000_000_000));

    let reasons = guard.take_reasons();
    assert_eq!(reasons.len(), 1);
    if let HostileArchiveReason::ZipBomb {
        compressed,
        uncompressed,
    } = &reasons[0]
    {
        assert_eq!(*compressed, 100);
        assert_eq!(*uncompressed, 1_000_000_000);
    } else {
        panic!("Expected ZipBomb reason");
    }
}

#[test]
fn test_compression_ratio_high_but_safe_sized_blob() {
    let guard = ExtractionGuard::new();

    // High ratio alone should not flag when the expanded payload remains under
    // the normal per-file extraction limit.
    assert!(guard.check_compression_ratio(32_498, 67_108_864));

    let reasons = guard.take_reasons();
    assert_eq!(reasons.len(), 0);
}

#[test]
fn test_compression_ratio_zero_compressed() {
    let guard = ExtractionGuard::new();

    // Edge case: zero compressed size (prevent division by zero)
    assert!(guard.check_compression_ratio(0, 1000));

    let reasons = guard.take_reasons();
    assert_eq!(reasons.len(), 0);
}

// =============================================================================
// File Count Limit Tests
// =============================================================================

#[test]
fn test_file_count_within_limit() {
    let guard = ExtractionGuard::new();

    // Extract 100 files - should be fine
    for _ in 0..100 {
        assert!(guard.check_file_count());
    }

    let reasons = guard.take_reasons();
    assert_eq!(reasons.len(), 0);
}

#[test]
fn test_file_count_exceeds_limit() {
    let guard = ExtractionGuard::new();

    // Extract MAX_FILE_COUNT files - should be fine
    for _ in 0..MAX_FILE_COUNT {
        assert!(guard.check_file_count());
    }

    // One more should fail
    assert!(!guard.check_file_count());

    let reasons = guard.take_reasons();
    assert_eq!(reasons.len(), 1);
    matches!(reasons[0], HostileArchiveReason::ExcessiveFileCount(_));
}

#[test]
fn test_file_count_boundary() {
    let guard = ExtractionGuard::new();

    // Test exactly at the boundary
    for i in 0..MAX_FILE_COUNT {
        let result = guard.check_file_count();
        assert!(result, "Failed at file {}", i + 1);
    }

    // Next one should fail
    assert!(!guard.check_file_count());
}

// =============================================================================
// File Size Limit Tests
// =============================================================================

#[test]
fn test_single_file_within_size_limit() {
    let guard = ExtractionGuard::new();

    // 10 MB file - should be fine
    assert!(guard.check_bytes(10 * 1024 * 1024, "test.bin"));

    let reasons = guard.take_reasons();
    assert_eq!(reasons.len(), 0);
}

#[test]
fn test_single_file_exceeds_size_limit() {
    let guard = ExtractionGuard::new();

    // A file just over MAX_FILE_SIZE should be rejected. Pin to the constant
    // so raising MAX_FILE_SIZE doesn't silently break this test.
    let oversize = MAX_FILE_SIZE + 1;
    assert!(!guard.check_bytes(oversize, "large.bin"));

    let reasons = guard.take_reasons();
    assert_eq!(reasons.len(), 1);
    if let HostileArchiveReason::ExcessiveFileSize { file, size } = &reasons[0] {
        assert_eq!(file, "large.bin");
        assert_eq!(*size, oversize);
    } else {
        panic!("Expected ExcessiveFileSize reason");
    }
}

#[test]
fn test_total_size_within_limit() {
    let guard = ExtractionGuard::new();

    // Extract 10 files of 50 MB each = 500 MB total (under 1 GB limit)
    for i in 0..10 {
        let filename = format!("file{}.bin", i);
        assert!(guard.check_bytes(50 * 1024 * 1024, &filename));
    }

    let reasons = guard.take_reasons();
    assert_eq!(reasons.len(), 0);
}

#[test]
fn test_total_size_exceeds_limit() {
    let guard = ExtractionGuard::new();

    // Each chunk must fit under MAX_FILE_SIZE; add enough of them to exceed
    // MAX_TOTAL_SIZE. Pinning to the constants keeps this test honest when
    // either limit is changed.
    let chunk_size = MAX_FILE_SIZE / 2;
    let needed_chunks = (MAX_TOTAL_SIZE / chunk_size) + 1;
    for i in 0..needed_chunks {
        let filename = format!("file{}.bin", i);
        let result = guard.check_bytes(chunk_size, &filename);
        if i + 1 < needed_chunks {
            assert!(result, "File {} should succeed", i);
        } else {
            assert!(!result, "File {} should fail (exceeds total size)", i);
        }
    }

    let reasons = guard.take_reasons();
    assert_eq!(reasons.len(), 1);
    matches!(reasons[0], HostileArchiveReason::ExcessiveTotalSize(_));
}

#[test]
fn test_total_size_boundary() {
    let guard = ExtractionGuard::new();

    // Test exactly at the MAX_TOTAL_SIZE boundary using multiple chunks under
    // MAX_FILE_SIZE. Pinning to constants keeps this test valid across limit
    // changes.
    let chunk_size = MAX_FILE_SIZE / 2;
    let fitting_chunks = MAX_TOTAL_SIZE / chunk_size;
    for i in 0..fitting_chunks {
        assert!(
            guard.check_bytes(chunk_size, &format!("chunk{}.bin", i)),
            "Chunk {} should succeed",
            i
        );
    }

    // One more chunk should push the total past MAX_TOTAL_SIZE.
    assert!(
        !guard.check_bytes(chunk_size, "overflow.bin"),
        "Should fail when total exceeds MAX_TOTAL_SIZE"
    );

    let reasons = guard.take_reasons();
    assert_eq!(reasons.len(), 1);
    matches!(reasons[0], HostileArchiveReason::ExcessiveTotalSize(_));
}

// =============================================================================
// LimitedReader Tests
// =============================================================================

#[test]
fn test_limited_reader_reads_within_limit() {
    let data = b"Hello, World!";
    let mut reader = LimitedReader::new(&data[..], 100);

    let mut buffer = Vec::new();
    let n = reader.read_to_end(&mut buffer).unwrap();

    assert_eq!(n, 13);
    assert_eq!(&buffer, data);
}

#[test]
fn test_limited_reader_enforces_limit() {
    let data = b"Hello, World! This is a longer message.";
    let mut reader = LimitedReader::new(&data[..], 10);

    let mut buffer = Vec::new();
    let n = reader.read_to_end(&mut buffer).unwrap();

    // Should read exactly 10 bytes (Ok, not Err — correct Read contract)
    assert_eq!(n, 10);
    assert_eq!(&buffer, b"Hello, Wor");
    // …and flag that the stream was truncated
    assert!(reader.is_limited());
}

#[test]
fn test_limited_reader_zero_limit() {
    let data = b"Test";
    let mut reader = LimitedReader::new(&data[..], 0);

    let mut buffer = [0u8; 10];
    let n = reader.read(&mut buffer).unwrap();

    // Returns Ok(0) (EOF) immediately; callers check is_limited()
    assert_eq!(n, 0);
    assert!(reader.is_limited());
}

#[test]
fn test_limited_reader_partial_reads() {
    let data = b"0123456789";
    let mut reader = LimitedReader::new(&data[..], 10);

    // Read in chunks
    let mut buf1 = [0u8; 5];
    let n1 = reader.read(&mut buf1).unwrap();
    assert_eq!(n1, 5);
    assert_eq!(&buf1, b"01234");

    let mut buf2 = [0u8; 5];
    let n2 = reader.read(&mut buf2).unwrap();
    assert_eq!(n2, 5);
    assert_eq!(&buf2, b"56789");

    // Limit exactly reached — next read returns Ok(0) and sets is_limited
    let mut buf3 = [0u8; 1];
    let n3 = reader.read(&mut buf3).unwrap();
    assert_eq!(n3, 0);
    assert!(reader.is_limited());
}

#[test]
fn test_limited_reader_not_limited_when_data_fits() {
    let data = b"tiny";
    let mut reader = LimitedReader::new(&data[..], 100);

    let mut buffer = Vec::new();
    reader.read_to_end(&mut buffer).unwrap();

    assert_eq!(&buffer, data);
    assert!(!reader.is_limited());
}

// =============================================================================
// Integration Tests
// =============================================================================

#[test]
fn test_hostile_reasons_accumulate() {
    let guard = ExtractionGuard::new();

    // Trigger multiple violations. Zip-bomb flagging requires both a high
    // compression ratio AND an uncompressed size above MIN_ZIP_BOMB_UNCOMPRESSED_SIZE,
    // so feed values derived from the constants.
    let big_uncompressed = MIN_ZIP_BOMB_UNCOMPRESSED_SIZE + 1;
    let tiny_compressed = big_uncompressed / (MAX_COMPRESSION_RATIO + 1);
    guard.check_compression_ratio(tiny_compressed, big_uncompressed); // Bomb
    guard.check_bytes(MAX_FILE_SIZE + 1, "huge.bin"); // Too large

    let reasons = guard.take_reasons();
    assert_eq!(reasons.len(), 2);
}

#[test]
fn test_hostile_reasons_take_clears_list() {
    let guard = ExtractionGuard::new();

    guard.add_hostile_reason(HostileArchiveReason::SymlinkEscape("test".into()));

    let reasons1 = guard.take_reasons();
    assert_eq!(reasons1.len(), 1);

    // Second take should return empty
    let reasons2 = guard.take_reasons();
    assert_eq!(reasons2.len(), 0);
}

#[test]
fn test_extraction_guard_concurrent_safety() {
    use std::sync::Arc;
    use std::thread;

    let guard = Arc::new(ExtractionGuard::new());
    let mut handles = vec![];

    // Simulate concurrent file extractions
    for i in 0..10 {
        let guard_clone = Arc::clone(&guard);
        let handle = thread::spawn(move || {
            let filename = format!("file{}.bin", i);
            guard_clone.check_bytes(1024, &filename);
            guard_clone.check_file_count();
        });
        handles.push(handle);
    }

    for handle in handles {
        handle.join().unwrap();
    }

    // All operations should have succeeded
    let reasons = guard.take_reasons();
    assert_eq!(reasons.len(), 0);
}

// =============================================================================
// Symlink Escape Detection Tests
// =============================================================================

#[test]
fn test_symlink_escapes_absolute_target() {
    let temp_dir = TempDir::new().unwrap();
    let dest = temp_dir.path();
    let symlink_path = dest.join("link");

    // Absolute paths always escape
    assert!(symlink_escapes(&symlink_path, "/etc/passwd", dest));
    assert!(symlink_escapes(&symlink_path, "/tmp/other", dest));
}

#[test]
fn test_symlink_escapes_parent_directory() {
    let temp_dir = TempDir::new().unwrap();
    let dest = temp_dir.path();
    let symlink_path = dest.join("foo/bar/link");

    // "../../../etc" would escape from foo/bar/link
    assert!(symlink_escapes(&symlink_path, "../../../etc", dest));

    // "../../../../etc" definitely escapes
    assert!(symlink_escapes(&symlink_path, "../../../../etc", dest));
}

#[test]
fn test_symlink_stays_within_directory() {
    let temp_dir = TempDir::new().unwrap();
    let dest = temp_dir.path();
    let symlink_path = dest.join("foo/bar/link");

    // "../baz" from foo/bar/link points to foo/baz - OK
    assert!(!symlink_escapes(&symlink_path, "../baz", dest));

    // "../../other" from foo/bar/link points to other - OK
    assert!(!symlink_escapes(&symlink_path, "../../other", dest));

    // "target" from foo/bar/link points to foo/bar/target - OK
    assert!(!symlink_escapes(&symlink_path, "target", dest));
}

#[test]
fn test_symlink_current_directory() {
    let temp_dir = TempDir::new().unwrap();
    let dest = temp_dir.path();
    let symlink_path = dest.join("link");

    // "./file" stays in dest - OK
    assert!(!symlink_escapes(&symlink_path, "./file", dest));

    // "././file" stays in dest - OK
    assert!(!symlink_escapes(&symlink_path, "././file", dest));
}

#[test]
fn test_symlink_complex_relative_path() {
    let temp_dir = TempDir::new().unwrap();
    let dest = temp_dir.path();
    let symlink_path = dest.join("a/b/c/link");

    // "../../d/e" from a/b/c/link points to a/d/e - OK
    assert!(!symlink_escapes(&symlink_path, "../../d/e", dest));

    // "../../../x" from a/b/c/link points to x in dest - OK
    assert!(!symlink_escapes(&symlink_path, "../../../x", dest));

    // "../../../../escape" would go above dest - ESCAPES
    assert!(symlink_escapes(&symlink_path, "../../../../escape", dest));
}

#[test]
fn test_symlink_at_root_level() {
    let temp_dir = TempDir::new().unwrap();
    let dest = temp_dir.path();
    let symlink_path = dest.join("link");

    // "file" stays in dest - OK
    assert!(!symlink_escapes(&symlink_path, "file", dest));

    // "../escape" goes above dest - ESCAPES
    assert!(symlink_escapes(&symlink_path, "../escape", dest));
}

// =============================================================================
// Long Entry Name Tests
// =============================================================================

#[test]
fn test_sanitize_truncates_long_path_component() {
    let temp_dir = TempDir::new().unwrap();
    let dest = temp_dir.path();

    // A 300-byte filename should be truncated to 255 bytes, not rejected.
    let long_name = "X".repeat(300);
    let result = sanitize_entry_path(&long_name, dest);
    assert!(
        result.is_some(),
        "long filename should be truncated, not rejected"
    );

    let path = result.unwrap();
    let component = path.file_name().unwrap().to_string_lossy();
    assert_eq!(component.len(), 255);
    assert!(path.starts_with(dest));
}

#[test]
fn test_sanitize_truncates_long_component_in_nested_path() {
    let temp_dir = TempDir::new().unwrap();
    let dest = temp_dir.path();

    let long_dir = "D".repeat(400);
    let entry = format!("{}/file.txt", long_dir);
    let result = sanitize_entry_path(&entry, dest);
    assert!(result.is_some());

    let path = result.unwrap();
    // The long directory component should be truncated
    let parent_name = path
        .parent()
        .unwrap()
        .file_name()
        .unwrap()
        .to_string_lossy();
    assert_eq!(parent_name.len(), 255);
    // The short filename should be preserved as-is
    assert_eq!(path.file_name().unwrap().to_string_lossy(), "file.txt");
}

#[test]
fn test_sanitize_truncates_on_char_boundary() {
    let temp_dir = TempDir::new().unwrap();
    let dest = temp_dir.path();

    // Build a name that would split a multi-byte char at exactly 255.
    // Each '文' is 3 bytes. 84 * 3 = 252, then "XXXX" = 256 bytes total.
    let mut name = "文".repeat(84); // 252 bytes
    name.push_str("XXXX"); // 256 bytes
    assert_eq!(name.len(), 256);

    let result = sanitize_entry_path(&name, dest).unwrap();
    let component = result.file_name().unwrap().to_string_lossy();
    // Must be valid UTF-8 and <= 255 bytes
    assert!(component.len() <= 255);
    assert!(component.len() >= 252); // should keep as much as possible
}

#[test]
fn test_sanitize_normal_names_unchanged() {
    let temp_dir = TempDir::new().unwrap();
    let dest = temp_dir.path();

    // Names under 255 bytes should pass through unchanged
    let name = "normal_file.txt";
    let result = sanitize_entry_path(name, dest).unwrap();
    assert_eq!(result.file_name().unwrap().to_string_lossy(), name);

    let name_255 = "A".repeat(255);
    let result = sanitize_entry_path(&name_255, dest).unwrap();
    assert_eq!(result.file_name().unwrap().to_string_lossy().len(), 255);
}

#[test]
fn test_sanitize_mega_filename_extracts_without_error() {
    let temp_dir = TempDir::new().unwrap();
    let dest = temp_dir.path();

    // Simulate the pax-bad-hdr-large.tar.bz2 case: ~1MB filename
    let mega_name = "X".repeat(1_048_563);
    let result = sanitize_entry_path(&mega_name, dest);
    assert!(result.is_some(), "million-byte filename must not crash");

    let path = result.unwrap();
    // Should be writable on the filesystem
    std::fs::create_dir_all(path.parent().unwrap_or(dest)).unwrap();
    std::fs::write(&path, b"ok").unwrap();
    assert_eq!(std::fs::read(&path).unwrap(), b"ok");
}

#[test]
fn test_excessive_entry_name_hostile_reason() {
    let guard = ExtractionGuard::new();

    // >255 should be flagged
    guard.add_hostile_reason(HostileArchiveReason::ExcessiveEntryName {
        len: 300,
        preview: "X".repeat(80),
    });

    // >1024 should also be flagged
    guard.add_hostile_reason(HostileArchiveReason::ExcessiveEntryName {
        len: 1_048_563,
        preview: "Y".repeat(80),
    });

    let reasons = guard.take_reasons();
    assert_eq!(reasons.len(), 2);
    assert!(matches!(
        &reasons[0],
        HostileArchiveReason::ExcessiveEntryName { len: 300, .. }
    ));
    assert!(matches!(
        &reasons[1],
        HostileArchiveReason::ExcessiveEntryName { len: 1_048_563, .. }
    ));
}

// =============================================================================
// Windows Filename Representability (unix archive -> Windows extraction)
// =============================================================================
//
// Every case below was measured on Windows 11 26200 before the escaping existed:
// the member either vanished (device name, alternate data stream), was silently
// renamed into a collision (trailing dot or space), or failed to create at all
// (forbidden character). All three end the same way — bytes that no rule ever
// sees — which is why these are escaped rather than skipped.

/// The leaf name `sanitize_entry_path` produces, for terse assertions.
fn leaf(entry_name: &str, dest: &std::path::Path) -> String {
    sanitize_entry_path(entry_name, dest)
        .unwrap_or_else(|| panic!("{entry_name:?} should sanitize, not be rejected"))
        .file_name()
        .unwrap()
        .to_string_lossy()
        .into_owned()
}

#[test]
fn sanitize_escapes_colons_so_a_member_cannot_become_an_alternate_data_stream() {
    let temp_dir = TempDir::new().unwrap();
    let dest = temp_dir.path();

    // `DateTime:Locale.gz` on NTFS writes into the `:Locale.gz` stream of a
    // zero-byte file called `DateTime`, which a directory walk never reports —
    // the payload is extracted and then invisible to the analyzer.
    assert_eq!(leaf("DateTime:Locale.gz", dest), "DateTime%3ALocale.gz");
    assert_eq!(leaf("a:b", dest), "a%3Ab");
    // Drive-*relative* (`C:rel`, and any single-letter name with a colon) is
    // escaped rather than rejected: skipping it would be the evasion. Only a
    // drive followed by a separator is genuinely anchored.
    assert_eq!(leaf("C:rel", dest), "C%3Arel");
    assert!(sanitize_entry_path("C:/Windows", dest).is_none());
}

#[test]
fn sanitize_escapes_reserved_device_names() {
    let temp_dir = TempDir::new().unwrap();
    let dest = temp_dir.path();

    // Bare, cased, with an extension, and with a multi-part extension: Windows
    // matches the device on the stem, so all four resolve to the device and
    // silently swallow the member's bytes.
    for name in [
        "nul",
        "NUL",
        "nul.exe",
        "con",
        "CON.txt",
        "com1.tar.gz",
        "lpt9",
        "conin$",
    ] {
        let got = leaf(name, dest);
        assert_ne!(got, name, "{name:?} must not survive unescaped");
        let stem = got.split('.').next().unwrap().to_ascii_lowercase();
        assert!(
            !["nul", "con", "com1", "lpt9", "conin$"].contains(&stem.as_str()),
            "{name:?} escaped to {got:?}, whose stem is still a device name",
        );
    }

    // The extension is preserved, so file-type detection still works on it.
    assert!(leaf("nul.exe", dest).ends_with(".exe"));
    assert!(leaf("com1.tar.gz", dest).ends_with(".tar.gz"));

    // A name that merely starts with a device name is not one.
    assert_eq!(leaf("nullable.txt", dest), "nullable.txt");
    assert_eq!(leaf("console.log", dest), "console.log");
}

#[test]
fn sanitize_escapes_characters_windows_cannot_put_in_a_filename() {
    let temp_dir = TempDir::new().unwrap();
    let dest = temp_dir.path();

    assert_eq!(leaf("a<b", dest), "a%3Cb");
    assert_eq!(leaf("a>b", dest), "a%3Eb");
    assert_eq!(leaf("a\"b", dest), "a%22b");
    assert_eq!(leaf("a|b", dest), "a%7Cb");
    assert_eq!(leaf("a?b", dest), "a%3Fb");
    assert_eq!(leaf("a*b", dest), "a%2Ab");
    // Control characters, including an embedded NUL, which would otherwise make
    // the create call fail outright on every platform.
    assert_eq!(leaf("a\u{0}b", dest), "a%00b");
    assert_eq!(leaf("a\u{1}b", dest), "a%01b");
    assert_eq!(leaf("a\u{7f}b", dest), "a%7Fb");
}

#[test]
fn sanitize_escapes_trailing_dots_and_spaces_windows_would_strip() {
    let temp_dir = TempDir::new().unwrap();
    let dest = temp_dir.path();

    // Windows drops these silently, so `report.` and `report` become one file
    // and the second member overwrites the first.
    assert_eq!(leaf("report.", dest), "report%2E");
    assert_eq!(leaf("report ", dest), "report%20");
    assert_eq!(leaf("report...", dest), "report%2E%2E%2E");
    assert_eq!(leaf("report . ", dest), "report%20%2E%20");
    // Interior and leading dots and spaces are ordinary.
    assert_eq!(leaf("re port.txt", dest), "re port.txt");
    assert_eq!(leaf(".hidden", dest), ".hidden");
}

#[test]
fn sanitize_is_injective_so_one_member_cannot_mask_another() {
    let temp_dir = TempDir::new().unwrap();
    let dest = temp_dir.path();

    // The whole point of escaping `%` too: without it, an archive could ship
    // `a%3Ab` alongside `a:b` and have the second overwrite the first.
    let names = [
        "a:b",
        "a%3Ab",
        "a%253Ab",
        "report.",
        "report",
        "report%2E",
        "nul",
        "%6Eul",
        "nul.exe",
        "a<b",
        "a%3Cb",
        "a b",
        "a%20b",
    ];
    let mut seen: std::collections::HashMap<String, &str> = std::collections::HashMap::new();
    for name in names {
        let got = leaf(name, dest);
        if let Some(previous) = seen.insert(got.clone(), name) {
            panic!("{name:?} and {previous:?} both sanitize to {got:?}");
        }
    }
}

#[test]
fn sanitize_rejects_entries_that_name_the_extraction_root_itself() {
    let temp_dir = TempDir::new().unwrap();
    let dest = temp_dir.path();

    // These used to return `dest_dir`, handing the caller the extraction root to
    // create as a *file*. Affects every platform, not just Windows.
    for name in [".", "", "./", "./.", "/", "././."] {
        assert!(
            sanitize_entry_path(name, dest).is_none(),
            "{name:?} must be rejected, not resolve to the extraction root",
        );
    }
}

#[test]
fn sanitize_splits_both_separators_on_every_platform() {
    let temp_dir = TempDir::new().unwrap();
    let dest = temp_dir.path();

    // A member name containing a backslash is one component on unix and two on
    // Windows. Treating both as separators everywhere keeps member names — and
    // so the corpus keys built from them — identical across a mixed fleet.
    let backslash = 0x5C_u8 as char;
    let nested = format!("a{backslash}b.txt");
    assert_eq!(escaped_relative_path(&nested).unwrap(), "a/b.txt");
    assert_eq!(leaf(&nested, dest), "b.txt");

    // Traversal spelled with backslashes is rejected the same way as with
    // forward slashes.
    let traversal = format!("..{backslash}..{backslash}evil");
    assert!(sanitize_entry_path(&traversal, dest).is_none());
    // ...as is a UNC root.
    let unc = format!("{backslash}{backslash}server{backslash}share{backslash}x");
    assert!(sanitize_entry_path(&unc, dest).is_none());
}

#[test]
fn sanitize_still_rejects_every_traversal_shape() {
    let temp_dir = TempDir::new().unwrap();
    let dest = temp_dir.path();

    for name in [
        "../etc/passwd",
        "foo/../../etc/passwd",
        "..",
        "/etc/passwd",
        "C:/Windows",
    ] {
        assert!(
            sanitize_entry_path(name, dest).is_none(),
            "{name:?} must be rejected"
        );
    }
    // A `..` buried mid-path is still a reject, and escaping must not launder it.
    assert!(sanitize_entry_path("ok/../../out", dest).is_none());
    // But a name that merely starts with dots is a legitimate file.
    assert_eq!(leaf("..hidden", dest), "..hidden");
    assert_eq!(leaf("...", dest), "%2E%2E%2E");
}

#[test]
fn truncation_never_leaves_a_half_written_escape() {
    let temp_dir = TempDir::new().unwrap();
    let dest = temp_dir.path();

    // Build a name whose escaped form lands a `%XX` exactly across the 255-byte
    // boundary, in each of the three possible alignments.
    for pad in 252..256 {
        let name = format!("{}:tail", "a".repeat(pad));
        let got = leaf(&name, dest);
        assert!(got.len() <= MAX_PATH_COMPONENT_LEN, "{} bytes", got.len());
        // No trailing `%` or `%X`: the result must stay decodable.
        assert!(!got.ends_with('%'), "dangling escape in {got:?}");
        let tail: String = got.chars().rev().take(2).collect();
        assert!(!tail.ends_with('%'), "half-written escape in {got:?}");
    }
}

#[test]
fn escaped_relative_path_agrees_with_sanitize_entry_path() {
    let temp_dir = TempDir::new().unwrap();
    let dest = temp_dir.path();

    // The metadata merge relies on these two agreeing: it looks up the walked
    // name using the escaped form of the name recorded inside the archive.
    for name in [
        "a:b/c.txt",
        "nul.exe",
        "plain/nested/file.bin",
        "trailing./x",
    ] {
        let relative = escaped_relative_path(name).unwrap();
        let full = sanitize_entry_path(name, dest).unwrap();
        let stripped = full
            .strip_prefix(dest)
            .unwrap()
            .to_string_lossy()
            .into_owned();
        let backslash = 0x5C_u8 as char;
        assert_eq!(stripped.replace(backslash, "/"), relative, "for {name:?}");
    }
    // Rejections agree too.
    for name in ["..", "/abs", ".", ""] {
        assert!(escaped_relative_path(name).is_none(), "for {name:?}");
    }
}

/// The end-to-end proof: sanitized names are all creatable, all distinct, and
/// all visible to the directory walk that feeds the analyzer.
#[test]
fn every_sanitized_name_lands_as_a_file_the_walk_can_see() {
    let temp_dir = TempDir::new().unwrap();
    let dest = temp_dir.path();

    let hostile = [
        "DateTime:Locale.gz",
        "nul",
        "nul.exe",
        "con",
        "com1",
        "prn.dll",
        "aux.txt",
        "trailing.",
        "trailing ",
        "a<b",
        "a|b",
        "a*b",
        "ordinary.exe",
    ];

    for name in hostile {
        let path = sanitize_entry_path(name, dest).unwrap();
        std::fs::write(&path, b"MZ-payload").unwrap();
    }

    let found: Vec<String> = std::fs::read_dir(dest)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();

    // Nothing was swallowed by a device, diverted into a data stream, or merged
    // with another member by a silent rename.
    assert_eq!(
        found.len(),
        hostile.len(),
        "expected every member on disk, got {found:?}",
    );
    for entry in &found {
        let bytes = std::fs::read(dest.join(entry)).unwrap();
        assert_eq!(bytes, b"MZ-payload", "{entry:?} did not keep its bytes");
    }
}

// =============================================================================
// Case-Insensitive Collisions
// =============================================================================

#[test]
fn claim_output_path_disambiguates_case_only_collisions() {
    let temp_dir = TempDir::new().unwrap();
    let dest = temp_dir.path();
    let guard = ExtractionGuard::new();

    // Distinct members on unix; one file on NTFS, where the second silently
    // overwrites the first and the first is never analyzed.
    let first = guard.claim_output_path(dest.join("evil.exe"));
    let second = guard.claim_output_path(dest.join("EVIL.exe"));
    let third = guard.claim_output_path(dest.join("Evil.Exe"));

    assert_eq!(first.file_name().unwrap(), "evil.exe");
    assert_eq!(second.file_name().unwrap(), "EVIL~2.exe");
    assert_eq!(third.file_name().unwrap(), "Evil~3.Exe");

    // All three can coexist on a case-insensitive filesystem.
    for path in [&first, &second, &third] {
        std::fs::write(path, b"payload").unwrap();
    }
    assert_eq!(std::fs::read_dir(dest).unwrap().count(), 3);
}

#[test]
fn claim_output_path_keeps_multi_part_extensions_intact() {
    let temp_dir = TempDir::new().unwrap();
    let dest = temp_dir.path();
    let guard = ExtractionGuard::new();

    // The suffix goes before the extension so file-type detection, which reads
    // the extension, is unaffected by disambiguation.
    guard.claim_output_path(dest.join("archive.tar.gz"));
    let second = guard.claim_output_path(dest.join("ARCHIVE.TAR.GZ"));
    assert_eq!(second.file_name().unwrap(), "ARCHIVE~2.TAR.GZ");

    // A name with no extension still disambiguates.
    guard.claim_output_path(dest.join("README"));
    let second = guard.claim_output_path(dest.join("readme"));
    assert_eq!(second.file_name().unwrap(), "readme~2");
}

#[test]
fn claim_output_path_leaves_distinct_names_alone() {
    let temp_dir = TempDir::new().unwrap();
    let dest = temp_dir.path();
    let guard = ExtractionGuard::new();

    // The common case must be untouched: no suffix, no allocation churn.
    for name in ["a.txt", "b.txt", "nested/c.txt"] {
        let path = dest.join(name);
        assert_eq!(guard.claim_output_path(path.clone()), path);
    }
    // Same leaf in different directories is not a collision.
    let one = guard.claim_output_path(dest.join("x").join("dup.txt"));
    let two = guard.claim_output_path(dest.join("y").join("dup.txt"));
    assert_eq!(one.file_name().unwrap(), "dup.txt");
    assert_eq!(two.file_name().unwrap(), "dup.txt");
}
