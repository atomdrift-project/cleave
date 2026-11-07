use super::*;

/// Every filefacts type a rule can name must convert to its rule-engine
/// counterpart. A missing arm here falls through to `Unknown`, and the
/// engine then skips every trait whose `for:` names that type -- silently,
/// with the file still reported under its correct detected type, so the
/// rules simply never fire and nothing says why.
///
/// `pbxproj` and `cmake` were added to the enum, to `from_str`, and to the
/// `build` group without this arm, which cost an afternoon: `cleave
/// test-rules` reported "Detected file type: Pbxproj" on the line above
/// "file is Unknown".
#[test]
fn build_file_types_convert_from_filefacts() {
    use filefacts::FileType as Ff;
    for (ff, expected) in [
        (Ff::Pbxproj, FileType::Pbxproj),
        (Ff::Cmake, FileType::Cmake),
        (Ff::Makefile, FileType::Makefile),
        (Ff::Dockerfile, FileType::Dockerfile),
        (Ff::Plist, FileType::Plist),
        (Ff::Nib, FileType::Nib),
        (Ff::Snap, FileType::Snap),
        (Ff::SquashFs, FileType::SquashFs),
    ] {
        assert_eq!(
            FileType::from(ff),
            expected,
            "{ff:?} must not fall through to Unknown"
        );
    }
}

/// Every Office extension filefacts recognises has to route to a rule
/// file type, or the rules written for that format never reach the file.
///
/// The macro-enabled add-in and template variants were the ones missing,
/// which is the wrong half to lose: `.ppam` and `.xlam` are what macro
/// delivery uses to get looked at less.
#[test]
fn office_variants_route_to_their_document_type() {
    for ext in [
        "docx", "xlsx", "pptx", "docm", "xlsm", "pptm", "dotx", "dotm", "xltx", "xltm", "xlam",
        "ppam", "potx", "potm", "ppsx", "ppsm", "sldx", "sldm", "ooxml",
    ] {
        assert_eq!(
            FileType::from_str(ext),
            FileType::Ooxml,
            "{ext} did not route to Ooxml"
        );
    }
    for ext in [
        "doc", "xls", "ppt", "msg", "dot", "pps", "pot", "ppa", "xlt", "xla", "oledoc",
    ] {
        assert_eq!(
            FileType::from_str(ext),
            FileType::OleDoc,
            "{ext} did not route to OleDoc"
        );
    }
}

// ==================== FileType::is_source_code Tests ====================

#[test]
fn test_is_source_code_true_for_shell() {
    assert!(FileType::Shell.is_source_code());
}

#[test]
fn test_is_source_code_true_for_python() {
    assert!(FileType::Python.is_source_code());
}

#[test]
fn test_is_source_code_true_for_javascript() {
    assert!(FileType::JavaScript.is_source_code());
}

#[test]
fn test_is_source_code_true_for_rust() {
    assert!(FileType::Rust.is_source_code());
}

#[test]
fn test_is_source_code_true_for_go() {
    assert!(FileType::Go.is_source_code());
}

#[test]
fn test_is_source_code_true_for_applescript() {
    assert!(FileType::AppleScript.is_source_code());
}

#[test]
fn test_is_source_code_false_for_elf() {
    assert!(!FileType::Elf.is_source_code());
}

#[test]
fn test_is_source_code_false_for_macho() {
    assert!(!FileType::Macho.is_source_code());
}

#[test]
fn test_is_source_code_false_for_pe() {
    assert!(!FileType::Pe.is_source_code());
}

#[test]
fn test_is_source_code_false_for_all() {
    assert!(!FileType::All.is_source_code());
}

#[test]
fn test_is_source_code_false_for_package_json() {
    assert!(!FileType::PackageJson.is_source_code());
}

#[test]
fn test_go_mod_is_raw_text_manifest() {
    assert!(!FileType::GoMod.is_source_code());
    assert!(FileType::GoMod.uses_raw_text_search());
    assert_eq!(FileType::from_str("go.mod"), FileType::GoMod);
    assert_eq!(FileType::from_str("gomod"), FileType::GoMod);
}

#[test]
fn test_is_source_code_false_for_plist() {
    assert!(!FileType::Plist.is_source_code());
}

#[test]
fn test_is_source_code_false_for_systemd_service() {
    assert!(!FileType::SystemdService.is_source_code());
    assert!(FileType::SystemdService.uses_raw_text_search());
}

#[test]
fn test_svg_is_raw_text() {
    assert!(!FileType::Svg.is_source_code());
    assert!(FileType::Svg.uses_raw_text_search());
}

#[test]
fn test_is_source_code_false_for_jpeg() {
    assert!(!FileType::Jpeg.is_source_code());
}

// ==================== FileType::all_concrete_variants Tests ====================

#[test]
fn test_all_concrete_variants_excludes_all() {
    let variants = FileType::all_concrete_variants();
    assert!(!variants.contains(&FileType::All));
}

#[test]
fn test_all_concrete_variants_includes_elf() {
    let variants = FileType::all_concrete_variants();
    assert!(variants.contains(&FileType::Elf));
}

#[test]
fn test_all_concrete_variants_includes_python() {
    let variants = FileType::all_concrete_variants();
    assert!(variants.contains(&FileType::Python));
}

#[test]
fn test_all_concrete_variants_includes_package_json() {
    let variants = FileType::all_concrete_variants();
    assert!(variants.contains(&FileType::PackageJson));
}

#[test]
fn test_all_concrete_variants_includes_package_lock_json() {
    let variants = FileType::all_concrete_variants();
    assert!(variants.contains(&FileType::PackageLockJson));
}

#[test]
fn test_all_concrete_variants_includes_go_mod() {
    let variants = FileType::all_concrete_variants();
    assert!(variants.contains(&FileType::GoMod));
}

#[test]
fn test_all_concrete_variants_includes_systemd_service() {
    let variants = FileType::all_concrete_variants();
    assert!(variants.contains(&FileType::SystemdService));
}

#[test]
fn test_all_concrete_variants_includes_jpeg() {
    let variants = FileType::all_concrete_variants();
    assert!(variants.contains(&FileType::Jpeg));
}

#[test]
fn test_all_concrete_variants_count() {
    let variants = FileType::all_concrete_variants();
    // Should have all variants except All
    assert!(variants.len() > 30); // At least 30+ variants
}

// ==================== default_platforms Tests ====================

#[test]
fn test_default_platforms_returns_all() {
    let platforms = default_platforms();
    assert_eq!(platforms.len(), 1);
    assert_eq!(platforms[0], Platform::All);
}

// ==================== default_file_types Tests ====================

#[test]
fn test_default_file_types_returns_all() {
    let file_types = default_file_types();
    assert_eq!(file_types.len(), 1);
    assert_eq!(file_types[0], FileType::All);
}

#[test]
fn recognized_binary_formats_use_data_rules() {
    assert_eq!(FileType::from_str("ani"), FileType::Data);
    assert_eq!(FileType::from_str("nrbf"), FileType::Data);
    assert_eq!(FileType::from_str("fat_boot_sector"), FileType::Data);
    assert_eq!(
        FileType::from(filefacts::FileType::FatBootSector),
        FileType::Data
    );
}

#[test]
fn test_from_str_systemd_service_aliases() {
    assert_eq!(
        FileType::from_str("systemd-service"),
        FileType::SystemdService
    );
    assert_eq!(FileType::from_str("systemd"), FileType::SystemdService);
    assert_eq!(FileType::from_str("service"), FileType::SystemdService);
}

#[test]
fn test_from_str_java_class_aliases() {
    assert_eq!(FileType::from_str("class"), FileType::Class);
    assert_eq!(FileType::from_str("java_class"), FileType::Class);
    assert_eq!(FileType::from_str("javaclass"), FileType::Class);
}

/// A report's `type` is filefacts's canonical `FileType::label()`. The
/// trait engine resolves that exact string via `from_str` to gate `for:`,
/// so every canonical label MUST route to its bucket — never `Unknown`.
/// Regression guard for the `objective_c`/`github_actions` detection break
/// where labels diverged from cleave's hand-rolled string table.
#[test]
fn from_str_resolves_canonical_filefacts_labels() {
    use filefacts::FileType as Ff;
    // The labels that actually regressed (snake_case diverged from the old
    // alias spellings the table knew).
    assert_eq!(
        FileType::from_str(Ff::ObjectiveC.label()),
        FileType::ObjectiveC
    );
    assert_eq!(
        FileType::from_str(Ff::GithubActions.label()),
        FileType::GithubActions
    );
    assert_eq!(
        FileType::from_str(Ff::PythonBytecode.label()),
        FileType::Pyc
    );
    assert_eq!(
        FileType::from_str(Ff::VsixManifest.label()),
        FileType::VsixManifest
    );
    assert_eq!(
        FileType::from_str(Ff::ChromeManifest.label()),
        FileType::ChromeManifest
    );
    assert_eq!(FileType::from_str(Ff::OleDoc.label()), FileType::OleDoc);
    assert_eq!(
        FileType::from_str(Ff::PgpSignature.label()),
        FileType::PgpSignature
    );
    // MSI is its own routing bucket: the office analyzer reports subtype
    // "msi", and filefacts labels .msi/.msp as `msi` (not ole_doc).
    assert_eq!(FileType::from_str("msi"), FileType::Msi);
    assert_eq!(FileType::from_str("msp"), FileType::Msi);
    assert_eq!(FileType::from_str("mst"), FileType::Msi);
    assert_eq!(FileType::from_str("msm"), FileType::Msi);
    assert_eq!(FileType::from_str(Ff::Msi.label()), FileType::Msi);
    // Deliberate foldings: the report keeps the precise label, routing uses
    // the coarse bucket.
    assert_eq!(
        FileType::from_str(Ff::TypeScript.label()),
        FileType::JavaScript
    );
    // SVG is its own rule type, not an alias for XML: it is a media
    // carrier, and while it was folded into `Xml` every `for: [svg]` rule
    // silently targeted Android manifests and MSBuild projects as well.
    assert_eq!(FileType::from_str(Ff::Svg.label()), FileType::Svg);
    assert_eq!(
        FileType::from_str(Ff::ApkAndroid.label()),
        FileType::AndroidApk
    );
    assert_eq!(
        FileType::from_str(Ff::ApkAlpine.label()),
        FileType::AlpineApk
    );
    assert_eq!(FileType::from_str(Ff::Dex.label()), FileType::Dex);
    assert_eq!(FileType::from_str("dex"), FileType::Dex);
    assert_eq!(FileType::from_str(Ff::Cab.label()), FileType::Cab);
    assert_eq!(FileType::from_str(Ff::PkgArch.label()), FileType::Pkg);
    assert_eq!(FileType::from_str(Ff::TarZst.label()), FileType::Tar);
    assert_eq!(FileType::from_str(Ff::Dmg.label()), FileType::Dmg);
    assert_eq!(FileType::from_str(Ff::Asar.label()), FileType::Asar);
    assert_eq!(FileType::from_str(Ff::Phar.label()), FileType::Phar);
    assert_eq!(FileType::from_str(Ff::OciImage.label()), FileType::OciImage);
    assert_eq!(FileType::from_str(Ff::Xbps.label()), FileType::Xbps);
    assert_eq!(
        FileType::from_str(Ff::GentooBinpkg.label()),
        FileType::GentooBinpkg
    );
    assert_eq!(FileType::from_str(Ff::Odf.label()), FileType::Odf);
    // A `.a` static library routes to its own StaticLib bucket (a native
    // binary), NOT to Deb (the `ar`-magic sibling) or Unknown.
    assert_eq!(
        FileType::from_str(Ff::StaticLib.label()),
        FileType::StaticLib
    );
}

#[test]
fn static_lib_is_a_binary_not_an_archive() {
    // A static library is native object code: it must not carry the
    // archive-family `for:` bypass (which applied zip/jar content rules to
    // its uncompressed `ar` member bytes), and it must be reachable via the
    // `static-lib`/`a` tokens.
    assert!(!FileType::StaticLib.is_archive());
    assert_eq!(FileType::from_str("static-lib"), FileType::StaticLib);
    assert_eq!(FileType::from_str("a"), FileType::StaticLib);
}

#[test]
fn every_variant_has_a_distinct_type_bit() {
    // The mask was a bare `u128` until the 129th variant made
    // `1 << 128` panic on every archive scanned. Each variant must land
    // on its own bit, no bit may be shared, and a mask built from the
    // whole inventory must intersect every single type -- across the
    // word boundary that a one-word mask never crossed.
    let variants = FileType::all_variants();
    assert_eq!(variants.len(), FileType::VARIANT_COUNT);
    let mut union = TypeMask::EMPTY;
    for (i, ft) in variants.iter().enumerate() {
        let bit = ft.type_bit();
        assert_ne!(bit, TypeMask::EMPTY, "{ft:?} has no bit");
        assert!(!union.intersects(bit), "{ft:?} shares a bit");
        assert_eq!(ft.variant_index(), i);
        union |= bit;
    }
    for ft in &variants {
        assert!(union.intersects(ft.type_bit()));
        assert!(TypeMask::ALL.intersects(ft.type_bit()));
    }
    assert!(!TypeMask::EMPTY.intersects(TypeMask::ALL));
    // Two types on different words of the mask do not intersect.
    let first = variants[0].type_bit();
    let last = variants[variants.len() - 1].type_bit();
    assert!(!first.intersects(last));
    assert!((first | last).intersects(last));
}

#[test]
#[cfg(feature = "lint")]
fn label_round_trips_through_from_str() {
    // Every type name an author is shown must be one they can type back.
    // Three deliberate exceptions, none of which `from_str` owns:
    // `All` is a group keyword resolved in `capabilities::parsing`, and
    // `TypeScript`/`Cpp` fold onto `JavaScript`/`C` (one grammar, one
    // rule surface), so neither has a spelling of its own.
    for ft in FileType::all_variants() {
        if matches!(ft, FileType::TypeScript | FileType::Cpp | FileType::All) {
            continue;
        }
        assert_eq!(
            FileType::from_str(ft.label()),
            ft,
            "label() for {ft:?} is {:?}, which from_str does not map back",
            ft.label()
        );
    }
}

#[test]
fn rar_7z_cpio_are_their_own_archive_family_members() {
    // The old generic `archive` bucket collapsed rar/7z/cpio into one
    // undifferentiated type; each now has its own concrete FileType so
    // `for:` can target them individually, and the bare literal
    // "archive" is retired -- it must not resolve to anything.
    assert_eq!(FileType::from_str("rar"), FileType::Rar);
    assert_eq!(FileType::from_str("7z"), FileType::SevenZ);
    assert_eq!(FileType::from_str("cpio"), FileType::Cpio);
    assert_eq!(FileType::from_str("snap"), FileType::Snap);
    assert_eq!(FileType::from_str("squashfs"), FileType::SquashFs);
    assert!(FileType::Rar.is_archive());
    assert!(FileType::SevenZ.is_archive());
    assert!(FileType::Cpio.is_archive());
    assert!(FileType::Snap.is_archive());
    assert!(FileType::SquashFs.is_archive());
    assert_ne!(FileType::from_str("archive"), FileType::Rar);
    assert_ne!(FileType::from_str("archive"), FileType::SevenZ);
    assert_ne!(FileType::from_str("archive"), FileType::Cpio);
    assert_eq!(FileType::from_str("archive"), FileType::Unknown);
}

#[test]
fn archive_family_is_generated_from_enum_markers() {
    let family = FileType::archive_family_types();
    assert!(family.contains(&FileType::Rar));
    assert!(family.contains(&FileType::SevenZ));
    assert!(family.contains(&FileType::Cpio));
    assert!(family.contains(&FileType::Snap));
    assert!(family.contains(&FileType::SquashFs));
    assert!(family.contains(&FileType::Dmg));
    assert!(family.contains(&FileType::Asar));
    assert!(family.contains(&FileType::Phar));
    assert!(family.contains(&FileType::OciImage));
    assert!(family.contains(&FileType::Xbps));
    assert!(family.contains(&FileType::GentooBinpkg));
    assert!(FileType::Dmg.is_archive());
    assert!(!FileType::Gz.is_archive());
    assert!(!FileType::StaticLib.is_archive());
}

#[test]
#[allow(clippy::panic)]
fn container_bases_mirror_filefacts_archive_format() {
    use filefacts::{ArchiveFormat, FileType as Ff};
    // Every base is itself a base-less archive type, and every type that
    // has one is an archive: the relation is one level deep.
    for ft in FileType::all_variants() {
        for base in ft.container_bases() {
            assert!(ft.is_archive(), "{ft:?} has a base but is no archive");
            assert!(base.is_archive() && base.container_bases().is_empty());
        }
    }
    // filefacts owns the container decomposition; the rule buckets that
    // map 1:1 onto a filefacts type must agree with it.
    for ff in [
        Ff::ApkAndroid,
        Ff::Jar,
        Ff::Whl,
        Ff::Nupkg,
        Ff::GoModule,
        Ff::Composer,
        Ff::Hex,
        Ff::Pub,
        Ff::Cran,
        Ff::Cpan,
        Ff::Hackage,
        Ff::Crx,
        Ff::Xpi,
        Ff::Vsix,
        Ff::Egg,
        Ff::Ipa,
        Ff::Conda,
        Ff::ApkAlpine,
        Ff::Npm,
        Ff::Crate,
        Ff::Gem,
        Ff::PythonSdist,
        Ff::OciImage,
        Ff::Xbps,
        Ff::GentooBinpkg,
        Ff::PkgArch,
    ] {
        let base = match ff.archive_format() {
            Some(ArchiveFormat::Zip) => FileType::Zip,
            Some(ArchiveFormat::Tar) => FileType::Tar,
            other => panic!("{ff:?} decomposes to {other:?}"),
        };
        let bucket = FileType::from(ff);
        assert!(
            bucket.container_bases().contains(&base),
            "{bucket:?} ({ff:?}) is a {base:?} per filefacts"
        );
    }
    // Not subtypes of anything a rule can name.
    for ft in [FileType::Deb, FileType::Rpm, FileType::Zip, FileType::Tar] {
        assert!(ft.container_bases().is_empty(), "{ft:?}");
    }
}

#[test]
fn rule_applies_to_is_not_an_archive_family_union() {
    use FileType as T;
    assert!(!T::rule_applies_to(&[T::AndroidApk], T::Jar));
    assert!(!T::rule_applies_to(&[T::AndroidApk], T::Zip));
    assert!(!T::rule_applies_to(&[T::Jar], T::Zip));
    assert!(!T::rule_applies_to(&[T::Deb], T::Whl));
    assert!(T::rule_applies_to(&[T::Zip], T::Jar));
    assert!(T::rule_applies_to(&[T::Zip, T::AndroidApk], T::AndroidApk));
    assert!(T::rule_applies_to(&[T::Tar], T::Npm));
    assert!(T::rule_applies_to(&[T::All], T::Elf));
    assert!(T::rule_applies_to(&[T::Deb], T::All));
    assert!(!T::rule_applies_to(&[T::Python], T::All));
}

#[test]
#[allow(clippy::expect_used)]
fn yaml_deserializes_filefacts_archive_labels() {
    #[derive(Deserialize)]
    struct RuleTarget {
        #[serde(rename = "for")]
        file_types: Vec<FileType>,
    }

    let parsed: RuleTarget =
        crate::yaml::from_str("for: [apk_android, apk_alpine, cab, snap, squashfs]")
            .expect("valid YAML rule target");

    // apk_android and apk_alpine are unrelated ecosystems (Android app
    // sideloading vs. a musl-libc Linux package manager) and must not
    // collapse onto the same FileType.
    assert_eq!(
        parsed.file_types,
        vec![
            FileType::AndroidApk,
            FileType::AlpineApk,
            FileType::Cab,
            FileType::Snap,
            FileType::SquashFs,
        ]
    );
}

/// Author-facing aliases that are NOT canonical labels must still resolve
/// through the explicit table (the filefacts pre-pass returns `None` for
/// them and falls through).
#[test]
fn from_str_keeps_author_aliases() {
    assert_eq!(FileType::from_str("objc"), FileType::ObjectiveC);
    assert_eq!(
        FileType::from_str("github-actions"),
        FileType::GithubActions
    );
    assert_eq!(FileType::from_str("cpp"), FileType::C);
    assert_eq!(FileType::from_str("gomod"), FileType::GoMod);
    assert_eq!(FileType::from_str("ts"), FileType::JavaScript);
}

// ==================== Platform Equality Tests ====================

#[test]
fn test_platform_equality() {
    assert_eq!(Platform::Linux, Platform::Linux);
    assert_ne!(Platform::Linux, Platform::Windows);
}

#[test]
fn test_platform_rollup_intersection() {
    assert!(platforms_intersect(
        &[Platform::Commodore64],
        &[Platform::Commodore64]
    ));
    assert!(!platforms_intersect(
        &[Platform::Commodore64],
        &[Platform::Unix]
    ));
    assert!(!platforms_intersect(
        &[Platform::Commodore64],
        &[Platform::Windows]
    ));
    assert!(platforms_intersect(&[Platform::FreeBsd], &[Platform::Unix]));
    assert!(platforms_intersect(&[Platform::Unix], &[Platform::OpenWrt]));
    assert!(platforms_intersect(
        &[Platform::RouterOs],
        &[Platform::Appliance]
    ));
    assert!(platforms_intersect(
        &[Platform::Appliance],
        &[Platform::FortiOs]
    ));
    assert!(!platforms_intersect(
        &[Platform::MacOS],
        &[Platform::OpenWrt]
    ));
    assert!(!platforms_intersect(
        &[Platform::RouterOs],
        &[Platform::FortiOs]
    ));
    assert!(!platforms_intersect(
        &[Platform::RouterOs],
        &[Platform::Unix]
    ));
    assert!(!platforms_intersect(
        &[Platform::FreeBsd],
        &[Platform::Windows]
    ));
}

// ==================== FileType Comparison Tests ====================

#[test]
fn test_file_type_equality() {
    assert_eq!(FileType::Elf, FileType::Elf);
    assert_ne!(FileType::Elf, FileType::Macho);
}

#[test]
fn test_file_type_hash() {
    use std::collections::HashSet;
    let mut set = HashSet::new();
    set.insert(FileType::Elf);
    set.insert(FileType::Macho);
    set.insert(FileType::Elf); // Duplicate
    assert_eq!(set.len(), 2);
}

#[test]
fn test_file_type_ord() {
    // FileType derives Ord, so we can compare
    // Just verify it doesn't panic
    let _ = FileType::Elf < FileType::Macho;
}

// ==================== Arch::from_yara_rule_name Tests ====================

#[test]
fn test_yara_arch_x64_middle() {
    assert_eq!(
        Arch::from_yara_rule_name("GCTI_Cobaltstrike_Resources_Beacon_X64_V3_2"),
        Some(Arch::X86_64)
    );
}

#[test]
fn test_yara_arch_x64_end() {
    assert_eq!(
        Arch::from_yara_rule_name("SomeRule_X64"),
        Some(Arch::X86_64)
    );
}

#[test]
fn test_yara_arch_x86_middle() {
    assert_eq!(
        Arch::from_yara_rule_name("GCTI_Cobaltstrike_Sleeve_Beaconloader_X86_O_V4_3"),
        Some(Arch::X86)
    );
}

#[test]
fn test_yara_arch_x86_end() {
    assert_eq!(
        Arch::from_yara_rule_name("Casper_Backdoor_X86"),
        Some(Arch::X86)
    );
}

#[test]
fn test_yara_arch_lowercase_x64() {
    assert_eq!(
        Arch::from_yara_rule_name("beacon_loader_x64_v4"),
        Some(Arch::X86_64)
    );
}

#[test]
fn test_yara_arch_amd64() {
    assert_eq!(
        Arch::from_yara_rule_name("Loader_AMD64_Variant"),
        Some(Arch::X86_64)
    );
}

#[test]
fn test_yara_arch_arm64() {
    assert_eq!(
        Arch::from_yara_rule_name("Malware_ARM64_Loader"),
        Some(Arch::Aarch64)
    );
}

#[test]
fn test_yara_arch_aarch64() {
    assert_eq!(
        Arch::from_yara_rule_name("Linux_Trojan_AArch64_Backdoor"),
        Some(Arch::Aarch64)
    );
}

#[test]
fn test_yara_arch_i386() {
    assert_eq!(
        Arch::from_yara_rule_name("Exploit_I386_Shellcode"),
        Some(Arch::X86)
    );
}

#[test]
fn test_yara_arch_x32() {
    assert_eq!(
        Arch::from_yara_rule_name("Template_X32_Payload"),
        Some(Arch::X86)
    );
}

#[test]
fn test_yara_arch_none_generic_rule() {
    // No arch indicator — rule applies to any architecture
    assert_eq!(
        Arch::from_yara_rule_name("Linux_Trojan_Chinaz_a2140ca1"),
        None
    );
}

#[test]
fn test_yara_arch_none_cobalt_generic() {
    assert_eq!(
        Arch::from_yara_rule_name("GCTI_Cobaltstrike_Resources_Artifact_Dll_V1_49_To_V3_14"),
        None
    );
}

#[test]
fn test_yara_arch_no_false_positive_hex_suffix() {
    // "64" alone inside a hash suffix should NOT be parsed as arch
    assert_eq!(
        Arch::from_yara_rule_name("Linux_Exploit_CVE_2016_5195_364f3b7b"),
        None
    );
}

#[test]
fn test_yara_arch_no_false_positive_version() {
    // "V3_14" should not match X86 due to partial overlap
    assert_eq!(Arch::from_yara_rule_name("Beacon_V3_14"), None);
}

#[test]
fn test_yara_arch_x86_64_explicit() {
    assert_eq!(
        Arch::from_yara_rule_name("Shellcode_X86_64_Reverse"),
        Some(Arch::X86_64)
    );
}

#[test]
fn test_yara_arch_win32_implies_x86_64() {
    assert_eq!(
        Arch::from_yara_rule_name("Win32_Trojan_Emotet_abc123"),
        Some(Arch::X86_64)
    );
}

#[test]
fn test_yara_arch_win64_implies_x86_64() {
    assert_eq!(
        Arch::from_yara_rule_name("Win64_Ransomware_LockBit"),
        Some(Arch::X86_64)
    );
}

#[test]
fn test_yara_arch_win32_arm64_override() {
    // Explicit ARM64 takes precedence over Win32 default
    assert_eq!(
        Arch::from_yara_rule_name("Win32_Trojan_ARM64_Loader"),
        Some(Arch::Aarch64)
    );
}

#[test]
fn test_yara_arch_win32_case_insensitive() {
    assert_eq!(
        Arch::from_yara_rule_name("win32_backdoor_cobalt"),
        Some(Arch::X86_64)
    );
}

#[test]
fn test_contains_word_boundaries() {
    // At start
    assert!(contains_word("X64_LOADER", "X64"));
    // At end
    assert!(contains_word("LOADER_X64", "X64"));
    // Middle
    assert!(contains_word("A_X64_B", "X64"));
    // Exact match
    assert!(contains_word("X64", "X64"));
    // Not a word boundary (embedded in larger token)
    assert!(!contains_word("FOX64BAR", "X64"));
    // Prefix match but not suffix
    assert!(!contains_word("X64BAR", "X64"));
    // Suffix match but not prefix
    assert!(!contains_word("FOX64", "X64"));
}
