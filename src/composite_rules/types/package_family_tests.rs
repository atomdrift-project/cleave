use super::FileType;

/// Every `#[package]` variant must also be `#[archive]`. A package is a
/// container by definition, and `parent_package` only ever inspects
/// ancestors that the archive walk produced -- a package-but-not-archive
/// type would be unreachable there, silently.
#[test]
fn every_package_is_an_archive() {
    let strays: Vec<_> = FileType::package_family_types()
        .iter()
        .filter(|ft| !FileType::is_archive(ft))
        .collect();
    assert!(
        strays.is_empty(),
        "package types missing #[archive]: {strays:?}"
    );
}

/// The split is "unit of distribution" vs "generic container". Spelled out
/// so a new variant has to make a deliberate choice rather than inherit one.
#[test]
fn the_split_is_distribution_versus_container() {
    for ft in [
        FileType::Npm,
        FileType::Gem,
        FileType::GoModule,
        FileType::Composer,
        FileType::Hex,
        FileType::Pub,
        FileType::Cran,
        FileType::Cpan,
        FileType::Hackage,
        FileType::Whl,
        FileType::Deb,
        FileType::Rpm,
        FileType::AlpineApk,
        FileType::AndroidApk,
        FileType::Ipa,
        FileType::VsixArchive,
        FileType::Crx,
        FileType::Xpi,
        FileType::OciImage,
    ] {
        assert!(ft.is_package(), "{ft:?} is a unit of distribution");
    }
    for ft in [
        FileType::Zip,
        FileType::Tar,
        FileType::Iso,
        FileType::Asar,
        FileType::Cab,
        FileType::Dmg,
        // A container format reused everywhere (jar-in-war, jar-in-ear),
        // not a boundary an author means by "this package".
        FileType::Jar,
    ] {
        assert!(!ft.is_package(), "{ft:?} is a generic container");
    }
}

/// Both halves of the old hand-written pair are gone; `from_str` has to
/// route every label filefacts emits for a package onto a `#[package]`
/// variant, or the ancestor walk stops recognising it.
#[test]
fn package_labels_round_trip_through_from_str() {
    for label in [
        "npm",
        "nupkg",
        "go_module",
        "composer",
        "hex",
        "pub",
        "cran",
        "cpan",
        "hackage",
        "gem",
        "whl",
        "python_sdist",
        "crate",
        "conda",
        "egg",
        "deb",
        "rpm",
        "apk_alpine",
        "apk_android",
        "xbps",
        "oci_image",
    ] {
        assert!(
            FileType::from_str(label).is_package(),
            "label {label} must route to a #[package] type"
        );
    }
    for label in ["zip", "tar", "iso", "jar", "elf", "javascript"] {
        assert!(
            !FileType::from_str(label).is_package(),
            "label {label} must not be a package"
        );
    }
}
