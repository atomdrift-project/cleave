//! Binary-metadata kv-tree synthesis.
//!
//! Cross-format string-typed binary metadata (compiler versions,
//! build-id strings, PE VERSIONINFO fields, Go buildinfo, ELF
//! interpreter / rpath / .comment strings, Mach-O LC_UUID, etc.)
//! — the binary-side equivalent of what `office_kv`/`rtf_kv`/
//! `pdf_kv` do for documents.
//!
//! Numeric metrics keep living on `BinaryMetrics`/`PeMetrics`/
//! `ElfMetrics`/`MachoMetrics`; the kv tree is for strings, paths,
//! and small structured values that benefit from `path:`/`regex:`/
//! `substr:` traits.
//!
//! # Schema (stable trait-base API — Pike-pass naming)
//!
//! Each field appears in exactly one place.  When a value could be
//! grouped under `build.*` or under a format-specific section, it
//! lives under the format-specific section ONLY when it has no
//! cross-format analogue.  Booleans use the `is_*`/`has_*` prefix
//! conventional in EMBER/lief/pefile.  Hashes group under
//! `hashes.*`; provenance under `<field>_from`.
//!
//! ```text
//! build:                    cross-format toolchain / build environment
//!   target_arch             "x86_64" | "aarch64" | "x86" | ...
//!   toolchain               "go1.26.2" | "gcc 13.2.0" | "MSVC 19.29" | ...
//!   toolchain_family        "go" | "gcc" | "clang" | "msvc" | "rustc" | ...
//!   distro                  "ubuntu" | "debian" | "alpine" | ...   (B0.5)
//!   command_line            "-O2 -fstack-protector-strong ..."     (B0.5)
//!   sanitizers[]            ["asan", "ubsan", "pgo", ...]          (B0.5)
//!   fortified[]             ["sprintf", "strcpy", "memcpy", ...]   (B3.5 — FORTIFY_SOURCE _chk imports)
//!   username                "alice"        (single canonical, present when unambiguous)
//!   usernames[]             ["alice", "bob"]   (only when multiple — exclusive with `username`)
//!   user_home               "/Users/alice"   (single, when `username` is set and prefix known)
//!   username_from           "pdb_path" | "byte_scan"
//!   source_paths[]          ["/Users/.../main.go", ...]  (capped, in scan order)
//!   build_root              "/Users/alice/projects/sample"  (longest common ancestor)
//!   is_pie                  bool
//!   is_stripped             bool
//!   has_debug_info          bool
//!   ci_environment          "github-actions" | "gitlab-ci" | ...   (planned)
//!   linker                  "ld" | "gold" | "lld" | "mold" | ...   (planned)
//!
//! signing:                  cross-format signing metadata
//!   is_signed               bool
//!   signature_valid         bool
//!   hardened_runtime        bool         (Mach-O)
//!   allow_jit               bool         (Mach-O)
//!   catalog                 "authenticode" | "apple_codesign"
//!   type                    "adhoc" | "developer-id" | "platform"       (Mach-O)
//!   signer_subject          "Adobe Inc." | "Microsoft Corporation"      (PE+Mach-O)
//!   authorities[]           ["Apple Root CA", ...]                      (Mach-O cert chain)
//!   signing_time            Unix epoch seconds                          (PE Authenticode)
//!   signed_before_built     bool — re-sign / replay attack flag
//!   signer_issuer           "CN=DigiCert Trusted G4 Code Signing ..."   (planned)
//!   signer_thumbprint       "<hex>"                                     (planned)
//!   countersign_time        "<ISO 8601>"                                (planned)
//!   team_id                 "9XQGPJ8B7K"                                (B4 — Mach-O)
//!   bundle_identifier       "com.example.app"                           (B4)
//!   notarized               bool                                        (B4)
//!   cs_flags[]              ["host", "runtime", "library_validation"]   (planned)
//!   entitlements            { entitlement_key: bool|string|[string] }   (B4)
//!
//! debug:                    cross-format debug metadata
//!   pdb_path                "C:\\Users\\dev\\projects\\sample.pdb"
//!   has_build_id            bool   (single source of truth)
//!   has_debuglink           bool
//!   producer                "GNU C++23 13.2.0 ..."                      (B3)
//!   comp_dir                "/home/dev/proj/build"                      (B3)
//!
//! pe:                       PE-specific
//!   timestamp               COFF TimeDateStamp (Unix epoch seconds; 0 = deterministic)
//!   timestamp_is_zero       bool — explicit deterministic-build flag
//!   checksum                "0x........" — populated only when set
//!   linker_version          "14.39"
//!   dll_characteristics:    decoded named flags (only true ones present)
//!     high_entropy_va, dynamic_base (ASLR), force_integrity,
//!     nx_compat (DEP), no_isolation, no_seh, no_bind, appcontainer,
//!     wdm_driver, guard_cf (Control Flow Guard), terminal_server_aware
//!   debug_directory_types[] [16, 13, ...] — sorted IMAGE_DEBUG_TYPE_* values
//!   is_reproducible_build   bool — IMAGE_DEBUG_TYPE_REPRO (16) present
//!   has_pogo                bool — IMAGE_DEBUG_TYPE_POGO (13) present (PGO data)
//!   has_iltcg               bool — IMAGE_DEBUG_TYPE_ILTCG (14) present
//!   has_vc_feature          bool — IMAGE_DEBUG_TYPE_VC_FEATURE (12) present
//!   codeview_guid           "XXXX-XXXX-..." — RSDS PDB age GUID
//!   codeview_age            integer — PDB age counter
//!   rich_header.entries[]   [{ product_id, product_name, build_number, use_count }, ...]
//!   rich_header.xor_key     "0x..."
//!   version_info.{...}      snake_case'd VS_VERSIONINFO StringTable
//!                           keys: company_name, file_description, file_version,
//!                                 internal_name, original_filename, product_name,
//!                                 product_version, legal_copyright,
//!                                 legal_trademarks, comments, private_build,
//!                                 special_build
//!
//! elf:                      ELF-specific
//!   entry_section           ".text" | ".init" | ".init_array" | ...
//!   has_interpreter         bool
//!   has_soname              bool
//!   has_canary              bool
//!   has_textrel             bool
//!   nx_stack                bool
//!   relro                   "full" | "partial" | "none"
//!   interpreter             "/lib64/ld-linux-x86-64.so.2"        (B0.5)
//!   comment                 "GCC: (Ubuntu 13.2.0-23ubuntu4) ..."  (B0.5)
//!   soname                  "libfoo.so.1"                         (B3)
//!   rpath[]                 ["/opt/local/lib"]                    (B3)
//!   runpath[]                                                     (B3)
//!   needed[]                ["libc.so.6", ...]                    (B3)
//!   gnu_property.{ibt,shstk,pac,bti,x86_isa_level}                (B3)
//!
//! macho:                    Mach-O specific
//!   uuid                    "<hex>"                               (B4)
//!   filetype                "executable" | "dylib" | "bundle" | ... (B4)
//!   platform                "macOS" | "iOS" | "tvOS" | ...        (B4 — from LC_BUILD_VERSION)
//!   min_os_version          "10.13.0"
//!   sdk_version             "11.0.0"
//!   tools[]                 [{ tool, version }]                   (B4 — clang / swiftc / ld)
//!   source_version          "1.2.3"                               (B4 — LC_SOURCE_VERSION)
//!   id_dylib                "@rpath/MyFramework"                  (B4 — dylibs only)
//!   load_dylibs[]           [{ path, kind, current_version, compatibility_version }]
//!   rpath[]                                                       (B4)
//!   linker_options[]                                              (B4)
//!
//! go:                       Go-specific (cross-binary)
//!   version                 "go1.26.2"
//!   main_path               "github.com/attacker/sample"
//!   main_module.{path, version, sum}
//!   dependencies[]          [{ path, version, sum, replaced_by }]
//!   build:                  flat dict; original Go-spec keys snake-cased
//!     mode                  "exe" | "c-archive" | "plugin" | ...     (was -buildmode)
//!     compiler              "gc" | "gccgo"                           (was -compiler)
//!     goos, goarch, goamd64, goarm                                   (env-style)
//!     cgo                   bool                                     (parsed from CGO_ENABLED)
//!     trimpath              bool                                     (was -trimpath)
//!     ldflags               "..."
//!     asmflags, gcflags     "..."
//!   vcs.{type, revision, time, modified}                             (was vcs.* keys)
//!
//! hashes:                   fuzzy / similarity / cluster hashes
//!   imphash                 "<md5>"                                  (PE)
//!   rich_header_hash        "<sha256>"                               (PE — single canonical location)
//!   ssdeep, tlsh            "..."                                    (cross-format)  (planned)
//!   authentihash            "..."                                    (PE)            (planned)
//!   cdhash                  "..."                                    (Mach-O)        (planned)
//!   gimphash                "..."                                    (Go)            (planned)
//! ```

use crate::types::AnalysisReport;
use serde_json::{json, Map, Value};

/// Build the cross-format binary kv tree from data already
/// populated on `report.metrics` and `report.target`.  Specialized
/// extractors (Go buildinfo, VERSIONINFO strings, ELF interpreter,
/// Mach-O LC_UUID) inject additional sections via [`extend_with`]
/// before the analyzer stashes the result on `report.kv_tree`.
#[must_use]
pub(crate) fn build_binary_kv(report: &AnalysisReport) -> Value {
    let mut root = Map::new();

    // build.* — cross-format toolchain + build environment
    let build = build_section(report);
    if !build.is_empty() {
        root.insert("build".into(), Value::Object(build));
    }

    // signing.* — cross-format signing metadata
    let signing = signing_section(report);
    if !signing.is_empty() {
        root.insert("signing".into(), Value::Object(signing));
    }

    // debug.* — cross-format debug metadata (PDB on PE; producer /
    // comp_dir / debuglink filled by per-format extenders)
    let debug = debug_section(report);
    if !debug.is_empty() {
        root.insert("debug".into(), Value::Object(debug));
    }

    // pe.*, elf.*, macho.* — format-specific
    if let Some(pe) = pe_section(report) {
        root.insert("pe".into(), Value::Object(pe));
    }
    if let Some(elf) = elf_section(report) {
        root.insert("elf".into(), Value::Object(elf));
    }
    if let Some(macho) = macho_section(report) {
        root.insert("macho".into(), Value::Object(macho));
    }

    Value::Object(root)
}

fn build_section(report: &AnalysisReport) -> Map<String, Value> {
    let mut out = Map::new();
    let metrics = match report.metrics.as_ref() {
        Some(m) => m,
        None => return out,
    };

    // Architecture is on TargetInfo, not metrics.
    if let Some(arches) = report.target.architectures.as_ref() {
        if let Some(first) = arches.first() {
            out.insert("target_arch".into(), json!(first));
        }
    }

    if let Some(bin) = metrics.binary.as_ref() {
        if bin.is_pie {
            out.insert("is_pie".into(), json!(true));
        }
        if bin.is_stripped {
            out.insert("is_stripped".into(), json!(true));
        }
        if bin.has_debug_info {
            out.insert("has_debug_info".into(), json!(true));
        }
        // signing flag lives on `signing.*` only (avoid duplicating
        // the same boolean across two namespaces).
    }

    out
}

fn signing_section(report: &AnalysisReport) -> Map<String, Value> {
    let mut out = Map::new();
    let metrics = match report.metrics.as_ref() {
        Some(m) => m,
        None => return out,
    };

    if let Some(bin) = metrics.binary.as_ref() {
        if bin.has_signature {
            out.insert("is_signed".into(), json!(true));
            if let Some(valid) = bin.signature_valid {
                out.insert("signature_valid".into(), json!(valid));
            }
        }
    }
    // PE Authenticode primary signer (Mach-O leaf-cert CN is surfaced
    // via the `binary_extractors` path; deep_merge gives macho-side
    // values precedence when both populate the field).
    if let Some(pe) = metrics.pe.as_ref() {
        if let Some(signer) = pe.primary_signer.as_deref() {
            if !signer.is_empty() {
                out.insert("signer_subject".into(), json!(signer));
            }
        } else if let Some(signer) = pe.signer.as_deref() {
            if !signer.is_empty() {
                out.insert("signer_subject".into(), json!(signer));
            }
        }
    }

    // PE-specific signing fields: timestamp + before-build sanity flag.
    if let Some(pe) = metrics.pe.as_ref() {
        if pe.signing_time != 0 {
            out.insert("signing_time".into(), json!(pe.signing_time));
        }
        if pe.signing_time_before_timestamp {
            // Signed before linked = re-signed binary or stripped/replayed
            // signature. Strong supply-chain swap signal.
            out.insert("signed_before_built".into(), json!(true));
        }
        // Cross-format catalog identifier so trait authors can
        // disambiguate Mach-O vs PE Authenticode without checking
        // file_type.  PE-side signature presence comes from the
        // shared `binary.has_signature` flag set above.
        if metrics.binary.as_ref().is_some_and(|b| b.has_signature) {
            out.entry("catalog".to_string())
                .or_insert_with(|| json!("authenticode"));
        }
    }

    // Mach-O hardened runtime / JIT entitlement live on MachoMetrics
    // as flat booleans; surface them under the unified signing tree
    // alongside the cross-format keys.
    if let Some(macho) = metrics.macho.as_ref() {
        if macho.hardened_runtime {
            out.insert("hardened_runtime".into(), json!(true));
        }
        if macho.allow_jit {
            out.insert("allow_jit".into(), json!(true));
        }
    }

    out
}

fn debug_section(report: &AnalysisReport) -> Map<String, Value> {
    let mut out = Map::new();
    let metrics = match report.metrics.as_ref() {
        Some(m) => m,
        None => return out,
    };

    if let Some(pe) = metrics.pe.as_ref() {
        if let Some(pdb) = pe.pdb_path.as_deref() {
            let trimmed = pdb.trim();
            if !trimmed.is_empty() {
                out.insert("pdb_path".into(), json!(trimmed));
            }
        }
    }

    if let Some(elf) = metrics.elf.as_ref() {
        if elf.debuglink_present {
            out.insert("has_debuglink".into(), json!(true));
        }
        if elf.build_id_present {
            out.insert("has_build_id".into(), json!(true));
        }
        if let Some(bid) = elf.build_id.as_deref() {
            if !bid.is_empty() {
                out.insert("build_id".into(), json!(bid));
            }
        }
    }
    // Mach-O UUID is mirrored to `build.build_id` by `binary_extractors`;
    // ELF GNU build-id sits at `debug.build_id` (above). Trait authors
    // should target `debug.build_id` for ELF and either `macho.uuid` or
    // `build.build_id` for Mach-O.

    out
}

fn pe_section(report: &AnalysisReport) -> Option<Map<String, Value>> {
    let metrics = report.metrics.as_ref()?;
    let pe = metrics.pe.as_ref()?;
    let mut out = Map::new();

    // Decode DLL characteristics into named flags. The raw bitfield is
    // also kept for ML, but trait authors can target the named bools
    // directly. Defaults zero across all flags drop the subtree.
    if pe.dll_characteristics != 0 {
        let dc = pe.dll_characteristics;
        let mut flags = Map::new();
        if dc & 0x0020 != 0 {
            flags.insert("high_entropy_va".into(), json!(true));
        }
        if dc & 0x0040 != 0 {
            flags.insert("dynamic_base".into(), json!(true));
        }
        if dc & 0x0080 != 0 {
            flags.insert("force_integrity".into(), json!(true));
        }
        if dc & 0x0100 != 0 {
            flags.insert("nx_compat".into(), json!(true));
        }
        if dc & 0x0200 != 0 {
            flags.insert("no_isolation".into(), json!(true));
        }
        if dc & 0x0400 != 0 {
            flags.insert("no_seh".into(), json!(true));
        }
        if dc & 0x0800 != 0 {
            flags.insert("no_bind".into(), json!(true));
        }
        if dc & 0x1000 != 0 {
            flags.insert("appcontainer".into(), json!(true));
        }
        if dc & 0x2000 != 0 {
            flags.insert("wdm_driver".into(), json!(true));
        }
        if dc & 0x4000 != 0 {
            flags.insert("guard_cf".into(), json!(true));
        }
        if dc & 0x8000 != 0 {
            flags.insert("terminal_server_aware".into(), json!(true));
        }
        if !flags.is_empty() {
            out.insert("dll_characteristics".into(), Value::Object(flags));
        }
    }

    // Debug Directory metadata. The Reproducible flag is the
    // supply-chain signal — vendors that previously set it and
    // stop are visibly tampered. POGO + ILTCG reveal MSVC release
    // builds with PGO/incremental link-time codegen.
    if !pe.debug_directory_types.is_empty() {
        out.insert(
            "debug_directory_types".into(),
            json!(pe.debug_directory_types.clone()),
        );
    }
    if pe.is_reproducible_build {
        out.insert("is_reproducible_build".into(), json!(true));
    }
    if pe.has_pogo {
        out.insert("has_pogo".into(), json!(true));
    }
    if pe.has_iltcg {
        out.insert("has_iltcg".into(), json!(true));
    }
    if pe.has_vc_feature {
        out.insert("has_vc_feature".into(), json!(true));
    }
    if let Some(guid) = pe.codeview_guid.as_deref() {
        if !guid.is_empty() {
            out.insert("codeview_guid".into(), json!(guid));
            if pe.codeview_age > 0 {
                out.insert("codeview_age".into(), json!(pe.codeview_age));
            }
        }
    }

    // Linker version — pair of (major, minor). Composes with Rich
    // header to identify the exact MSVC link-time toolchain.
    if pe.linker_major_version > 0 || pe.linker_minor_version > 0 {
        out.insert(
            "linker_version".into(),
            json!(format!(
                "{}.{}",
                pe.linker_major_version, pe.linker_minor_version
            )),
        );
    }

    // COFF timestamp — the canonical "when was this linked" field.
    // Zero / hash-based values indicate deterministic builds.
    if pe.timestamp != 0 {
        out.insert("timestamp".into(), json!(pe.timestamp));
    }
    if pe.timestamp_is_zero {
        out.insert("timestamp_is_zero".into(), json!(true));
    }

    // Optional-header checksum. Most modern compilers leave this 0;
    // populated values identify Windows-specific link toolchains.
    if pe.checksum_present {
        out.insert("checksum".into(), json!(format!("0x{:08x}", pe.checksum)));
    }

    if out.is_empty() {
        return None;
    }
    Some(out)
}

fn elf_section(report: &AnalysisReport) -> Option<Map<String, Value>> {
    let metrics = report.metrics.as_ref()?;
    let elf = metrics.elf.as_ref()?;
    let mut out = Map::new();

    if let Some(entry) = elf.entry_section.as_deref() {
        if !entry.is_empty() {
            out.insert("entry_section".into(), json!(entry));
        }
    }
    if elf.has_interpreter {
        out.insert("has_interpreter".into(), json!(true));
    }
    if elf.has_soname {
        out.insert("has_soname".into(), json!(true));
    }
    // build-id / debuglink flags are cross-format debug metadata —
    // exposed once under `debug.*` and not duplicated here.
    if elf.stack_canary {
        out.insert("has_canary".into(), json!(true));
    }
    if elf.nx_enabled {
        out.insert("nx_stack".into(), json!(true));
    }
    if elf.textrel_present {
        out.insert("has_textrel".into(), json!(true));
    }
    if let Some(relro) = elf.relro.as_deref() {
        if !relro.is_empty() {
            out.insert("relro".into(), json!(relro));
        }
    }
    // Dynamic-table strings — single canonical location for trait
    // authors hunting for "what does this binary depend on" and
    // "where does the loader look for libraries".
    if let Some(soname) = elf.soname.as_deref() {
        if !soname.is_empty() {
            out.insert("soname".into(), json!(soname));
        }
    }
    if !elf.needed.is_empty() {
        out.insert("needed".into(), json!(elf.needed.clone()));
    }
    if !elf.rpaths.is_empty() {
        out.insert("rpath".into(), json!(elf.rpaths.clone()));
    }
    if !elf.runpaths.is_empty() {
        out.insert("runpath".into(), json!(elf.runpaths.clone()));
    }

    if out.is_empty() {
        return None;
    }
    Some(out)
}

fn macho_section(report: &AnalysisReport) -> Option<Map<String, Value>> {
    let metrics = report.metrics.as_ref()?;
    let macho = metrics.macho.as_ref()?;
    let mut out = Map::new();

    // Compose minos/sdk version strings from numeric pieces if non-zero.
    if macho.min_os_major > 0 {
        let minos = format!(
            "{}.{}.{}",
            macho.min_os_major, macho.min_os_minor, macho.min_os_patch
        );
        out.insert("min_os_version".into(), json!(minos));
    }
    if macho.sdk_major > 0 {
        let sdk = format!(
            "{}.{}.{}",
            macho.sdk_major, macho.sdk_minor, macho.sdk_patch
        );
        out.insert("sdk_version".into(), json!(sdk));
    }

    if out.is_empty() {
        return None;
    }
    Some(out)
}

/// Merge a partial value into the binary kv root in place.  Used by
/// the format-specific extractors (Go buildinfo, VERSIONINFO,
/// `.comment`, LC_UUID, etc.) to layer their data without re-walking
/// the whole structure.  Empty objects/arrays are dropped.
pub(crate) fn extend_with(root: &mut Value, key: &str, value: Value) {
    if value.is_null() {
        return;
    }
    if let Some(obj) = value.as_object() {
        if obj.is_empty() {
            return;
        }
    }
    if let Some(arr) = value.as_array() {
        if arr.is_empty() {
            return;
        }
    }
    if let Some(obj) = root.as_object_mut() {
        obj.insert(key.to_string(), value);
    }
}

/// Stash the synthesized binary kv tree on `report.kv_tree`.  Drops
/// when the tree comes back empty so non-binary file types and
/// minimal stub binaries don't carry an empty `kv_tree` field.
pub(crate) fn attach_to_report(report: &mut AnalysisReport) {
    let kv = build_binary_kv(report);
    if kv.as_object().is_some_and(|m| !m.is_empty()) {
        report.kv_tree = Some(Box::new(kv));
    }
}

/// `cleave kv` dispatcher entry — takes a parsed binary report and
/// returns its kv tree. Used by the kv command after the analyzer
/// has run; not a parser-from-bytes entry.
pub(crate) fn extract_binary_kv(report: &AnalysisReport) -> Option<Value> {
    let kv = build_binary_kv(report);
    if kv.as_object().is_some_and(|m| !m.is_empty()) {
        Some(kv)
    } else {
        None
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::types::binary_metrics::{BinaryMetrics, ElfMetrics, MachoMetrics, PeMetrics};
    use crate::types::scores::Metrics;
    use crate::types::TargetInfo;

    fn report_with_metrics(metrics: Metrics, ftype: &str) -> AnalysisReport {
        let mut report = AnalysisReport::new(TargetInfo {
            path: "test".into(),
            file_type: ftype.into(),
            size_bytes: 4096,
            sha256: "0".repeat(64),
            architectures: Some(vec!["x86_64".into()]),
        });
        report.metrics = Some(metrics);
        report
    }

    #[test]
    fn build_section_includes_arch_and_pie() {
        let m = Metrics {
            binary: Some(BinaryMetrics {
                is_pie: true,
                is_stripped: true,
                ..Default::default()
            }),
            ..Default::default()
        };
        let r = report_with_metrics(m, "elf");
        let kv = build_binary_kv(&r);
        assert_eq!(kv["build"]["target_arch"], "x86_64");
        assert_eq!(kv["build"]["is_pie"], true);
        assert_eq!(kv["build"]["is_stripped"], true);
    }

    #[test]
    fn debug_pdb_path_surfaces_for_pe() {
        let m = Metrics {
            pe: Some(PeMetrics {
                pdb_path: Some("C:\\Users\\dev\\projects\\sample.pdb".into()),
                ..Default::default()
            }),
            ..Default::default()
        };
        let r = report_with_metrics(m, "pe");
        let kv = build_binary_kv(&r);
        assert_eq!(
            kv["debug"]["pdb_path"],
            "C:\\Users\\dev\\projects\\sample.pdb"
        );
    }

    #[test]
    fn elf_section_surfaces_canary_and_relro() {
        let m = Metrics {
            elf: Some(ElfMetrics {
                stack_canary: true,
                nx_enabled: true,
                relro: Some("full".into()),
                build_id_present: true,
                entry_section: Some(".text".into()),
                ..Default::default()
            }),
            ..Default::default()
        };
        let r = report_with_metrics(m, "elf");
        let kv = build_binary_kv(&r);
        assert_eq!(kv["elf"]["entry_section"], ".text");
        assert_eq!(kv["elf"]["has_canary"], true);
        assert_eq!(kv["elf"]["nx_stack"], true);
        assert_eq!(kv["elf"]["relro"], "full");
        // build-id flag exposed once under `debug.*`, not duplicated
        // under format-specific subtrees.
        assert!(kv["elf"].get("has_build_id").is_none());
        assert_eq!(kv["debug"]["has_build_id"], true);
    }

    #[test]
    fn elf_dynamic_strings_surface_under_kv() {
        let m = Metrics {
            elf: Some(ElfMetrics {
                soname: Some("libfoo.so.1".into()),
                needed: vec!["libc.so.6".into(), "libpthread.so.0".into()],
                rpaths: vec!["/opt/local/lib".into(), "$ORIGIN/lib".into()],
                runpaths: vec!["/usr/local/lib".into()],
                ..Default::default()
            }),
            ..Default::default()
        };
        let r = report_with_metrics(m, "elf");
        let kv = build_binary_kv(&r);
        assert_eq!(kv["elf"]["soname"], "libfoo.so.1");
        assert_eq!(kv["elf"]["needed"][0], "libc.so.6");
        assert_eq!(kv["elf"]["needed"][1], "libpthread.so.0");
        assert_eq!(kv["elf"]["rpath"][0], "/opt/local/lib");
        assert_eq!(kv["elf"]["rpath"][1], "$ORIGIN/lib");
        assert_eq!(kv["elf"]["runpath"][0], "/usr/local/lib");
    }

    #[test]
    fn macho_min_and_sdk_version_composed() {
        let m = Metrics {
            macho: Some(MachoMetrics {
                min_os_major: 10,
                min_os_minor: 13,
                min_os_patch: 0,
                sdk_major: 11,
                sdk_minor: 0,
                sdk_patch: 0,
                hardened_runtime: true,
                ..Default::default()
            }),
            ..Default::default()
        };
        let r = report_with_metrics(m, "macho");
        let kv = build_binary_kv(&r);
        assert_eq!(kv["macho"]["min_os_version"], "10.13.0");
        assert_eq!(kv["macho"]["sdk_version"], "11.0.0");
        assert_eq!(kv["signing"]["hardened_runtime"], true);
    }

    #[test]
    fn signing_signed_with_valid_signature() {
        let m = Metrics {
            binary: Some(BinaryMetrics {
                has_signature: true,
                signature_valid: Some(true),
                ..Default::default()
            }),
            ..Default::default()
        };
        let r = report_with_metrics(m, "pe");
        let kv = build_binary_kv(&r);
        assert_eq!(kv["signing"]["is_signed"], true);
        assert_eq!(kv["signing"]["signature_valid"], true);
        // is_signed lives on `signing.*` only (no `build.is_signed`
        // duplicate); the build section omits the flag entirely.
        assert!(kv["build"].get("is_signed").is_none());
    }

    #[test]
    fn report_with_no_metrics_produces_empty_tree() {
        let r = AnalysisReport::new(TargetInfo {
            path: "test".into(),
            file_type: "elf".into(),
            size_bytes: 4096,
            sha256: "0".repeat(64),
            architectures: None,
        });
        let kv = build_binary_kv(&r);
        assert_eq!(kv, json!({}));
    }

    #[test]
    fn extend_with_drops_empty() {
        let mut root = json!({});
        extend_with(&mut root, "go", json!({}));
        extend_with(&mut root, "elf", json!([]));
        extend_with(&mut root, "macho", json!({"uuid": "abc"}));
        assert!(root.get("go").is_none());
        assert!(root.get("elf").is_none());
        assert_eq!(root["macho"]["uuid"], "abc");
    }
}
