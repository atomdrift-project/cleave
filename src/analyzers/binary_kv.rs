//! Binary-metadata kv-tree synthesis.
//!
//! The kv tree is the **values** half of cleave's binary surface:
//! strings, paths, identifiers, hex digests, structured trees, and
//! decoded named bit-flags lifted directly from the binary. Trait
//! authors target it with `type: kv, path: ..., regex:/exists:`.
//!
//! The other half — booleans, counts, derived numerics, cross-format
//! comparisons — lives on metrics structs (`BinaryMetrics`,
//! `PeMetrics`, `ElfMetrics`, `MachoMetrics`) and is the ML feature
//! surface. Trait authors target it with `type: metrics, field: ...`.
//!
//! # Disjoint by data kind
//!
//! Every fact lives in exactly one tree. There are no metric→kv
//! mirrors. A field is in kv iff it's a value; in metrics iff it's a
//! bool, count, or computed scalar. The one carve-out: decoded
//! named-bit subtrees in kv (`pe.dll_characteristics.*`,
//! `elf.dt_flags.*`, `macho.cs_flags.*`, `macho.header_flags.*`) are
//! a labeling convenience over a single raw `u32` bitfield that lives
//! on metrics — same source, two access modes (numeric thresholds vs
//! `exists:` per-bit traits).
//!
//! # Naming rules
//!
//! - `_` separates words inside one identifier; `.` traverses into a
//!   sub-object. Never create a one-child subtree.
//! - Promote atomic→subtree only when ≥2 sibling fields share a
//!   meaningful conceptual prefix (`pe.codeview.{guid, age}` not
//!   `pe.codeview_guid`).
//! - Industry-canonical names preserved verbatim
//!   (`imphash`, `dll_characteristics`, `package.type` per FDO,
//!   `bundle_identifier`).
//! - Booleans live on metrics — kv carries only values. Where a value
//!   exists, traits test presence via `exists: true|false`.
//!
//! # Schema
//!
//! ```text
//! build:                    cross-format toolchain / build environment
//!   target_arch             "x86_64" | "aarch64" | "x86" | ...
//!   toolchain               "go1.26.2" | "gcc 13.2.0" | "MSVC 19.29" | ...
//!   toolchain_family        "go" | "gcc" | "clang" | "msvc" | "rustc" | ...
//!   linker                  "gold" | "lld" | "mold" | "bfd"
//!   distro                  "ubuntu" | "debian" | "alpine" | ...
//!   command_line            "-O2 -fstack-protector-strong ..."
//!   sanitizers[]            ["asan", "ubsan", "pgo", ...]
//!   fortified[]             ["sprintf", "strcpy", "memcpy", ...]
//!   username                "alice"   (canonical, when unambiguous)
//!   usernames[]             ["alice", "bob"]   (only when multiple)
//!   user_home               "/Users/alice"
//!   username_from           "pdb_path" | "byte_scan"
//!   source_paths[]          ["/Users/.../main.go", ...]  (capped)
//!   build_root              "/Users/alice/projects/sample"
//!   rust_runtime_symbols[]  ["rust_alloc", "rust_panic", ...]
//!   rust_mangling           "v0" | "legacy"
//!
//! signing:                  cross-format signing metadata
//!   catalog                 "authenticode" | "apple_codesign"
//!   format                  "adhoc" | "developer-id" | "platform" | "app-store"  (Mach-O)
//!   time                    Unix epoch seconds                          (PE Authenticode / Mach-O)
//!   countersigner           timestamping authority CN                   (PE)
//!   team_id                 "9XQGPJ8B7K"                                (Mach-O)
//!   bundle_identifier       "com.example.app"                           (Mach-O)
//!   authorities[]           ["Apple Root CA", ...]                      (Mach-O cert chain)
//!   requirements_sha256     SHA-256 of the embedded Requirements blob   (Mach-O)
//!   requirements_slot_count u32 — count of designated/host/guest slots  (Mach-O)
//!   entitlements            { key: bool|string|[string] }               (Mach-O)
//!   cert.subject            leaf cert Subject CN                        (PE+Mach-O)
//!   cert.issuer             leaf cert Issuer CN                         (PE)
//!   cert.serial             leaf cert serial (lowercase hex)            (PE)
//!   cert.thumbprint_sha1    SHA-1 of leaf cert DER (lowercase hex)      (PE)
//!   validity.not_before     Unix epoch — cert validity start            (PE)
//!   validity.not_after      Unix epoch — cert validity end              (PE)
//!
//! hash:                     similarity / cluster digests (industry-canonical names)
//!   imp                     PE imphash (md5)
//!   rich_header             PE Rich-header hash (sha256)
//!   authenti                PE Authentihash (sha256, signed-region digest)
//!   cd                      Mach-O CDHash (sha256)
//!   dylib                   Mach-O dylib-name similarity (sha256)
//!   sym                     Mach-O imported-symbol similarity (sha256)
//!   export                  Mach-O exported-symbol similarity (sha256)
//!   entitlement             Mach-O entitlement-key similarity (sha256)
//!   gimp                    Go-binary similarity                        (planned)
//!   tlsh, ssdeep            cross-format fuzzy hashes                   (planned)
//!
//! debug:                    cross-format debug metadata
//!   pdb_path                "C:\\Users\\dev\\projects\\sample.pdb"
//!   build_id                "<hex>" — GNU build-id / Mach-O LC_UUID
//!   producer                "GNU C++23 13.2.0 ..."
//!   comp_dir                "/home/dev/proj/build"
//!
//! pe:                       PE-specific
//!   timestamp               COFF TimeDateStamp (epoch; 0 = deterministic)
//!   checksum                "0x........" (when set)
//!   linker_version          "14.39"
//!   dll_characteristics.{...}  decoded named flags (only true ones present)
//!                              high_entropy_va, dynamic_base (ASLR), force_integrity,
//!                              nx_compat (DEP), no_isolation, no_seh, no_bind,
//!                              appcontainer, wdm_driver, guard_cf (CFG),
//!                              terminal_server_aware
//!   debug_directory_types[] [16, 13, ...] — sorted IMAGE_DEBUG_TYPE_* values
//!   codeview.guid           RSDS PDB age GUID
//!   codeview.age            PDB age counter
//!   rich_header.entries[]   [{ product_id, product_name, build_number, use_count }, ...]
//!   rich_header.xor_key     "0x..."
//!   version_info.{...}      snake_cased VS_VERSIONINFO keys
//!                           (company_name, file_description, file_version,
//!                            internal_name, original_filename, product_name,
//!                            product_version, legal_copyright,
//!                            legal_trademarks, comments, private_build,
//!                            special_build)
//!   manifest.assembly_identity.{name, version, processor_architecture, type, public_key_token, language}
//!   manifest.requested_execution_level
//!   manifest.{ui_access, auto_elevate, long_path_aware, ...}  raw XML values
//!   manifest.supported_os[]   [{ guid, name }]
//!   manifest.dependencies[]
//!   resource_types[]        ["RT_ICON", "RT_VERSION", "RT_MANIFEST", ...]
//!   bound_imports[]         [{ name, time_date_stamp, forwarder_ref_count }]
//!   load_config.security_cookie    "/GS cookie address"
//!   load_config.cfg_check_func     CFG check fn pointer
//!   load_config.cfg_guard_flags    raw CFG guard-flags bitfield
//!   load_config.cfg_flags.{...}    decoded named CFG flags
//!
//! elf:                      ELF-specific
//!   entry_section           ".text" | ".init" | ".init_array" | ...
//!   relro                   "full" | "partial" | "none"
//!   interpreter             "/lib64/ld-linux-x86-64.so.2"
//!   comment                 ".comment" section text
//!   soname                  "libfoo.so.1"
//!   rpath[]                 ["/opt/local/lib"]
//!   runpath[]
//!   needed[]                ["libc.so.6", ...]   (DT_NEEDED entries)
//!   linker_family           "gold" | "lld" | "mold" | "bfd"
//!   pauth_scheme            ARM PAuth ABI scheme
//!   x86_isa_level           "x86-64" | "x86-64-v2" | "x86-64-v3" | "x86-64-v4"
//!   gnu_abi_min_kernel      "<major>.<minor>.<patch>" from NT_GNU_ABI_TAG
//!   gnu_property.{ibt,shstk,pac,bti,x86_isa_level}
//!   dt_flags.{raw, raw_1, bind_now, textrel, symbolic, static_tls,
//!             now, nodelete, initfirst, noopen, nodeflib, nodump,
//!             pie, global, group, interpose, direct}
//!   needed_versions[]       [{ lib: "libc.so.6", versions: ["GLIBC_2.34", ...] }]
//!   provided_versions[]     versions this .so itself defines
//!
//! dwarf:                    DWARF debug-info attribution (unstripped ELF only)
//!   producers[]             ["GNU C17 13.2.0 -O2 -mtune=generic ...", ...]
//!   comp_dirs[]             ["/builddir/build/BUILD/glibc-2.34/...", ...]
//!   languages[]             ["c", "cpp", "rust", ...]
//!   source_files[]          ["/build/glibc/elf/dl-init.c", ...] (capped at 32)
//!
//! package:                  FDO `.note.package` self-attestation (ELF)
//!   type                    "rpm" | "deb" | "apk" | "pacman" | ...   (FDO-canonical)
//!   name, version, architecture, os, osVersion, license
//!   buildId, url, vcs, cpe  attestation provenance fields
//!
//! macho:                    Mach-O specific
//!   uuid                    "<hex>"
//!   filetype                "executable" | "dylib" | "bundle" | ...
//!   platform                "macOS" | "iOS" | "tvOS" | ...
//!   min_os_version          "10.13.0"
//!   sdk_version             "11.0.0"
//!   tools[]                 [{ tool, version }]
//!   source_version          "1.2.3"  (LC_SOURCE_VERSION)
//!   install_name            "@rpath/MyFramework"  (dylibs; LC_ID_DYLIB)
//!   install_name_kind       "absolute" | "rpath" | "executable_path" | ...
//!   load_dylibs[]           [{ path, kind, current_version, compatibility_version }]
//!   rpath[]
//!   linker_options[]
//!   info_plist              { Info.plist tree, PascalCase keys }
//!   launchd_plist           { launchd plist tree, PascalCase keys }
//!   slices[]                [{ arch, uuid, file_offset, has_code_signature }]
//!   segments[]              [{ name, vmaddr, vmsize, fileoff, perms, flags_hex }]
//!   dylibs[]                [{ kind, name }]
//!   header_flags.{...}      decoded MH_* named flags
//!   cs_flags.{...}          decoded CodeDirectory named flags
//!                           (runtime, library_validation, linker_signed,
//!                            adhoc, kill, hard, restrict, enforcement, …)
//!   cs_runtime_version      "<major>.<minor>.<patch>"
//!   pauth_scheme            ARM PAuth scheme
//!   swift_sections[]        ["__swift5_proto", "__swift5_types", ...]
//!   objc.{swift_version, is_simulated, optimized_by_dyld, has_category_class_properties}
//!
//! go:                       Go-specific (cross-binary)
//!   version                 "go1.26.2"
//!   main_path               "github.com/attacker/sample"
//!   main_module.{path, version, sum}
//!   dependencies[]          [{ path, version, sum, replaced_by }]
//!   build:                  flat dict; Go-spec keys snake-cased
//!     mode                  "exe" | "c-archive" | "plugin" | ...
//!     compiler              "gc" | "gccgo"
//!     goos, goarch, goamd64, goarm
//!     cgo, trimpath         bool (raw values from buildinfo)
//!     ldflags, asmflags, gcflags
//!   vcs.system              "git" | "hg" | "svn"
//!   vcs.{revision, time, modified}
//! ```
//!
//! # Where derived data lives (not in kv)
//!
//! Booleans, counts, and computed scalars live on metrics structs.
//! Trait authors target them with `type: metrics, field: <path>, min:/max:`:
//!
//!   - `binary.{is_pie, is_stripped, has_signature, has_debug_info}`
//!   - `pe.{has_checksum, checksum_valid, signature_digest_mismatch,
//!          cert_chain_depth, signing_time_before_timestamp,
//!          is_reproducible_build, has_pogo, has_iltcg, ...}`
//!   - `elf.{stack_canary, nx_enabled, has_textrel, has_interpreter,
//!          has_soname, has_rpath, has_runpath, has_direct_loader_dep,
//!          has_rustc_section, has_build_id, has_debuglink,
//!          dt_flags_1 (raw u32), ...}`
//!   - `macho.{is_notarized, hardened_runtime, allow_jit, is_universal,
//!            slice_count, has_chained_fixups, has_dyld_info_legacy,
//!            has_data_const_segment, cs_flags (raw u32), flags (raw MH_*), ...}`

use crate::types::AnalysisReport;
use serde_json::{json, Map, Value};

/// Build the cross-format binary kv tree from data already
/// populated on `report.metrics` and `report.target`.  Specialized
/// extractors (Go buildinfo, VERSIONINFO strings, ELF interpreter,
/// Mach-O LC_UUID) merge additional sections directly into the kv
/// tree via the binary-extractors augment pass before the analyzer
/// stashes the result on `report.kv_tree`.
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

    // pe.*, elf.*, macho.* live in expose now. The evaluator
    // pipeline (`evaluate_and_merge_findings_with_precomputed` in the
    // mapper) parses each binary once via expose and merges its
    // `values` tree directly into `report.kv_tree`, so cleave no
    // longer synthesizes those namespaces here. The legacy
    // `pe_section` / `elf_section` / `macho_section` builders remain
    // available for the `cleave kv` debug command, which still
    // dumps cleave-analyzer state, but the analyze pipeline relies
    // exclusively on the expose view.

    // hash.* — unified similarity / digest hashes. Industry-canonical
    // names preserved as terse stems under the namespace
    // (imp, sym, gimp, tlsh, ssdeep, cd, authenti, rich_header).
    let hash = hash_section(report);
    if !hash.is_empty() {
        root.insert("hash".into(), Value::Object(hash));
    }

    Value::Object(root)
}

fn hash_section(report: &AnalysisReport) -> Map<String, Value> {
    let mut out = Map::new();
    let Some(metrics) = report.metrics.as_ref() else {
        return out;
    };
    if let Some(pe) = metrics.pe.as_ref() {
        if let Some(h) = pe.authentihash.as_deref() {
            if !h.is_empty() {
                out.insert("authenti".into(), json!(h));
            }
        }
    }
    if let Some(macho) = metrics.macho.as_ref() {
        if let Some(h) = macho.dylib_hash.as_deref() {
            out.insert("dylib".into(), json!(h));
        }
        if let Some(h) = macho.symhash.as_deref() {
            out.insert("sym".into(), json!(h));
        }
        if let Some(h) = macho.export_hash.as_deref() {
            out.insert("export".into(), json!(h));
        }
        if let Some(h) = macho.entitlement_hash.as_deref() {
            out.insert("entitlement".into(), json!(h));
        }
    }
    out
}

fn build_section(report: &AnalysisReport) -> Map<String, Value> {
    let mut out = Map::new();

    // Architecture is on TargetInfo, not metrics.
    if let Some(arches) = report.target.architectures.as_ref() {
        if let Some(first) = arches.first() {
            out.insert("target_arch".into(), json!(first));
        }
    }

    out
}

fn signing_section(report: &AnalysisReport) -> Map<String, Value> {
    let mut out = Map::new();
    let Some(metrics) = report.metrics.as_ref() else {
        return out;
    };

    if let Some(pe) = metrics.pe.as_ref() {
        // Leaf cert details under `signing.cert.*` subtree. Subject
        // prefers the leaf cert's own CN (most accurate), falling
        // back to primary_signer (CA-filtered org name) then signer
        // (raw Authenticode CN list). Mach-O side adds `signing.cert.subject`
        // separately in `binary_extractors`.
        let mut cert = Map::new();
        let subject = pe
            .leaf_subject
            .as_deref()
            .or(pe.primary_signer.as_deref())
            .or(pe.signer.as_deref())
            .filter(|s| !s.is_empty());
        if let Some(s) = subject {
            cert.insert("subject".into(), json!(s));
        }
        if let Some(s) = pe.leaf_issuer.as_deref().filter(|s| !s.is_empty()) {
            cert.insert("issuer".into(), json!(s));
        }
        if let Some(s) = pe.leaf_thumbprint_sha1.as_deref().filter(|s| !s.is_empty()) {
            cert.insert("thumbprint_sha1".into(), json!(s));
        }
        if let Some(s) = pe.leaf_serial.as_deref().filter(|s| !s.is_empty()) {
            cert.insert("serial".into(), json!(s));
        }
        if !cert.is_empty() {
            out.insert("cert".into(), Value::Object(cert));
        }
        // Cert validity window — `signing.validity.{not_before, not_after}`.
        if pe.leaf_not_before != 0 || pe.leaf_not_after != 0 {
            let mut validity = Map::new();
            if pe.leaf_not_before != 0 {
                validity.insert("not_before".into(), json!(pe.leaf_not_before));
            }
            if pe.leaf_not_after != 0 {
                validity.insert("not_after".into(), json!(pe.leaf_not_after));
            }
            out.insert("validity".into(), Value::Object(validity));
        }
        // PE-specific signing fields: signing time + countersigner.
        if pe.signing_time != 0 {
            out.insert("time".into(), json!(pe.signing_time));
        }
        // Identify the timestamping authority CN from the chain.
        // Heuristic: chain CN containing a time-stamping marker.
        // Trojanized installers sometimes use a *different* TSA than
        // the legitimate vendor's normal pipeline.
        if let Some(signer_chain) = pe.signer.as_deref() {
            if let Some(ts) = identify_timestamping_authority(signer_chain) {
                out.insert("countersigner".into(), json!(ts));
            }
        }
        // Cross-format catalog identifier so trait authors can
        // disambiguate Mach-O vs PE Authenticode without checking
        // file_type. `chain_depth` is a derived count — lives on
        // `pe.cert_chain_depth` metric. Authentihash and other digests
        // live under `hash.*`.
        if metrics.binary.as_ref().is_some_and(|b| b.has_signature) {
            out.entry("catalog".to_string())
                .or_insert_with(|| json!("authenticode"));
        }
    }

    out
}

fn debug_section(report: &AnalysisReport) -> Map<String, Value> {
    let mut out = Map::new();
    let Some(metrics) = report.metrics.as_ref() else {
        return out;
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

/// True when an `elf.needed` SONAME names the dynamic loader directly
/// (`ld-linux-*`, `ld-musl-*`). A *library* with this dependency
/// declared explicitly is anomalous — the loader is normally pulled
/// in transitively via libc.
/// Pick the timestamping-authority CN from an Authenticode chain.
/// Returns the leaf-most TSA entry (the actual Time Stamping Signer)
/// rather than the TSA's CA. Returns `None` for an unsigned binary or
/// a chain with no detectable TSA — many code-signed PEs are signed
/// without a timestamp.
fn identify_timestamping_authority(chain: &str) -> Option<String> {
    let lower_markers = [
        "time stamping signer",
        "timestamp signer",
        "time-stamp signer",
        "time stamping",
        "timestamp",
        "time-stamp",
        "tsa",
    ];
    chain
        .split(", ")
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .find(|s| {
            let lower = s.to_lowercase();
            lower_markers.iter().any(|m| lower.contains(m))
        })
        .map(str::to_string)
}

/// Stash the synthesized binary kv tree on `report.kv_tree`.  Drops
/// when the tree comes back empty so non-binary file types and
/// minimal stub binaries don't carry an empty `kv_tree` field.
pub(crate) fn attach_to_report(report: &mut AnalysisReport) {
    let kv = build_binary_kv(report);
    if let Value::Object(map) = kv {
        for (ns, value) in map {
            report.merge_kv_subtree(&ns, value);
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::types::binary_metrics::{BinaryMetrics, PeMetrics};
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
    fn build_section_surfaces_target_arch() {
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
        // Boolean predicates (is_pie, is_stripped, has_signature, ...)
        // live exclusively on metrics — kv carries values, not bools.
        assert!(kv["build"].get("is_pie").is_none());
        assert!(kv["build"].get("is_stripped").is_none());
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
    fn signing_subject_surfaces_for_signed_pe() {
        let m = Metrics {
            binary: Some(BinaryMetrics {
                has_signature: true,
                ..Default::default()
            }),
            pe: Some(crate::types::binary_metrics::PeMetrics {
                signature_valid: Some(true),
                leaf_subject: Some("Acme Corp".into()),
                ..Default::default()
            }),
            ..Default::default()
        };
        let r = report_with_metrics(m, "pe");
        let kv = build_binary_kv(&r);
        assert_eq!(kv["signing"]["cert"]["subject"], "Acme Corp");
        // is_signed and signature_valid live on metrics
        // (binary.has_signature, pe.signature_valid) — kv carries
        // signer identity strings, not predicates.
        assert!(kv["signing"].get("is_signed").is_none());
        assert!(kv["signing"].get("signature_valid").is_none());
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
}
