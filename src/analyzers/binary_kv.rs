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

    if !pe.debug_directory_types.is_empty() {
        out.insert(
            "debug_directory_types".into(),
            json!(pe.debug_directory_types.clone()),
        );
    }
    if let Some(guid) = pe.codeview_guid.as_deref().filter(|s| !s.is_empty()) {
        let mut cv = Map::new();
        cv.insert("guid".into(), json!(guid));
        if pe.codeview_age > 0 {
            cv.insert("age".into(), json!(pe.codeview_age));
        }
        out.insert("codeview".into(), Value::Object(cv));
    }
    if pe.linker_major_version > 0 || pe.linker_minor_version > 0 {
        out.insert(
            "linker_version".into(),
            json!(format!(
                "{}.{}",
                pe.linker_major_version, pe.linker_minor_version
            )),
        );
    }
    if pe.timestamp != 0 {
        out.insert("timestamp".into(), json!(pe.timestamp));
    }
    if pe.has_checksum {
        out.insert("checksum".into(), json!(format!("0x{:08x}", pe.checksum)));
    }
    // Resource types present (sorted, distinct RT_* names).
    if !pe.resource_types.is_empty() {
        out.insert("resource_types".into(), json!(pe.resource_types.clone()));
    }
    // Section-level malformations from `compute_pe_metrics`. Names come
    // out as kv arrays so trait authors can target individual section
    // names (e.g. `path: pe.overflowing_sections[*]`) the same way they
    // do `pe.inflated_sections[*]`.  Counts live on metrics.
    if !pe.overflowing_sections.is_empty() {
        out.insert(
            "overflowing_sections".into(),
            json!(pe.overflowing_sections.clone()),
        );
    }
    if !pe.misaligned_sections.is_empty() {
        out.insert(
            "misaligned_sections".into(),
            json!(pe.misaligned_sections.clone()),
        );
    }
    if !pe.overlapping_sections.is_empty() {
        out.insert(
            "overlapping_sections".into(),
            json!(pe.overlapping_sections.clone()),
        );
    }
    // Per-section header summary — characteristics + sizing per section.
    if !pe.section_characteristics_entries.is_empty() {
        let arr: Vec<Value> = pe
            .section_characteristics_entries
            .iter()
            .map(|s| {
                json!({
                    "name": s.name,
                    "characteristics_hex": s.characteristics_hex,
                    "virtual_address": s.virtual_address,
                    "virtual_size": s.virtual_size,
                    "raw_size": s.raw_size,
                })
            })
            .collect();
        out.insert("section_characteristics".into(), Value::Array(arr));
    }
    // Non-zero data directory slots.
    if !pe.data_directory_entries.is_empty() {
        let arr: Vec<Value> = pe
            .data_directory_entries
            .iter()
            .map(|d| {
                json!({
                    "name": d.name,
                    "rva": d.rva,
                    "size": d.size,
                })
            })
            .collect();
        out.insert("data_directories".into(), Value::Array(arr));
    }
    // TLS callback addresses (RVAs) — list-style kv carrier so trait
    // authors can match individual callback RVAs.
    if !pe.tls_callback_addresses.is_empty() {
        out.insert(
            "tls_callback_addresses".into(),
            json!(pe.tls_callback_addresses.clone()),
        );
    }
    // Rich Header CompID + count + product-name tuples.
    if !pe.rich_header_compids.is_empty() {
        let arr: Vec<Value> = pe
            .rich_header_compids
            .iter()
            .map(|r| {
                let mut obj = serde_json::Map::new();
                obj.insert("compid".into(), json!(r.compid));
                obj.insert("count".into(), json!(r.count));
                if let Some(p) = r.product.as_deref() {
                    obj.insert("product".into(), json!(p));
                }
                Value::Object(obj)
            })
            .collect();
        out.insert("rich_header_compids".into(), Value::Array(arr));
    }

    // Bound imports — DLL+timestamp pairs that fingerprint the
    // build-host's WinSxS state at link time. Identical timestamps
    // across vendor releases prove same-machine link.
    if !pe.bound_imports.is_empty() {
        let arr: Vec<Value> = pe
            .bound_imports
            .iter()
            .map(|b| {
                json!({
                    "name": b.name,
                    "time_date_stamp": b.time_date_stamp,
                    "forwarder_ref_count": b.forwarder_ref_count,
                })
            })
            .collect();
        out.insert("bound_imports".into(), Value::Array(arr));
    }

    // Load Config + TLS — security cookie + CFG/SafeSEH addresses are
    // raw structural reads (RVA-style integers). Counts live on
    // metrics. Hex-formatted addresses for trait readability.
    if pe.security_cookie != 0 {
        let mut lc = Map::new();
        lc.insert(
            "security_cookie".into(),
            json!(format!("0x{:x}", pe.security_cookie)),
        );
        if pe.cfg_check_func != 0 {
            lc.insert(
                "cfg_check_func".into(),
                json!(format!("0x{:x}", pe.cfg_check_func)),
            );
        }
        if pe.cfg_guard_flags != 0 {
            lc.insert(
                "cfg_guard_flags".into(),
                json!(format!("0x{:x}", pe.cfg_guard_flags)),
            );
            // Decoded named flags for trait ergonomics.
            let mut named = Map::new();
            let f = pe.cfg_guard_flags;
            if f & 0x100 != 0 {
                named.insert("instrumented".into(), json!(true));
            }
            if f & 0x200 != 0 {
                named.insert("write_instrumented".into(), json!(true));
            }
            if f & 0x400 != 0 {
                named.insert("function_table_present".into(), json!(true));
            }
            if f & 0x800 != 0 {
                named.insert("export_suppression_info".into(), json!(true));
            }
            if f & 0x4000 != 0 {
                named.insert("longjump_table_present".into(), json!(true));
            }
            if f & 0x10000 != 0 {
                named.insert("rf_instrumented".into(), json!(true));
            }
            if !named.is_empty() {
                lc.insert("cfg_flags".into(), Value::Object(named));
            }
        }
        out.insert("load_config".into(), Value::Object(lc));
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

    // Per-program-header carrier — surface every PT_* entry so trait
    // authors can match individual segment permissions / extents.
    if !elf.segment_entries.is_empty() {
        let arr: Vec<Value> = elf
            .segment_entries
            .iter()
            .map(|s| {
                json!({
                    "p_type": s.p_type,
                    "p_vaddr": s.p_vaddr,
                    "p_offset": s.p_offset,
                    "p_filesz": s.p_filesz,
                    "p_memsz": s.p_memsz,
                    "flags_hex": s.flags_hex,
                    "perms": s.perms,
                })
            })
            .collect();
        out.insert("segments".into(), Value::Array(arr));
    }
    // Decoded DT_FLAGS_1 named-bit subtree (mirrors PE
    // `pe.dll_characteristics.*`). Bits per glibc <elf.h>.
    if elf.dt_flags_1 != 0 {
        let mut flags = Map::new();
        let f = elf.dt_flags_1;
        let pairs: &[(u32, &str)] = &[
            (0x00000001, "now"),
            (0x00000002, "global"),
            (0x00000004, "group"),
            (0x00000008, "nodelete"),
            (0x00000010, "loadfltr"),
            (0x00000020, "initfirst"),
            (0x00000040, "noopen"),
            (0x00000080, "origin"),
            (0x00000100, "direct"),
            (0x00000200, "trans"),
            (0x00000400, "interpose"),
            (0x00000800, "nodeflib"),
            (0x00001000, "nodump"),
            (0x00002000, "confalt"),
            (0x00004000, "endfiltee"),
            (0x00008000, "dispreldne"),
            (0x00010000, "disprelpnd"),
            (0x00020000, "nodirect"),
            (0x00040000, "ignmuldef"),
            (0x00080000, "noksyms"),
            (0x00100000, "nohdr"),
            (0x00200000, "edited"),
            (0x00400000, "noreloc"),
            (0x00800000, "symintpose"),
            (0x01000000, "globaudit"),
            (0x02000000, "singleton"),
            (0x04000000, "stub"),
            (0x08000000, "pie"),
        ];
        for (bit, name) in pairs {
            if f & bit != 0 {
                flags.insert((*name).to_string(), json!(true));
            }
        }
        if !flags.is_empty() {
            out.insert("dt_flags_1".into(), Value::Object(flags));
        }
    }

    // Tier A — modern toolchain / hardening surface for trait
    // authors. These are raw enough to live in kv (they're either
    // version strings or linker family names, no interpretation).
    if let Some(s) = elf.x86_isa_level.as_deref() {
        out.insert("x86_isa_level".into(), json!(s));
    }
    if let Some(s) = elf.pauth_scheme.as_deref() {
        out.insert("pauth_scheme".into(), json!(s));
    }
    if let Some(s) = elf.linker_family.as_deref() {
        out.insert("linker_family".into(), json!(s));
    }
    if let Some(s) = elf.gnu_abi_min_kernel.as_deref() {
        out.insert("gnu_abi_min_kernel".into(), json!(s));
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

    // Per-segment carrier — every LC_SEGMENT entry surfaces.
    if !macho.segment_entries.is_empty() {
        let arr: Vec<Value> = macho
            .segment_entries
            .iter()
            .map(|s| {
                json!({
                    "name": s.name,
                    "vmaddr": s.vmaddr,
                    "vmsize": s.vmsize,
                    "fileoff": s.fileoff,
                    "filesize": s.filesize,
                    "maxprot_hex": s.maxprot_hex,
                    "initprot_hex": s.initprot_hex,
                    "perms": s.perms,
                })
            })
            .collect();
        out.insert("segments".into(), Value::Array(arr));
    }
    // Per-dylib carrier — install_name + versions + load kind.
    if !macho.dylib_entries.is_empty() {
        let arr: Vec<Value> = macho
            .dylib_entries
            .iter()
            .map(|d| {
                json!({
                    "name": d.name,
                    "current_version": d.current_version,
                    "compatibility_version": d.compatibility_version,
                    "kind": d.kind,
                })
            })
            .collect();
        out.insert("dylibs".into(), Value::Array(arr));
    }
    // Decoded MH_* header flags subtree — mirrors PE's
    // `pe.dll_characteristics.*` decoded named-bit pattern.
    if macho.flags != 0 {
        let mut hf = Map::new();
        let f = macho.flags;
        let pairs: &[(u32, &str)] = &[
            (0x0000_0001, "noundefs"),
            (0x0000_0002, "incrlink"),
            (0x0000_0004, "dyldlink"),
            (0x0000_0008, "bindatload"),
            (0x0000_0010, "prebound"),
            (0x0000_0020, "split_segs"),
            (0x0000_0080, "twolevel"),
            (0x0000_0400, "weak_defines"),
            (0x0000_0800, "binds_to_weak"),
            (0x0000_1000, "subsections_via_symbols"),
            (0x0008_0000, "allow_stack_execution"),
            (0x0010_0000, "root_safe"),
            (0x0020_0000, "pie"),
            (0x0080_0000, "has_tlv_descriptors"),
            (0x0100_0000, "no_heap_execution"),
            (0x0200_0000, "app_extension_safe"),
            (0x0400_0000, "nlist_outofsync_with_dyldinfo"),
            (0x0800_0000, "sim_support"),
            (0x8000_0000, "dylib_in_cache"),
        ];
        for (bit, name) in pairs {
            if f & bit != 0 {
                hf.insert((*name).to_string(), json!(true));
            }
        }
        if !hf.is_empty() {
            out.insert("header_flags".into(), Value::Object(hf));
        }
    }
    // Decoded CodeDirectory flag bits — mirrors header_flags /
    // dt_flags_1. Bit values from Apple's <Security/CSCommon.h> /
    // XNU cs_blobs.h.
    if macho.cs_flags != 0 {
        let mut cs = Map::new();
        let f = macho.cs_flags;
        let pairs: &[(u32, &str)] = &[
            (0x0000_0001, "valid"),
            (0x0000_0002, "adhoc"),
            (0x0000_0004, "get_task_allow"),
            (0x0000_0008, "installer"),
            (0x0000_0010, "forced_lv"),
            (0x0000_0020, "invalid_allowed"),
            (0x0000_0100, "hard"),
            (0x0000_0200, "kill"),
            (0x0000_0400, "check_expiration"),
            (0x0000_0800, "restrict"),
            (0x0000_1000, "enforcement"),
            (0x0000_2000, "library_validation"),
            (0x0000_4000, "entitlements_validated"),
            (0x0000_8000, "nvram_unrestricted"),
            (0x0001_0000, "runtime"),
            (0x0002_0000, "linker_signed"),
        ];
        for (bit, name) in pairs {
            if f & bit != 0 {
                cs.insert((*name).to_string(), json!(true));
            }
        }
        if !cs.is_empty() {
            out.insert("cs_flags".into(), Value::Object(cs));
        }
    }
    if let Some(rv) = macho.cs_runtime_version.as_deref() {
        out.insert("cs_runtime_version".into(), json!(rv));
    }
    if !macho.overlapping_segments.is_empty() {
        out.insert(
            "overlapping_segments".into(),
            json!(macho.overlapping_segments.clone()),
        );
    }
    // Mach-O similarity hashes live under unified `hash.*` namespace.

    if out.is_empty() {
        return None;
    }
    Some(out)
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
    fn elf_section_surfaces_entry_and_relro() {
        let m = Metrics {
            elf: Some(ElfMetrics {
                stack_canary: true,
                nx_enabled: true,
                relro: Some("full".into()),
                has_build_id: true,
                build_id: Some("abcd1234".into()),
                entry_section: Some(".text".into()),
                ..Default::default()
            }),
            ..Default::default()
        };
        let r = report_with_metrics(m, "elf");
        let kv = build_binary_kv(&r);
        assert_eq!(kv["elf"]["entry_section"], ".text");
        assert_eq!(kv["elf"]["relro"], "full");
        // Boolean hardening flags (stack_canary, nx_enabled, has_textrel,
        // has_interpreter, …) live on `elf.*` metrics only.
        assert!(kv["elf"].get("has_canary").is_none());
        assert!(kv["elf"].get("nx_stack").is_none());
        // Build-id surfaces as a value in kv; the boolean lives on metrics.
        assert!(kv["debug"].get("has_build_id").is_none());
        assert_eq!(kv["debug"]["build_id"], "abcd1234");
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
        // hardened_runtime is a metric-only bool; not surfaced in kv.
        assert!(kv["signing"].get("hardened_runtime").is_none());
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
