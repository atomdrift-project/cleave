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
//!   is_pie                  bool   (mirrors `binary.is_pie` metric)
//!   is_stripped             bool   (mirrors `binary.is_stripped` metric)
//!   has_debug_info          bool   (mirrors `binary.has_debug_info` metric)
//!   ci_environment          "github-actions" | "gitlab-ci" | ...   (planned)
//!   linker                  "gold" | "lld" | "mold" | "bfd"        (B7 — ELF only)
//!   rust_runtime_symbols[]  ["rust_alloc", "rust_panic", ...]      (B7.5 — Rust ABI markers)
//!   rust_mangling           "v0" | "legacy"                        (B7.5 — Rust symbol mangling style)
//!   has_rustc_section       bool — `.rustc` ELF section present    (B7.5 — Rust crate metadata)
//!
//! signing:                  cross-format signing metadata
//!   is_signed               bool   (mirrors `binary.has_signature` metric)
//!   signature_valid         bool
//!   hardened_runtime        bool   (Mach-O — mirrors `macho.hardened_runtime`)
//!   allow_jit               bool   (Mach-O — mirrors `macho.allow_jit`)
//!   notarized               bool   (Mach-O — mirrors `macho.is_notarized`)
//!   catalog                 "authenticode" | "apple_codesign"
//!   type                    "adhoc" | "developer-id" | "platform"       (Mach-O)
//!   subject                 leaf cert Subject CN                        (PE+Mach-O)
//!   issuer                  leaf cert Issuer CN (immediate CA above leaf)  (PE)
//!   thumbprint_sha1         SHA-1 of leaf cert DER (lowercase hex)      (PE)
//!   serial                  leaf cert serial number (lowercase hex)     (PE)
//!   not_before              Unix epoch seconds — cert validity start    (PE)
//!   not_after               Unix epoch seconds — cert validity end      (PE)
//!   authorities[]           ["Apple Root CA", ...]                      (Mach-O cert chain)
//!   signing_time            Unix epoch seconds                          (PE Authenticode)
//!   countersign_time        "<ISO 8601>"                                (planned)
//!   team_id                 "9XQGPJ8B7K"                                (B4 — Mach-O)
//!   bundle_identifier       "com.example.app"                           (B4)
//!   cs_flags[]              ["host", "runtime", "library_validation"]   (planned)
//!   requirements_sha256     SHA-256 of the embedded Requirements blob   (Mach-O)
//!   requirements_slot_count u32 — count of designated/host/guest slots  (Mach-O)
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
//!   manifest.assembly_identity.{name, version, processor_architecture, type, public_key_token, language}
//!   manifest.description
//!   manifest.requested_execution_level   "asInvoker" | "requireAdministrator" | "highestAvailable"
//!   manifest.ui_access                   bool
//!   manifest.auto_elevate                bool — UAC-bypass tooling marker
//!   manifest.dpi_aware / dpi_awareness   bool | string
//!   manifest.long_path_aware             bool
//!   manifest.supported_os[]              [{ guid, name }]   names: vista|win7|win8|win8.1|win10
//!   manifest.dependencies[]              [{ name, version, processor_architecture, public_key_token, ... }]
//!   manifest.windows_settings.{...}      remaining settings not hoisted above
//!   resource_types[]                     ["RT_ICON", "RT_VERSION", "RT_MANIFEST", ...]
//!   bound_imports[]                      [{ name, time_date_stamp, forwarder_ref_count }]
//!                                        — build-host WinSxS state fingerprint
//!   load_config.security_cookie          "0x140295040" — /GS cookie address
//!   load_config.cfg_check_func       "0x140287418" — CFG check fn pointer
//!   load_config.cfg_guard_flags          "0x10500" — raw CFG guard-flags bitfield
//!   load_config.cfg_flags.{...}          decoded named CFG flags
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
//!   dt_flags.{raw, raw_1, bind_now, textrel, symbolic, static_tls,
//!             now, nodelete, initfirst, noopen, nodeflib, nodump,
//!             pie, global, group, interpose, direct}              (B7)
//!   needed_versions[]       [{ lib: "libc.so.6", versions: ["GLIBC_2.34", ...] }]  (B7)
//!   provided_versions[]     versions this .so itself defines               (B7)
//!
//! dwarf:                    DWARF debug-info attribution (unstripped ELF only)
//!   producers[]             ["GNU C17 13.2.0 -O2 -mtune=generic ...", ...]
//!   comp_dirs[]             ["/builddir/build/BUILD/glibc-2.34/...", ...]
//!   languages[]             ["c", "cpp", "rust", ...]
//!   source_files[]          ["/build/glibc/elf/dl-init.c", ...] (capped at 32)
//!   cu_count                u32 — total compilation units (also on `elf.dwarf_cu_count` metric)
//!
//! package:                  FDO `.note.package` self-attestation (ELF; opt-in)
//!   type                    "rpm" | "deb" | "apk" | "pacman" | ...
//!   name                    "<package-name>"
//!   version                 "<package-version>"
//!   architecture            "<arch>"
//!   os, osVersion           "<distro>" / "<release>"
//!   license                 "<spdx>"
//!   buildId, url, vcs, cpe  attestation provenance fields
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
//!   info_plist              { Info.plist tree, PascalCase keys }  (B4.5 — __TEXT,__info_plist)
//!   launchd_plist           { launchd plist tree, PascalCase keys}(B4.5 — __TEXT,__launchd_plist)
//!   is_fat                  bool — multi-arch universal binary
//!   slice_count             u32 — number of slices when fat (also on `macho.slice_count` metric)
//!   slices[]                [{ arch, uuid, file_offset, has_code_signature }]
//!   swift_sections[]        ["__swift5_proto", "__swift5_types", ...]   (B7.5 — Swift code marker)
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
//! Note: derived booleans (cross-format consistency flags, "is_zero"
//! checks, "mismatch" comparisons) and derived counts (chain_depth,
//! number-of-mixed-producers) live on metrics structs, not in the kv
//! tree. Trait authors target them via
//! `type: metrics, field: <path>, min:/max:`. Examples:
//!   - `consistency.{bundle_identifier_mismatch, dwarf_mixed_producers, ...}` (boolean)
//!   - `pe.cert_chain_depth` (u32)
//!   - `pe.signing_time_before_timestamp` (boolean — signed-before-built)
//!
//! The kv tree carries only raw structural reads: strings, names,
//! identities, hex digests, raw bit-flag values lifted directly from
//! the binary.
//!
//! hashes:                   fuzzy / similarity / cluster hashes
//!   imphash                 "<md5>"                                  (PE)
//!   rich_header_hash        "<sha256>"                               (PE — single canonical location)
//!   ssdeep, tlsh            "..."                                    (cross-format)  (planned)
//!   authentihash            "..."                                    (PE)            (planned)
//!   cdhash                  "..."                                    (Mach-O)        (planned)
//!   cdhash_sha256           "<sha256-hex>"                                            (Mach-O)
//!   gimphash                "..."                                    (Go)            (planned)
//! ```

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

    Value::Object(root)
}

fn build_section(report: &AnalysisReport) -> Map<String, Value> {
    let mut out = Map::new();

    // Architecture is on TargetInfo, not metrics.
    if let Some(arches) = report.target.architectures.as_ref() {
        if let Some(first) = arches.first() {
            out.insert("target_arch".into(), json!(first));
        }
    }

    // Mirror raw structural bools from `binary.*` metrics into kv so
    // ML pipelines and trait authors can read either path freely.
    if let Some(bin) = report.metrics.as_ref().and_then(|m| m.binary.as_ref()) {
        if bin.is_pie {
            out.insert("is_pie".into(), json!(true));
        }
        if bin.is_stripped {
            out.insert("is_stripped".into(), json!(true));
        }
        if bin.has_debug_info {
            out.insert("has_debug_info".into(), json!(true));
        }
    }

    out
}

fn signing_section(report: &AnalysisReport) -> Map<String, Value> {
    let mut out = Map::new();
    let Some(metrics) = report.metrics.as_ref() else {
        return out;
    };

    // Mirror cross-format signing bools from metrics for ML
    // pipelines and trait ergonomics.
    if let Some(bin) = metrics.binary.as_ref() {
        if bin.has_signature {
            out.insert("is_signed".into(), json!(true));
            // signature_valid lives on the format-specific struct; pull
            // from whichever format is present.
            let valid = metrics
                .pe
                .as_ref()
                .and_then(|p| p.signature_valid)
                .or_else(|| metrics.macho.as_ref().and_then(|m| m.signature_valid));
            if let Some(v) = valid {
                out.insert("signature_valid".into(), json!(v));
            }
        }
    }
    // Cross-format signer identity. PE side prefers the leaf cert's
    // own CN (most accurate); falls back to primary_signer (org name
    // with CA filtering) then signer (raw Authenticode CN list).
    // Mach-O side is populated separately in `binary_extractors`;
    // deep_merge there gives macho the final say.
    if let Some(pe) = metrics.pe.as_ref() {
        let subject = pe
            .leaf_subject
            .as_deref()
            .or(pe.primary_signer.as_deref())
            .or(pe.signer.as_deref())
            .filter(|s| !s.is_empty());
        if let Some(s) = subject {
            out.insert("subject".into(), json!(s));
        }
    }

    // PE-specific signing fields: timestamp + before-build sanity flag.
    if let Some(pe) = metrics.pe.as_ref() {
        if pe.signing_time != 0 {
            out.insert("signing_time".into(), json!(pe.signing_time));
        }
        // Identify the timestamping authority CN from the chain.
        // Heuristic: chain CN containing a time-stamping marker.
        // Trojanized installers sometimes use a *different* TSA than the
        // legitimate vendor's normal pipeline.
        if let Some(signer_chain) = pe.signer.as_deref() {
            if let Some(ts) = identify_timestamping_authority(signer_chain) {
                out.insert("countersigner".into(), json!(ts));
            }
        }
        // `signed_before_built` is a derived comparison (signing_time
        // < timestamp), not a raw structural read — lives on the
        // metric `pe.signing_time_before_timestamp`, not in kv.
        // Cross-format catalog identifier so trait authors can
        // disambiguate Mach-O vs PE Authenticode without checking
        // file_type.  PE-side signature presence comes from the
        // shared `binary.has_signature` flag set above.
        if metrics.binary.as_ref().is_some_and(|b| b.has_signature) {
            out.entry("catalog".to_string())
                .or_insert_with(|| json!("authenticode"));
        }
        // Leaf cert details (PE Authenticode). `subject` is set above
        // by the cross-format identity path.
        if let Some(s) = pe.leaf_issuer.as_deref() {
            if !s.is_empty() {
                out.insert("issuer".into(), json!(s));
            }
        }
        if let Some(s) = pe.leaf_thumbprint_sha1.as_deref() {
            if !s.is_empty() {
                out.insert("thumbprint_sha1".into(), json!(s));
            }
        }
        if let Some(s) = pe.leaf_serial.as_deref() {
            if !s.is_empty() {
                out.insert("serial".into(), json!(s));
            }
        }
        if pe.leaf_not_before != 0 {
            out.insert("not_before".into(), json!(pe.leaf_not_before));
        }
        if pe.leaf_not_after != 0 {
            out.insert("not_after".into(), json!(pe.leaf_not_after));
        }
        // Authentihash mirror — Authenticode-canonical SHA-256, useful
        // for "same body, different cert" detection across releases.
        if let Some(h) = pe.authentihash.as_deref() {
            if !h.is_empty() {
                out.insert("authentihash".into(), json!(h));
            }
        }
        // `chain_depth` is a derived count — lives on
        // `pe.cert_chain_depth` metric, not in kv.
    }

    // Mirror Mach-O hardened_runtime / allow_jit from
    // `macho.*` metrics for ML pipelines and trait ergonomics.
    if let Some(macho) = metrics.macho.as_ref() {
        if macho.hardened_runtime {
            out.insert("hardened_runtime".into(), json!(true));
        }
        if macho.allow_jit {
            out.insert("allow_jit".into(), json!(true));
        }
        if macho.is_notarized {
            out.insert("notarized".into(), json!(true));
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
    if pe.timestamp_is_zero {
        out.insert("timestamp_is_zero".into(), json!(true));
    }
    if pe.checksum_present {
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
    if elf.has_interpreter {
        out.insert("has_interpreter".into(), json!(true));
    }
    if elf.has_soname {
        out.insert("has_soname".into(), json!(true));
    }
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
        // Library declaring a direct dependency on the dynamic linker
        // (`ld-linux-*`, `ld-musl-*`) is a topology anomaly. Loader
        // libs are normally pulled in transitively by libc; an
        // explicit DT_NEEDED is rare outside of statically-linked
        // glibc internals and the xz 5.6.0 backdoor.
        if elf
            .needed
            .iter()
            .any(|n| is_dynamic_loader_soname(n.as_str()))
        {
            out.insert("has_direct_interp_dep".into(), json!(true));
        }
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
    if let Some(s) = elf.x86_isa_level_required.as_deref() {
        out.insert("x86_isa_level_required".into(), json!(s));
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
    // Modern-vs-legacy markers (mirror cleave's existing
    // `pe.is_reproducible_build`-style booleans).
    if macho.has_chained_fixups {
        out.insert("has_chained_fixups".into(), json!(true));
    }
    if macho.has_dyld_info_legacy {
        out.insert("has_dyld_info_legacy".into(), json!(true));
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
    // Decoded CodeDirectory flag bits when signed — mirrors the
    // header_flags pattern but for the codesign side. Sourced from
    // the per-bit booleans on MachoMetrics (raw flags live on
    // CodeSignature, not exposed at the metric level).
    let mut cs = Map::new();
    if macho.cs_runtime_flag {
        cs.insert("runtime".into(), json!(true));
    }
    if macho.cs_library_validation {
        cs.insert("library_validation".into(), json!(true));
    }
    if macho.cs_linker_signed {
        cs.insert("linker_signed".into(), json!(true));
    }
    if macho.cs_force_kill {
        cs.insert("force_kill".into(), json!(true));
    }
    if !cs.is_empty() {
        out.insert("cs_flags".into(), Value::Object(cs));
    }
    if let Some(rv) = macho.cs_runtime_version.as_deref() {
        out.insert("cs_runtime_version".into(), json!(rv));
    }
    if macho.has_data_const_segment {
        out.insert("has_data_const_segment".into(), json!(true));
    }
    if !macho.overlapping_segments.is_empty() {
        out.insert(
            "overlapping_segments".into(),
            json!(macho.overlapping_segments.clone()),
        );
    }
    // Tier 1 — supply-chain similarity hashes (machofile-inspired).
    if let Some(h) = macho.dylib_hash.as_deref() {
        out.insert("dylib_hash".into(), json!(h));
    }
    if let Some(h) = macho.symhash.as_deref() {
        out.insert("symhash".into(), json!(h));
    }
    if let Some(h) = macho.export_hash.as_deref() {
        out.insert("export_hash".into(), json!(h));
    }
    if let Some(h) = macho.entitlement_hash.as_deref() {
        out.insert("entitlement_hash".into(), json!(h));
    }

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

fn is_dynamic_loader_soname(name: &str) -> bool {
    let base = name.rsplit('/').next().unwrap_or(name);
    base.starts_with("ld-linux")
        || base.starts_with("ld-musl")
        || base.starts_with("ld.so")
        || base.starts_with("ld64.so")
        || base == "ld.so"
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
                ..Default::default()
            }),
            pe: Some(crate::types::binary_metrics::PeMetrics {
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
}
