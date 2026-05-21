//! PE (Portable Executable) analyzer for Windows binaries.
//!
//! Every PE-internal helper takes a non-optional
//! [`crate::analysis_context::AnalysisContext`]: structural data
//! (sections, imports, exports, characteristics) is read from
//! `expose`'s typed views rather than re-walked with goblin. The
//! analyzer no longer carries its own goblin parse path.
use crate::analyzers::{AnalysisInput, Analyzer};
use crate::capabilities::CapabilityMapper;
use crate::radare2::Radare2Analyzer;
use crate::strings::StringExtractor;
use crate::types::{
    AnalysisReport, Criticality, Evidence, Export, Finding, FindingKind, Function, Import, Metrics,
    Section, StringInfo, StructuralFeature, TargetInfo,
};
use crate::yara_engine::YaraEngine;
use anyhow::{Context, Result};
use std::collections::HashSet;
use std::fs;
use std::path::Path;
use std::sync::Arc;

type Ctx<'a> = crate::analysis_context::AnalysisContext<'a>;

/// Analyzer for Windows PE binaries (executables, DLLs, drivers)
#[derive(Debug)]
pub struct PEAnalyzer {
    capability_mapper: Arc<CapabilityMapper>,
    radare2: Radare2Analyzer,
    string_extractor: StringExtractor,
    yara_engine: Option<Arc<YaraEngine>>,
    /// Pre-extracted strings from stng (avoids redundant extraction)
    preextracted_strings: Option<Vec<StringInfo>>,
    /// When true, skip scanning for embedded PE/ELF binaries (prevents recursion in sub-analysis).
    skip_embedded_scan: bool,
    /// Per-request cancellation flag.
    cancellation: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
}

/// True when the PE has the IMAGE_FILE_DLL characteristic
/// (`0x2000`) set. Reads from expose's `pe.characteristics_raw`
/// emission, which always carries the raw COFF Characteristics u16.
fn is_dll_from_ctx(ctx: &Ctx<'_>) -> bool {
    ctx.parsed
        .values()
        .get("pe.characteristics_raw")
        .and_then(|v| v.as_u64())
        .is_some_and(|c| c & 0x2000 != 0)
}

/// Read the certificate-table range (offset, end) from expose's
/// emitted security-directory metrics. Returns `None` when the
/// directory is absent, empty, or extends past the file end.
fn pe_certificate_range_from_ctx(ctx: &Ctx<'_>, data: &[u8]) -> Option<(usize, usize)> {
    let arr = ctx
        .parsed
        .values()
        .get("pe.data_directories")
        .and_then(|v| v.as_array())?;
    for node in arr {
        let name = node.get("name").and_then(|x| x.as_str())?;
        if name != "certificate" {
            continue;
        }
        let offset = node.get("rva").and_then(|x| x.as_u64())? as usize;
        let size = node.get("size").and_then(|x| x.as_u64())? as usize;
        if offset == 0 || size == 0 || offset.checked_add(size)? > data.len() {
            return None;
        }
        return Some((offset, offset + size));
    }
    None
}

/// Canonical list of Microsoft-shipped DLLs commonly abused as sideload
/// forward targets.  Matching is case-insensitive and ignores any `.dll`
/// suffix (goblin returns forwards with or without it depending on the
/// binary).
fn is_system_dll(name: &str) -> bool {
    // Goblin returns forwards with or without the `.dll` suffix depending on
    // the source binary; strip a trailing `.dll` before matching.
    let stem = name.strip_suffix(".dll").unwrap_or(name);
    let stem = stem.strip_suffix(".DLL").unwrap_or(stem);
    matches!(
        stem.to_ascii_lowercase().as_str(),
        "kernel32"
            | "kernelbase"
            | "ntdll"
            | "user32"
            | "advapi32"
            | "gdi32"
            | "shell32"
            | "shlwapi"
            | "ole32"
            | "oleaut32"
            | "comctl32"
            | "comdlg32"
            | "ws2_32"
            | "wininet"
            | "winhttp"
            | "crypt32"
            | "version"
            | "msvcrt"
            | "rpcrt4"
            | "secur32"
            | "iphlpapi"
            | "dnsapi"
            | "netapi32"
            | "mswsock"
            | "psapi"
            | "userenv"
            | "winmm"
            | "uxtheme"
            | "setupapi"
            | "imm32"
    )
}

/// True when `name` looks like a CA, timestamp authority, or other chain
/// entry rather than a code-signing identity. Used to pick the "who really
/// signed this" organization out of the Authenticode chain.
fn is_ca_identity(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    // Role keywords that only appear in CA / intermediate / timestamp CNs.
    const ROLE_MARKERS: &[&str] = &[
        "root ca",
        "intermediate",
        "certificate authority",
        "certification authority",
        "timestamp",
        "timestamping",
        "time stamping",
        "time-stamping",
        "code signing ca",
        "code signing pca",
        "assured id",
        "worldwide developer relations",
    ];
    for marker in ROLE_MARKERS {
        if lower.contains(marker) {
            return true;
        }
    }
    // Standalone " ca" token (e.g. "Some Vendor CA") — match word-boundary
    // only, to avoid swallowing names like "California Corp".
    if lower.ends_with(" ca") || lower.contains(" ca ") {
        return true;
    }
    // Well-known CA vendor brand names. If the name *is* one of these (or
    // starts with one as a brand prefix), treat it as a CA identity.
    const CA_BRANDS: &[&str] = &[
        "digicert",
        "sectigo",
        "comodo",
        "globalsign",
        "verisign",
        "symantec",
        "thawte",
        "geotrust",
        "entrust",
        "usertrust",
        "addtrust",
        "starfield",
        "godaddy secure",
        "go daddy secure",
        "quovadis",
        "letsencrypt",
        "let's encrypt",
        "amazon trust",
        "actalis",
    ];
    for brand in CA_BRANDS {
        if lower.starts_with(brand) {
            let next = lower.as_bytes().get(brand.len()).copied();
            if next.is_none_or(|c| !c.is_ascii_alphanumeric()) {
                return true;
            }
        }
    }
    false
}

/// Strip a trailing `.dll` suffix (case-insensitive) and lowercase the result.
fn normalize_dll_stem(name: &str) -> String {
    let stem = name.strip_suffix(".dll").unwrap_or(name);
    let stem = stem.strip_suffix(".DLL").unwrap_or(stem);
    stem.to_ascii_lowercase()
}

/// Lowercased basename of `path` with any `.dll` / `.DLL` suffix removed.
/// Empty string if the path has no file component.
fn self_basename_stem(path: &Path) -> String {
    path.file_name()
        .and_then(|f| f.to_str())
        .map(normalize_dll_stem)
        .unwrap_or_default()
}

/// True when `target` is a version-suffixed variant of `self_stem` —
/// i.e. both names strip to the same non-empty alphabetic prefix once any
/// trailing ASCII digits are removed. `python3` vs `python312` → match;
/// `version` vs `version_orig` → no match (the malicious sideload pattern).
fn is_version_variant(self_stem: &str, target: &str) -> bool {
    if self_stem.is_empty() || target.is_empty() {
        return false;
    }
    let self_alpha = self_stem.trim_end_matches(|c: char| c.is_ascii_digit());
    let target_alpha = target.trim_end_matches(|c: char| c.is_ascii_digit());
    !self_alpha.is_empty() && self_alpha == target_alpha
}

fn is_standard_entry_section(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        ".text" | "text" | ".code" | "code" | ".itext" | "init" | ".init"
    )
}

/// True if a section is "BSS-like" (raw=0, virt>0) AND doesn't carry
/// one of the conventional BSS-style PE section names. The metric
/// targets packer/runtime-decompression patterns where a non-standard
/// section name claims virtual memory the file doesn't back.
/// `.bss` and `.tls` are excluded because Borland/Delphi/InnoSetup
/// binaries routinely have them zero-raw.
fn is_unusual_bss_like(name: &str, raw_size: u32, virtual_size: u32) -> bool {
    if raw_size != 0 || virtual_size == 0 {
        return false;
    }
    !matches!(
        name.to_ascii_lowercase().as_str(),
        ".bss" | "bss" | ".tls" | "tls"
    )
}

fn looks_like_dos_executable(data: &[u8]) -> bool {
    if data.len() < 0x40 || !data.starts_with(b"MZ") {
        return false;
    }

    let pe_offset = u32::from_le_bytes([data[0x3c], data[0x3d], data[0x3e], data[0x3f]]) as usize;
    if pe_offset + 4 <= data.len() && &data[pe_offset..pe_offset + 4] == b"PE\x00\x00" {
        return false;
    }

    let last_page_bytes = u16::from_le_bytes([data[2], data[3]]) as usize;
    let page_count = u16::from_le_bytes([data[4], data[5]]) as usize;
    let header_paragraphs = u16::from_le_bytes([data[8], data[9]]) as usize;
    if page_count == 0 || header_paragraphs == 0 {
        return false;
    }

    let declared_size = (page_count.saturating_sub(1) * 512)
        + if last_page_bytes == 0 {
            512
        } else {
            last_page_bytes
        };
    let header_size = header_paragraphs * 16;
    declared_size >= header_size
        && declared_size <= data.len().saturating_add(512)
        && header_size < data.len()
}

/// Aggregate debug-directory metrics from expose's emitted view in
/// `ctx.parsed.values()`. Mirrors the legacy goblin walk inside
/// `compute_pe_metrics` so callers see byte-identical PeMetrics
/// regardless of whether ctx was available.
///
/// Reads:
/// - `pe.debug.entries[]` — array of `{type, type_id, timestamp_unix, size_bytes}`
/// - `pe.debug.pdb.{path,guid,age}` — CodeView PDB fingerprint
///
/// Expose normalises the GUID to lowercase Microsoft format; this
/// helper uppercases it to match the legacy `format_pdb_guid` output.
fn fill_debug_metrics_from_ctx(
    ctx: &crate::analysis_context::AnalysisContext<'_>,
    metrics: &mut crate::types::binary_metrics::PeMetrics,
) {
    let values = ctx.parsed.values();
    let Some(entries) = values.get("pe.debug.entries").and_then(|v| v.as_array()) else {
        // PDB fields can still exist when goblin parsed an isolated
        // CodeView entry — fall through to read them below.
        fill_debug_pdb_fields_from_values(values, metrics);
        return;
    };
    metrics.debug_directory_entries = entries.len() as u32;

    let mut debug_timestamps: Vec<u32> = entries
        .iter()
        .filter_map(|e| e.get("timestamp_unix").and_then(|t| t.as_u64()))
        .map(|t| t as u32)
        .filter(|&ts| ts != 0)
        .collect();
    metrics.debug_timestamp_nonzero_count = debug_timestamps.len() as u32;
    if !debug_timestamps.is_empty() {
        debug_timestamps.sort_unstable();
        debug_timestamps.dedup();
        metrics.debug_timestamp_unique_count = debug_timestamps.len() as u32;
        metrics.debug_timestamp_min = *debug_timestamps.first().unwrap_or(&0);
        metrics.debug_timestamp_max = *debug_timestamps.last().unwrap_or(&0);
        metrics.debug_timestamp_consistent = debug_timestamps.len() == 1;
    }

    let mut types: Vec<u32> = entries
        .iter()
        .filter_map(|e| e.get("type_id").and_then(|t| t.as_u64()))
        .map(|t| t as u32)
        .collect();
    types.sort_unstable();
    types.dedup();
    metrics.has_vc_feature = types.contains(&12);
    metrics.has_pogo = types.contains(&13);
    metrics.has_iltcg = types.contains(&14);
    metrics.is_reproducible_build = types.contains(&16);
    metrics.debug_directory_types = types;

    fill_debug_pdb_fields_from_values(values, metrics);
}

/// Pull the first RFC-2253 CN value out of a DN string. The format
/// expose emits is `"CN=Foo,O=Bar,L=Baz,C=US"` — comma-separated
/// `attr=value` segments. We split on commas, skip the trailing
/// whitespace x509-cert sometimes leaves, and return the first
/// segment whose attribute is exactly `CN`.
///
/// Returns `None` for malformed inputs or DNs without a CN.
fn dn_extract_cn(dn: &str) -> Option<String> {
    for raw in dn.split(',') {
        let seg = raw.trim();
        // Accept `CN=…` case-insensitively — RFC 4514 attributes are
        // case-insensitive and x509-cert canonicalises to upper-case
        // but we don't rely on the canonicalisation.
        if let Some(rest) = seg.strip_prefix("CN=").or_else(|| seg.strip_prefix("cn=")) {
            return Some(rest.trim().to_string());
        }
    }
    None
}

/// Pull the first O attribute from a DN string. Same comma-split as
/// `dn_extract_cn`; returns `None` when the DN doesn't carry one.
fn dn_extract_o(dn: &str) -> Option<String> {
    for raw in dn.split(',') {
        let seg = raw.trim();
        if let Some(rest) = seg.strip_prefix("O=").or_else(|| seg.strip_prefix("o=")) {
            return Some(rest.trim().to_string());
        }
    }
    None
}

/// Parse expose's ISO-8601 timestamp form back to a Unix epoch.
/// Format is `"YYYY-MM-DDTHH:MM:SSZ"` exactly (no fractional, always
/// UTC) — matches what `der::DateTime::to_string()` produces.
/// Returns 0 on parse failure; callers treat 0 as "unset".
fn parse_iso8601_to_unix(s: &str) -> i64 {
    chrono::DateTime::parse_from_rfc3339(s)
        .map(|dt| dt.timestamp())
        .unwrap_or(0)
}

/// Populate every PeMetrics Authenticode field from expose's typed
/// `pe.signatures[]` view. Mirrors the goblin-walking block inside
/// `compute_pe_metrics` byte-for-byte where the underlying data is
/// available; fields that depend on the full SignerInfo / certificate
/// bag (e.g. `signer_info_matches_leaf` semantics) are derived from
/// what expose already exposes about the signer cert.
///
/// Behaviour notes:
/// - The signature claim ("is the file signed?") is `pe.signatures[]
///   non-empty`. Empty array (or absent) leaves `has_signature = false`
///   and the other fields at their `PeMetrics::default()` values.
/// - When expose's `pe.security_directory_out_of_bounds` metric is set
///   (the cert-table directory points past EOF), we set the legacy
///   typed boolean accordingly and skip the rest — there is no signature
///   to extract.
/// - `signer_info_matches_leaf` is `true` when expose was able to
///   resolve the signer's cert from the bag (which means
///   `subject`/`thumbprint_sha1` are populated). `signer_info_mismatches_leaf`
///   is the inverse on a signed binary — SignerInfo present but cert
///   not in bag — but expose doesn't surface that condition explicitly
///   yet; we leave it at default `false`.
fn fill_authenticode_metrics_from_ctx(
    ctx: &crate::analysis_context::AnalysisContext<'_>,
    metrics: &mut crate::types::binary_metrics::PeMetrics,
) {
    let m = ctx.parsed.metrics();
    let v = ctx.parsed.values();

    // Cert-table size + out-of-bounds marker first — they're emitted
    // even when the PKCS#7 parse failed. `pe.cert_table_size` is a
    // values key (u64); `pe.security_directory_out_of_bounds` is a
    // metric presence flag.
    metrics.certificate_table_size = v
        .get("pe.cert_table_size")
        .and_then(|x| x.as_u64())
        .unwrap_or(0);
    metrics.security_directory_out_of_bounds =
        m.get("pe.security_directory_out_of_bounds").is_some();

    let Some(sig) = v
        .get("pe.signatures")
        .and_then(|x| x.as_array())
        .and_then(|a| a.first())
    else {
        return;
    };
    metrics.has_signature = true;

    populate_leaf_fields(sig, metrics);
    populate_signing_time(sig, metrics);
    populate_spc_digest(sig, metrics);

    // Cert-chain depth: expose emits the count of certs in the
    // SignedData bag, which matches what cleave used to derive from
    // `parse_pkcs7_certificates(...).len()` once.
    metrics.cert_chain_depth = sig
        .get("cert_chain_depth")
        .and_then(|x| x.as_u64())
        .map(|x| x as u32)
        .unwrap_or(0);

    metrics.has_nested_signature = sig.get("nested").is_some();
    if let Some(nested) = sig.get("nested") {
        populate_nested_signer_fields(nested, metrics);
    }
}

/// Map expose's per-signature object onto the typed leaf-cert fields.
/// Pure transformation — string parsing only; no I/O. Splits the
/// helper out so the parent function stays scannable.
fn populate_leaf_fields(
    sig: &serde_json::Value,
    metrics: &mut crate::types::binary_metrics::PeMetrics,
) {
    if let Some(subject) = sig.get("subject").and_then(|x| x.as_str()) {
        metrics.leaf_subject = dn_extract_cn(subject);
        // `signer` is the leaf CN, by convention — historic cleave
        // joined multiple CNs but the leaf is what every consumer
        // actually wants. `primary_signer` prefers the leaf O when
        // present, falling back to the leaf CN if the org isn't set
        // or is a CA identity.
        if metrics.leaf_subject.is_some() {
            metrics.signer = metrics.leaf_subject.clone();
            let o = dn_extract_o(subject);
            let primary = o
                .as_deref()
                .filter(|s| !is_ca_identity(s))
                .or(metrics.leaf_subject.as_deref().filter(|s| !is_ca_identity(s)));
            metrics.primary_signer = primary.map(str::to_string);
            // Platform/developer classification — same Microsoft /
            // Windows substring check the legacy path uses.
            let s = metrics.leaf_subject.as_deref().unwrap_or("");
            metrics.signature_type = Some(
                if s.contains("Microsoft") || s.contains("Windows") {
                    "platform".to_string()
                } else {
                    "developer".to_string()
                },
            );
        }
    }
    if let Some(issuer) = sig.get("issuer").and_then(|x| x.as_str()) {
        metrics.leaf_issuer = dn_extract_cn(issuer);
        // Also surface the full issuer DN's first CN on
        // `signer_info_issuer` — the legacy path populates it from
        // SignerInfo.issuerAndSerialNumber, but expose's signer-cert
        // resolution already matched on that pair, so the leaf's
        // issuer CN is the same value.
        metrics.signer_info_issuer = metrics.leaf_issuer.clone();
    }
    if let (Some(s), Some(i)) = (
        metrics.leaf_subject.as_deref(),
        metrics.leaf_issuer.as_deref(),
    ) {
        metrics.leaf_self_issued = !s.is_empty() && s == i;
    }
    metrics.leaf_eku_code_signing = sig
        .get("eku_code_signing")
        .and_then(|x| x.as_bool())
        .unwrap_or(false);
    if let Some(s) = sig.get("signature_algorithm").and_then(|x| x.as_str()) {
        metrics.leaf_signature_algorithm = Some(s.to_string());
    }
    if let Some(s) = sig.get("serial").and_then(|x| x.as_str()) {
        metrics.leaf_serial = Some(s.to_string());
        metrics.signer_info_serial = Some(s.to_string());
    }
    metrics.leaf_not_before = sig
        .get("not_before")
        .and_then(|x| x.as_str())
        .map(parse_iso8601_to_unix)
        .unwrap_or(0);
    metrics.leaf_not_after = sig
        .get("not_after")
        .and_then(|x| x.as_str())
        .map(parse_iso8601_to_unix)
        .unwrap_or(0);
    let validity_secs = metrics.leaf_not_after.saturating_sub(metrics.leaf_not_before);
    if validity_secs > 0 {
        metrics.cert_validity_days = (validity_secs / 86_400) as u32;
    }
    if let Some(s) = sig.get("thumbprint_sha1").and_then(|x| x.as_str()) {
        metrics.leaf_thumbprint_sha1 = Some(s.to_string());
    }
    // Signature verification outcome. Expose emits `verified` as a
    // bool when verification ran (true/false), and the companion
    // `verification_unsupported = true` when the OID combination
    // was off-pair. We mirror that on the typed fields.
    match sig.get("verified") {
        Some(serde_json::Value::Bool(b)) => {
            metrics.signature_verified = Some(*b);
        }
        Some(serde_json::Value::Null) | None => {
            metrics.signature_verified = None;
        }
        _ => {}
    }
    metrics.sig_algorithm_unsupported = sig
        .get("verification_unsupported")
        .and_then(|x| x.as_bool())
        .unwrap_or(false);

    // The SignerInfo→cert bag match: when expose resolved the signer
    // cert (subject populated), the SI and the chosen leaf agreed.
    metrics.signer_info_matches_leaf = sig.get("subject").is_some();
}

fn populate_signing_time(
    sig: &serde_json::Value,
    metrics: &mut crate::types::binary_metrics::PeMetrics,
) {
    let Some(unix) = sig.get("signing_time_unix").and_then(|x| x.as_i64()) else {
        return;
    };
    metrics.signing_time = unix.max(0) as u64;
    metrics.signing_time_before_timestamp = unix < metrics.timestamp as i64;
}

fn populate_spc_digest(
    sig: &serde_json::Value,
    metrics: &mut crate::types::binary_metrics::PeMetrics,
) {
    if let Some(s) = sig.get("signature_digest_algorithm").and_then(|x| x.as_str()) {
        metrics.signature_digest_algorithm = Some(s.to_string());
    }
    if let Some(s) = sig.get("signature_digest").and_then(|x| x.as_str()) {
        metrics.signature_digest = Some(s.to_string());
    }
}

/// Data-directory bounds checks. For the export + import directories
/// we ask "is the directory's RVA inside any section's virtual extent?";
/// for the resource directory we further check "does it span past
/// the containing section's end?".
///
/// Drives off expose's typed `pe.data_directories[]` (canonical names)
/// + typed `Sections` view. The string-name match (`"export"`,
/// `"import"`, `"resource"`) is the contract expose's emitter
/// established; if it ever changes those names, this code (and the
/// parity test) catch the drift immediately.
fn fill_data_directory_bounds_from_ctx(
    ctx: &crate::analysis_context::AnalysisContext<'_>,
    metrics: &mut crate::types::binary_metrics::PeMetrics,
) {
    let v = ctx.parsed.values();
    let sections = ctx.parsed.sections();
    let Some(arr) = v.get("pe.data_directories").and_then(|x| x.as_array()) else {
        return;
    };
    // Local "RVA is inside this section's virtual extent" predicate.
    let section_containing = |rva: u32| -> Option<&expose::Section> {
        if rva == 0 {
            return None;
        }
        sections.iter().find(|s| {
            let start = s.vaddr as u32;
            let span = (s.vsize.max(s.file_size)) as u32;
            rva >= start && rva < start.saturating_add(span)
        })
    };
    for node in arr {
        let (Some(name), Some(rva), Some(size)) = (
            node.get("name").and_then(|x| x.as_str()),
            node.get("rva").and_then(|x| x.as_u64()).map(|x| x as u32),
            node.get("size").and_then(|x| x.as_u64()).map(|x| x as u32),
        ) else {
            continue;
        };
        if rva == 0 || size == 0 {
            continue;
        }
        match name {
            "export" => {
                metrics.export_dir_outside_section = section_containing(rva).is_none();
            }
            "import" => {
                metrics.import_dir_outside_section = section_containing(rva).is_none();
            }
            "resource" => match section_containing(rva) {
                Some(s) => {
                    let section_end =
                        (s.vaddr as u32).saturating_add((s.vsize.max(s.file_size)) as u32);
                    let dir_end = rva.saturating_add(size);
                    if dir_end > section_end {
                        metrics.rsrc_dir_overruns_section = true;
                    }
                }
                None => metrics.rsrc_dir_overruns_section = true,
            },
            _ => {}
        }
    }
}

/// Count TLS callback RVAs that land in non-executable sections —
/// a classic shellcode-loader indicator. Reads the callback VAs from
/// expose's `pe.tls_callbacks[]` (each entry's `addr` is the absolute
/// VA as a hex string), subtracts image_base to get the RVA, and
/// asks the typed Sections view whether the RVA's containing section
/// carries the `executable` flag.
fn fill_tls_callbacks_outside_code_from_ctx(
    ctx: &crate::analysis_context::AnalysisContext<'_>,
    metrics: &mut crate::types::binary_metrics::PeMetrics,
) {
    let v = ctx.parsed.values();
    let sections = ctx.parsed.sections();
    let Some(arr) = v.get("pe.tls_callbacks").and_then(|x| x.as_array()) else {
        return;
    };
    let image_base = metrics.image_base;
    let in_executable_section = |rva: u32| -> bool {
        if rva == 0 {
            return false;
        }
        sections.iter().any(|s| {
            let start = s.vaddr as u32;
            let span = (s.vsize.max(s.file_size)) as u32;
            rva >= start
                && rva < start.saturating_add(span)
                && s.flags.iter().any(|f| f == "executable")
        })
    };
    for node in arr {
        let Some(addr_str) = node.get("addr").and_then(|x| x.as_str()) else {
            continue;
        };
        let s = addr_str.strip_prefix("0x").unwrap_or(addr_str);
        let Ok(va) = u64::from_str_radix(s, 16) else {
            continue;
        };
        let rva = va.saturating_sub(image_base) as u32;
        if rva != 0 && !in_executable_section(rva) {
            metrics.tls_callbacks_outside_code =
                metrics.tls_callbacks_outside_code.saturating_add(1);
        }
    }
}

/// Pull expose's pre-computed Authenticode image hashes
/// (`pe.image_hash.sha1` / `.sha256` / `.sha384` / `.sha512`) and the
/// overlay padding metric into the typed PeMetrics fields.
/// Names map historically as: SHA-256 → `authentihash` (the legacy
/// default), the other algorithms → `authentihash_{sha1,sha384,sha512}`.
fn fill_image_hashes_from_ctx(
    ctx: &crate::analysis_context::AnalysisContext<'_>,
    metrics: &mut crate::types::binary_metrics::PeMetrics,
) {
    let v = ctx.parsed.values();
    metrics.authentihash = v
        .get("pe.image_hash.sha256")
        .and_then(|x| x.as_str())
        .map(str::to_string);
    metrics.authentihash_sha1 = v
        .get("pe.image_hash.sha1")
        .and_then(|x| x.as_str())
        .map(str::to_string);
    metrics.authentihash_sha384 = v
        .get("pe.image_hash.sha384")
        .and_then(|x| x.as_str())
        .map(str::to_string);
    metrics.authentihash_sha512 = v
        .get("pe.image_hash.sha512")
        .and_then(|x| x.as_str())
        .map(str::to_string);
    metrics.overlay_padding = ctx
        .parsed
        .metrics()
        .get("pe.overlay_padding")
        .map(|x| x as u64)
        .unwrap_or(0);
}

/// `signature_digest_mismatch` — the signature's claimed PE image
/// digest disagrees with the recomputed Authentihash for the same
/// algorithm. A non-default `true` is a strong tampering signal: the
/// signed bytes were modified post-signing-time.
///
/// Pure derivation off already-populated PeMetrics fields — works
/// identically whether the digests came from the ctx path or the
/// legacy goblin walker.
fn derive_signature_digest_mismatch(metrics: &crate::types::binary_metrics::PeMetrics) -> bool {
    let (Some(alg), Some(claimed)) = (
        metrics.signature_digest_algorithm.as_deref(),
        metrics.signature_digest.as_deref(),
    ) else {
        return false;
    };
    let computed = match alg {
        "sha1" => metrics.authentihash_sha1.as_deref(),
        "sha256" => metrics.authentihash.as_deref(),
        "sha384" => metrics.authentihash_sha384.as_deref(),
        "sha512" => metrics.authentihash_sha512.as_deref(),
        _ => return false,
    };
    computed.is_some_and(|c| c != claimed)
}

/// Populate the typed `bound_imports` Vec + `bound_imports_checksum`
/// from expose's emitted view. Expose already walks the bound-import
/// directory under panic-safety and emits the per-module triple
/// (name, time_date_stamp, forwarder_ref_count) alongside the CRC-32
/// fingerprint over the canonical-sorted set. We copy the values
/// across without re-hashing.
fn fill_bound_imports_from_ctx(
    ctx: &crate::analysis_context::AnalysisContext<'_>,
    metrics: &mut crate::types::binary_metrics::PeMetrics,
) {
    use crate::types::binary_metrics::BoundImportDescriptor;
    let v = ctx.parsed.values();
    let Some(arr) = v.get("pe.bound_imports").and_then(|x| x.as_array()) else {
        return;
    };
    let mut out: Vec<BoundImportDescriptor> = Vec::with_capacity(arr.len());
    for node in arr {
        let (Some(name), Some(ts), Some(fc)) = (
            node.get("name").and_then(|x| x.as_str()),
            node.get("time_date_stamp").and_then(|x| x.as_u64()),
            node.get("forwarder_ref_count").and_then(|x| x.as_u64()),
        ) else {
            continue;
        };
        out.push(BoundImportDescriptor {
            name: name.to_string(),
            time_date_stamp: ts as u32,
            forwarder_ref_count: fc as u32,
        });
    }
    if out.is_empty() {
        return;
    }
    metrics.bound_imports = out;
    metrics.bound_imports_checksum = ctx
        .parsed
        .metrics()
        .get("pe.bound_imports_fingerprint")
        .map(|x| x as u32)
        .unwrap_or(0);
}

/// Populate the LoadConfig typed fields (security_cookie, CFG check
/// function pointer, CFG function count, CFG guard flags) from
/// expose's `pe.load_config.*` object. Expose surfaces the raw u64 /
/// u32 values directly out of goblin's parsed structure — no manual
/// byte-walk on this side.
fn fill_load_config_from_ctx(
    ctx: &crate::analysis_context::AnalysisContext<'_>,
    metrics: &mut crate::types::binary_metrics::PeMetrics,
) {
    let v = ctx.parsed.values();
    let Some(obj) = v.get("pe.load_config") else {
        return;
    };
    if let Some(x) = obj.get("security_cookie").and_then(|x| x.as_u64()) {
        metrics.security_cookie = x;
    }
    if let Some(x) = obj
        .get("guard_cf_check_function_pointer")
        .and_then(|x| x.as_u64())
    {
        metrics.cfg_check_func = x;
    }
    if let Some(x) = obj.get("guard_cf_function_count").and_then(|x| x.as_u64()) {
        metrics.cfg_func_count = x as u32;
    }
    if let Some(x) = obj.get("guard_flags_raw").and_then(|x| x.as_u64()) {
        metrics.cfg_guard_flags = x as u32;
    }
}

fn populate_nested_signer_fields(
    nested: &serde_json::Value,
    metrics: &mut crate::types::binary_metrics::PeMetrics,
) {
    if let Some(subject) = nested.get("subject").and_then(|x| x.as_str()) {
        metrics.nested_leaf_subject = dn_extract_cn(subject);
    }
    if let Some(issuer) = nested.get("issuer").and_then(|x| x.as_str()) {
        metrics.nested_leaf_issuer = dn_extract_cn(issuer);
    }
    metrics.nested_leaf_eku_code_signing = nested
        .get("eku_code_signing")
        .and_then(|x| x.as_bool())
        .unwrap_or(false);
    if let Some(s) = nested.get("signature_algorithm").and_then(|x| x.as_str()) {
        metrics.nested_leaf_signature_algorithm = Some(s.to_string());
    }
    if let Some(s) = nested.get("thumbprint_sha1").and_then(|x| x.as_str()) {
        metrics.nested_leaf_thumbprint_sha1 = Some(s.to_string());
    }
}

/// Populate the section-walk metrics block from expose's typed
/// Sections view. Mirrors the legacy goblin walk byte-for-byte:
/// entry-point anomalies, raw-overflow + misalignment audit, section
/// count mismatch (skipped — needs COFF NumberOfSections), pairwise
/// virtual-range overlap, first-section gap, entry-in-last-section,
/// and BSS-like count.
///
/// `file_alignment` comes from goblin until expose surfaces it; pass
/// zero to skip the misalignment audit.
fn fill_section_walk_metrics_from_ctx(
    ctx: &crate::analysis_context::AnalysisContext<'_>,
    ep_rva: u32,
    is_lib: bool,
    file_size: u64,
    file_alignment: u32,
    metrics: &mut crate::types::binary_metrics::PeMetrics,
) {
    let sections = ctx.parsed.sections();

    if metrics.size_of_headers != 0 && ep_rva < metrics.size_of_headers {
        metrics.entry_in_header = true;
    }

    // Entry-point containment + writable-section flag.
    let mut ep_in_section = false;
    for s in sections.iter() {
        let start = s.vaddr as u32;
        let span = (s.vsize.max(s.file_size)) as u32;
        let end = start.saturating_add(span);
        if ep_rva >= start && ep_rva < end {
            ep_in_section = true;
            metrics.entry_in_writable_section =
                s.flags.iter().any(|f| f == "writable");
            break;
        }
    }
    if !ep_in_section && ep_rva != 0 && !is_lib {
        metrics.entry_outside_sections = true;
    }

    // Section overflow + misalignment audit.
    for s in sections.iter() {
        let raw_end = s.file_offset.saturating_add(s.file_size);
        if s.file_size > 0 && raw_end > file_size {
            metrics.section_raw_overflow_count =
                metrics.section_raw_overflow_count.saturating_add(1);
            metrics.overflowing_sections.push(s.name.clone());
        }
        if file_alignment > 0
            && s.file_offset != 0
            && (s.file_offset as u32) % file_alignment != 0
        {
            metrics.misaligned_section_count =
                metrics.misaligned_section_count.saturating_add(1);
            metrics.misaligned_sections.push(s.name.clone());
        }
    }

    // Section count mismatch — expose emits `pe.section_count_mismatch`
    // as a presence flag when the COFF NumberOfSections diverges from
    // the actual table length.
    metrics.section_count_mismatch =
        ctx.parsed.metrics().get("pe.section_count_mismatch").is_some();

    // Pairwise virtual-range overlap.
    if sections.len() > 1 {
        let mut by_va: Vec<(u32, u32, String)> = sections
            .iter()
            .map(|s| {
                let span = (s.vsize.max(s.file_size)) as u32;
                (
                    s.vaddr as u32,
                    (s.vaddr as u32).saturating_add(span),
                    s.name.clone(),
                )
            })
            .collect();
        by_va.sort_by_key(|t| t.0);
        let mut overlap_names: HashSet<String> = HashSet::new();
        for w in by_va.windows(2) {
            let (a_start, a_end, a_name) = (w[0].0, w[0].1, w[0].2.clone());
            let (b_start, _, b_name) = (w[1].0, w[1].1, w[1].2.clone());
            if a_end > b_start && b_start >= a_start {
                overlap_names.insert(a_name);
                overlap_names.insert(b_name);
            }
        }
        metrics.section_overlap_count = overlap_names.len() as u32;
        metrics.overlapping_sections = overlap_names.into_iter().collect();
        metrics.overlapping_sections.sort();
    }

    // First-section gap = (smallest non-zero file_offset) − size_of_headers.
    if metrics.size_of_headers != 0 {
        if let Some(first_raw) = sections
            .iter()
            .map(|s| s.file_offset as u32)
            .filter(|&p| p > 0)
            .min()
        {
            metrics.first_section_gap = first_raw.saturating_sub(metrics.size_of_headers);
        }
    }

    // Entry-in-last-section by virtual address.
    if let Some(last) = sections.iter().max_by_key(|s| s.vaddr) {
        let start = last.vaddr as u32;
        let span = (last.vsize.max(last.file_size)) as u32;
        let end = start.saturating_add(span);
        if ep_rva >= start && ep_rva < end && ep_rva != 0 {
            metrics.entry_in_last_section = true;
        }
    }

    // BSS-like count over the same `is_unusual_bss_like` predicate the
    // legacy walk uses. `file_size` here is the section file_size from
    // the typed view (raw bytes on disk); `vsize` is the in-memory
    // size.
    metrics.bss_like_section_count = sections
        .iter()
        .filter(|s| is_unusual_bss_like(&s.name, s.file_size as u32, s.vsize as u32))
        .count() as u32;
}

fn fill_debug_pdb_fields_from_values(
    values: &expose::Values,
    metrics: &mut crate::types::binary_metrics::PeMetrics,
) {
    if let Some(path) = values.get("pe.debug.pdb.path").and_then(|v| v.as_str()) {
        let trimmed = path.trim_end_matches('\0');
        if !trimmed.is_empty() {
            metrics.pdb_path = Some(trimmed.to_string());
        }
    }
    // Expose's PDB 7.0 GUID format is Microsoft canonical (lowercase,
    // hyphenated). The legacy `format_pdb_guid` produces uppercase;
    // trait authors and downstream consumers match against either
    // case insensitively, but for byte-equal parity with the legacy
    // path we uppercase here.
    if let Some(guid) = values.get("pe.debug.pdb.guid").and_then(|v| v.as_str()) {
        metrics.codeview_guid = Some(guid.to_ascii_uppercase());
    }
    if let Some(age) = values.get("pe.debug.pdb.age").and_then(|v| v.as_u64()) {
        metrics.codeview_age = age as u32;
    }
}

impl PEAnalyzer {
    /// Emit the small list of structural-feature entries cleave's
    /// downstream consumers expect: `pe/header`, `pe/dll` (when the
    /// IMAGE_FILE_DLL characteristic is set), and `pe/optional_header`
    /// (when the optional header is present). All facts come from
    /// expose's emitted values — no goblin re-walk.
    fn structural_features(&self, ctx: &Ctx<'_>) -> Vec<StructuralFeature> {
        let mut features = Vec::new();
        let values = ctx.parsed.values();
        let machine = values
            .get("pe.machine")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        let subsystem = values
            .get("pe.subsystem")
            .and_then(|v| v.as_str())
            .map(str::to_string);
        features.push(StructuralFeature {
            id: "pe/header".to_string(),
            desc: format!("PE file (machine: {}, subsystem: {:?})", machine, subsystem),
            evidence: vec![Evidence {
                method: "header".to_string(),
                source: "expose".to_string(),
                value: "PE".to_string(),
                location: None,
                ..Default::default()
            }],
        });

        if is_dll_from_ctx(ctx) {
            features.push(StructuralFeature {
                id: "pe/dll".to_string(),
                desc: "Dynamic Link Library (DLL)".to_string(),
                evidence: vec![Evidence {
                    method: "header".to_string(),
                    source: "expose".to_string(),
                    value: "DLL".to_string(),
                    location: None,
                    ..Default::default()
                }],
            });
        }

        if values.get("pe.subsystem").is_some() {
            features.push(StructuralFeature {
                id: "pe/optional_header".to_string(),
                desc: "Has optional header (standard Windows executable)".to_string(),
                evidence: vec![Evidence {
                    method: "header".to_string(),
                    source: "expose".to_string(),
                    value: "OptionalHeader".to_string(),
                    location: None,
                    ..Default::default()
                }],
            });
        }
        features
    }

    /// Project expose's typed `Imports` view into `Vec<Import>` and
    /// run capability-mapper lookups over the symbol set. Symbol
    /// names are pre-normalised inside `imports_from_expose`.
    fn pe_imports(&self, ctx: &Ctx<'_>) -> (Vec<Import>, Vec<Finding>) {
        let imports = ctx.imports_from_expose();
        let mut findings = Vec::new();
        for imp in &imports {
            let normalized = crate::types::binary::normalize_symbol(&imp.symbol);
            if let Some(capability) = self.capability_mapper.lookup(&normalized, &imp.source) {
                findings.push(capability);
            }
        }
        (imports, findings)
    }

    /// Project expose's typed `Exports` view and the
    /// `pe.aliased_export_count` metric. Aliased exports are stub
    /// chains where multiple exported names land at the same target;
    /// expose's `aliased_exports` walker emits the count, so cleave
    /// doesn't disassemble locally.
    fn pe_exports(&self, ctx: &Ctx<'_>) -> (Vec<Export>, Option<u32>) {
        let exports = ctx.exports_from_expose();
        let aliased = if exports.len() < 2 {
            None
        } else {
            let count = ctx
                .parsed
                .metrics()
                .get("pe.aliased_export_count")
                .map(|v| v as u32)
                .unwrap_or(0);
            (count > 0).then_some(count)
        };
        (exports, aliased)
    }

    /// Project expose's typed `Sections` view into `Vec<Section>`.
    /// Per-section entropy comes from expose's metric map (no second
    /// scan over the section bytes).
    fn pe_sections(&self, ctx: &Ctx<'_>) -> Vec<Section> {
        ctx.sections_from_expose()
    }
    /// Creates a new PE analyzer with default configuration
    #[must_use]
    pub fn new() -> Self {
        Self {
            capability_mapper: Arc::new(CapabilityMapper::empty()),
            radare2: Radare2Analyzer::new(),
            string_extractor: StringExtractor::new(),
            yara_engine: None,
            preextracted_strings: None,
            skip_embedded_scan: false,
            cancellation: None,
        }
    }

    /// Disable embedded binary scanning (used when analyzing extracted sub-files).
    #[must_use]
    pub(crate) fn without_embedded_scan(mut self) -> Self {
        self.skip_embedded_scan = true;
        self
    }

    /// Set per-request cancellation flag.
    #[must_use]
    pub(crate) fn with_cancellation(
        mut self,
        flag: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
    ) -> Self {
        self.cancellation = flag;
        self
    }

    fn is_cancelled(&self) -> bool {
        self.cancellation
            .as_ref()
            .is_some_and(|c| c.load(std::sync::atomic::Ordering::Relaxed))
    }

    /// Create analyzer with shared YARA engine
    #[allow(dead_code)] // Used by binary target
    #[must_use]
    pub(crate) fn with_yara_arc(mut self, yara_engine: Arc<YaraEngine>) -> Self {
        self.yara_engine = Some(yara_engine);
        self
    }

    /// Create analyzer with pre-existing capability mapper (wraps in Arc)
    #[must_use]
    pub(crate) fn with_capability_mapper(mut self, capability_mapper: CapabilityMapper) -> Self {
        self.capability_mapper = Arc::new(capability_mapper);
        self
    }

    /// Create analyzer with shared capability mapper (avoids cloning)
    #[must_use]
    pub(crate) fn with_capability_mapper_arc(
        mut self,
        capability_mapper: Arc<CapabilityMapper>,
    ) -> Self {
        self.capability_mapper = capability_mapper;
        self
    }

    /// Set pre-extracted strings (avoids redundant stng/radare2 extraction)
    #[must_use]
    #[allow(dead_code)] // Used by binary target, not visible to library
    pub(crate) fn with_preextracted_strings(mut self, strings: Vec<StringInfo>) -> Self {
        self.preextracted_strings = Some(strings);
        self
    }

    /// Structural analysis of a PE binary (no main YARA scan, no trait evaluation).
    /// Overlay analysis (self-extracting archives) still runs and uses the YARA engine
    /// stored in this analyzer if set. Callers are responsible for running the main YARA
    /// scan and calling `evaluate_and_merge_findings` on the returned report.
    ///
    /// Handles UPX decompression internally - unpacked content becomes a separate FileAnalysis
    /// entry in `report.files` with `encoding: ["upx"]`.
    ///
    /// If `stng_strings` is provided, uses those directly (avoids redundant extraction).
    /// Structural analysis driven entirely by an
    /// [`AnalysisContext`]. The ctx must borrow the same bytes
    /// passed in `data`; downstream helpers source sections,
    /// imports, exports, signatures, and resource metadata from
    /// `ctx.parsed` rather than re-walking goblin.
    ///
    /// Handles UPX decompression internally — unpacked content
    /// becomes a separate `FileAnalysis` entry in `report.files`
    /// with `encoding: ["upx"]`. The unpacked layer opens its own
    /// `AnalysisContext` against the decompressed bytes.
    pub(crate) fn analyze_structural_with_ctx<'a>(
        &self,
        file_path: &'a Path,
        data: &'a [u8],
        precomputed_sha256: Option<String>,
        ctx: &Ctx<'a>,
    ) -> AnalysisReport {
        use crate::types::file_analysis::encode_upx_path;
        use crate::upx::{UPXDecompressor, UPXError};

        if !UPXDecompressor::is_upx_packed(data) {
            return self.analyze_structural_with_strings(
                file_path,
                file_path,
                data,
                None,
                true,
                precomputed_sha256,
                ctx,
            );
        }

        // UPX-packed: structural analysis of packed binary first
        let mut report = self.analyze_structural_with_strings(
            file_path,
            file_path,
            data,
            None,
            true,
            precomputed_sha256.clone(),
            ctx,
        );

        report.findings.push(
            Finding::structural(
                "anti-static/packer/upx".to_string(),
                "Binary contains a UPX packing marker".to_string(),
                1.0,
            )
            .with_criticality(Criticality::Suspicious),
        );

        if !UPXDecompressor::is_available() {
            report.findings.push(
                Finding::structural(
                    "anti-static/packer/upx/tool-missing".to_string(),
                    "UPX binary not found in PATH - unpacked analysis skipped".to_string(),
                    1.0,
                )
                .with_criticality(Criticality::Suspicious),
            );
            return report;
        }

        if self.is_cancelled() {
            return report;
        }

        match UPXDecompressor::decompress(file_path) {
            Ok(unpacked_data) => {
                if let Ok(temp_file) = tempfile::NamedTempFile::new() {
                    if fs::write(temp_file.path(), &unpacked_data).is_ok() {
                        let opts = crate::analyzers::stng_analysis_opts(4);
                        let unpacked_strings =
                            stng::extract_strings_with_options(&unpacked_data, &opts);
                        // UPX-unpacked bytes differ from the caller's
                        // bytes; open a fresh context on the
                        // decompressed payload so the downstream
                        // helpers see a self-consistent view.
                        let unpacked_ctx = match crate::analysis_context::AnalysisContext::open(
                            temp_file.path(),
                            &unpacked_data,
                        ) {
                            Ok(c) => c,
                            Err(_) => return report,
                        };
                        let mut unpacked_report = self.analyze_structural_with_strings(
                            temp_file.path(),
                            temp_file.path(),
                            &unpacked_data,
                            Some(&unpacked_strings),
                            true,
                            None, // Hash will change after decompression
                            &unpacked_ctx,
                        );
                        crate::analyzers::binary_kv::attach_to_report(&mut unpacked_report);
                        crate::analyzers::binary_extractors::augment_report(
                            &mut unpacked_report,
                            &unpacked_data,
                        );
                        if let Some(yara) = &self.yara_engine {
                            match yara.scan_bytes_to_findings(&unpacked_data, Some(&["pe"])) {
                                Ok((matches, findings)) => {
                                    unpacked_report.yara_matches = matches;
                                    for finding in findings {
                                        unpacked_report.push_finding_capped(finding);
                                    }
                                }
                                Err(e) => unpacked_report
                                    .metadata
                                    .errors
                                    .push(format!("yara(upx): {e:#}")),
                            }
                        }
                        // Evaluate composites against the unpacked layer so that
                        // objective-level findings (infostealers, etc.) appear in the child.
                        self.capability_mapper.evaluate_and_merge_findings(
                            &mut unpacked_report,
                            &unpacked_data,
                            None,
                            None,
                        );

                        // Create separate FileAnalysis for unpacked layer
                        let unpacked_sha256 =
                            crate::analyzers::utils::calculate_sha256(&unpacked_data);
                        let virtual_path = encode_upx_path(&file_path.display().to_string());

                        let mut unpacked_file = unpacked_report.to_file_analysis(0);
                        unpacked_file.path = virtual_path;
                        unpacked_file.sha256 = unpacked_sha256;
                        unpacked_file.size = unpacked_data.len() as u64;
                        unpacked_file.depth = 1;
                        unpacked_file.parent_id = Some(0);
                        unpacked_file.encoding = Some(vec!["upx".to_string()]);
                        unpacked_file.compute_summary();

                        // The packed wrapper represents the executable users see, so
                        // its findings include the behavior exposed by the UPX layer
                        // while the child retains layer-specific attribution.
                        for finding in &unpacked_file.findings {
                            report.push_finding_capped(finding.clone());
                        }

                        // Add nested files from unpacked analysis (e.g., embedded code)
                        report.files.extend(unpacked_report.files);
                        report.files.push(unpacked_file);

                        report.metadata.tools_used.push("upx".to_string());
                    }
                }
            }
            Err(e) => {
                let description = match e {
                    UPXError::DecompressionFailed(msg) => {
                        format!("UPX decompression failed (possibly tampered): {}", msg)
                    }
                    _ => format!("UPX decompression failed: {}", e),
                };
                report.findings.push(
                    Finding::structural(
                        "anti-static/packer/upx/decompression-failed".to_string(),
                        description,
                        1.0,
                    )
                    .with_criticality(Criticality::Hostile),
                );
            }
        }

        report
    }

    /// Structural analysis with optional pre-extracted strings.
    /// The caller provides an `AnalysisContext` borrowing `data`;
    /// every PE-internal helper reads from expose's typed views via
    /// that ctx (no goblin re-parse).
    #[allow(clippy::too_many_arguments)]
    fn analyze_structural_with_strings<'a>(
        &self,
        logical_path: &Path,
        analysis_path: &Path,
        data: &'a [u8],
        stng_strings: Option<&[stng::ExtractedString]>,
        allow_rizin: bool,
        precomputed_sha256: Option<String>,
        ctx: &Ctx<'a>,
    ) -> AnalysisReport {
        let start = std::time::Instant::now();

        // Detect and handle tampered PE (junk prefix before MZ header).
        // The ctx was opened on `data`; when stripping moves the MZ
        // header, the ctx still describes the original layout (which
        // is what trait authors want to see — the tampering itself
        // is the signal). The bytes we hand to downstream helpers
        // remain `data`.
        let (pe_data, tamper_findings) = self.detect_and_strip_tampering(data);

        self.analyze_pe(
            logical_path,
            analysis_path,
            data,
            pe_data,
            tamper_findings,
            start,
            stng_strings,
            allow_rizin,
            precomputed_sha256,
            ctx,
        )
    }

    /// Unified PE analysis driven by an `AnalysisContext`. Structure,
    /// imports, exports, sections, and per-format metrics all flow
    /// from expose's typed views. Rizin runs in parallel for
    /// disassembly-derived metrics (function counts, complexity,
    /// strings) and as a fallback when expose surfaces no sections
    /// or imports (e.g. corrupted import directories).
    ///
    /// `pe_data` is the post-tamper-strip slice; `original_data` is
    /// the caller's bytes verbatim. The two diverge only when
    /// `detect_and_strip_tampering` peeled a junk prefix off the
    /// front — overlay extraction and embedded-binary scanning
    /// operate on `pe_data`, while file-size metrics use
    /// `original_data`.
    #[allow(clippy::unnecessary_wraps, clippy::too_many_arguments)]
    fn analyze_pe<'a>(
        &self,
        logical_path: &Path,
        analysis_path: &Path,
        original_data: &[u8],
        pe_data: &'a [u8],
        mut tamper_findings: Vec<Finding>,
        start: std::time::Instant,
        stng_strings: Option<&[stng::ExtractedString]>,
        allow_rizin: bool,
        precomputed_sha256: Option<String>,
        ctx: &Ctx<'a>,
    ) -> AnalysisReport {
        // `expose_ok` is true whenever expose identified the bytes as
        // PE and emitted at least the COFF header. The fallback path
        // (no PE values present) still produces a report so that
        // tamper findings and rizin disassembly surface for triage.
        let expose_ok = ctx.parsed.values().get("pe.machine").is_some();
        let lazy_walker_panicked = ctx
            .parsed
            .metrics()
            .get("pe.resource_walk_panicked")
            .is_some();
        let parse_panicked = ctx.parsed.metrics().get("pe.parse_panicked").is_some();
        let partial_parse = ctx.parsed.values().get("pe.partial_parse").is_some();

        let (pe_metrics, compute_panicked) = if expose_ok {
            let (m, panicked) = self.compute_pe_metrics(logical_path, ctx);
            (Some(m), panicked)
        } else {
            (None, false)
        };
        let any_lazy_panic = lazy_walker_panicked || compute_panicked || parse_panicked;

        let file_size = original_data.len() as u64;
        // Executable-code size sums every section flagged `executable`
        // on expose's typed Sections view, capped to the file extent.
        let code_size_from_ctx: u64 = ctx
            .parsed
            .sections()
            .iter()
            .filter(|s| s.flags.iter().any(|f| f == "executable"))
            .map(|s| {
                let raw_end = s.file_offset.saturating_add(s.file_size);
                if raw_end > file_size {
                    file_size.saturating_sub(s.file_offset)
                } else {
                    s.file_size
                }
            })
            .sum();

        // Create target info
        let target = TargetInfo {
            path: logical_path.display().to_string(),
            file_type: "pe".to_string(),
            size_bytes: original_data.len() as u64,
            sha256: precomputed_sha256
                .clone()
                .unwrap_or_else(|| crate::analyzers::utils::calculate_sha256(original_data)),
            architectures: expose_ok.then(|| vec![self.arch_name(ctx)]),
        };

        let mut report = AnalysisReport::new(target);
        let mut tools_used = Vec::new();
        let mut embedded_binary_count: u32 = 0;
        let mut embedded_archive_count: u32 = 0;
        if expose_ok {
            tools_used.push("expose".to_string());
        }

        // Add any tampering findings detected during preprocessing
        report.findings.append(&mut tamper_findings);

        // Tell rizin the binary "has symbols" if expose found
        // structural metadata, or if expose's PE parse failed
        // entirely (so rizin tries harder).
        let has_symbols = !expose_ok
            || !ctx.parsed.imports().is_empty()
            || !ctx.parsed.exports().is_empty()
            || !ctx.parsed.sections().is_empty();
        // Skip rizin entirely for resource-only DLLs (e.g. `.mui` MUI
        // files): expose has all the structure we need, and rizin on
        // a binary with no executable sections only does
        // startup/teardown work, adding thread contention.
        let has_executable_section = ctx
            .parsed
            .sections()
            .iter()
            .any(|s| s.flags.iter().any(|f| f == "executable"));
        // Pure IL-only .NET assemblies contain managed bytecode
        // (CIL), not native machine code. Rizin's `aa` pass on a
        // ~500KB .NET DLL costs ~17 seconds while producing
        // pseudo-functions with no meaningful native CFG. Mixed-mode
        // assemblies stay on the rizin path (this is the inverse of
        // the `mixed_mode` derivation in `compute_pe_metrics`).
        let is_il_only_dotnet = ctx.parsed.values().get("pe.clr.is_il_only").is_some()
            && ctx
                .parsed
                .values()
                .get("pe.clr.is_native_entrypoint")
                .is_none();
        let allow_rizin =
            allow_rizin && (!expose_ok || has_executable_section) && !is_il_only_dotnet;
        let needs_r2_strings = stng_strings.is_none() && self.preextracted_strings.is_none();

        let mut r2_result = None;
        let mut report_parts: (
            Vec<StructuralFeature>,
            (Vec<Import>, Vec<Finding>),
            (Vec<Export>, Option<u32>),
            Vec<Section>,
        ) = (
            Vec::new(),
            (Vec::new(), Vec::new()),
            (Vec::new(), None),
            Vec::new(),
        );

        let scope_start = std::time::Instant::now();
        // Overlap rizin (subprocess-bound) with expose-driven
        // structural work (CPU-bound) for off-pool callers, but
        // never from inside an existing rayon worker — nested join
        // can starve the pool.
        let on_rayon_worker = rayon::current_thread_index().is_some();
        let mut struct_ms = 0u128;
        let mut rizin_ms = 0u128;
        if on_rayon_worker && allow_rizin {
            tracing::debug!(
                path = %logical_path.display(),
                analysis_path = %analysis_path.display(),
                size_bytes = original_data.len(),
                has_symbols,
                needs_r2_strings,
                rayon_thread = ?rayon::current_thread_index(),
                "PE analysis on rayon worker; running structural and rizin sequentially to avoid nested join starvation",
            );
        }
        if on_rayon_worker {
            if expose_ok {
                let s_start = std::time::Instant::now();
                report_parts.0 = self.structural_features(ctx);
                report_parts.1 = self.pe_imports(ctx);
                report_parts.2 = self.pe_exports(ctx);
                report_parts.3 = self.pe_sections(ctx);
                struct_ms = s_start.elapsed().as_millis();
            }
            if allow_rizin && !self.is_cancelled() && Radare2Analyzer::is_available() {
                let rizin_start = std::time::Instant::now();
                r2_result = Some(self.radare2.extract_batched(
                    analysis_path,
                    original_data.len() as u64,
                    has_symbols,
                    expose_ok,
                    needs_r2_strings,
                    precomputed_sha256,
                    self.cancellation.as_ref(),
                    Some(original_data),
                ));
                rizin_ms = rizin_start.elapsed().as_millis();
            }
        } else {
            rayon::join(
                || {
                    if allow_rizin && !self.is_cancelled() && Radare2Analyzer::is_available() {
                        let rizin_start = std::time::Instant::now();
                        r2_result = Some(self.radare2.extract_batched(
                            analysis_path,
                            original_data.len() as u64,
                            has_symbols,
                            expose_ok,
                            needs_r2_strings,
                            precomputed_sha256,
                            self.cancellation.as_ref(),
                            Some(original_data),
                        ));
                        rizin_ms = rizin_start.elapsed().as_millis();
                    }
                },
                || {
                    if expose_ok {
                        let s_start = std::time::Instant::now();
                        report_parts.0 = self.structural_features(ctx);
                        report_parts.1 = self.pe_imports(ctx);
                        report_parts.2 = self.pe_exports(ctx);
                        report_parts.3 = self.pe_sections(ctx);
                        struct_ms = s_start.elapsed().as_millis();
                    }
                },
            );
        }
        let scope_ms = scope_start.elapsed().as_millis();
        if allow_rizin || struct_ms > 0 {
            tracing::info!(
                path = %logical_path.display(),
                analysis_path = %analysis_path.display(),
                on_rayon_worker,
                rayon_thread = ?rayon::current_thread_index(),
                scope_ms = scope_ms as u64,
                struct_ms = struct_ms as u64,
                rizin_ms = rizin_ms as u64,
                allow_rizin,
                has_symbols,
                "PE structural phase timings",
            );
        }
        if scope_ms > 10000 {
            tracing::warn!(
                path = %logical_path.display(),
                elapsed_ms = scope_ms,
                struct_ms = struct_ms as u64,
                rizin_ms = rizin_ms as u64,
                on_rayon_worker,
                "PE structural analysis completed slowly",
            );
        }

        // Merge structural results
        report.structure.extend(report_parts.0);
        report.imports.extend(report_parts.1 .0);
        for finding in report_parts.1 .1 {
            if !report.findings.iter().any(|f| f.id == finding.id) {
                report.findings.push(finding);
            }
        }
        report.exports.extend(report_parts.2 .0);
        if let Some(aliased) = report_parts.2 .1 {
            let metrics = report
                .metrics
                .get_or_insert_with(crate::types::Metrics::default);
            let binary_metrics = metrics.binary.get_or_insert_with(Default::default);
            binary_metrics.aliased_exports = aliased;
        }
        report.sections.extend(report_parts.3);

        // Detect inflated section headers (declared size extends
        // beyond EOF). Reads expose's typed Sections view.
        if expose_ok {
            let has_inflated = ctx
                .parsed
                .sections()
                .iter()
                .any(|s| s.file_offset.saturating_add(s.file_size) > file_size);
            if has_inflated {
                report.findings.push(
                    Finding::structural(
                        "metadata/binary/anomaly::inflated-section-headers".to_string(),
                        "PE section headers declare sizes beyond end of file".to_string(),
                        0.9,
                    )
                    .with_criticality(Criticality::Notable),
                );
            }
        }

        // --- Process radare2 results, with fallback for ctx gaps ---
        let r2_strings = if let Some(Ok(batched)) = r2_result {
            tools_used.push("radare2".to_string());
            crate::radare2::push_rizin_warnings(&mut report, &batched);

            let mut binary_metrics = self.radare2.compute_metrics_from_batched(
                &batched,
                original_data.len() as u64,
                "pe",
            );

            // When expose parsed the PE, override r2 metrics with
            // the more accurate ctx-derived values.
            if expose_ok {
                let mut code_size = code_size_from_ctx;
                if code_size > file_size {
                    tracing::warn!(
                        "code_size ({}) > file_size ({}) — capping",
                        code_size,
                        file_size
                    );
                    code_size = file_size;
                }
                binary_metrics.code_size = code_size;

                // .pdata function count correction
                if let Some(pdata) = ctx.parsed.sections().iter().find(|s| s.name == ".pdata") {
                    let pdata_functions = (pdata.vsize / 12) as u32;
                    if pdata_functions > 0
                        && (binary_metrics.func_count <= 1
                            || pdata_functions > binary_metrics.func_count * 10)
                    {
                        binary_metrics.func_count = pdata_functions;
                    }
                }

                // Section permission counts come from expose's
                // metric map — populated alongside the typed
                // Sections view, so no second walk is needed here.
                let m = ctx.parsed.metrics();
                binary_metrics.executable_section_count = m
                    .get("sections.executable_count")
                    .map(|v| v as u32)
                    .unwrap_or(0);
                binary_metrics.writable_section_count = m
                    .get("sections.writable_count")
                    .map(|v| v as u32)
                    .unwrap_or(0);
                binary_metrics.wx_section_count = m
                    .get("sections.executable_writable_count")
                    .map(|v| v as u32)
                    .unwrap_or(0);

                // Recalculate ratios with the corrected code_size.
                if file_size > 0 {
                    let data_size = file_size.saturating_sub(code_size);
                    if data_size > 0 {
                        binary_metrics.code_to_data_ratio = code_size as f32 / data_size as f32;
                    }
                }
                let code_kb = code_size as f32 / 1024.0;
                if code_kb > 0.0 {
                    binary_metrics.import_density = binary_metrics.import_count as f32 / code_kb;
                    binary_metrics.string_density = binary_metrics.string_count as f32 / code_kb;
                    binary_metrics.func_density = binary_metrics.func_count as f32 / code_kb;
                    binary_metrics.relocation_density =
                        binary_metrics.relocation_count as f32 / code_kb;
                    binary_metrics.complexity_per_kb =
                        binary_metrics.avg_complexity * 1024.0 / code_size as f32;
                }
            }

            report.metrics = Some(Metrics {
                binary: Some(binary_metrics),
                pe: pe_metrics,
                ..Default::default()
            });

            report.functions = batched.functions.into_iter().map(Function::from).collect();

            // --- Rizin fallback: sections ---
            if report.sections.is_empty() && !batched.sections.is_empty() {
                tracing::info!(
                    "expose returned 0 sections but rizin found {} — using rizin fallback",
                    batched.sections.len()
                );
                for section in &batched.sections {
                    let mut flag_tokens = Vec::new();
                    if let Some(perm) = section.perm.as_deref() {
                        if perm.contains('r') {
                            flag_tokens.push("readable".to_string());
                        }
                        if perm.contains('w') {
                            flag_tokens.push("writable".to_string());
                        }
                        if perm.contains('x') {
                            flag_tokens.push("executable".to_string());
                        }
                    }
                    report.sections.push(Section {
                        name: section.name.clone(),
                        address: None,
                        offset: None,
                        size: section.size,
                        entropy: section.entropy,
                        permissions: section.perm.clone(),
                        flags: flag_tokens,
                    });
                }
                if expose_ok {
                    report.findings.push(
                        Finding::structural(
                            "objectives/anti-static/pe-tampering/hidden-sections".to_string(),
                            format!(
                                "PE section table empty but rizin found {} sections — possible header manipulation",
                                batched.sections.len()
                            ),
                            0.9,
                        )
                        .with_criticality(Criticality::Suspicious),
                    );
                }
            }

            // --- Rizin fallback: imports ---
            if report.imports.is_empty() && !batched.imports.is_empty() {
                let known_section_names: HashSet<String> = report
                    .sections
                    .iter()
                    .map(|section| section.name.to_ascii_lowercase())
                    .chain(
                        batched
                            .sections
                            .iter()
                            .map(|section| section.name.to_ascii_lowercase()),
                    )
                    .collect();
                let plausible_imports: Vec<_> = batched
                    .imports
                    .iter()
                    .filter(|import| {
                        let name = import.name.trim();
                        !name.is_empty()
                            && !name.starts_with('.')
                            && !known_section_names.contains(&name.to_ascii_lowercase())
                    })
                    .collect();
                tracing::info!(
                    "expose returned 0 imports but rizin found {} ({} plausible after filtering) — using rizin fallback",
                    batched.imports.len(),
                    plausible_imports.len()
                );
                for import in &plausible_imports {
                    report.imports.push(Import::new(
                        &import.name,
                        import.lib_name.clone(),
                        "radare2",
                    ));
                    let normalized = crate::types::binary::normalize_symbol(&import.name);
                    if let Some(capability) = self.capability_mapper.lookup(&normalized, "radare2")
                    {
                        if !report.findings.iter().any(|c| c.id == capability.id) {
                            report.findings.push(capability);
                        }
                    }
                }
                if expose_ok && !report.imports.is_empty() {
                    report.findings.push(
                        Finding::structural(
                            "objectives/anti-static/pe-tampering/hidden-imports".to_string(),
                            format!(
                                "PE import table empty but rizin found {} imports — possible IAT manipulation",
                                report.imports.len()
                            ),
                            0.9,
                        )
                        .with_criticality(Criticality::Suspicious),
                    );
                }
            }

            Some(batched.strings)
        } else {
            // No rizin available — set metrics from ctx-derived data
            // only.
            if let Some(pe_m) = pe_metrics {
                report.metrics = Some(Metrics {
                    pe: Some(pe_m),
                    ..Default::default()
                });
            }
            None
        };

        // --- Corrupted-header findings (expose's PE parse fell back
        // to header-only, or failed entirely). The exact failure
        // detail isn't surfaced by expose's metrics; the absence of
        // `pe.machine` or presence of `pe.partial_parse` IS the
        // signal.
        if !expose_ok || partial_parse {
            let rizin_found_hidden_content =
                !report.sections.is_empty() || !report.imports.is_empty();
            let is_dos_executable = looks_like_dos_executable(pe_data);
            // Partial parse (header-only fallback) means the COFF
            // header was readable but a downstream walker failed;
            // resource-only DLLs and resource-table errors land
            // here. Treat as informational unless rizin found
            // something the parse missed.
            let (crit, conf) = if !expose_ok && !is_dos_executable {
                if rizin_found_hidden_content {
                    (Criticality::Suspicious, 0.8)
                } else {
                    (Criticality::Suspicious, 0.85)
                }
            } else {
                (Criticality::Baseline, 0.3)
            };

            let msg = if !expose_ok {
                "PE could not be identified by expose"
            } else {
                "PE parsed with header-only fallback (downstream walker failed)"
            };
            report.findings.push(Finding {
                id: "objectives/anti-analysis/pe-tampering/corrupted-header".to_string(),
                kind: FindingKind::Structural,
                desc: msg.to_string(),
                conf,
                crit,
                mbc: Some("B0001".to_string()),
                attack: Some("T1027".to_string()),
                trait_refs: vec![],
                evidence: vec![Evidence {
                    method: "parse-failure".to_string(),
                    source: "expose".to_string(),
                    value: msg.to_string(),
                    location: None,
                    ..Default::default()
                }],
                match_count: 1,
                source_file: None,
            });

            report.structure.push(StructuralFeature {
                id: "pe/corrupted".to_string(),
                desc: "Corrupted/tampered PE binary (header parsing failed)".to_string(),
                evidence: vec![Evidence {
                    method: "parse-failure".to_string(),
                    source: "expose".to_string(),
                    value: msg.to_string(),
                    location: None,
                    ..Default::default()
                }],
            });

            report.metadata.errors.push(msg.to_string());
        }

        // Surface "expose couldn't be trusted on this binary" as a
        // single metric bit. Set whenever the parse fell back to
        // header-only, expose failed to identify the format, or a
        // lazy walker (resource directory, debug data, ...) panicked
        // during metric extraction. The exact reason lives in
        // `metadata.errors`.
        if !expose_ok || partial_parse || any_lazy_panic {
            if let Some(metrics) = report.metrics.as_mut() {
                if let Some(bm) = metrics.binary.as_mut() {
                    bm.has_malformed_structure = true;
                }
            }
            if any_lazy_panic && expose_ok && !partial_parse {
                report
                    .metadata
                    .errors
                    .push("expose lazy walker panicked during PE metric extraction".to_string());
            }
        }

        // --- Shared post-processing (strings, embedded code, metrics, overlay, SFX) ---

        // String extraction (preference: stng_strings > preextracted > extract_smart)
        let (report_strings, raw_stng_strings) = if let Some(strings) = stng_strings {
            (
                self.string_extractor.convert_stng_strings(strings),
                Some(strings.to_vec()),
            )
        } else if let Some(ref strings) = self.preextracted_strings {
            // If we have preextracted strings but they are already converted, we can't easily get back to raw.
            // But usually preextracted_strings are from stng-local path or similar.
            (strings.clone(), None)
        } else {
            let raw = self.string_extractor.extract_raw_smart(pe_data, r2_strings);
            (self.string_extractor.convert_stng_strings(&raw), Some(raw))
        };
        report.strings = report_strings;

        // Report string truncation if limits were hit
        if self
            .string_extractor
            .truncated
            .load(std::sync::atomic::Ordering::SeqCst)
        {
            report.findings.push(Finding {
                id: "metadata/strings-truncated".to_string(),
                kind: FindingKind::Structural,
                desc: format!(
                    "String extraction truncated due to limits (count: {}, total bytes: {} MB)",
                    crate::strings::MAX_STRINGS_PER_FILE,
                    crate::strings::MAX_TOTAL_STRING_BYTES / (1024 * 1024)
                )
                .to_string(),
                conf: 1.0,
                crit: Criticality::Notable,
                mbc: None,
                attack: None,
                trait_refs: vec![],
                evidence: vec![],
                match_count: 0,
                source_file: None,
            });
        }
        tools_used.push("stng".to_string());

        // Embedded code in strings
        let (encoded_layers, plain_findings) =
            crate::analyzers::embedded_code_detector::process_all_strings(
                &logical_path.display().to_string(),
                &report.strings,
                &self.capability_mapper,
                0,
                Some(&crate::FileType::Pe),
                self.cancellation.as_deref(),
            );
        report.files.extend(encoded_layers);
        report.findings.extend(plain_findings);

        // Common binary metrics
        crate::analyzers::metrics_utils::populate_binary_metrics(&mut report, original_data);

        // Emit signature findings
        if let Some(metrics) = &report.metrics {
            if let Some(pe_metrics) = &metrics.pe {
                if let Some(signer_full) = &pe_metrics.signer {
                    let sig_type = pe_metrics.signature_type.as_deref().unwrap_or("unknown");
                    // Chain entries (each CN in the Authenticode chain) are
                    // kept at Baseline so composite rules like fake-certificate
                    // can still match them by ID, but they stop cluttering the
                    // Notable output alongside the actual signer.
                    for signer in signer_full.split(", ") {
                        let normalized_signer = signer
                            .to_lowercase()
                            .replace(' ', "-")
                            .replace(',', "")
                            .replace("(", "")
                            .replace(")", "");
                        report.findings.push(Finding {
                            id: format!("metadata/signed/{}::{}", sig_type, normalized_signer),
                            kind: FindingKind::Capability,
                            desc: format!("Authenticode chain CN: {}", signer),
                            conf: 1.0,
                            crit: Criticality::Baseline,
                            mbc: None,
                            attack: None,
                            trait_refs: vec![],
                            evidence: vec![Evidence {
                                method: "authenticode".to_string(),
                                source: "cleave".to_string(),
                                value: signer.to_string(),
                                ..Default::default()
                            }],
                            match_count: 1,
                            source_file: None,
                        });
                    }
                    // Primary signer: the leaf code-signing identity
                    // (organization if available, else filtered leaf CN),
                    // elevated to Notable so the real "who signed this"
                    // answer stands out from the chain.
                    if let Some(primary) = &pe_metrics.primary_signer {
                        let normalized = primary
                            .to_lowercase()
                            .replace(' ', "-")
                            .replace(',', "")
                            .replace("(", "")
                            .replace(")", "");
                        report.findings.push(Finding {
                            id: format!("metadata/signed/leaf::{}", normalized),
                            kind: FindingKind::Capability,
                            desc: format!("Signed by {}", primary),
                            conf: 1.0,
                            crit: Criticality::Notable,
                            mbc: None,
                            attack: None,
                            trait_refs: vec![],
                            evidence: vec![Evidence {
                                method: "authenticode".to_string(),
                                source: "cleave".to_string(),
                                value: primary.clone(),
                                ..Default::default()
                            }],
                            match_count: 1,
                            source_file: None,
                        });
                    }
                }
                // The unsigned-PE case is now emitted by the YAML
                // trait `metadata/signed::unsigned-pe-executable`
                // (in `metadata/signed/unsigned-pe.yaml`) reading
                // `kv: signing.is_signed exists: false`. That YAML
                // version has `unless:` exclusions for .NET, Go,
                // NSIS, etc. — strictly better than the hardcoded
                // unconditional `metadata/unsigned` that lived here.
            }
        }

        // Overlay analysis. The overlay extent comes from expose's
        // emitted `pe.overlay_offset` / `pe.overlay_end` metrics —
        // the same range the legacy "sections end → cert table"
        // derivation produced.
        let overlay_bounds = {
            let m = ctx.parsed.metrics();
            let start = m.get("pe.overlay_offset").map(|v| v as usize);
            let end = m.get("pe.overlay_end").map(|v| v as usize);
            match (start, end) {
                (Some(s), Some(e)) if e > s => Some((s, e)),
                _ => None,
            }
        };
        if let Some((overlay_start, overlay_end)) = overlay_bounds {
            let overlay_size = (overlay_end - overlay_start) as u64;
            if let Some(ref mut metrics) = report.metrics {
                if let Some(ref mut binary) = metrics.binary {
                    binary.has_overlay = true;
                    binary.overlay_size = overlay_size;
                    binary.overlay_ratio = overlay_size as f32 / pe_data.len() as f32;
                    binary.overlay_entropy =
                        crate::entropy::calculate_entropy(&pe_data[overlay_start..overlay_end])
                            as f32;
                }
            }
        }

        if let Some(ref metrics) = report.metrics {
            if let Some(ref binary) = metrics.binary {
                binary.validate(&report.target.path, report.target.size_bytes);
            }
        }

        // Overlay archive analysis
        if let Some((overlay_start, overlay_end)) = overlay_bounds {
            let overlay_data = &pe_data[overlay_start..overlay_end];
            if let Ok(Some(overlay_analysis)) = crate::analyzers::overlay::analyze_overlay(
                overlay_data,
                &report.target.path,
                Some(self.capability_mapper.clone()),
                self.yara_engine.clone(),
            ) {
                embedded_archive_count = embedded_archive_count.saturating_add(1);
                let pe_filename = std::path::Path::new(&report.target.path)
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("binary.exe");

                report.findings.push(overlay_analysis.sfx_finding);

                for mut finding in overlay_analysis.archive_report.findings {
                    for evidence in &mut finding.evidence {
                        if let Some(ref loc) = evidence.location {
                            if let Some(rest) = loc.strip_prefix("archive:") {
                                evidence.location = Some(format!(
                                    "archive:{}{}{}",
                                    pe_filename,
                                    crate::types::file_analysis::ARCHIVE_DELIMITER,
                                    rest
                                ));
                            } else if !loc.contains(crate::types::file_analysis::ARCHIVE_DELIMITER)
                            {
                                evidence.location = Some(format!(
                                    "archive:{}{}{}",
                                    pe_filename,
                                    crate::types::file_analysis::ARCHIVE_DELIMITER,
                                    loc
                                ));
                            }
                        }
                    }
                    report.findings.push(finding);
                }

                for mut entry in overlay_analysis.archive_report.archive_contents {
                    if !entry
                        .path
                        .contains(crate::types::file_analysis::ARCHIVE_DELIMITER)
                    {
                        entry.path = crate::types::file_analysis::encode_archive_path(
                            pe_filename,
                            &entry.path,
                        );
                    }
                    report.archive_contents.push(entry);
                }

                report.files.extend(overlay_analysis.archive_report.files);
                report
                    .strings
                    .extend(overlay_analysis.archive_report.strings);
                for tool in overlay_analysis.archive_report.metadata.tools_used {
                    if !tools_used.contains(&tool) {
                        tools_used.push(tool);
                    }
                }
            }
        }

        // NSIS / Inno Setup detection
        let detected_sfx_kind = crate::analyzers::sfx_detector::detect_sfx(pe_data);
        if let Some(sfx_kind) = detected_sfx_kind {
            let sfx_result = crate::analyzers::sfx_detector::analyze_sfx(
                analysis_path,
                sfx_kind,
                pe_data,
                Some(self.capability_mapper.clone()),
                self.yara_engine.clone(),
            );
            report.findings.push(sfx_result.sfx_finding);
            if let Some(archive_report) = sfx_result.archive_report {
                embedded_archive_count = embedded_archive_count.saturating_add(1);
                report.findings.extend(archive_report.findings);
                report.files.extend(archive_report.files);
                // Merge per-format kv subtrees from the inner archive report
                // (e.g. `pyinstaller.*`) into the host PE's kv_tree so they
                // surface in the host's `k` field at finalize time.
                if let Some(inner_kv) = archive_report.kv_tree {
                    if let serde_json::Value::Object(map) = *inner_kv {
                        for (ns, value) in map {
                            report.merge_kv_subtree(&ns, value);
                        }
                    }
                }
                for tool in archive_report.metadata.tools_used {
                    if !tools_used.contains(&tool) {
                        tools_used.push(tool);
                    }
                }
            }
        }

        // Embedded PE / ELF scanning
        if !self.skip_embedded_scan {
            let host_name = std::path::Path::new(&report.target.path)
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("binary.exe")
                .to_string();
            let cert_range = pe_certificate_range_from_ctx(ctx, pe_data);
            let embedded = crate::analyzers::embedded_binary_detector::scan_for_embedded_binaries(
                pe_data,
                self.cancellation.as_deref(),
            );
            for binary in &embedded {
                if self.is_cancelled() {
                    break;
                }
                if cert_range
                    .is_some_and(|(start, end)| binary.offset >= start && binary.offset < end)
                {
                    continue;
                }
                embedded_binary_count = embedded_binary_count.saturating_add(1);
                let mut finding = crate::analyzers::embedded_binary_detector::finding_for(
                    binary,
                    &report.target.path,
                );
                // Downgrade embedded binaries in .rsrc or .NET
                // managed resources to Notable (legitimate use —
                // e.g. resource-only DLLs, .NET assemblies bundling
                // drivers). Section lookup runs over expose's typed
                // Sections view.
                if expose_ok {
                    let in_rsrc = ctx.parsed.sections().iter().any(|s| {
                        if s.name != ".rsrc" {
                            return false;
                        }
                        let start = s.file_offset as usize;
                        let end = start + s.file_size as usize;
                        binary.offset >= start && binary.offset < end
                    });
                    // .NET assemblies store managed resources —
                    // including embedded native drivers — in the
                    // .text section, not .rsrc. Detect .NET via the
                    // CLR metadata root BSJB signature, which is
                    // present in every valid .NET assembly.
                    let is_dotnet = pe_data.windows(4).any(|w| w == b"BSJB");
                    let in_nsis_overlay =
                        matches!(
                            detected_sfx_kind,
                            Some(crate::analyzers::sfx_detector::SfxKind::Nsis)
                        ) && overlay_bounds.is_some_and(|(overlay_start, overlay_end)| {
                            binary.offset >= overlay_start && binary.offset < overlay_end
                        });
                    if std::env::var("DEBUG_CLEAVE_DOTNET").is_ok() {
                        eprintln!(
                            "[DEBUG] embedded PE check: in_rsrc={}, is_dotnet={}, in_nsis_overlay={}, data_len={}",
                            in_rsrc,
                            is_dotnet,
                            in_nsis_overlay,
                            pe_data.len()
                        );
                    }
                    // NSIS installers legitimately carry native
                    // plugin DLLs inside the overlay; those child
                    // binaries are still extracted and analyzed, so
                    // the host-level embedded-PE marker should be
                    // informational rather than suspicious.
                    //
                    // Platform-signed PEs (e.g. Microsoft Windows
                    // drivers) legitimately carry firmware blobs
                    // (Intel microcode, etc.) formatted as ELF
                    // inside non-standard sections like .drt.
                    let host_is_platform_signed = report
                        .findings
                        .iter()
                        .any(|f| f.id.starts_with("metadata/signed/platform::"));
                    if in_rsrc || is_dotnet || in_nsis_overlay || host_is_platform_signed {
                        finding.crit = Criticality::Notable;
                    }
                }

                if binary.offset >= pe_data.len() {
                    report.findings.push(finding);
                    continue;
                }
                // Decode base64-encoded payloads before recursing —
                // otherwise the child analyzer reads encoded text
                // and reports the dropper as a malformed binary.
                let decoded_storage: Vec<u8>;
                let embedded_bytes: &[u8] = if binary.encoding == Some("base64") {
                    let run_end = binary.offset
                        + pe_data[binary.offset..]
                            .iter()
                            .take_while(|&&b| {
                                b.is_ascii_alphanumeric() || b == b'+' || b == b'/' || b == b'='
                            })
                            .count();
                    let trimmed_end = run_end - (run_end - binary.offset) % 4;
                    match base64::Engine::decode(
                        &base64::engine::general_purpose::STANDARD,
                        &pe_data[binary.offset..trimmed_end],
                    ) {
                        Ok(b) => {
                            decoded_storage = b;
                            &decoded_storage[..]
                        }
                        Err(_) => {
                            report.findings.push(finding);
                            continue;
                        }
                    }
                } else {
                    let slice_end = (binary.offset + binary.estimated_size).min(pe_data.len());
                    &pe_data[binary.offset..slice_end]
                };
                let kind_str = binary.kind.as_str();
                let display_kind = binary.display_kind();
                if let Some(files) = crate::analyzers::utils::analyze_embedded_as_child(
                    embedded_bytes,
                    &host_name,
                    kind_str,
                    &display_kind,
                    binary.offset,
                    self.capability_mapper.clone(),
                    self.yara_engine.clone(),
                    raw_stng_strings.as_deref().unwrap_or(&[]),
                ) {
                    if finding.crit == Criticality::Suspicious
                        && files
                            .iter()
                            .flat_map(|file| &file.findings)
                            .any(|child_finding| {
                                child_finding.crit <= Criticality::Notable
                                    && child_finding.id.starts_with("metadata/signed/")
                            })
                    {
                        finding.crit = Criticality::Notable;
                    }
                    report.files.extend(files);
                }
                report.findings.push(finding);
            }
        }

        // Flush embedded content counters into binary metrics.
        if let Some(ref mut metrics) = report.metrics {
            if let Some(ref mut binary) = metrics.binary {
                binary.embedded_binary_count = embedded_binary_count;
                binary.embedded_archive_count = embedded_archive_count;
                binary.embedded_file_count =
                    embedded_binary_count.saturating_add(embedded_archive_count);
            }
        }

        report.metadata.analysis_duration_ms = start.elapsed().as_millis() as u64;
        report.metadata.tools_used = tools_used;

        report
    }
    /// Canonical machine-type label for the parsed PE, read from
    /// expose's `pe.machine` (lowercase forms like `"x86_64"`,
    /// `"i386"`, `"arm64"`). Falls back to a literal `"unknown"`
    /// only when expose didn't identify the binary as PE — every
    /// successful PE parse emits the field.
    fn arch_name(&self, ctx: &Ctx<'_>) -> String {
        ctx.parsed
            .values()
            .get("pe.machine")
            .and_then(|x| x.as_str())
            .map(str::to_string)
            .unwrap_or_else(|| "unknown".to_string())
    }

    /// Compute PE-specific metrics from the shared expose-side parse.
    ///
    /// Returns the populated metrics together with a
    /// `lazy_walker_panicked` flag set when expose surfaced
    /// `pe.resource_walk_panicked` during metric extraction. The
    /// caller propagates that flag into
    /// `BinaryMetrics::has_malformed_structure` so downstream
    /// consumers see the same signal regardless of whether the
    /// parse failed at the COFF stage or while walking lazy fields
    /// later.
    fn compute_pe_metrics<'a>(
        &self,
        logical_path: &Path,
        ctx: &Ctx<'a>,
    ) -> (crate::types::binary_metrics::PeMetrics, bool) {
        use crate::types::binary_metrics::PeMetrics;

        let c = ctx;
        let mut metrics = PeMetrics::default();
        let mut lazy_walker_panicked = false;

        // Top-of-function header fields. Timestamp, entry RVA,
        // entry_section, machine, and characteristics all come from
        // expose's emitted values.
        let timestamp = c
            .parsed
            .values()
            .get("pe.timestamp")
            .and_then(|v| v.as_i64())
            .map(|v| v as u32)
            .unwrap_or(0);
        metrics.timestamp = timestamp;
        metrics.machine = c
            .parsed
            .values()
            .get("pe.machine_id")
            .and_then(|v| v.as_u64())
            .map(|v| v as u32)
            .unwrap_or(0);
        metrics.characteristics = c
            .parsed
            .values()
            .get("pe.characteristics_raw")
            .and_then(|v| v.as_u64())
            .map(|v| v as u32)
            .unwrap_or(0);
        // (raw COFF NumberOfSections dropped from the metric surface;
        // sections.len() flows into binary.section_count, and the
        // mismatch case is exposed via pe.section_count_mismatch.)
        metrics.entry = c
            .parsed
            .values()
            .get("pe.entry_point")
            .and_then(|v| v.as_u64())
            .map(|v| v as u32)
            .unwrap_or(0);
        metrics.entry_section = c
            .parsed
            .values()
            .get("pe.entry_section")
            .and_then(|v| v.as_str())
            .map(str::to_string);

        // Timestamp anomaly check
        metrics.timestamp_is_zero = timestamp == 0;
        metrics.timestamp_pre_2000 = timestamp > 0 && timestamp < 946684800;
        metrics.timestamp_in_future = timestamp > chrono::Utc::now().timestamp() as u32 + 31536000;
        metrics.timestamp_anomaly =
            metrics.timestamp_is_zero || timestamp < 631152000 || metrics.timestamp_in_future;

        // DOS stub anomalies + Rich header presence are emitted by expose
        // (formats/pe.rs: `pe.dos_stub_modified`, `pe.dos_stub_zeroed`;
        // formats/pe_rich.rs: `pe.rich.entries`).
        {
            let m = c.parsed.metrics();
            metrics.dos_stub_modified = m.get("pe.dos_stub_modified").is_some();
            metrics.dos_stub_zeroed = m.get("pe.dos_stub_zeroed").is_some();
            metrics.has_rich_header = c.parsed.values().get("pe.rich.entries").is_some();
        }

        // `.rsrc` size + entropy. Expose's typed Sections view carries
        // file_size, and `sections[idx].entropy` lives in metrics under
        // the section's positional key.
        {
            let typed = c.parsed.sections();
            let m = c.parsed.metrics();
            for (idx, section) in typed.iter().enumerate() {
                if section.name == ".rsrc" {
                    metrics.rsrc_size = section.file_size;
                    if let Some(e) = m.get(&format!("sections[{idx}].entropy")) {
                        metrics.rsrc_entropy = e as f32;
                    }
                    break;
                }
            }
        }

        // Optional-header fields. Every value comes from expose's
        // emitted set — raw u32 fields land under the
        // `pe.{file_alignment,section_alignment,subsystem_raw,
        // dll_characteristics_raw,linker_major_version,
        // linker_minor_version}` keys alongside the string-flag
        // projections downstream traits consume.
        if c.parsed.values().get("pe.subsystem").is_some() {
            let v = c.parsed.values();
            let m = c.parsed.metrics();
            metrics.file_alignment = v
                .get("pe.file_alignment")
                .and_then(|x| x.as_u64())
                .map(|x| x as u32)
                .unwrap_or(0);
            metrics.section_alignment = v
                .get("pe.section_alignment")
                .and_then(|x| x.as_u64())
                .map(|x| x as u32)
                .unwrap_or(0);
            metrics.subsystem = v
                .get("pe.subsystem_raw")
                .and_then(|x| x.as_u64())
                .map(|x| x as u32)
                .unwrap_or(0);
            metrics.dll_characteristics = v
                .get("pe.dll_characteristics_raw")
                .and_then(|x| x.as_u64())
                .map(|x| x as u32)
                .unwrap_or(0);
            metrics.linker_major_version = v
                .get("pe.linker_major_version")
                .and_then(|x| x.as_u64())
                .map(|x| x as u32)
                .unwrap_or(0);
            metrics.linker_minor_version = v
                .get("pe.linker_minor_version")
                .and_then(|x| x.as_u64())
                .map(|x| x as u32)
                .unwrap_or(0);

            metrics.checksum = m.get("pe.checksum").map(|x| x as u32).unwrap_or(0);
            metrics.has_checksum = metrics.checksum != 0;
            metrics.computed_checksum =
                m.get("pe.computed_checksum").map(|x| x as u32).unwrap_or(0);
            metrics.checksum_valid = m.get("pe.checksum_valid").is_some();
            metrics.image_base = v
                .get("pe.image_base")
                .and_then(|x| x.as_u64())
                .unwrap_or(0);
            metrics.size_of_image = v
                .get("pe.image_size")
                .and_then(|x| x.as_u64())
                .map(|x| x as u32)
                .unwrap_or(0);
            metrics.size_of_headers = v
                .get("pe.headers_size")
                .and_then(|x| x.as_u64())
                .map(|x| x as u32)
                .unwrap_or(0);

            // Debug directory + CodeView fields. Expose's pe_debug
            // module emits `pe.debug.entries[]` (each with `type`,
            // `type_id`, `timestamp_unix`, `size_bytes`) plus
            // `pe.debug.pdb.{path,guid,age}`.
            fill_debug_metrics_from_ctx(c, &mut metrics);

            // Authenticode / cert-table handling. Ctx reads expose's
            // `pe.signatures[]` (parsed PKCS#7) and `pe.cert_table_size`
            // / `pe.security_directory_out_of_bounds` markers.
            fill_authenticode_metrics_from_ctx(c, &mut metrics);

            // Delay-load import directory presence. Scans the
            // already-emitted `pe.data_directories[]` for the
            // canonical-named slot.
            let present = c
                .parsed
                .values()
                .get("pe.data_directories")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter().any(|n| {
                        n.get("name").and_then(|x| x.as_str()) == Some("delay_import")
                            && n.get("size").and_then(|x| x.as_u64()).unwrap_or(0) > 0
                    })
                })
                .unwrap_or(false);
            if present {
                metrics.delay_load_import_count = 1;
            }
        }

        // Trivial counts. Ctx reads `pe.imported_library_count`
        // (metric) for distinct DLL names, and the length of
        // `pe.signatures[]` (values) for the cert-blob count.
        metrics.import_dll_count = c
            .parsed
            .metrics()
            .get("pe.imported_library_count")
            .map(|x| x as u32)
            .unwrap_or(0);
        metrics.certificate_count = c
            .parsed
            .values()
            .get("pe.signatures")
            .and_then(|v| v.as_array())
            .map(|a| a.len() as u32)
            .unwrap_or(0);
        metrics.entry_in_nonstandard_section = metrics
            .entry_section
            .as_deref()
            .is_some_and(|name| !is_standard_entry_section(name));

        // Authenticode chain shape: depth-1 chains are normally self-
        // signed roots. A non-self-issued leaf at depth 1 means the
        // intermediate CA(s) were stripped — the Remus botnet sample
        // (May 2026) embeds a stolen `itunes.apple.com` TLS leaf with
        // exactly this shape.
        metrics.cert_chain_truncated =
            metrics.has_signature && metrics.cert_chain_depth == 1 && !metrics.leaf_self_issued;
        // "Signed PE with a leaf cert that isn't authorized for code
        // signing" — collapses the EKU and has_signature checks into
        // one atomic-trait-friendly bool. Catches the Remus pattern.
        metrics.non_codesign_leaf = metrics.has_signature
            && metrics.leaf_subject.is_some()
            && !metrics.leaf_eku_code_signing;
        // Derived sibling booleans — atomic-trait friendly so authors
        // can write `min: 1` instead of `max: 0` (which over-fires on
        // unsigned binaries because the underlying field is absent).
        metrics.signature_verification_failed =
            metrics.has_signature && matches!(metrics.signature_verified, Some(false));
        // signer_info_mismatches_leaf is set directly during cert
        // resolution above when SignerInfo references a cert not in
        // the bag — no derivation here. The legacy "heuristic
        // disagrees with SI" semantics no longer apply because we
        // now use SI as the authoritative leaf source.
        metrics.nested_leaf_no_codesign_eku = metrics.has_nested_signature
            && metrics.nested_leaf_subject.is_some()
            && !metrics.nested_leaf_eku_code_signing;

        // COFF symbol table — modern toolchains zero these fields.
        let pst = pe.header.coff_header.pointer_to_symbol_table;
        let nst = pe.header.coff_header.number_of_symbol_table;
        metrics.has_coff_symbols = pst != 0 && nst != 0;

        // Section-walk metrics — entry-point anomalies, section
        // overflow/misalignment, section overlap, first-section gap,
        // entry-in-last-section, BSS-like count. Drives off expose's
        // typed Sections view (name, vaddr, vsize, file_offset,
        // file_size, flags vocabulary).
        //
        // `file_alignment` is still goblin-sourced — expose doesn't
        // emit it. We pass the goblin-derived alignment in so the
        // misalignment audit stays valid.
        let ep_rva = pe.entry;
        let file_alignment = pe
            .header
            .optional_header
            .as_ref()
            .map(|h| h.windows_fields.file_alignment)
            .unwrap_or(0);
        fill_section_walk_metrics_from_ctx(
            c,
            ep_rva,
            pe.is_lib,
            data.len() as u64,
            file_alignment,
            &mut metrics,
        );

        if let Some(opt) = pe.header.optional_header.as_ref() {
            metrics.number_of_rva_and_sizes = opt.windows_fields.number_of_rva_and_sizes;
        }

        // .NET native entry — only meaningful when CLR data is present.
        // Expose emits `pe.clr.is_native_entrypoint` (presence = bit set).
        metrics.dotnet_has_native_entry = c
            .parsed
            .values()
            .get("pe.clr.is_native_entrypoint")
            .is_some();

        // Data-directory bounds checks + TLS-callbacks-outside-code.
        // Drive off expose's typed Sections + data directories +
        // tls_callbacks views.
        fill_data_directory_bounds_from_ctx(c, &mut metrics);
        fill_tls_callbacks_outside_code_from_ctx(c, &mut metrics);

        // Authenticode image hashes. Ctx reads expose's already-
        // computed `pe.image_hash.{sha1,sha256,sha384,sha512}` +
        // `pe.overlay_padding`. The `signature_digest_mismatch`
        // derivation — comparing the signature's claimed digest
        // against the recomputed hash under the same algorithm — runs
        // off the now-populated metric fields.
        fill_image_hashes_from_ctx(c, &mut metrics);
        if metrics.has_signature {
            metrics.signature_digest_mismatch = derive_signature_digest_mismatch(&metrics);
        }

        // Per-section header summary. Reads from expose's typed
        // Section view (name/vaddr/vsize/file_size) plus the positional
        // `sections[N].characteristics` metric (raw IMAGE_SCN_* u32).
        {
            let m = c.parsed.metrics();
            for (idx, s) in c.parsed.sections().iter().enumerate() {
                let chars_u32 = m
                    .get(&format!("sections[{idx}].characteristics"))
                    .map(|x| x as u32)
                    .unwrap_or(0);
                metrics.section_characteristics_entries.push(
                    crate::types::binary_metrics::SectionCharacteristics {
                        name: s.name.clone(),
                        characteristics_hex: format!("{:08x}", chars_u32),
                        virtual_address: s.vaddr as u32,
                        virtual_size: s.vsize as u32,
                        raw_size: s.file_size as u32,
                    },
                );
            }
        }

        // Non-zero data directory slots, with canonical names. Reads
        // `pe.data_directories[]` from expose (already in canonical
        // name + rva + size shape).
        if let Some(arr) = c
            .parsed
            .values()
            .get("pe.data_directories")
            .and_then(|v| v.as_array())
        {
            for node in arr {
                let (Some(name), Some(rva), Some(size)) = (
                    node.get("name").and_then(|v| v.as_str()),
                    node.get("rva").and_then(|v| v.as_u64()),
                    node.get("size").and_then(|v| v.as_u64()),
                ) else {
                    continue;
                };
                metrics.data_directory_entries.push(
                    crate::types::binary_metrics::DataDirectoryEntry {
                        name: name.to_string(),
                        rva: rva as u32,
                        size: size as u32,
                    },
                );
            }
        }
        // Rich Header CompID tuples.
        if metrics.has_rich_header {
            metrics.rich_header_compids = parse_rich_header(data, pe_offset);
        }

        // Export-directory timestamp is its own field (distinct from
        // COFF `pe.timestamp`). Reads from expose's `pe.export_timestamp`,
        // which is only emitted when the export directory carries a
        // non-zero stamp.
        if let Some(ts) = c
            .parsed
            .values()
            .get("pe.export_timestamp")
            .and_then(|v| v.as_i64())
        {
            metrics.export_timestamp = ts as u32;
            metrics.has_export_timestamp = metrics.export_timestamp != 0;
        }

        // Check for overlay data (appended after PE image, excluding signature)
        // This can be:
        // 1. Self-extracting archive (7z, ZIP, RAR)
        // 2. Resources or other data
        let sig_sections_end = pe
            .sections
            .iter()
            .map(|s| (s.pointer_to_raw_data + s.size_of_raw_data) as u64)
            .max()
            .unwrap_or(0);

        // Calculate overlay start, taking into account that the signature might be at the end
        let mut overlay_end = data.len() as u64;
        if let Some(opt) = &pe.header.optional_header {
            if let Some(Some(cert_table_entry)) = opt.data_directories.data_directories.get(4) {
                let cert_table = &cert_table_entry.1;
                let cert_offset = cert_table.virtual_address as u64;
                if cert_offset > sig_sections_end && cert_offset < overlay_end {
                    overlay_end = cert_offset;
                }
            }
        }

        if overlay_end > sig_sections_end && sig_sections_end > 0 {
            let _overlay_start = sig_sections_end as usize;
            let _overlay_data = &data[_overlay_start..overlay_end as usize];
        }

        // Import walks. Drives off expose's typed Imports
        // (`source == "pe"` only, since the Imports view aggregates
        // across formats).
        {
            let pe_imports: Vec<&expose::Import> = c
                .parsed
                .imports()
                .iter()
                .filter(|i| i.source == "pe")
                .collect();
            metrics.ordinal_import_count = pe_imports
                .iter()
                .filter(|i| i.name.is_empty())
                .count() as u32;
            let names: HashSet<String> = pe_imports
                .iter()
                .map(|i| i.name.to_ascii_lowercase())
                .collect();
            if names.contains("loadlibrarya")
                || names.contains("loadlibraryw")
                || names.contains("getprocaddress")
                || names.contains("ldrloaddll")
                || names.contains("ldrgetprocedureaddress")
            {
                metrics.api_hashing_indicator_count += 1;
            }
        }

        // Export forwarders. Drives off typed Exports (where
        // `forward_to` is the unified projection of goblin's
        // `Reexport::DLLName` / `DLLOrdinal` shapes). The forwarder
        // counts feed both typed metrics and the
        // `self_versioned_forwarder` heuristic.
        let mut total_exports: u32 = 0;
        let mut forwarded: u32 = 0;
        let mut forwards_to_system: u32 = 0;
        let mut forward_targets: HashSet<String> = HashSet::new();
        for exp in c
            .parsed
            .exports()
            .iter()
            .filter(|e| e.source == "pe" && !e.name.is_empty())
        {
            total_exports += 1;
            if let Some(target) = exp.forward_to.as_deref() {
                forwarded += 1;
                // `forward_to` is `"<DLL>.<sym>"` or `"<DLL>.#<ord>"`.
                // Split on the first `.` to recover the DLL stem.
                let lib = target.split_once('.').map(|(l, _)| l).unwrap_or(target);
                if is_system_dll(lib) {
                    forwards_to_system += 1;
                }
                forward_targets.insert(normalize_dll_stem(lib));
            }
        }
        metrics.export_forwarder_count = forwarded;
        metrics.system_dll_forward_count = forwards_to_system;
        metrics.forward_ratio = if total_exports > 0 {
            forwarded as f32 / total_exports as f32
        } else {
            0.0
        };
        metrics.self_versioned_forwarder = total_exports > 0
            && forwarded == total_exports
            && forward_targets.len() == 1
            && is_version_variant(
                &self_basename_stem(logical_path),
                forward_targets
                    .iter()
                    .next()
                    .map(String::as_str)
                    .unwrap_or(""),
            );

        // (unusual_alignment metric removed; trait authors compare
        // pe.file_alignment / pe.section_alignment directly.)

        // Resource directory. Reads expose's already-walked resource
        // metrics (the walker is wrapped in goblin_safe — if expose's
        // walker panicked, `pe.resource_walk_panicked` is set and we
        // lift the local lazy_walker_panicked flag).
        {
            let m = c.parsed.metrics();
            let v = c.parsed.values();
            if m.get("pe.resource_walk_panicked").is_some() {
                lazy_walker_panicked = true;
            }
            metrics.resource_count = m
                .get("pe.resource_count")
                .map(|x| x as u32)
                .unwrap_or(0);
            metrics.has_version_info = m.get("pe.has_version_info").is_some();
            metrics.has_manifest = m.get("pe.has_manifest").is_some();
            metrics.icon_count = m.get("pe.icon_count").map(|x| x as u32).unwrap_or(0);
            metrics.resource_timestamp = v
                .get("pe.resource_timestamp")
                .and_then(|x| x.as_u64())
                .map(|x| x as u32)
                .unwrap_or(0);
            metrics.has_resource_timestamp = metrics.resource_timestamp != 0;
            if let Some(arr) = v.get("pe.resource_types").and_then(|x| x.as_array()) {
                metrics.resource_types = arr
                    .iter()
                    .filter_map(|n| n.as_str().map(str::to_string))
                    .collect();
            }
        }

        // CLR / .NET metadata. Presence of `pe.clr.runtime_version` in
        // expose's values IS the "is managed?" signal — distinct from
        // PE Authenticode signing.
        {
            let v = c.parsed.values();
            if let Some(ver) = v.get("pe.clr.runtime_version").and_then(|x| x.as_str()) {
                metrics.is_dotnet = true;
                metrics.clr_version = Some(ver.to_string());
                let is_il_only = v.get("pe.clr.is_il_only").is_some();
                let is_native_ep = v.get("pe.clr.is_native_entrypoint").is_some();
                metrics.mixed_mode = !is_il_only || is_native_ep;
            }
        }

        // TLS callbacks. Expose emits `pe.tls_callback_count` (metric)
        // and `pe.tls_callbacks[]` (values) — each entry carries an
        // `addr` field as a hex string. We subtract image_base from
        // each VA to get RVAs so `tls_callback_addresses` carries
        // section-relative offsets.
        {
            let m = c.parsed.metrics();
            metrics.tls_callback_count =
                m.get("pe.tls_callback_count").map(|x| x as u32).unwrap_or(0);
            if let Some(arr) = c
                .parsed
                .values()
                .get("pe.tls_callbacks")
                .and_then(|v| v.as_array())
            {
                let image_base = metrics.image_base;
                metrics.tls_callback_addresses = arr
                    .iter()
                    .filter_map(|node| {
                        let s = node.get("addr")?.as_str()?;
                        let s = s.strip_prefix("0x").unwrap_or(s);
                        let va = u64::from_str_radix(s, 16).ok()?;
                        Some((va.saturating_sub(image_base)) as u32)
                    })
                    .collect();
            }
        }

        // Bound Import Directory. Reads expose's already-parsed
        // `pe.bound_imports[]` + `pe.bound_imports_fingerprint` metric.
        fill_bound_imports_from_ctx(c, &mut metrics);

        // Load Config Directory. Reads expose's typed `pe.load_config.*`
        // view (raw u64 cookie + GuardCF fields + u32 guard_flags).
        fill_load_config_from_ctx(c, &mut metrics);

        // Promote the resource-walker panic into the explicit metric —
        // both states ("couldn't traverse .rsrc safely") map onto the
        // same trait-author signal.
        if lazy_walker_panicked {
            metrics.rsrc_dir_overruns_section = true;
        }

        (metrics, lazy_walker_panicked)
    }

    fn compute_section_permission_counts<'a>(&self, pe: &PE<'a>) -> (u32, u32, u32) {
        let mut executable_section_count = 0;
        let mut writable_section_count = 0;
        let mut wx_section_count = 0;

        for section in &pe.sections {
            let characteristics = section.characteristics;
            let is_executable = (characteristics & 0x20000000) != 0;
            let is_writable = (characteristics & 0x80000000) != 0;

            if is_executable {
                executable_section_count += 1;
            }
            if is_writable {
                writable_section_count += 1;
            }
            if is_executable && is_writable {
                wx_section_count += 1;
            }
        }

        (
            executable_section_count,
            writable_section_count,
            wx_section_count,
        )
    }

    /// Calculate code size from PE section headers using IMAGE_SCN_MEM_EXECUTE characteristic
    /// This is more accurate than radare2's section classification
    fn compute_code_size<'a>(&self, pe: &PE<'a>, file_size: u64) -> u64 {
        const IMAGE_SCN_MEM_EXECUTE: u32 = 0x20000000;

        let mut code_size: u64 = 0;

        for section in &pe.sections {
            if section.characteristics & IMAGE_SCN_MEM_EXECUTE != 0 {
                // Cap at section's actual extent within the file
                let raw_end = (section.pointer_to_raw_data as u64)
                    .saturating_add(section.size_of_raw_data as u64);
                let capped_size = if raw_end > file_size {
                    file_size.saturating_sub(section.pointer_to_raw_data as u64)
                } else {
                    section.size_of_raw_data as u64
                };
                code_size += capped_size;
            }
        }

        code_size
    }

    /// Detect PE tampering and return stripped data plus findings.
    ///
    /// Detects common anti-analysis techniques:
    /// - Junk bytes prepended before MZ header
    /// - Systematic byte injection (e.g., 0x20 padding throughout header)
    /// - .NET BSJB signature presence
    /// - PE signature corruption
    ///
    /// Returns (data_to_parse, findings) where data_to_parse may be a slice
    /// starting at the MZ header if junk prefix was detected.
    fn detect_and_strip_tampering<'a>(&self, data: &'a [u8]) -> (&'a [u8], Vec<Finding>) {
        let mut findings = Vec::new();

        // Check if MZ is at offset 0
        if data.starts_with(b"MZ") {
            // Normal PE, but still check for other tampering
            self.detect_header_tampering(data, 0, &mut findings);
            return (data, findings);
        }

        // Search for MZ header within first 64 bytes
        let mz_offset = self.find_mz_offset(data, 64);

        if let Some(offset) = mz_offset {
            // Found MZ at non-zero offset - junk prefix detected
            let prefix = &data[..offset];
            let prefix_display = if prefix.len() <= 32 {
                String::from_utf8_lossy(prefix).to_string()
            } else {
                format!(
                    "{}... ({} bytes)",
                    String::from_utf8_lossy(&prefix[..32]),
                    prefix.len()
                )
            };

            findings.push(Finding {
                id: "objectives/anti-analysis/pe-tampering/junk-prefix".to_string(),
                kind: FindingKind::Structural,
                desc: format!(
                    "PE has {} bytes prepended before MZ header (anti-analysis)",
                    offset
                ),
                conf: 1.0,
                crit: Criticality::Hostile,
                mbc: Some("B0001".to_string()), // Executable Code Obfuscation
                attack: Some("T1027".to_string()), // Obfuscated Files or Information
                trait_refs: vec![],
                evidence: vec![Evidence {
                    method: "header-analysis".to_string(),
                    source: "cleave".to_string(),
                    value: format!("MZ at offset {:#x}, prefix: {:?}", offset, prefix_display),
                    location: Some(format!("0x0-{:#x}", offset)),
                    ..Default::default()
                }],
                match_count: 1,
                source_file: None,
            });

            // Check for additional tampering in the actual PE data
            let pe_data = &data[offset..];
            self.detect_header_tampering(pe_data, offset, &mut findings);

            return (pe_data, findings);
        }

        // No MZ found - check for BSJB (.NET) signature without valid PE
        if let Some(bsjb_offset) = self.find_signature(data, b"BSJB") {
            findings.push(Finding {
                id: "objectives/anti-analysis/pe-tampering/dotnet-invalid-pe".to_string(),
                kind: FindingKind::Structural,
                desc: ".NET assembly (BSJB signature) with corrupted/missing PE header".to_string(),
                conf: 0.95,
                crit: Criticality::Hostile,
                mbc: Some("B0001".to_string()),
                attack: Some("T1027".to_string()),
                trait_refs: vec![],
                evidence: vec![Evidence {
                    method: "signature".to_string(),
                    source: "cleave".to_string(),
                    value: format!("BSJB at offset {:#x}, no valid MZ header", bsjb_offset),
                    location: Some(format!("{:#x}", bsjb_offset)),
                    ..Default::default()
                }],
                match_count: 1,
                source_file: None,
            });
        }

        // Return original data (goblin will fail to parse, but that's expected)
        (data, findings)
    }

    /// Detect tampering within PE header area
    fn detect_header_tampering(
        &self,
        data: &[u8],
        base_offset: usize,
        findings: &mut Vec<Finding>,
    ) {
        if data.len() < 64 {
            return;
        }

        // Check for systematic byte injection (e.g., 0x20 padding)
        let header_area = &data[..data.len().min(512)];
        let mut byte_counts = [0u32; 256];
        for &b in header_area {
            byte_counts[b as usize] += 1;
        }

        let header_len = header_area.len() as u32;
        for (byte_val, &count) in byte_counts.iter().enumerate() {
            // Skip 0x00 (common in headers) and check if any byte is >40% of header
            if byte_val != 0 && count > header_len * 2 / 5 {
                findings.push(Finding {
                    id: "objectives/anti-analysis/pe-tampering/byte-injection".to_string(),
                    kind: FindingKind::Structural,
                    desc: format!(
                        "PE header has excessive 0x{:02X} bytes ({} of {} = {:.1}%)",
                        byte_val,
                        count,
                        header_len,
                        count as f32 / header_len as f32 * 100.0
                    ),
                    conf: 0.9,
                    crit: Criticality::Suspicious,
                    mbc: Some("B0001".to_string()),
                    attack: Some("T1027".to_string()),
                    trait_refs: vec![],
                    evidence: vec![Evidence {
                        method: "frequency-analysis".to_string(),
                        source: "cleave".to_string(),
                        value: format!("byte 0x{:02X} appears {} times in header", byte_val, count),
                        location: Some(format!("{:#x}-{:#x}", base_offset, base_offset + 512)),
                        ..Default::default()
                    }],
                    match_count: 1,
                    source_file: None,
                });
                break; // Only report the most prominent injection
            }
        }

        // Check the actual PE signature location from the DOS header, not the first
        // incidental `PE` byte sequence anywhere in the file.
        let pe_sig_offset =
            u32::from_le_bytes([data[0x3c], data[0x3d], data[0x3e], data[0x3f]]) as usize;
        if pe_sig_offset + 4 <= data.len() {
            let sig = &data[pe_sig_offset..pe_sig_offset + 4];
            if sig != b"PE\x00\x00" && !looks_like_dos_executable(data) {
                findings.push(Finding {
                    id: "objectives/anti-analysis/pe-tampering/pe-signature-corrupted".to_string(),
                    kind: FindingKind::Structural,
                    desc: format!(
                        "PE signature corrupted: expected PE\\x00\\x00, got {:02X} {:02X} {:02X} {:02X}",
                        sig[0], sig[1], sig[2], sig[3]
                    ),
                    conf: 0.85,
                    crit: Criticality::Suspicious,
                    mbc: Some("B0001".to_string()),
                    attack: Some("T1027".to_string()),
                    trait_refs: vec![],
                    evidence: vec![Evidence {
                        method: "signature".to_string(),
                        source: "cleave".to_string(),
                        value: format!("PE signature at {:#x}: {:?}", pe_sig_offset, sig),
                        location: Some(format!("{:#x}", base_offset + pe_sig_offset)),
                        ..Default::default()
                    }],
                    match_count: 1,
                    source_file: None,
                });
            }
        }

        // Detect .NET via BSJB signature
        if let Some(bsjb_offset) = self.find_signature(data, b"BSJB") {
            findings.push(Finding {
                id: "metadata/dotnet/bsjb-signature".to_string(),
                kind: FindingKind::Structural,
                desc: ".NET assembly detected via BSJB CLR metadata signature".to_string(),
                conf: 1.0,
                crit: Criticality::Baseline,
                mbc: None,
                attack: None,
                trait_refs: vec![],
                evidence: vec![Evidence {
                    method: "signature".to_string(),
                    source: "cleave".to_string(),
                    value: format!("BSJB at offset {:#x}", bsjb_offset),
                    location: Some(format!("{:#x}", base_offset + bsjb_offset)),
                    ..Default::default()
                }],
                match_count: 1,
                source_file: None,
            });
        }
    }

    /// Find MZ header within first max_offset bytes
    #[allow(clippy::manual_find)]
    fn find_mz_offset(&self, data: &[u8], max_offset: usize) -> Option<usize> {
        let limit = data.len().min(max_offset);
        for i in 0..limit.saturating_sub(1) {
            if data[i] == b'M' && data.get(i + 1) == Some(&b'Z') {
                return Some(i);
            }
        }
        None
    }

    /// Find a byte signature in data
    fn find_signature(&self, data: &[u8], needle: &[u8]) -> Option<usize> {
        data.windows(needle.len()).position(|w| w == needle)
    }
}

impl Default for PEAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl Analyzer for PEAnalyzer {
    fn analyze_input(&self, input: &AnalysisInput<'_>) -> Result<AnalysisReport> {
        // Use caller-provided strings when present; an empty slice means the
        // caller only supplied bytes, so the structural analyzer should extract.
        let strings = if input.strings.is_empty() {
            None
        } else {
            Some(input.strings)
        };
        // Open expose-side parse so structural helpers (sections,
        // imports, exports, signature verification) source from
        // expose's typed view rather than re-walking goblin. Falls
        // through to legacy goblin paths when expose can't open
        // (tampered PE / unknown shape).
        let ctx = crate::analysis_context::AnalysisContext::open(input.path, input.data).ok();
        let mut report = self.analyze_structural_with_strings(
            input.path,
            input.backing_path(),
            input.data,
            strings,
            !input.skip_rizin,
            input.sha256.clone(),
            ctx.as_ref(),
        );

        // Post-processing
        self.capability_mapper
            .evaluate_and_merge_findings(&mut report, input.data, None, None);
        Ok(report)
    }

    fn analyze(&self, file_path: &Path) -> Result<AnalysisReport> {
        let data = fs::read(file_path).context("Failed to read file")?;
        let opts = crate::analyzers::stng_analysis_opts(4);
        let strings = stng::extract_strings_with_options(&data, &opts);
        tracing::debug!(
            path = %file_path.display(),
            strings = strings.len(),
            string_mode = "stng-local",
            reason = "legacy analyze() path without pre-extracted AnalysisInput",
            "PE analyzer extracting strings locally before analyze_input"
        );
        let input =
            AnalysisInput::with_strings(file_path, &data, &strings, crate::analyzers::FileType::Pe);
        self.analyze_input(&input)
    }

    fn can_analyze(&self, file_path: &Path) -> bool {
        // PE magic-byte check: `MZ` + valid `e_lfanew` pointing at `PE\0\0`.
        // A full goblin parse just to gate analyzability is wasted work
        // — the actual parse happens once we commit to analyze().
        let Ok(mut file) = fs::File::open(file_path) else {
            return false;
        };
        use std::io::{Read, Seek, SeekFrom};
        let mut head = [0u8; 64];
        if file.read_exact(&mut head).is_err() || &head[0..2] != b"MZ" {
            return false;
        }
        let e_lfanew = u32::from_le_bytes([head[60], head[61], head[62], head[63]]) as u64;
        if file.seek(SeekFrom::Start(e_lfanew)).is_err() {
            return false;
        }
        let mut sig = [0u8; 4];
        file.read_exact(&mut sig).is_ok() && &sig == b"PE\0\0"
    }
}

/// Count exports whose first instruction jumps/calls to the same target as another export.
///
/// Malware often aliases multiple export names to a single function via stub thunks.
/// This decodes the first instruction at each export RVA and groups by jump target.
fn count_aliased_exports(pe: &goblin::pe::PE<'_>, data: &[u8], bitness: u32) -> u32 {
    use iced_x86::{Decoder, DecoderOptions, Mnemonic};
    use std::collections::HashMap;

    let mut targets: HashMap<u64, u32> = HashMap::new();

    for export in &pe.exports {
        let rva = export.rva;
        // Convert RVA to file offset using PE sections
        let Some(file_offset) = rva_to_offset(pe, rva) else {
            continue;
        };

        if file_offset + 16 > data.len() {
            continue;
        }

        let code = &data[file_offset..file_offset + 16];
        let mut decoder = Decoder::with_ip(bitness, code, rva as u64, DecoderOptions::NONE);

        if let Some(instr) = decoder.iter().next() {
            let target = match instr.mnemonic() {
                Mnemonic::Jmp | Mnemonic::Call => {
                    let t = instr.near_branch_target();
                    if t != 0 {
                        t
                    } else {
                        rva as u64
                    }
                }
                // Not a stub — use the RVA itself as the "target"
                _ => rva as u64,
            };
            *targets.entry(target).or_insert(0) += 1;
        }
    }

    targets.values().filter(|&&c| c > 1).copied().sum()
}

/// Convert a PE RVA to a file offset using section headers.
fn rva_to_offset(pe: &goblin::pe::PE<'_>, rva: usize) -> Option<usize> {
    for section in &pe.sections {
        let vaddr = section.virtual_address as usize;
        let vsize = section.virtual_size as usize;
        if rva >= vaddr && rva < vaddr + vsize {
            let raw_offset = section.pointer_to_raw_data as usize;
            return Some(raw_offset + (rva - vaddr));
        }
    }
    None
}

/// Resolve a Rich Header product ID (low 16 bits of CompID) to a
/// human-readable toolchain name. Coverage focuses on the products
/// trait authors care about for build-pipeline fingerprinting:
/// MSVC compilers, the linker, MASM, the resource compiler, and
/// import-library entries.
fn rich_product_name(product_id: u16) -> Option<&'static str> {
    let name = match product_id {
        0x0000 => "Unknown",
        0x0001 => "Import (object from .lib)",
        0x0002 => "Linker (LINK)",
        0x0003 => "MASM (object)",
        0x0004 => "MSVC C compiler (CL)",
        0x0005 => "MSVC C++ compiler (CL)",
        0x0006 => "Linker 5.10",
        0x0007 => "MASM 6.13",
        0x0008 => "MSVC 6.0 compiler",
        0x0009 => "MSVC 6.0 C++ compiler",
        0x000A => "MSVC 6.0 export",
        0x000B | 0x000C => "Linker 6.0",
        0x000D => "MSVC 7.0 compiler",
        0x000E => "MSVC 7.0 C++ compiler",
        0x000F => "MSVC 7.0 export",
        0x0010 => "Linker 7.0",
        0x0019 => "Linker 7.10",
        0x001C => "MASM 8.0",
        0x001D => "MSVC 8.0 C compiler",
        0x001E => "MSVC 8.0 C++ compiler",
        0x0021 => "Linker 8.0",
        0x0022 => "Resource compiler (RC)",
        0x0023 => "MSVC 9.0 C compiler",
        0x0024 => "MSVC 9.0 C++ compiler",
        0x0027 => "Linker 9.0",
        0x0028 => "MASM 9.0",
        0x0029..=0x002B => "MSVC 10.0 toolchain",
        0x002C => "Linker 10.0",
        0x002D => "MASM 10.0",
        0x0035 => "MSVC 11.0 C compiler",
        0x0036 => "MSVC 11.0 C++ compiler",
        0x0038 => "Linker 11.0",
        0x003A | 0x003B => "MSVC 12.0 toolchain",
        0x003D => "Linker 12.0",
        0x0040 => "MSVC 14.0 C compiler",
        0x0041 => "MSVC 14.0 C++ compiler",
        0x0043 => "Linker 14.0",
        0x0078 | 0x007A => "MSVC 14.x C/C++ compiler (VS2017+)",
        0x007B | 0x007C => "Linker 14.x (VS2017+)",
        0x009B..=0x009E => "MSVC 14.2x C/C++ compiler (VS2019)",
        0x009F..=0x00A0 => "Linker 14.2x (VS2019)",
        0x00FF..=0x0102 => "MSVC 14.3x C/C++ compiler (VS2022)",
        0x0103 => "Linker 14.3x (VS2022)",
        _ => return None,
    };
    Some(name)
}

/// Parse the Rich Header — Microsoft's undocumented "what built this
/// PE" footer between the DOS stub and the PE signature.
///
/// Layout: `DanS` marker XOR'd with the 4-byte key (terminator), 12
/// bytes of XOR'd zero padding, pairs of `(CompID, count)` each XOR'd
/// with the key, the literal `Rich` marker, and finally the 4-byte
/// plain-text XOR key.
///
/// Walks the region between `0x80` and the PE signature, locates the
/// `Rich` + key, then walks backwards in 8-byte `(CompID, count)`
/// tuples to the `DanS` terminator.
fn parse_rich_header(
    data: &[u8],
    pe_offset: usize,
) -> Vec<crate::types::binary_metrics::RichCompId> {
    use crate::types::binary_metrics::RichCompId;

    let region_end = pe_offset.min(data.len());
    if region_end < 0x80 + 8 {
        return Vec::new();
    }
    let region = &data[0x80..region_end];

    // Find "Rich" marker.
    let Some(rich_pos) = region.windows(4).position(|w| w == b"Rich") else {
        return Vec::new();
    };
    if rich_pos + 8 > region.len() {
        return Vec::new();
    }
    let key = u32::from_le_bytes([
        region[rich_pos + 4],
        region[rich_pos + 5],
        region[rich_pos + 6],
        region[rich_pos + 7],
    ]);

    // Walk backward in 4-byte words, looking for the XOR'd "DanS"
    // terminator (raw word XOR key == "DanS").
    let dans_marker = u32::from_le_bytes(*b"DanS");
    let mut dans_offset = None;
    let mut i = rich_pos;
    while i >= 4 {
        i -= 4;
        let w = u32::from_le_bytes([region[i], region[i + 1], region[i + 2], region[i + 3]]);
        if w ^ key == dans_marker {
            dans_offset = Some(i);
            break;
        }
    }
    let Some(dans_offset) = dans_offset else {
        return Vec::new();
    };

    // Tuple zone: from `dans_offset + 16` (DanS + 12 bytes padding) to `rich_pos`.
    let tuple_start = dans_offset + 16;
    if tuple_start >= rich_pos {
        return Vec::new();
    }
    let tuple_zone = &region[tuple_start..rich_pos];

    let mut entries = Vec::new();
    for chunk in tuple_zone.chunks_exact(8) {
        let compid = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]) ^ key;
        let count = u32::from_le_bytes([chunk[4], chunk[5], chunk[6], chunk[7]]) ^ key;
        let product_id = (compid & 0xFFFF) as u16;
        entries.push(RichCompId {
            compid,
            count,
            product: rich_product_name(product_id).map(str::to_string),
        });
    }
    entries
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn test_pe_path() -> PathBuf {
        PathBuf::from("tests/fixtures/test.exe")
    }

    #[test]
    fn test_rich_product_name_resolution() {
        assert_eq!(rich_product_name(0x0002), Some("Linker (LINK)"));
        assert_eq!(rich_product_name(0x0040), Some("MSVC 14.0 C compiler"));
        assert_eq!(rich_product_name(0xFFFE), None);
    }

    #[test]
    fn test_parse_rich_header_empty_when_no_marker() {
        let data = vec![0u8; 0x200];
        assert!(parse_rich_header(&data, 0x100).is_empty());
    }

    #[test]
    fn test_is_unusual_bss_like_excludes_dot_bss() {
        // Standard `.bss` with rsize=0, vsize>0 must NOT count as unusual.
        assert!(!is_unusual_bss_like(".bss", 0, 0x1000));
        assert!(!is_unusual_bss_like("bss", 0, 0x1000));
        assert!(!is_unusual_bss_like(".BSS", 0, 0x1000));
    }

    #[test]
    fn test_is_unusual_bss_like_excludes_dot_tls() {
        assert!(!is_unusual_bss_like(".tls", 0, 0x100));
        assert!(!is_unusual_bss_like("tls", 0, 0x100));
        assert!(!is_unusual_bss_like(".TLS", 0, 0x100));
    }

    #[test]
    fn test_is_unusual_bss_like_flags_unusual_name() {
        // Random/packer-style section name with rsize=0 vsize>0 IS unusual.
        assert!(is_unusual_bss_like(".upx0", 0, 0x10000));
        assert!(is_unusual_bss_like(".x", 0, 0x100));
        assert!(is_unusual_bss_like(".decompr", 0, 0x10000));
    }

    #[test]
    fn test_is_unusual_bss_like_requires_zero_raw() {
        // Non-zero raw_size means the section is backed by file data.
        assert!(!is_unusual_bss_like(".upx0", 1, 0x10000));
    }

    #[test]
    fn test_is_unusual_bss_like_requires_nonzero_virtual() {
        // Both raw and virtual zero is just an empty section, not BSS.
        assert!(!is_unusual_bss_like(".upx0", 0, 0));
    }

    #[test]
    fn test_can_analyze_pe() {
        let analyzer = PEAnalyzer::new();
        let test_file = test_pe_path();

        if test_file.exists() {
            assert!(analyzer.can_analyze(&test_file));
        }
    }

    #[test]
    fn test_cannot_analyze_non_pe() {
        let analyzer = PEAnalyzer::new();
        assert!(!analyzer.can_analyze(&PathBuf::from("/dev/null")));
        assert!(!analyzer.can_analyze(&PathBuf::from("tests/fixtures/test.elf")));
    }

    #[test]
    fn test_analyze_pe_file() {
        let analyzer = PEAnalyzer::new();
        let test_file = test_pe_path();

        if !test_file.exists() {
            return;
        }

        let result = analyzer.analyze(&test_file);
        assert!(result.is_ok());

        let report = result.unwrap();
        assert_eq!(report.target.file_type, "pe");
        assert!(report.target.size_bytes > 0);
        assert!(!report.target.sha256.is_empty());
    }

    #[test]
    fn test_pe_has_structure() {
        let analyzer = PEAnalyzer::new();
        let test_file = test_pe_path();

        if !test_file.exists() {
            return;
        }

        let report = analyzer.analyze(&test_file).unwrap();
        assert!(!report.structure.is_empty());
    }

    #[test]
    fn test_pe_architecture_detected() {
        let analyzer = PEAnalyzer::new();
        let test_file = test_pe_path();

        if !test_file.exists() {
            return;
        }

        let report = analyzer.analyze(&test_file).unwrap();
        let archs = report
            .target
            .architectures
            .expect("PE analyzer should detect at least one architecture");
        // test.exe is a 64-bit MSVC build. The canonical label is
        // `"x86_64"` — what expose emits and what every analyst-facing
        // tool (objdump, file(1), LIEF) reports. The ctx-fed path
        // returns this verbatim; the legacy fallback maps 0x8664 to
        // the same string.
        assert_eq!(
            archs,
            vec!["x86_64".to_string()],
            "test.exe arch label drifted from canonical x86_64",
        );
    }

    /// Verify `arch_name` returns expose's canonical lowercase label
    /// when ctx is available, and the legacy mapping otherwise. The
    /// two agree for x86_64 but diverge for i386 / arm64 — this test
    /// pins both branches.
    #[test]
    fn arch_name_prefers_expose_canonical_label() {
        let analyzer = PEAnalyzer::new();
        let test_file = test_pe_path();
        if !test_file.exists() {
            return;
        }
        let bytes = std::fs::read(&test_file).unwrap();
        let pe = PE::parse(&bytes).expect("test.exe parses");

        let legacy = analyzer.arch_name(&pe, None);
        let ctx = crate::analysis_context::AnalysisContext::open(&test_file, &bytes).unwrap();
        let bridged = analyzer.arch_name(&pe, Some(&ctx));

        // test.exe is x86_64; both paths agree on this fixture.
        assert_eq!(legacy, "x86_64");
        assert_eq!(bridged, "x86_64");
    }

    #[test]
    fn test_pe_sections_analyzed() {
        let analyzer = PEAnalyzer::new();
        let test_file = test_pe_path();

        if !test_file.exists() {
            return;
        }

        let report = analyzer.analyze(&test_file).unwrap();
        assert!(!report.sections.is_empty());
    }

    #[test]
    fn test_pe_has_imports() {
        let analyzer = PEAnalyzer::new();
        let test_file = test_pe_path();

        if !test_file.exists() {
            return;
        }

        let report = analyzer.analyze(&test_file).unwrap();
        assert!(!report.imports.is_empty());
    }

    /// `analyze_structural_with_ctx` produces equivalent
    /// `report.imports` to the legacy goblin path. When the
    /// AnalysisContext is provided, the bridge tags entries with
    /// `source: "pe"` (from expose's typed view); when it's `None`,
    /// the legacy path tags them `source: "goblin"`. Both should
    /// populate the same symbol names.
    #[test]
    fn analyze_structural_with_ctx_matches_legacy_imports() {
        let analyzer = PEAnalyzer::new();
        let test_file = test_pe_path();
        if !test_file.exists() {
            return;
        }
        let bytes = std::fs::read(&test_file).unwrap();

        // Legacy path: no context, imports tagged "goblin".
        let legacy = analyzer.analyze_structural(&test_file, &bytes, None);
        // Bridged path: AnalysisContext provided, imports tagged "pe".
        let ctx = crate::analysis_context::AnalysisContext::open(&test_file, &bytes).unwrap();
        let bridged = analyzer.analyze_structural_with_ctx(&test_file, &bytes, None, Some(&ctx));

        // Both paths populate imports.
        assert!(!legacy.imports.is_empty());
        assert!(!bridged.imports.is_empty());

        // Source tags differ between the two paths — that's the
        // observable signal that the bridge is actually engaged.
        let legacy_sources: std::collections::HashSet<&str> =
            legacy.imports.iter().map(|i| i.source.as_str()).collect();
        let bridged_sources: std::collections::HashSet<&str> =
            bridged.imports.iter().map(|i| i.source.as_str()).collect();
        assert!(legacy_sources.contains("goblin"));
        assert!(bridged_sources.contains("pe"));

        // The symbol *names* should match (modulo cleave's
        // normalize_symbol leading-underscore strip, which both
        // paths apply uniformly).
        let legacy_names: std::collections::BTreeSet<String> =
            legacy.imports.iter().map(|i| i.symbol.clone()).collect();
        let bridged_names: std::collections::BTreeSet<String> =
            bridged.imports.iter().map(|i| i.symbol.clone()).collect();
        assert_eq!(legacy_names, bridged_names);

        // Exports parity — names, offsets (RVA), and forward_to
        // semantics must match between the two paths. The source
        // tag differs (`"goblin"` vs `"pe"`); everything else is
        // the same.
        let legacy_export_names: std::collections::BTreeSet<String> =
            legacy.exports.iter().map(|e| e.symbol.clone()).collect();
        let bridged_export_names: std::collections::BTreeSet<String> =
            bridged.exports.iter().map(|e| e.symbol.clone()).collect();
        assert_eq!(legacy_export_names, bridged_export_names);

        // RVA-derived offsets must match byte-for-byte. Pair on
        // symbol name so order doesn't matter.
        let legacy_offsets: std::collections::BTreeMap<String, Option<String>> = legacy
            .exports
            .iter()
            .map(|e| (e.symbol.clone(), e.offset.clone()))
            .collect();
        let bridged_offsets: std::collections::BTreeMap<String, Option<String>> = bridged
            .exports
            .iter()
            .map(|e| (e.symbol.clone(), e.offset.clone()))
            .collect();
        assert_eq!(legacy_offsets, bridged_offsets);

        // Sections parity — names, sizes, addresses, and permission
        // flags must match. Per-section entropy comes from a single
        // entropy computation in either path, so the values are
        // byte-identical too.
        assert_eq!(legacy.sections.len(), bridged.sections.len());
        let legacy_section_names: std::collections::BTreeSet<&str> =
            legacy.sections.iter().map(|s| s.name.as_str()).collect();
        let bridged_section_names: std::collections::BTreeSet<&str> =
            bridged.sections.iter().map(|s| s.name.as_str()).collect();
        assert_eq!(legacy_section_names, bridged_section_names);
        // Permissions and sizes by name.
        let legacy_perms: std::collections::BTreeMap<String, (u64, Option<String>)> = legacy
            .sections
            .iter()
            .map(|s| (s.name.clone(), (s.size, s.permissions.clone())))
            .collect();
        let bridged_perms: std::collections::BTreeMap<String, (u64, Option<String>)> = bridged
            .sections
            .iter()
            .map(|s| (s.name.clone(), (s.size, s.permissions.clone())))
            .collect();
        assert_eq!(legacy_perms, bridged_perms);

        // BinaryMetrics-level section permission counts must match
        // between the two paths — bridged reads from
        // `sections.executable_count` / `writable_count` /
        // `executable_writable_count` metrics emitted by expose;
        // legacy walks goblin's section characteristics directly.
        let legacy_bin = legacy
            .metrics
            .as_ref()
            .and_then(|m| m.binary.as_ref())
            .expect("legacy binary metrics present");
        let bridged_bin = bridged
            .metrics
            .as_ref()
            .and_then(|m| m.binary.as_ref())
            .expect("bridged binary metrics present");
        assert_eq!(
            legacy_bin.executable_section_count, bridged_bin.executable_section_count,
            "executable_section_count diverged",
        );
        assert_eq!(
            legacy_bin.writable_section_count, bridged_bin.writable_section_count,
            "writable_section_count diverged",
        );
        assert_eq!(
            legacy_bin.wx_section_count, bridged_bin.wx_section_count,
            "wx_section_count diverged",
        );
        // code_size derives from the executable-section sum on both
        // paths — bridged sums expose's typed Section.file_size,
        // legacy sums goblin's size_of_raw_data. Same value.
        assert_eq!(
            legacy_bin.code_size, bridged_bin.code_size,
            "code_size diverged between bridged and legacy paths",
        );
    }

    #[test]
    fn test_pe_capabilities_detected() {
        let analyzer = PEAnalyzer::new();
        let test_file = test_pe_path();

        if !test_file.exists() {
            return;
        }

        let report = analyzer.analyze(&test_file).unwrap();
        // Capabilities may or may not be detected depending on the binary
        // Just verify the analysis completes successfully
        let _ = &report.traits;
    }

    #[test]
    fn test_pe_strings_extracted() {
        let analyzer = PEAnalyzer::new();
        let test_file = test_pe_path();

        if !test_file.exists() {
            return;
        }

        let report = analyzer.analyze(&test_file).unwrap();
        assert!(!report.strings.is_empty());
    }

    #[test]
    fn test_pe_tools_used() {
        let analyzer = PEAnalyzer::new();
        let test_file = test_pe_path();

        if !test_file.exists() {
            return;
        }

        let report = analyzer.analyze(&test_file).unwrap();
        assert!(report.metadata.tools_used.contains(&"goblin".to_string()));
    }

    #[test]
    fn test_pe_analysis_duration() {
        let analyzer = PEAnalyzer::new();
        let test_file = test_pe_path();

        if !test_file.exists() {
            return;
        }

        let report = analyzer.analyze(&test_file).unwrap();
        // Duration may be 0 for very fast analysis (sub-millisecond).
        // The important thing is that analysis completes and the field is set.
        // Duration is a u64, so it's always >= 0.
        assert!(
            report.metadata.analysis_duration_ms < 60000,
            "Analysis should complete in under a minute"
        );
    }

    #[test]
    fn test_analyze_self_extracting_7z() {
        use std::fs;
        use std::io::Write;

        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("sfx.exe");

        let Ok(mut host) = fs::read("tests/fixtures/test.exe") else {
            eprintln!("skipping test_analyze_self_extracting_7z: missing tests/fixtures/test.exe");
            return;
        };

        // Append a tiny ZIP archive as overlay so the PE behaves like a
        // self-extracting archive without relying on developer-local samples.
        let cursor = std::io::Cursor::new(Vec::new());
        let mut zip = zip::ZipWriter::new(cursor);
        let options = zip::write::SimpleFileOptions::default();
        zip.start_file("hello.txt", options).unwrap();
        zip.write_all(b"hello from overlay").unwrap();
        let cursor = zip.finish().unwrap();
        host.extend_from_slice(&cursor.into_inner());
        fs::write(&path, &host).unwrap();

        let analyzer = PEAnalyzer::new();
        let report = analyzer.analyze(&path).unwrap();

        // Should detect the self-extracting archive
        assert!(
            report
                .findings
                .iter()
                .any(|f| f.id.contains("self-extracting")),
            "Should detect self-extracting archive"
        );

        // Should have analyzed the embedded archive contents
        assert!(
            !report.archive_contents.is_empty(),
            "Should have extracted archive contents"
        );

        // Should have findings from the embedded files
        eprintln!(
            "SFX analysis found {} files in archive",
            report.archive_contents.len()
        );
        eprintln!(
            "SFX analysis found {} total findings",
            report.findings.len()
        );

        // All archive content paths should use standard archive delimiter
        for entry in &report.archive_contents {
            assert!(
                entry
                    .path
                    .contains(crate::types::file_analysis::ARCHIVE_DELIMITER),
                "Archive path should use '!!': {}",
                entry.path
            );
            assert!(
                entry.path.starts_with("sfx.exe!!"),
                "Archive path should start with PE filename: {}",
                entry.path
            );
        }
    }

    // =========================================================================
    // UPX Integration Tests
    // =========================================================================

    #[test]
    fn test_pe_upx_detection_in_data() {
        use crate::upx::UPXDecompressor;

        // PE with UPX magic
        let mut upx_data = vec![0u8; 256];
        // MZ header
        upx_data[0..2].copy_from_slice(b"MZ");
        // UPX magic
        upx_data[100..104].copy_from_slice(b"UPX!");
        assert!(UPXDecompressor::is_upx_packed(&upx_data));

        // PE without UPX magic
        let mut normal_data = vec![0u8; 256];
        normal_data[0..2].copy_from_slice(b"MZ");
        assert!(!UPXDecompressor::is_upx_packed(&normal_data));
    }

    #[test]
    fn test_pe_upx_packed_creates_finding() {
        use crate::upx::UPXDecompressor;

        let analyzer = PEAnalyzer::new();

        // Create minimal UPX-packed PE-like data (won't actually decompress)
        let mut upx_data = vec![0u8; 512];
        // DOS header
        upx_data[0..2].copy_from_slice(b"MZ");
        // e_lfanew pointing to PE header
        upx_data[0x3c..0x40].copy_from_slice(&[0x80, 0x00, 0x00, 0x00]);
        // PE signature at offset 0x80
        upx_data[0x80..0x84].copy_from_slice(b"PE\x00\x00");
        // Machine type (x64)
        upx_data[0x84..0x86].copy_from_slice(&[0x64, 0x86]);
        // UPX magic
        upx_data[200..204].copy_from_slice(b"UPX!");

        assert!(UPXDecompressor::is_upx_packed(&upx_data));

        let temp_file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(temp_file.path(), &upx_data).unwrap();

        let report = analyzer.analyze_structural(temp_file.path(), &upx_data, None);

        // Should have UPX packer finding
        assert!(
            report
                .findings
                .iter()
                .any(|f| f.id == "anti-static/packer/upx"),
            "Should have UPX packer finding"
        );
    }

    #[test]
    fn test_pe_upx_tool_missing_creates_finding() {
        use crate::upx::{disable_upx, UPXDecompressor};

        // Temporarily disable UPX to simulate tool not available
        disable_upx();

        let analyzer = PEAnalyzer::new();

        // Create minimal UPX-packed PE-like data
        let mut upx_data = vec![0u8; 512];
        upx_data[0..2].copy_from_slice(b"MZ");
        upx_data[0x3c..0x40].copy_from_slice(&[0x80, 0x00, 0x00, 0x00]);
        upx_data[0x80..0x84].copy_from_slice(b"PE\x00\x00");
        upx_data[0x84..0x86].copy_from_slice(&[0x64, 0x86]);
        upx_data[200..204].copy_from_slice(b"UPX!");

        assert!(UPXDecompressor::is_upx_packed(&upx_data));

        let temp_file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(temp_file.path(), &upx_data).unwrap();

        let report = analyzer.analyze_structural(temp_file.path(), &upx_data, None);

        // Should have both UPX finding and tool-missing finding
        assert!(
            report
                .findings
                .iter()
                .any(|f| f.id == "anti-static/packer/upx"),
            "Should have UPX packer finding"
        );
        assert!(
            report
                .findings
                .iter()
                .any(|f| f.id == "anti-static/packer/upx/tool-missing"),
            "Should have tool-missing finding when UPX is disabled"
        );

        // Should NOT have unpacked file analysis
        assert!(
            report.files.is_empty(),
            "Should not have unpacked FileAnalysis when tool is missing"
        );
    }

    #[test]
    fn test_pe_non_upx_data_no_upx_finding() {
        let analyzer = PEAnalyzer::new();

        // Create minimal PE-like data without UPX magic
        let mut pe_data = vec![0u8; 512];
        pe_data[0..2].copy_from_slice(b"MZ");
        pe_data[0x3c..0x40].copy_from_slice(&[0x80, 0x00, 0x00, 0x00]);
        pe_data[0x80..0x84].copy_from_slice(b"PE\x00\x00");
        pe_data[0x84..0x86].copy_from_slice(&[0x64, 0x86]);

        let temp_file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(temp_file.path(), &pe_data).unwrap();

        let report = analyzer.analyze_structural(temp_file.path(), &pe_data, None);

        // Should NOT have UPX packer finding
        assert!(
            !report
                .findings
                .iter()
                .any(|f| f.id == "anti-static/packer/upx"),
            "Should not have UPX finding for non-UPX binary"
        );

        // Should NOT have unpacked file analysis
        assert!(
            report.files.is_empty(),
            "Should not have unpacked FileAnalysis for non-UPX binary"
        );
    }

    #[test]
    fn test_pe_upx_finding_criticality() {
        use crate::upx::UPXDecompressor;

        let analyzer = PEAnalyzer::new();

        let mut upx_data = vec![0u8; 512];
        upx_data[0..2].copy_from_slice(b"MZ");
        upx_data[0x3c..0x40].copy_from_slice(&[0x80, 0x00, 0x00, 0x00]);
        upx_data[0x80..0x84].copy_from_slice(b"PE\x00\x00");
        upx_data[0x84..0x86].copy_from_slice(&[0x64, 0x86]);
        upx_data[200..204].copy_from_slice(b"UPX!");

        assert!(UPXDecompressor::is_upx_packed(&upx_data));

        let temp_file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(temp_file.path(), &upx_data).unwrap();

        let report = analyzer.analyze_structural(temp_file.path(), &upx_data, None);

        // Find the UPX finding
        let upx_finding = report
            .findings
            .iter()
            .find(|f| f.id == "anti-static/packer/upx");

        assert!(upx_finding.is_some(), "Should have UPX finding");
        let finding = upx_finding.unwrap();

        // UPX materially changes static visibility even when otherwise legitimate.
        assert_eq!(finding.crit, Criticality::Suspicious);
        assert_eq!(finding.conf, 1.0);
        assert_eq!(finding.desc, "Binary contains a UPX packing marker");
    }

    #[test]
    fn test_pe_overlay_bounds_exclude_certificate_table() {
        let mut pe_data = vec![0u8; 0x420];
        pe_data[0..2].copy_from_slice(b"MZ");
        pe_data[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        pe_data[0x80..0x84].copy_from_slice(b"PE\0\0");
        pe_data[0x84..0x86].copy_from_slice(&0x014cu16.to_le_bytes());
        pe_data[0x86..0x88].copy_from_slice(&1u16.to_le_bytes());
        pe_data[0x94..0x96].copy_from_slice(&0xE0u16.to_le_bytes());
        pe_data[0x98..0x9a].copy_from_slice(&0x010bu16.to_le_bytes());
        pe_data[0x80 + 24 + 92..0x80 + 24 + 96].copy_from_slice(&16u32.to_le_bytes());

        let data_directories = 0x80 + 24 + 96;
        let security_dir = data_directories + (4 * 8);
        pe_data[security_dir..security_dir + 4].copy_from_slice(&0x300u32.to_le_bytes());
        pe_data[security_dir + 4..security_dir + 8].copy_from_slice(&0x120u32.to_le_bytes());

        let section_table = 0x80 + 24 + 0xE0;
        pe_data[section_table..section_table + 5].copy_from_slice(b".text");
        pe_data[section_table + 16..section_table + 20].copy_from_slice(&0x200u32.to_le_bytes());
        pe_data[section_table + 20..section_table + 24].copy_from_slice(&0x100u32.to_le_bytes());

        // WIN_CERTIFICATE header at the certificate table offset (0x300)
        // dwLength: 0x120 (total size including header)
        pe_data[0x300..0x304].copy_from_slice(&0x120u32.to_le_bytes());
        // wRevision: WIN_CERT_REVISION_2_0 (0x0200)
        pe_data[0x304..0x306].copy_from_slice(&0x0200u16.to_le_bytes());
        // wCertificateType: WIN_CERT_TYPE_PKCS_SIGNED_DATA (0x0002)
        pe_data[0x306..0x308].copy_from_slice(&0x0002u16.to_le_bytes());

        let pe = PE::parse(&pe_data).expect("synthetic PE should parse");
        assert_eq!(pe_certificate_range(&pe, &pe_data), Some((0x300, 0x420)));
        assert_eq!(
            pe_overlay_bounds_excluding_certificate(&pe, &pe_data),
            Some((0x300, 0x300)).filter(|(start, end)| end > start),
        );
    }

    // ──── Pure-function helpers ────────────────────────────────────

    #[test]
    fn dn_extract_cn_handles_canonical_dn() {
        let dn = "CN=Microsoft Corporation,O=Microsoft Corporation,L=Redmond,ST=Washington,C=US";
        assert_eq!(
            super::dn_extract_cn(dn).as_deref(),
            Some("Microsoft Corporation"),
        );
        assert_eq!(
            super::dn_extract_o(dn).as_deref(),
            Some("Microsoft Corporation"),
        );
        // Empty input → None, not a panic.
        assert_eq!(super::dn_extract_cn(""), None);
        // DN with no CN attribute returns None.
        assert_eq!(super::dn_extract_cn("OU=Engineering"), None);
        // RFC 4514 attributes are case-insensitive.
        assert_eq!(
            super::dn_extract_cn("cn=acme corp").as_deref(),
            Some("acme corp"),
        );
    }

    #[test]
    fn parse_iso8601_to_unix_handles_known_values() {
        assert_eq!(super::parse_iso8601_to_unix("1970-01-01T00:00:00Z"), 0);
        assert_eq!(
            super::parse_iso8601_to_unix("2022-05-12T20:45:59Z"),
            1_652_388_359,
        );
        // Malformed input → 0, not a panic.
        assert_eq!(super::parse_iso8601_to_unix("not-a-timestamp"), 0);
    }

    #[test]
    fn derive_signature_digest_mismatch_flags_real_divergence() {
        use crate::types::binary_metrics::PeMetrics;
        let mut m = PeMetrics::default();
        m.signature_digest_algorithm = Some("sha256".into());
        m.signature_digest = Some("deadbeef".into());
        m.authentihash = Some("cafebabe".into());
        assert!(super::derive_signature_digest_mismatch(&m));
        m.authentihash = Some("deadbeef".into());
        assert!(!super::derive_signature_digest_mismatch(&m));
    }

    #[test]
    fn derive_signature_digest_mismatch_is_false_when_fields_missing() {
        use crate::types::binary_metrics::PeMetrics;
        let mut m = PeMetrics::default();
        // No claimed digest → not a mismatch (no claim to disagree with).
        assert!(!super::derive_signature_digest_mismatch(&m));
        // Algorithm we don't recognise → not a mismatch (can't compare).
        m.signature_digest_algorithm = Some("blake2b".into());
        m.signature_digest = Some("deadbeef".into());
        assert!(!super::derive_signature_digest_mismatch(&m));
    }

    // ──── compute_pe_metrics integration tests ─────────────────────
    //
    // Each test runs `compute_pe_metrics` once against a real fixture
    // and asserts the produced fields directly. Together they cover
    // every block in the function: header fields, DOS stub, Rich
    // header, sections, debug directory, image hashes, .NET, TLS,
    // bound imports, load config, data directories, resources, and
    // Authenticode (when the fixture is signed).

    /// `compute_pe_metrics` on the in-repo `test.exe` (64-bit MSVC,
    /// unsigned, with CFG + Rich header + debug directory). The
    /// expected values below are stable properties of the fixture —
    /// regenerate by running `cleave inspect values tests/fixtures/test.exe`
    /// if the fixture itself is ever replaced.
    #[test]
    fn compute_pe_metrics_test_exe() {
        let analyzer = PEAnalyzer::new();
        let test_file = test_pe_path();
        if !test_file.exists() {
            return;
        }
        let bytes = std::fs::read(&test_file).unwrap();
        let pe = PE::parse(&bytes).expect("test.exe parses");
        let ctx = crate::analysis_context::AnalysisContext::open(&test_file, &bytes).unwrap();
        let (m, _) = analyzer.compute_pe_metrics(&pe, &bytes, &test_file, &ctx);

        // Header fields.
        assert_eq!(m.timestamp, 1_720_640_421);
        assert_eq!(m.entry, 4784);
        assert_eq!(m.entry_section.as_deref(), Some(".text"));
        assert_eq!(m.machine, 0x8664);
        assert_eq!(m.image_base, 0x1_4000_0000);
        assert_eq!(m.size_of_image, 28_672);
        assert_eq!(m.size_of_headers, 1024);

        // DOS stub + Rich header — clean MSVC build, no anomalies.
        assert!(!m.dos_stub_modified);
        assert!(!m.dos_stub_zeroed);
        assert!(m.has_rich_header);
        assert_eq!(m.rich_header_compids.len(), 10);

        // Sections — `.text` is the entry section, `.rsrc` carries
        // a non-empty resource directory. No anomalies.
        assert!(!m.entry_in_header);
        assert!(!m.entry_outside_sections);
        assert!(!m.entry_in_writable_section);
        assert_eq!(m.section_raw_overflow_count, 0);
        assert_eq!(m.misaligned_section_count, 0);
        assert_eq!(m.section_overlap_count, 0);
        assert!(!m.section_count_mismatch);
        // `.rsrc` has a small icon group.
        assert!(m.rsrc_size > 0);
        assert!(m.rsrc_entropy > 0.0);

        // Debug directory + PDB.
        assert_eq!(m.debug_directory_entries, 4);
        assert_eq!(
            m.pdb_path.as_deref(),
            Some("C:\\Users\\forveined\\Documents\\nil\\x64\\Release\\Nil.pdb"),
        );
        assert!(m.codeview_guid.is_some());

        // Checksum: stored = 0 on this fixture (linker left it
        // unfilled, which is common for non-production builds). The
        // computed checksum is still non-zero — that's how `editbin
        // /release` would fill it later if it ever ran.
        assert_eq!(m.checksum, 0);
        assert!(!m.has_checksum);
        assert!(m.computed_checksum > 0);
        // checksum_valid stays false when stored is 0 (it requires a
        // non-zero stored value matching the computed one).
        assert!(!m.checksum_valid);

        // Image hashes — all four lengths.
        assert_eq!(m.authentihash.as_deref().map(str::len), Some(64));
        assert_eq!(m.authentihash_sha1.as_deref().map(str::len), Some(40));
        assert_eq!(m.authentihash_sha384.as_deref().map(str::len), Some(96));
        assert_eq!(m.authentihash_sha512.as_deref().map(str::len), Some(128));

        // Load Config (CFG flags set; CFG function table empty for this build).
        assert!(m.security_cookie != 0);
        assert!(m.cfg_check_func != 0);
        assert_eq!(m.cfg_func_count, 0);
        assert_eq!(m.cfg_guard_flags & 0x100, 0x100); // cf_instrumented

        // No signature, no nested signature, no delay imports.
        assert!(!m.has_signature);
        assert!(!m.has_nested_signature);
        assert_eq!(m.delay_load_import_count, 0);

        // Not a .NET binary.
        assert!(!m.is_dotnet);
        assert!(m.clr_version.is_none());

        // Data directory + section_characteristics typed kv carriers.
        assert_eq!(m.data_directory_entries.len(), 7);
        assert!(!m.section_characteristics_entries.is_empty());
    }

    /// Microsoft-signed Sysinternals PsInfo64. Asserts the Authenticode
    /// block end-to-end: signer identity, EKU, thumbprint, signature
    /// verification, and the SHA-256 image hash matching the signature's
    /// own claimed digest (the load-bearing property of Authenticode).
    #[test]
    fn compute_pe_metrics_psinfo64_signed_authenticode() {
        let path = std::path::PathBuf::from("/Users/t/data/good/dissect-random/PsInfo64.exe");
        if !path.exists() {
            return;
        }
        let analyzer = PEAnalyzer::new();
        let bytes = std::fs::read(&path).unwrap();
        let Ok(pe) = PE::parse(&bytes) else { return };
        let ctx = crate::analysis_context::AnalysisContext::open(&path, &bytes).unwrap();
        let (m, _) = analyzer.compute_pe_metrics(&pe, &bytes, &path, &ctx);

        assert!(m.has_signature);
        assert_eq!(m.leaf_subject.as_deref(), Some("Microsoft Corporation"));
        assert_eq!(m.signature_type.as_deref(), Some("platform"));
        assert!(m.leaf_eku_code_signing);
        // Expose surfaces the friendly OID name as `sha256WithRSAEncryption`
        // (the RFC-spelled algorithm identifier). Cleave's old goblin
        // walker used `"sha256_rsa"`; tests + traits should be
        // updated to the canonical RFC name in a follow-up.
        assert_eq!(
            m.leaf_signature_algorithm.as_deref(),
            Some("sha256WithRSAEncryption"),
        );
        assert_eq!(
            m.leaf_thumbprint_sha1.as_deref(),
            Some("f372c27f6e052a6be8bab3112b465c692196cd6f"),
        );
        assert_eq!(m.signature_verified, Some(true));
        assert!(!m.sig_algorithm_unsupported);

        // The image hash under the algorithm the signature claims
        // MUST equal the signature's claimed digest — that's what
        // Authenticode verifies. signature_digest_mismatch should
        // therefore be `false`.
        assert_eq!(m.signature_digest_algorithm.as_deref(), Some("sha256"));
        assert_eq!(m.signature_digest, m.authentihash);
        assert!(!m.signature_digest_mismatch);

        // Cert chain depth is the outer SignedData bag's cert count —
        // non-zero on a signed PE.
        assert!(m.cert_chain_depth > 0);
    }

    /// Heavy real fixture — kernel32.dll. Asserts non-trivial counts
    /// across imports, exports (with forwarders), debug directory,
    /// and image hashes. Skips silently if the fixture isn't present.
    #[test]
    fn compute_pe_metrics_kernel32_heavy() {
        let path = std::path::PathBuf::from("/Users/t/data/good/data2/kernel32.dll");
        if !path.exists() {
            return;
        }
        let analyzer = PEAnalyzer::new();
        let bytes = std::fs::read(&path).unwrap();
        let Ok(pe) = PE::parse(&bytes) else { return };
        let ctx = crate::analysis_context::AnalysisContext::open(&path, &bytes).unwrap();
        let (m, _) = analyzer.compute_pe_metrics(&pe, &bytes, &path, &ctx);

        // Kernel32 forwards ~208 entries (the canonical Windows shape:
        // forwarders to KernelBase.dll). Exact counts drift across
        // Windows builds; we assert the order of magnitude is right.
        assert!(
            m.export_forwarder_count > 100,
            "kernel32 forwarder count looks too low: {}",
            m.export_forwarder_count,
        );
        assert!(m.system_dll_forward_count > 0);
        assert!(m.forward_ratio > 0.0 && m.forward_ratio < 1.0);

        // Imports — at least one library, non-trivial count.
        assert!(m.import_dll_count > 0);
        assert!(m.ordinal_import_count == 0); // KernelBase imports by name

        // PDB + image hashes always populate on a signed Windows DLL.
        assert!(m.pdb_path.is_some());
        assert!(m.authentihash.is_some());
        assert_eq!(m.authentihash.as_deref().map(str::len), Some(64));

        // Section walk produces sane values.
        assert!(!m.section_count_mismatch);
        assert_eq!(m.section_raw_overflow_count, 0);
    }

    /// `compute_pe_metrics` on a real IL-only .NET binary. Asserts the
    /// CLR detection path: `is_dotnet = true`, runtime version populated,
    /// `mixed_mode = false` (IL-only means no native entrypoint).
    #[test]
    fn compute_pe_metrics_dotnet_il_only() {
        let path = std::path::PathBuf::from("/Users/t/data/benchmark/100MB/TaskschDemo.exe");
        if !path.exists() {
            return;
        }
        let analyzer = PEAnalyzer::new();
        let bytes = std::fs::read(&path).unwrap();
        let Ok(pe) = PE::parse(&bytes) else { return };
        let ctx = crate::analysis_context::AnalysisContext::open(&path, &bytes).unwrap();
        let (m, _) = analyzer.compute_pe_metrics(&pe, &bytes, &path, &ctx);

        assert!(m.is_dotnet);
        assert!(m.clr_version.is_some(), "clr_version should be populated");
        assert!(!m.mixed_mode, "IL-only PE must not be mixed-mode");
        assert!(!m.dotnet_has_native_entry);
    }
}
