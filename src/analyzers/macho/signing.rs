//! Code-signature verification and entitlement findings.

use super::{AnalysisReport, Criticality, Evidence, Finding, FindingKind};
use sha2::{Digest, Sha256, Sha384};

/// Outcome of checking the supported CodeDirectory page-hash tables in an
/// embedded Mach-O signature. Unsupported algorithms or scatter tables are
/// deliberately silent: absence of verification is not proof of tampering.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum CodeDirectoryIntegrity {
    Valid { checked: usize },
    Invalid { mismatched: usize, checked: usize },
    Unsupported,
    Malformed,
}

/// Verify SHA-256/SHA-384 CodeDirectory page hashes. Modern Developer ID
/// signatures use these algorithms; legacy SHA-1 and scatter-vector layouts
/// remain unsupported rather than being guessed at.
pub(super) fn verify_code_directory_hashes(
    data: &[u8],
    sig_offset: usize,
) -> CodeDirectoryIntegrity {
    const EMBEDDED_SIGNATURE: u32 = 0xfade_0cc0;
    const DETACHED_SIGNATURE: u32 = 0xfade_0cc1;
    const CODE_DIRECTORY: u32 = 0xfade_0c02;
    /// Slots a CodeDirectory may occupy: the primary (`CSSLOT_CODEDIRECTORY`)
    /// and the five alternates (`CSSLOT_ALTERNATE_CODEDIRECTORIES`).
    const CODE_DIRECTORY_SLOTS: [u32; 6] = [0, 0x1000, 0x1001, 0x1002, 0x1003, 0x1004];

    let Some(magic) = read_be_u32(data, sig_offset) else {
        return CodeDirectoryIntegrity::Malformed;
    };
    if !matches!(magic, EMBEDDED_SIGNATURE | DETACHED_SIGNATURE) {
        return CodeDirectoryIntegrity::Malformed;
    }
    // A big-endian u32 at `base + rel`, or `None` past the end (or on overflow).
    let field =
        |base: usize, rel: usize| base.checked_add(rel).and_then(|at| read_be_u32(data, at));
    let Some(total_len) = field(sig_offset, 4).map(|v| v as usize) else {
        return CodeDirectoryIntegrity::Malformed;
    };
    let Some(sig_end) = sig_offset.checked_add(total_len) else {
        return CodeDirectoryIntegrity::Malformed;
    };
    if total_len < 12 || sig_end > data.len() {
        return CodeDirectoryIntegrity::Malformed;
    }
    let Some(count) = field(sig_offset, 8).map(|v| v as usize) else {
        return CodeDirectoryIntegrity::Malformed;
    };
    let Some(index_end) = count.checked_mul(8).and_then(|n| n.checked_add(12)) else {
        return CodeDirectoryIntegrity::Malformed;
    };
    if index_end > total_len {
        return CodeDirectoryIntegrity::Malformed;
    }
    let Some(index) = sig_offset
        .checked_add(12)
        .zip(sig_offset.checked_add(index_end))
        .and_then(|(start, end)| data.get(start..end))
    else {
        return CodeDirectoryIntegrity::Malformed;
    };

    let mut checked = 0usize;
    let mut mismatched = 0usize;
    let mut saw_supported = false;
    // Each CodeDirectory slot, and each blob, is hashed at most once. A page
    // hash covers up to the whole file, so an index naming one CodeDirectory
    // thousands of times (or CodeDirectories in arbitrary slots) made this
    // quadratic in the signature size; now it is at most six passes.
    let mut verified_slots: Vec<u32> = Vec::new();
    let mut verified_blobs: Vec<usize> = Vec::new();
    for entry in index.as_chunks::<8>().0 {
        let (Some(slot_type), Some(blob_rel)) = (
            read_be_u32(entry, 0),
            read_be_u32(entry, 4).map(|v| v as usize),
        ) else {
            return CodeDirectoryIntegrity::Malformed;
        };
        if blob_rel.checked_add(8).is_none_or(|end| end > total_len) {
            return CodeDirectoryIntegrity::Malformed;
        }
        let Some(blob_start) = sig_offset.checked_add(blob_rel) else {
            return CodeDirectoryIntegrity::Malformed;
        };
        if read_be_u32(data, blob_start) != Some(CODE_DIRECTORY)
            || !CODE_DIRECTORY_SLOTS.contains(&slot_type)
            || verified_slots.contains(&slot_type)
            || verified_blobs.contains(&blob_rel)
        {
            continue;
        }
        verified_slots.push(slot_type);
        verified_blobs.push(blob_rel);
        let Some(blob_len) = field(blob_start, 4).map(|v| v as usize) else {
            return CodeDirectoryIntegrity::Malformed;
        };
        let Some(blob_end) = blob_start.checked_add(blob_len) else {
            return CodeDirectoryIntegrity::Malformed;
        };
        if blob_len < 44 || blob_end > sig_end {
            return CodeDirectoryIntegrity::Malformed;
        }
        let Some(blob) = data.get(blob_start..blob_end) else {
            return CodeDirectoryIntegrity::Malformed;
        };
        let version = read_be_u32(blob, 8).unwrap_or(0);
        let hash_offset = read_be_u32(blob, 16).unwrap_or(0) as usize;
        let slots = read_be_u32(blob, 28).unwrap_or(0) as usize;
        let mut code_limit = read_be_u32(blob, 32).unwrap_or(0) as usize;
        let (Some(&hash_size), Some(&hash_type), Some(&page_log2)) =
            (blob.get(36), blob.get(37), blob.get(39))
        else {
            return CodeDirectoryIntegrity::Malformed;
        };
        let hash_size = usize::from(hash_size);

        // Scatter-vector CodeDirectories describe non-contiguous ranges and
        // require a different slot-to-file mapping.
        if version >= 0x0002_0100 && read_be_u32(blob, 44).unwrap_or(0) != 0 {
            continue;
        }
        if version >= 0x0002_0300 && blob.len() >= 64 {
            let limit64 = read_be_u64(blob, 56).unwrap_or(0);
            if limit64 != 0 {
                let Ok(limit) = usize::try_from(limit64) else {
                    return CodeDirectoryIntegrity::Malformed;
                };
                code_limit = limit;
            }
        }
        if code_limit > data.len() || hash_size == 0 {
            return CodeDirectoryIntegrity::Malformed;
        }
        let page_size = if page_log2 == 0 {
            code_limit.max(1)
        } else {
            match 1usize.checked_shl(u32::from(page_log2)) {
                Some(size) => size,
                None => return CodeDirectoryIntegrity::Malformed,
            }
        };
        let expected_slots = code_limit.div_ceil(page_size);
        if slots != expected_slots {
            return CodeDirectoryIntegrity::Malformed;
        }
        let Some(hash_end) = slots
            .checked_mul(hash_size)
            .and_then(|n| hash_offset.checked_add(n))
        else {
            return CodeDirectoryIntegrity::Malformed;
        };
        if hash_offset < 44 || hash_end > blob.len() {
            return CodeDirectoryIntegrity::Malformed;
        }
        let digest_len = match hash_type {
            2 | 3 => 32,
            4 => 48,
            _ => continue,
        };
        if hash_size > digest_len {
            return CodeDirectoryIntegrity::Malformed;
        }
        saw_supported = true;
        for slot in 0..slots {
            let start = slot.saturating_mul(page_size);
            let end = start.saturating_add(page_size).min(code_limit);
            let stored = slot
                .checked_mul(hash_size)
                .and_then(|rel| hash_offset.checked_add(rel))
                .and_then(|at| blob.get(at..at.checked_add(hash_size)?));
            let (Some(stored), Some(page)) = (stored, data.get(start..end)) else {
                return CodeDirectoryIntegrity::Malformed;
            };
            let matches = match hash_type {
                2 | 3 => Sha256::digest(page).get(..hash_size) == Some(stored),
                4 => Sha384::digest(page).get(..hash_size) == Some(stored),
                _ => return CodeDirectoryIntegrity::Unsupported,
            };
            checked = checked.saturating_add(1);
            if !matches {
                mismatched = mismatched.saturating_add(1);
            }
        }
    }

    if !saw_supported {
        CodeDirectoryIntegrity::Unsupported
    } else if mismatched > 0 {
        CodeDirectoryIntegrity::Invalid {
            mismatched,
            checked,
        }
    } else {
        CodeDirectoryIntegrity::Valid { checked }
    }
}

pub(super) fn read_be_u32(data: &[u8], offset: usize) -> Option<u32> {
    let bytes: [u8; 4] = data.get(offset..offset.checked_add(4)?)?.try_into().ok()?;
    Some(u32::from_be_bytes(bytes))
}

pub(super) fn read_be_u64(data: &[u8], offset: usize) -> Option<u64> {
    let bytes: [u8; 8] = data.get(offset..offset.checked_add(8)?)?.try_into().ok()?;
    Some(u64::from_be_bytes(bytes))
}

pub(super) fn emit_signature_findings(
    report: &mut AnalysisReport,
    sig_offset: u64,
    identifier_offset: Option<u64>,
    identity: &filefacts::Identity,
    entitlements: Option<&serde_json::Map<String, serde_json::Value>>,
    failure: Option<crate::analyzers::signature::Failure>,
    issuer: Option<&str>,
) {
    use filefacts::Trust;
    let location = format!("0x{sig_offset:x}");

    // The signer, filed under how far the signature is trusted (see
    // `analyzers::signature`). Ad-hoc signatures carry no certificate; the
    // YAML side reads their `ad_hoc` flag from `macho.code_signature.flags`.
    report
        .findings
        .extend(crate::analyzers::signature::findings(
            identity,
            failure,
            issuer,
            "code_signature",
            Some(&location),
        ));
    // Only a platform signature over intact code earns platform leniency
    // for its entitlements.
    let is_platform =
        failure.is_none() && matches!(identity.trust, Trust::System | Trust::Platform);

    // Bundle / executable identifier — the identity the binary claims, filed
    // under its signer's trust state. Anchors at the identifier string's own
    // offset, falling back to the signature blob only when filefacts couldn't
    // resolve the string offset.
    if let Some(identifier) = identity.identifier.as_ref().map(|c| c.value.as_str()) {
        let id_location =
            identifier_offset.map_or_else(|| location.clone(), |off| format!("0x{off:x}"));
        report
            .findings
            .extend(crate::analyzers::signature::identifier_finding(
                identity,
                failure,
                issuer,
                identifier,
                &id_location,
            ));
    }

    // Entitlements — each granted capability is at least Notable.
    let Some(entitlements) = entitlements else {
        return;
    };
    let has_disable_lib_val =
        entitlements.contains_key("com.apple.security.cs.disable-library-validation");
    for (key, value) in entitlements {
        report.findings.push(signature_finding(
            format!(
                "metadata/entitlement/{}::{}",
                entitlement_category(key),
                key
            ),
            describe_entitlement(key),
            determine_entitlement_criticality(key, is_platform, has_disable_lib_val),
            "entitlements_plist",
            format!("{key}={}", entitlement_value_string(value)),
            &location,
        ));
    }
}

/// One code-signature finding, anchored at the signature blob `location`.
/// All signature findings share this shape: a full-confidence Capability
/// sourced from filefacts.
pub(super) fn signature_finding(
    id: String,
    desc: String,
    crit: Criticality,
    method: &str,
    value: String,
    location: &str,
) -> Finding {
    Finding {
        precomputed_spans: None,
        src: None,
        kind: FindingKind::Capability,
        trait_refs: vec![],
        id: id.into(),
        desc: desc.into(),
        conf: 1.0,
        crit,
        mbc: None,
        attack: None,
        evidence: vec![Evidence {
            method: method.to_string(),
            source: "filefacts".to_string(),
            value,
            location: Some(location.to_string()),
            ..Default::default()
        }],
        match_count: 0,
        source_file: None,
        downgraded: false,
    }
}

/// Render an entitlement value (from the projected plist JSON) as the
/// compact `key=value` evidence string. Mirrors the prior
/// boolean/string/array handling and adds numbers; nested objects are
/// vanishingly rare in entitlements and fall back to their JSON form.
pub(super) fn entitlement_value_string(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::Bool(b) => b.to_string(),
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Number(n) => n.to_string(),
        serde_json::Value::Array(a) => a
            .iter()
            .map(entitlement_value_string)
            .collect::<Vec<_>>()
            .join(", "),
        other => other.to_string(),
    }
}

/// Determine criticality of an entitlement based on its key
pub(super) fn describe_entitlement(key: &str) -> String {
    // Extract meaningful description from entitlement key
    let descriptions = [
        // Privacy/Device Access
        ("device.camera", "Camera access"),
        ("device.audio-input", "Microphone access"),
        ("device.microphone", "Microphone access"),
        ("device.bluetooth", "Bluetooth access"),
        ("personal-information.location", "Location data access"),
        ("personal-information.health", "Health data access"),
        (
            "personal-information.photos-library",
            "Photos library access",
        ),
        ("personal-information.contacts", "Contacts access"),
        ("personal-information.calendar", "Calendar access"),
        ("personal-information.reminders", "Reminders access"),
        // System Access
        ("keystore.access-keychain-keys", "Keychain key access"),
        ("keystore.lockassertion", "Keychain lock assertion"),
        ("security.storage.Keychains", "Keychain storage access"),
        // Code Execution & Security
        (
            "cs.disable-library-validation",
            "Allows libraries without signature validation",
        ),
        ("cs.allow-jit", "Allows JIT-compiled executable memory"),
        (
            "cs.allow-unsigned-executable-memory",
            "Allows unsigned executable memory",
        ),
        ("cs.debugger", "Debugger entitlement"),
        // Process & XPC
        (
            "xpc.launchd.ios-system-session",
            "iOS system session access",
        ),
        ("xpc.launchd", "Launchd XPC access"),
        // Application Features
        ("application-identifier", "Application identifier"),
        ("app-identifier", "App identifier"),
        ("push-service", "Push notification service"),
        ("icloud-container-identifiers", "iCloud container access"),
        // Databases & Storage
        ("sqlite.sqlite-encryption", "SQLite encryption"),
        // Debugging & Diagnostics
        ("symptom_diagnostics.report", "System diagnostics reporting"),
        // Private APIs (Apple Internal)
        ("private.MobileGestalt", "MobileGestalt queries"),
        ("private.applecredentialmanager", "Apple credential manager"),
        ("private.security.storage", "Private security storage"),
        // File/Sandbox Access
        ("sandbox.read-write", "Sandbox read-write"),
        (
            "files.user-selected.read-write",
            "Can read and modify user-selected files",
        ),
        ("home-directory", "Home directory access"),
        // Network client/server entitlement names are otherwise reduced by the
        // fallback to the unhelpful one-word labels "Client" and "Server".
        (
            "security.network.client",
            "Can make outbound network connections",
        ),
        (
            "security.network.server",
            "Can accept incoming network connections",
        ),
    ];

    for (key_part, desc) in descriptions {
        if key.contains(key_part) {
            return desc.to_string();
        }
    }

    // Fallback: clean up the key name for readability
    let short_name = key
        .split('.')
        .next_back()
        .unwrap_or(key)
        .replace(['-', '_'], " ");

    // Capitalize first letter
    let mut chars = short_name.chars();
    match chars.next() {
        None => key.to_string(),
        Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
    }
}

/// Categorize an entitlement key into a subdirectory for the ML pipeline.
/// The full finding ID becomes `metadata/entitlement/<category>::<key>`.
/// Every value [`entitlement_category`] returns: the `<category>` segment of
/// `metadata/entitlement/<category>::<key>`.
#[cfg(feature = "lint")]
pub(crate) const ENTITLEMENT_CATEGORIES: &[&str] = &[
    "device",
    "privacy",
    "security",
    "network",
    "filesystem",
    "keychain",
    "ipc",
    "cloud",
    "identity",
    "private-api",
    "virtualization",
    "automation",
    "other",
];

pub(crate) fn entitlement_category(key: &str) -> &'static str {
    // Device hardware access
    if key.contains("device.") {
        return "device";
    }
    // Personal/private data access
    if key.contains("personal-information") {
        return "privacy";
    }
    // Code-signing / runtime security policy
    if key.contains(".cs.") {
        return "security";
    }
    // Network capabilities
    if key.contains("network.") {
        return "network";
    }
    // File system / sandbox scope
    if key.contains("files.")
        || key.contains("sandbox")
        || key.contains("home-directory")
        || key.contains("temporary-exception.files")
    {
        return "filesystem";
    }
    // Keychain / credential storage
    if key.contains("keychain")
        || key.contains("keystore")
        || key.contains("Keychain")
        || key.contains("credential")
    {
        return "keychain";
    }
    // IPC: XPC, launchd, mach services
    if key.contains("xpc")
        || key.contains("launchd")
        || key.contains("mach-lookup")
        || key.contains("mach-register")
    {
        return "ipc";
    }
    // iCloud / push / app services
    if key.contains("icloud")
        || key.contains("push-service")
        || key.contains("aps-environment")
        || key.contains("ubiquity")
    {
        return "cloud";
    }
    // Application identity
    if key.contains("application-identifier")
        || key.contains("app-identifier")
        || key.contains("team-identifier")
        || key.contains("bundle-identifier")
    {
        return "identity";
    }
    // Apple private/internal APIs
    if key.contains("private.") || key.contains("root-access") {
        return "private-api";
    }
    // Virtualization / hypervisor
    if key.contains("hypervisor") || key.contains("virtualization") {
        return "virtualization";
    }
    // Accessibility / automation
    if key.contains("accessibility") || key.contains("automation") || key.contains("apple-events") {
        return "automation";
    }
    "other"
}

/// Criticality for a single entitlement. Permissions are *always*
/// Notable-or-higher, never Baseline: an entitlement is a capability the
/// binary is granted (debugger access, JIT, disabled library validation),
/// which is exactly the kind of provenance signal an analyst reads in a
/// diff. Dangerous entitlements escalate to Suspicious; nothing here returns
/// Baseline. This mirrors the cross-format identity/permissions principle in
/// traits/metadata/signature/ad-hoc/macho.yaml.
pub(super) fn determine_entitlement_criticality(
    entitlement_key: &str,
    is_platform: bool,
    has_disable_library_validation: bool,
) -> Criticality {
    // Platform/system (Apple-signed) binaries: all entitlements are notable
    if is_platform {
        return Criticality::Notable;
    }

    // Dangerous entitlements are suspicious on non-Apple binaries:
    // - allow-jit: allows JIT compilation (code generation at runtime)
    // - debugger: allows attaching to other processes
    // - allow-unsigned-executable-memory: bypasses code signing enforcement
    if entitlement_key.contains("debugger") {
        return Criticality::Suspicious;
    }

    if entitlement_key.contains("allow-unsigned-executable-memory") {
        if has_disable_library_validation {
            return Criticality::Notable;
        }
        return Criticality::Suspicious;
    }

    Criticality::Notable
}
