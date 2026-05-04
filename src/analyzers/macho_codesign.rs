//! Mach-O code signature parser for extracting signature types, team IDs, and entitlements
//!
//! Parses the SuperBlob structure from LC_CODE_SIGNATURE load command to extract:
//! - Signature type (adhoc, developer-id, platform, app-store)
//! - Team identifier from CMS certificate
//! - Entitlements from XML plist blob

use anyhow::{anyhow, Result};
use roxmltree::Document;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Signature types extracted from code signature
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub(crate) enum SignatureType {
    /// Ad-hoc signature without an external certificate chain.
    Adhoc,
    /// Developer ID signature used for distribution outside the App Store.
    DeveloperID,
    /// Apple platform signature used for first-party or platform binaries.
    Platform,
    /// Signature type could not be determined from the available metadata.
    #[default]
    Unknown,
}

impl SignatureType {
    #[must_use]
    pub(crate) fn as_str(&self) -> &str {
        match self {
            SignatureType::Adhoc => "adhoc",
            SignatureType::DeveloperID => "developer-id",
            SignatureType::Platform => "platform",
            SignatureType::Unknown => "unknown",
        }
    }
}

/// Entitlement values (simplified from full plist support)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) enum EntitlementValue {
    /// Boolean entitlement value.
    Boolean(bool),
    /// String entitlement value.
    String(String),
    /// Array entitlement value containing strings.
    Array(Vec<String>),
}

/// Parsed code signature information
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub(crate) struct CodeSignature {
    /// High-level signature classification derived from the embedded certificate chain.
    pub signature_type: SignatureType,
    /// Apple team identifier extracted from the signing certificate, when present.
    pub team_id: Option<String>,
    /// Common name of the leaf signer certificate, when present.
    pub signer: Option<String>,
    /// Certificate authorities observed while parsing the CMS signature.
    pub authorities: Vec<String>,
    /// Parsed entitlements keyed by entitlement name.
    pub entitlements: HashMap<String, EntitlementValue>,
    /// Whether the signature appears notarized based on the available code-signing metadata.
    pub is_notarized: bool,
    /// Whether the code directory enables hardened runtime.
    pub has_hardened_runtime: bool,
    /// Bundle or executable identifier extracted from the code directory.
    pub identifier: Option<String>,
    /// CDHash — SHA-256 of the entire CodeDirectory blob (including
    /// its 8-byte header). This is what `codesign -d --cdhashes`
    /// prints; Apple uses it as a per-binary identity for trust
    /// caches, notarization records, and crash-report linkage.
    /// Hex-encoded lowercase. Empty when no CodeDirectory present.
    pub cdhash_sha256: Option<String>,
    /// SHA-256 of the entire embedded Requirements blob, when
    /// present. The Requirements blob holds the compiled
    /// designated-requirement (DR) expression that names which
    /// authorities are allowed to validate this binary. Stable per
    /// build pipeline; differs across vendors. Hex-encoded lowercase.
    pub requirements_sha256: Option<String>,
    /// Number of requirement slots in the Requirements blob.
    /// Indexed slots: host=1, guest=2, designated=3, library=4,
    /// plugin=5. Most binaries carry only the designated requirement.
    pub requirements_slot_count: u32,
    /// Unix timestamp (seconds) recovered from the CMS signing-time
    /// authenticated attribute (PKCS#9 OID 1.2.840.113549.1.9.5).
    /// `None` for ad-hoc / platform binaries with no CMS, or when
    /// the timestamp is absent / unparseable.
    pub signing_time: Option<u64>,
}

// Magic numbers for Mach-O code signature blobs
const SUPERBLOB_MAGIC: u32 = 0xFADE0CC0;
const CODE_DIRECTORY_MAGIC: u32 = 0xFADE0C02;
const ENTITLEMENTS_BLOB_MAGIC: u32 = 0xFADE7171;
const CMS_SIGNATURE_MAGIC: u32 = 0xFADE0B01;
/// Set of compiled requirement blobs, indexed by slot type (host=1,
/// guest=2, designated=3, library=4, plugin=5). Each slot is itself a
/// `0xfade0c00`-magic Requirement blob with the compiled opcode
/// stream of that requirement's expression.
const REQUIREMENTS_MAGIC: u32 = 0xFADE0C01;

/// Parse code signature from binary data
pub(crate) fn parse_code_signature(
    data: &[u8],
    cs_offset: u32,
    cs_size: u32,
) -> Result<CodeSignature> {
    let offset = cs_offset as usize;
    let size = cs_size as usize;

    if offset + size > data.len() {
        return Err(anyhow!("Code signature offset/size out of bounds"));
    }

    let cs_data = &data[offset..offset + size];

    // Parse superblob to get individual blobs
    let blobs = parse_superblob(cs_data)?;

    // Extract entitlements from blob if present
    let entitlements = if let Some(ent_data) = blobs.get(&ENTITLEMENTS_BLOB_MAGIC) {
        parse_entitlements_blob(ent_data).unwrap_or_default()
    } else {
        HashMap::new()
    };

    // Extract team ID and signature type from CMS blob. A Mach-O with a
    // CodeDirectory but no CMS (no certificate chain) is adhoc-signed — this
    // is the default for Go's linker on macOS since Go 1.20 and for any
    // developer-local build before `codesign -s ...`.
    let (team_id, signature_type, authorities, signing_time) =
        if let Some(cms_data) = blobs.get(&CMS_SIGNATURE_MAGIC) {
            let (tid, st, auths) = extract_certificate_info(cms_data);
            (tid, st, auths, extract_cms_signing_time(cms_data))
        } else if blobs.contains_key(&CODE_DIRECTORY_MAGIC) {
            (None, SignatureType::Adhoc, vec![], None)
        } else {
            (None, SignatureType::Unknown, vec![], None)
        };

    let signer = authorities.first().cloned();

    // Check for hardened runtime flag in code directory
    let has_hardened_runtime = if let Some(cd_data) = blobs.get(&CODE_DIRECTORY_MAGIC) {
        check_hardened_runtime_flag(cd_data)
    } else {
        false
    };

    // Extract identifier from code directory
    let identifier = if let Some(cd_data) = blobs.get(&CODE_DIRECTORY_MAGIC) {
        extract_identifier(cd_data)
    } else {
        None
    };

    // CDHash — SHA-256 over the *full* CodeDirectory blob (including
    // its 8-byte magic+length header), which `parse_superblob` strips
    // before storing.  Walk the SuperBlob index a second time to
    // recover the un-stripped slice.
    let cdhash_sha256 = compute_cdhash_sha256(cs_data);

    // Requirements blob — fingerprint by SHA-256 of the full blob and
    // count of slots. Differential anchor for designated-requirement
    // language tampering.
    let (requirements_sha256, requirements_slot_count) = compute_requirements_summary(cs_data);

    // Determine if notarized (would need notarization ticket blob, for now just check for strictness)
    let is_notarized = !entitlements.is_empty() && has_hardened_runtime;

    Ok(CodeSignature {
        signature_type,
        team_id,
        signer,
        authorities,
        entitlements,
        is_notarized,
        has_hardened_runtime,
        identifier,
        cdhash_sha256,
        requirements_sha256,
        requirements_slot_count,
        signing_time,
    })
}

/// Scan a CMS blob for the PKCS#9 signing-time authenticated
/// attribute and decode the timestamp to Unix seconds.
///
/// Strategy: locate the OID 1.2.840.113549.1.9.5 in DER (`06 09 2A
/// 86 48 86 F7 0D 01 09 05`), then look ahead for a SET (`0x31`)
/// containing either UTCTime (`0x17`) or GeneralizedTime (`0x18`).
/// Lenient — bails on malformed input rather than propagating errors.
fn extract_cms_signing_time(cms_data: &[u8]) -> Option<u64> {
    const SIGNING_TIME_OID: [u8; 11] = [
        0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x05,
    ];
    let pos = cms_data
        .windows(SIGNING_TIME_OID.len())
        .position(|w| w == SIGNING_TIME_OID)?;
    // Search up to 32 bytes past the OID for the time tag.
    let scan_end = (pos + SIGNING_TIME_OID.len() + 32).min(cms_data.len());
    let region = &cms_data[pos + SIGNING_TIME_OID.len()..scan_end];
    for (i, &byte) in region.iter().enumerate() {
        match byte {
            0x17 if i + 14 < region.len() => {
                let len = region[i + 1] as usize;
                if len < 11 || i + 2 + len > region.len() {
                    continue;
                }
                let s = std::str::from_utf8(&region[i + 2..i + 2 + len]).ok()?;
                return parse_utctime(s);
            }
            0x18 if i + 16 < region.len() => {
                let len = region[i + 1] as usize;
                if len < 14 || i + 2 + len > region.len() {
                    continue;
                }
                let s = std::str::from_utf8(&region[i + 2..i + 2 + len]).ok()?;
                return parse_generalizedtime(s);
            }
            _ => {}
        }
    }
    None
}

/// Parse ASN.1 UTCTime (`YYMMDDHHMMSSZ` or `YYMMDDHHMMZ`) to Unix
/// seconds. Y2K convention: 2-digit years 00-49 = 2000-2049; 50-99
/// = 1950-1999.
fn parse_utctime(s: &str) -> Option<u64> {
    let s = s.trim_end_matches('Z');
    if s.len() != 12 && s.len() != 10 {
        return None;
    }
    let yy: u32 = s[0..2].parse().ok()?;
    let year = if yy < 50 { 2000 + yy } else { 1900 + yy };
    let mo: u32 = s[2..4].parse().ok()?;
    let dy: u32 = s[4..6].parse().ok()?;
    let hr: u32 = s[6..8].parse().ok()?;
    let mn: u32 = s[8..10].parse().ok()?;
    let sc: u32 = if s.len() == 12 {
        s[10..12].parse().ok()?
    } else {
        0
    };
    civil_to_unix(year, mo, dy, hr, mn, sc)
}

/// Parse ASN.1 GeneralizedTime (`YYYYMMDDHHMMSSZ`) to Unix seconds.
fn parse_generalizedtime(s: &str) -> Option<u64> {
    let s = s.trim_end_matches('Z');
    if s.len() < 14 {
        return None;
    }
    let year: u32 = s[0..4].parse().ok()?;
    let mo: u32 = s[4..6].parse().ok()?;
    let dy: u32 = s[6..8].parse().ok()?;
    let hr: u32 = s[8..10].parse().ok()?;
    let mn: u32 = s[10..12].parse().ok()?;
    let sc: u32 = s[12..14].parse().ok()?;
    civil_to_unix(year, mo, dy, hr, mn, sc)
}

/// Convert a civil UTC date/time to Unix seconds. Uses Hinnant's
/// algorithm (no chrono dependency required, no leap-second support
/// — sufficient for build-attribution comparison).
fn civil_to_unix(year: u32, month: u32, day: u32, hour: u32, min: u32, sec: u32) -> Option<u64> {
    if !(1970..=2200).contains(&year)
        || !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || hour >= 24
        || min >= 60
        || sec >= 62
    {
        return None;
    }
    let y = if month <= 2 { year - 1 } else { year };
    let era = y / 400;
    let yoe = y - era * 400;
    let doy = (153 * if month > 2 { month - 3 } else { month + 9 } + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = (era as i64) * 146097 + (doe as i64) - 719468;
    let seconds = days * 86400 + i64::from(hour) * 3600 + i64::from(min) * 60 + i64::from(sec);
    if seconds < 0 {
        None
    } else {
        Some(seconds as u64)
    }
}

/// Parse superblob structure and extract individual blobs
fn parse_superblob(data: &[u8]) -> Result<HashMap<u32, Vec<u8>>> {
    if data.len() < 8 {
        return Err(anyhow!("Superblob too small"));
    }

    let magic = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
    if magic != SUPERBLOB_MAGIC {
        return Err(anyhow!("Invalid superblob magic: 0x{:x}", magic));
    }

    let _total_length = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
    let count = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);

    if data.len() < (12 + count as usize * 8) {
        return Err(anyhow!("Superblob index out of bounds"));
    }

    let mut blobs = HashMap::new();

    for i in 0..count as usize {
        let idx_offset = 12 + i * 8;
        let _blob_slot = u32::from_be_bytes([
            data[idx_offset],
            data[idx_offset + 1],
            data[idx_offset + 2],
            data[idx_offset + 3],
        ]);
        let blob_offset = u32::from_be_bytes([
            data[idx_offset + 4],
            data[idx_offset + 5],
            data[idx_offset + 6],
            data[idx_offset + 7],
        ]) as usize;

        if blob_offset + 8 > data.len() {
            continue;
        }

        // Read actual blob magic (not the slot index!)
        let blob_magic = u32::from_be_bytes([
            data[blob_offset],
            data[blob_offset + 1],
            data[blob_offset + 2],
            data[blob_offset + 3],
        ]);
        let blob_size = u32::from_be_bytes([
            data[blob_offset + 4],
            data[blob_offset + 5],
            data[blob_offset + 6],
            data[blob_offset + 7],
        ]) as usize;

        if blob_offset + blob_size > data.len() {
            continue;
        }

        // Store blob data (skip 8-byte header)
        let blob_data = &data[blob_offset + 8..blob_offset + blob_size];
        blobs.insert(blob_magic, blob_data.to_vec());
    }

    Ok(blobs)
}

/// Parse entitlements blob (XML plist format)
/// Note: blob header (magic + size) has already been skipped by caller
fn parse_entitlements_blob(data: &[u8]) -> Result<HashMap<String, EntitlementValue>> {
    if data.is_empty() {
        return Err(anyhow!("Entitlements blob empty"));
    }

    // Data has already had the 8-byte blob header (magic + size) removed by caller
    let plist_data = data;

    // Parse as XML plist
    let plist_str = match std::str::from_utf8(plist_data) {
        Ok(s) => s,
        Err(e) => {
            tracing::debug!("Failed to convert plist to UTF-8: {}", e);
            return Err(anyhow!("Failed to convert plist to UTF-8: {}", e));
        }
    };

    // roxmltree doesn't support DTDs, so strip the DOCTYPE declaration
    let plist_str_no_dtd = if let Some(plist_start) = plist_str.find("<plist") {
        plist_str[plist_start..].to_string()
    } else {
        plist_str.to_string()
    };

    let doc = match Document::parse(&plist_str_no_dtd) {
        Ok(d) => d,
        Err(e) => {
            tracing::debug!("Failed to parse plist XML: {}", e);
            return Err(anyhow!("Failed to parse plist XML: {}", e));
        }
    };
    let mut entitlements = HashMap::new();

    // Navigate plist structure: plist -> dict -> key/value pairs
    let root_elem = doc.root();

    if let Some(first_elem) = root_elem.first_element_child() {
        // If it's a plist element, get its dict child; otherwise use it directly
        let dict_elem = if first_elem.tag_name().name() == "plist" {
            first_elem.first_element_child()
        } else {
            Some(first_elem)
        };

        if let Some(root) = dict_elem {
            if root.tag_name().name() == "dict" {
                let mut current_key: Option<String> = None;

                for child in root.children() {
                    if !child.is_element() {
                        continue;
                    }

                    match child.tag_name().name() {
                        "key" => {
                            current_key = child.text().map(std::string::ToString::to_string);
                        }
                        "true" => {
                            if let Some(key) = current_key.take() {
                                entitlements.insert(key, EntitlementValue::Boolean(true));
                            }
                        }
                        "false" => {
                            if let Some(key) = current_key.take() {
                                entitlements.insert(key, EntitlementValue::Boolean(false));
                            }
                        }
                        "string" => {
                            if let Some(key) = current_key.take() {
                                if let Some(text) = child.text() {
                                    entitlements
                                        .insert(key, EntitlementValue::String(text.to_string()));
                                }
                            }
                        }
                        "array" => {
                            if let Some(key) = current_key.take() {
                                let mut array_values = Vec::new();
                                for array_child in child.children() {
                                    if array_child.is_element()
                                        && array_child.tag_name().name() == "string"
                                    {
                                        if let Some(text) = array_child.text() {
                                            array_values.push(text.to_string());
                                        }
                                    }
                                }
                                entitlements.insert(key, EntitlementValue::Array(array_values));
                            }
                        }
                        _ => {}
                    }
                }
            } else {
                tracing::debug!("First element is not dict: {}", root.tag_name().name());
            }
        } else {
            tracing::debug!("No dict element found in plist");
        }
    } else {
        tracing::debug!("No root element found");
    }

    tracing::debug!(
        "parse_entitlements_blob: extracted {} entitlements",
        entitlements.len()
    );
    Ok(entitlements)
}

/// Extract team ID and signature type from CMS blob
fn extract_certificate_info(cms_data: &[u8]) -> (Option<String>, SignatureType, Vec<String>) {
    let mut team_id = None;
    let mut authorities = Vec::new();
    let mut signature_type = SignatureType::Unknown;

    // Look for DER-encoded patterns in certificate
    // This is a simplified approach - full PKCS#7 parsing would be complex

    // Find all CN and OU values, then pick the one that looks like the leaf cert
    let mut all_cns = Vec::new();
    let mut all_ous = Vec::new();

    // Extract all OU fields
    for i in 0..cms_data.len().saturating_sub(5) {
        if cms_data[i..i + 3] == [0x55, 0x04, 0x0B] {
            if let Some(ou) = extract_der_string(&cms_data[i..], &[0x55, 0x04, 0x0B]) {
                all_ous.push(ou);
            }
        }
    }

    // Extract all CN fields
    for i in 0..cms_data.len().saturating_sub(5) {
        if cms_data[i..i + 3] == [0x55, 0x04, 0x03] {
            if let Some(cn) = extract_der_string(&cms_data[i..], &[0x55, 0x04, 0x03]) {
                all_cns.push(cn);
            }
        }
    }

    // Pick the CN that has "Developer ID" or "Mac Developer" (leaf cert, not intermediate)
    for cn in &all_cns {
        if cn.contains("Developer ID Application: ")
            || cn.contains("Developer ID Installer: ")
            || cn.contains("Mac Developer: ")
            || cn.contains("iPhone Developer: ")
            || cn.contains("3rd Party Mac Developer: ")
        {
            let cn_trimmed = cn.trim().to_string();
            authorities.push(cn_trimmed.clone());

            // Determine signature type from CN
            if cn.contains("Developer ID Application") || cn.contains("Developer ID Installer") {
                signature_type = SignatureType::DeveloperID;
            } else if cn.contains("Mac Developer")
                || cn.contains("iPhone Developer")
                || cn.contains("3rd Party Mac Developer")
            {
                signature_type = SignatureType::Platform;
            }
            break;
        }
    }

    // Pick the OU that looks like a team ID (alphanumeric, 10-11 chars)
    for ou in &all_ous {
        let ou_trimmed = ou.trim();
        // Team IDs are typically 10 alphanumeric characters
        if ou_trimmed.len() >= 8
            && ou_trimmed.len() <= 12
            && ou_trimmed.chars().all(|c| c.is_ascii_alphanumeric())
        {
            team_id = Some(ou_trimmed.to_string());
            break;
        }
    }

    // If no developer/platform cert found, check if we have Apple Root CA or other CAs
    if matches!(signature_type, SignatureType::Unknown) {
        // Check if any CN has "Apple" in it
        for cn in &all_cns {
            if cn.contains("Apple") && (cn.contains("Root") || cn.contains("Code")) {
                signature_type = SignatureType::Platform;
                if authorities.is_empty() {
                    authorities.push(cn.trim().to_string());
                }
                break;
            }
        }
    }

    // If still no signature type and no team ID, assume adhoc
    if matches!(signature_type, SignatureType::Unknown) && team_id.is_none() {
        signature_type = SignatureType::Adhoc;
    }

    (team_id, signature_type, authorities)
}

/// Extract DER-encoded string from certificate data
/// After OID tag, there's a string type byte (0x0C UTF8String, 0x13 PrintableString, etc),
/// then length, then data
fn extract_der_string(data: &[u8], tag: &[u8]) -> Option<String> {
    for i in 0..data.len().saturating_sub(tag.len() + 2) {
        if &data[i..i + tag.len()] == tag {
            // Found OID tag, next byte should be string type (0x0C, 0x13, 0x16, etc)
            let type_pos = i + tag.len();
            if type_pos >= data.len() {
                continue;
            }

            let string_type = data[type_pos];
            // Valid ASN.1 string types
            if ![0x0C, 0x13, 0x16, 0x1A, 0x1B, 0x1C].contains(&string_type) {
                continue;
            }

            let len_pos = type_pos + 1;
            if len_pos >= data.len() {
                continue;
            }

            let length = data[len_pos] as usize;
            let str_pos = len_pos + 1;

            if str_pos + length > data.len() {
                continue;
            }

            // Try to parse as UTF-8 string
            if let Ok(s) = std::str::from_utf8(&data[str_pos..str_pos + length]) {
                // Verify it looks like a valid string (printable ASCII mostly)
                if s.chars()
                    .all(|c| c.is_ascii_graphic() || c.is_ascii_whitespace())
                {
                    return Some(s.to_string());
                }
            }
        }
    }
    None
}

/// Check for hardened runtime flag in code directory.
///
/// CodeDirectory layout (blob header already skipped):
///   offset 0: version (4), offset 4: flags (4), offset 8: hashOffset (4), ...
fn check_hardened_runtime_flag(cd_data: &[u8]) -> bool {
    if cd_data.len() < 8 {
        return false;
    }

    // Flags field is at offset 4 (after version)
    // CS_RUNTIME (hardened runtime) = 0x00010000
    let flags = u32::from_be_bytes([cd_data[4], cd_data[5], cd_data[6], cd_data[7]]);
    (flags & 0x00010000) != 0
}

/// Locate the Requirements blob inside the SuperBlob and return
/// `(SHA-256 of full blob, slot count)`. Returns `(None, 0)` when no
/// Requirements blob is present (common for adhoc-signed binaries).
///
/// The Requirements blob is itself a small SuperBlob: u32 magic
/// (0xfade0c01), u32 length, u32 count, then count×(u32 slot_index,
/// u32 offset). Each offset points to a Requirement blob (magic
/// 0xfade0c00) carrying the compiled requirement bytecode.
fn compute_requirements_summary(cs_data: &[u8]) -> (Option<String>, u32) {
    use sha2::{Digest, Sha256};

    if cs_data.len() < 12 {
        return (None, 0);
    }
    let magic = u32::from_be_bytes([cs_data[0], cs_data[1], cs_data[2], cs_data[3]]);
    if magic != SUPERBLOB_MAGIC {
        return (None, 0);
    }
    let count = u32::from_be_bytes([cs_data[8], cs_data[9], cs_data[10], cs_data[11]]) as usize;
    if cs_data.len() < 12 + count * 8 {
        return (None, 0);
    }

    for i in 0..count {
        let idx_off = 12 + i * 8;
        let blob_off = u32::from_be_bytes([
            cs_data[idx_off + 4],
            cs_data[idx_off + 5],
            cs_data[idx_off + 6],
            cs_data[idx_off + 7],
        ]) as usize;
        if blob_off + 12 > cs_data.len() {
            continue;
        }
        let blob_magic = u32::from_be_bytes([
            cs_data[blob_off],
            cs_data[blob_off + 1],
            cs_data[blob_off + 2],
            cs_data[blob_off + 3],
        ]);
        if blob_magic != REQUIREMENTS_MAGIC {
            continue;
        }
        let blob_size = u32::from_be_bytes([
            cs_data[blob_off + 4],
            cs_data[blob_off + 5],
            cs_data[blob_off + 6],
            cs_data[blob_off + 7],
        ]) as usize;
        if blob_off + blob_size > cs_data.len() || blob_size < 12 {
            continue;
        }
        let inner_count = u32::from_be_bytes([
            cs_data[blob_off + 8],
            cs_data[blob_off + 9],
            cs_data[blob_off + 10],
            cs_data[blob_off + 11],
        ]);
        let mut hasher = Sha256::new();
        hasher.update(&cs_data[blob_off..blob_off + blob_size]);
        return (Some(hex::encode(hasher.finalize())), inner_count);
    }
    (None, 0)
}

/// Locate the CodeDirectory blob inside a SuperBlob and SHA-256 the
/// *full* blob (including its 8-byte magic+length header).  This is
/// the value Apple's `codesign -d --cdhashes` prints under "CDHash"
/// when the binary uses SHA-256 hashing (the modern default).
///
/// Returns `None` if the SuperBlob is malformed or no CodeDirectory
/// is present. Lenient — bails on bounds errors rather than
/// propagating them.
fn compute_cdhash_sha256(cs_data: &[u8]) -> Option<String> {
    use sha2::{Digest, Sha256};

    if cs_data.len() < 12 {
        return None;
    }
    let magic = u32::from_be_bytes([cs_data[0], cs_data[1], cs_data[2], cs_data[3]]);
    if magic != SUPERBLOB_MAGIC {
        return None;
    }
    let count = u32::from_be_bytes([cs_data[8], cs_data[9], cs_data[10], cs_data[11]]) as usize;
    if cs_data.len() < 12 + count * 8 {
        return None;
    }
    for i in 0..count {
        let idx_off = 12 + i * 8;
        let blob_off = u32::from_be_bytes([
            cs_data[idx_off + 4],
            cs_data[idx_off + 5],
            cs_data[idx_off + 6],
            cs_data[idx_off + 7],
        ]) as usize;
        if blob_off + 8 > cs_data.len() {
            continue;
        }
        let blob_magic = u32::from_be_bytes([
            cs_data[blob_off],
            cs_data[blob_off + 1],
            cs_data[blob_off + 2],
            cs_data[blob_off + 3],
        ]);
        if blob_magic != CODE_DIRECTORY_MAGIC {
            continue;
        }
        let blob_size = u32::from_be_bytes([
            cs_data[blob_off + 4],
            cs_data[blob_off + 5],
            cs_data[blob_off + 6],
            cs_data[blob_off + 7],
        ]) as usize;
        if blob_off + blob_size > cs_data.len() || blob_size < 8 {
            continue;
        }
        let mut hasher = Sha256::new();
        hasher.update(&cs_data[blob_off..blob_off + blob_size]);
        return Some(hex::encode(hasher.finalize()));
    }
    None
}

/// Extract identifier string from code directory.
///
/// CodeDirectory layout (blob header already stripped by `parse_superblob`):
///   offset 0: version (4), offset 4: flags (4), offset 8: hashOffset (4),
///   offset 12: identOffset (4)
///
/// `identOffset` is **blob-relative** (measured from the magic field, i.e.
/// before the 8-byte header `parse_superblob` strips), so we subtract 8 to
/// get the offset into `cd_data`. Without this, we read 8 bytes past the
/// real start of the identifier string — which truncated `com.apple.ls` to
/// `e.ls`, etc.
fn extract_identifier(cd_data: &[u8]) -> Option<String> {
    if cd_data.len() < 16 {
        return None;
    }

    let blob_relative_offset =
        u32::from_be_bytes([cd_data[12], cd_data[13], cd_data[14], cd_data[15]]) as usize;
    let ident_offset = blob_relative_offset.checked_sub(8)?;

    if ident_offset >= cd_data.len() {
        return None;
    }

    let ident_data = &cd_data[ident_offset..];
    let len = ident_data
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(ident_data.len());
    if len == 0 {
        return None;
    }

    std::str::from_utf8(&ident_data[..len])
        .ok()
        .map(String::from)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn test_signature_type_str() {
        assert_eq!(SignatureType::Adhoc.as_str(), "adhoc");
        assert_eq!(SignatureType::DeveloperID.as_str(), "developer-id");
        assert_eq!(SignatureType::Platform.as_str(), "platform");
        assert_eq!(SignatureType::Unknown.as_str(), "unknown");
    }

    #[test]
    fn test_entitlement_value_types() {
        let bool_ent = EntitlementValue::Boolean(true);
        match bool_ent {
            EntitlementValue::Boolean(b) => assert!(b),
            _ => panic!("Expected boolean"),
        }

        let str_ent = EntitlementValue::String("test".to_string());
        match str_ent {
            EntitlementValue::String(s) => assert_eq!(s, "test"),
            _ => panic!("Expected string"),
        }

        let arr_ent = EntitlementValue::Array(vec!["a".to_string(), "b".to_string()]);
        match arr_ent {
            EntitlementValue::Array(a) => assert_eq!(a.len(), 2),
            _ => panic!("Expected array"),
        }
    }

    #[test]
    fn test_parse_superblob_invalid_magic() {
        let data = vec![0xBA, 0xD0, 0xBA, 0xD0, 0x00, 0x00, 0x00, 0x10];
        let result = parse_superblob(&data);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Invalid superblob magic"));
    }

    #[test]
    fn test_parse_superblob_too_small() {
        let data = vec![0xFA, 0xDE, 0x0C];
        let result = parse_superblob(&data);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_empty_entitlements_blob() {
        let data = vec![];
        let result = parse_entitlements_blob(&data);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_entitlements_blob_simple_boolean() {
        // Minimal valid plist with one boolean entitlement
        let plist = r#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0">
<dict>
    <key>com.apple.security.debugger</key>
    <true/>
</dict>
</plist>"#;

        let result = parse_entitlements_blob(plist.as_bytes());
        assert!(result.is_ok());
        let ents = result.unwrap();
        assert_eq!(ents.len(), 1);
        assert!(ents.contains_key("com.apple.security.debugger"));
        if let Some(EntitlementValue::Boolean(b)) = ents.get("com.apple.security.debugger") {
            assert!(*b);
        } else {
            panic!("Expected boolean entitlement");
        }
    }

    #[test]
    fn test_parse_entitlements_blob_string_value() {
        let plist = r#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0">
<dict>
    <key>com.apple.developer.team-identifier</key>
    <string>ABCD1234EF</string>
</dict>
</plist>"#;

        let result = parse_entitlements_blob(plist.as_bytes());
        assert!(result.is_ok());
        let ents = result.unwrap();
        assert_eq!(ents.len(), 1);
        if let Some(EntitlementValue::String(s)) = ents.get("com.apple.developer.team-identifier") {
            assert_eq!(s, "ABCD1234EF");
        } else {
            panic!("Expected string entitlement");
        }
    }

    #[test]
    fn test_parse_entitlements_blob_array_value() {
        let plist = r#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0">
<dict>
    <key>com.apple.developer.icloud-container-identifiers</key>
    <array>
        <string>iCloud.com.example.app</string>
        <string>iCloud.com.example.shared</string>
    </array>
</dict>
</plist>"#;

        let result = parse_entitlements_blob(plist.as_bytes());
        assert!(result.is_ok());
        let ents = result.unwrap();
        if let Some(EntitlementValue::Array(arr)) =
            ents.get("com.apple.developer.icloud-container-identifiers")
        {
            assert_eq!(arr.len(), 2);
            assert!(arr.contains(&"iCloud.com.example.app".to_string()));
            assert!(arr.contains(&"iCloud.com.example.shared".to_string()));
        } else {
            panic!("Expected array entitlement");
        }
    }

    #[test]
    fn test_parse_entitlements_blob_mixed_types() {
        let plist = r#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0">
<dict>
    <key>com.apple.security.debugger</key>
    <true/>
    <key>com.apple.developer.team-identifier</key>
    <string>ABCD1234EF</string>
    <key>com.apple.developer.icloud-container-identifiers</key>
    <array>
        <string>iCloud.com.example</string>
    </array>
    <key>com.apple.security.allow-unsigned-executable-memory</key>
    <false/>
</dict>
</plist>"#;

        let result = parse_entitlements_blob(plist.as_bytes());
        assert!(result.is_ok());
        let ents = result.unwrap();
        assert_eq!(ents.len(), 4);
        assert!(ents.contains_key("com.apple.security.debugger"));
        assert!(ents.contains_key("com.apple.developer.team-identifier"));
        assert!(ents.contains_key("com.apple.developer.icloud-container-identifiers"));
        assert!(ents.contains_key("com.apple.security.allow-unsigned-executable-memory"));
    }

    #[test]
    fn test_parse_entitlements_blob_with_doctype() {
        let plist = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>com.apple.security.debugger</key>
    <true/>
</dict>
</plist>"#;

        let result = parse_entitlements_blob(plist.as_bytes());
        assert!(result.is_ok());
        let ents = result.unwrap();
        assert_eq!(ents.len(), 1);
    }

    #[test]
    fn test_check_hardened_runtime_flag_set() {
        let mut cd_data = vec![0u8; 40];
        // Flags field at offset 4 (after version), CS_RUNTIME = 0x00010000
        cd_data[4] = 0x00;
        cd_data[5] = 0x01;
        cd_data[6] = 0x00;
        cd_data[7] = 0x00;

        assert!(check_hardened_runtime_flag(&cd_data));
    }

    #[test]
    fn test_check_hardened_runtime_flag_not_set() {
        let cd_data = vec![0u8; 8];
        assert!(!check_hardened_runtime_flag(&cd_data));
    }

    #[test]
    fn test_check_hardened_runtime_flag_too_small() {
        let cd_data = vec![0u8; 7];
        assert!(!check_hardened_runtime_flag(&cd_data));
    }

    #[test]
    fn test_extract_der_string_utf8() {
        // Simplified test: OU tag followed by UTF8String type and length
        let mut data = vec![0x00; 100];
        let tag_pos = 10;
        data[tag_pos] = 0x55; // OID class
        data[tag_pos + 1] = 0x04; // OID number
        data[tag_pos + 2] = 0x0B; // OID sub (OU)
        data[tag_pos + 3] = 0x0C; // UTF8String type
        data[tag_pos + 4] = 5; // Length
        let test_string = b"ABCD1";
        data[tag_pos + 5..tag_pos + 10].copy_from_slice(test_string);

        let result = extract_der_string(&data, &[0x55, 0x04, 0x0B]);
        assert!(result.is_some());
        assert_eq!(result.unwrap(), "ABCD1");
    }

    #[test]
    fn test_extract_der_string_invalid_type() {
        let mut data = vec![0x00; 100];
        let tag_pos = 10;
        data[tag_pos] = 0x55;
        data[tag_pos + 1] = 0x04;
        data[tag_pos + 2] = 0x0B;
        data[tag_pos + 3] = 0xFF; // Invalid string type
        data[tag_pos + 4] = 5;

        let result = extract_der_string(&data, &[0x55, 0x04, 0x0B]);
        assert!(result.is_none());
    }

    #[test]
    fn test_extract_der_string_not_found() {
        let data = vec![0x00; 100];
        let result = extract_der_string(&data, &[0x55, 0x04, 0x0B]);
        assert!(result.is_none());
    }

    #[test]
    fn test_extract_identifier_valid() {
        // identOffset is blob-relative (counts the 8-byte blob header
        // that parse_superblob already stripped), so a string at
        // body-offset 50 is identOffset=58 on the wire.
        let mut cd_data = vec![0u8; 100];
        cd_data[12..16].copy_from_slice(&58u32.to_be_bytes());

        let identifier = b"com.example.app";
        cd_data[50..50 + identifier.len()].copy_from_slice(identifier);
        cd_data[50 + identifier.len()] = 0;

        let result = extract_identifier(&cd_data);
        assert_eq!(result.as_deref(), Some("com.example.app"));
    }

    #[test]
    fn test_extract_identifier_handles_apple_short_id() {
        // Regression: `com.apple.ls` was getting truncated to `e.ls`
        // because identOffset (blob-relative) was used as a body
        // offset directly.  Place the string at body-offset 36
        // (identOffset=44 on the wire) and verify the full string
        // round-trips.
        let mut cd_data = vec![0u8; 64];
        cd_data[12..16].copy_from_slice(&44u32.to_be_bytes());
        let identifier = b"com.apple.ls";
        cd_data[36..36 + identifier.len()].copy_from_slice(identifier);
        cd_data[36 + identifier.len()] = 0;

        assert_eq!(
            extract_identifier(&cd_data).as_deref(),
            Some("com.apple.ls")
        );
    }

    #[test]
    fn test_extract_identifier_too_small() {
        let cd_data = vec![0u8; 10];
        let result = extract_identifier(&cd_data);
        assert!(result.is_none());
    }

    #[test]
    fn test_extract_identifier_offset_out_of_bounds() {
        let mut cd_data = vec![0u8; 50];
        // Blob-relative offset 200 → body-relative 192, beyond data.
        cd_data[12..16].copy_from_slice(&200u32.to_be_bytes());

        let result = extract_identifier(&cd_data);
        assert!(result.is_none());
    }

    #[test]
    fn test_extract_identifier_offset_below_header() {
        // A blob-relative offset < 8 would point inside the (stripped)
        // header — return None rather than wrap-around.
        let mut cd_data = vec![0u8; 50];
        cd_data[12..16].copy_from_slice(&4u32.to_be_bytes());
        assert!(extract_identifier(&cd_data).is_none());
    }

    #[test]
    fn test_code_signature_with_entitlements() {
        // Test by parsing actual entitlements blob
        let plist = r#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0">
<dict>
    <key>com.apple.security.debugger</key>
    <true/>
    <key>com.apple.developer.team-identifier</key>
    <string>ABCD1234EF</string>
</dict>
</plist>"#;

        let result = parse_entitlements_blob(plist.as_bytes());
        assert!(result.is_ok());

        let ents = result.unwrap();
        assert_eq!(ents.len(), 2);
        assert!(ents.contains_key("com.apple.security.debugger"));
        assert!(ents.contains_key("com.apple.developer.team-identifier"));
    }

    #[test]
    fn test_extract_certificate_info_developer_id() {
        // Create synthetic DER data with Developer ID certificate
        let mut cms_data = vec![0u8; 500];

        // Insert CN: "Developer ID Application: Example Corp (ABCD1234EF)"
        let cn_oid = &[0x55, 0x04, 0x03];
        let cn_str = b"Developer ID Application: Example Corp (ABCD1234EF)";
        let cn_pos = 100;
        cms_data[cn_pos..cn_pos + 3].copy_from_slice(cn_oid);
        cms_data[cn_pos + 3] = 0x0C; // UTF8String
        cms_data[cn_pos + 4] = cn_str.len() as u8;
        cms_data[cn_pos + 5..cn_pos + 5 + cn_str.len()].copy_from_slice(cn_str);

        // Insert OU: "ABCD1234EF" (team ID)
        let ou_oid = &[0x55, 0x04, 0x0B];
        let ou_str = b"ABCD1234EF";
        let ou_pos = 200;
        cms_data[ou_pos..ou_pos + 3].copy_from_slice(ou_oid);
        cms_data[ou_pos + 3] = 0x0C; // UTF8String
        cms_data[ou_pos + 4] = ou_str.len() as u8;
        cms_data[ou_pos + 5..ou_pos + 5 + ou_str.len()].copy_from_slice(ou_str);

        let (team_id, sig_type, authorities) = extract_certificate_info(&cms_data);

        assert_eq!(team_id, Some("ABCD1234EF".to_string()));
        assert!(matches!(sig_type, SignatureType::DeveloperID));
        assert!(!authorities.is_empty());
    }

    #[test]
    fn test_extract_certificate_info_adhoc() {
        // Empty CMS data results in adhoc signature
        let cms_data = vec![0u8; 100];
        let (team_id, sig_type, _) = extract_certificate_info(&cms_data);

        assert_eq!(team_id, None);
        assert!(matches!(sig_type, SignatureType::Adhoc));
    }

    #[test]
    fn test_extract_certificate_info_platform() {
        let mut cms_data = vec![0u8; 500];

        // Insert CN: "Mac Developer: Example (XYZ9876543)"
        let cn_oid = &[0x55, 0x04, 0x03];
        let cn_str = b"Mac Developer: Example (XYZ9876543)";
        let cn_pos = 100;
        cms_data[cn_pos..cn_pos + 3].copy_from_slice(cn_oid);
        cms_data[cn_pos + 3] = 0x0C;
        cms_data[cn_pos + 4] = cn_str.len() as u8;
        cms_data[cn_pos + 5..cn_pos + 5 + cn_str.len()].copy_from_slice(cn_str);

        let (_, sig_type, _) = extract_certificate_info(&cms_data);
        assert!(matches!(sig_type, SignatureType::Platform));
    }
}
