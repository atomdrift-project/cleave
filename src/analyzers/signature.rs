//! Signer findings, filed under how far the signature is trusted.
//!
//! The trust state is the first segment under `metadata/signature/`, so a
//! rule cannot name a signer without also naming what is proven about it:
//!
//! - `verified/`: filefacts verified the signature, it covers this file, and
//!   either its chain ends at a pinned platform root (Apple or Microsoft) or
//!   a pinned code-signing CA ([`PINNED_ISSUERS`]) signed its code-signing
//!   leaf. Only here is the signer's name a fact.
//! - `self-signed/`: the signature verifies, but nothing vouches for the
//!   certificate. Anyone can mint one in any name.
//! - `unverified/`: the signature verifies under a CA nobody pinned, or the
//!   verifier could not reach a verdict. The name is a claim.
//! - `invalid/<reason>/`: the signature's own cryptography fails
//!   (`bad-signature`), or the file changed after signing (`tampered`).
//!
//! The leaf after `::` is the claimed name, which whoever made the certificate
//! chose; [`normalize_name`] confines it to a small alphabet and length.
//! Every finding here is Notable: a signature is identity, and identity is
//! what an analyst reads first. Judging an invalid signature (Suspicious,
//! Hostile) is left to the trait rules under `metadata/signature/invalid/`,
//! which know the false-positive cases (carved images, toolchains whose
//! layout the image hash cannot reproduce).

use crate::types::{Criticality, Evidence, Finding, FindingKind};
use filefacts::{Identity, Trust};

/// The trust states, as path segments under `metadata/signature/`.
#[cfg(feature = "lint")]
pub(crate) const STATES: &[&str] = &["verified", "self-signed", "unverified", "invalid"];

/// Why an `invalid/` signature fails, as path segments under it.
#[cfg(feature = "lint")]
pub(crate) const INVALID_REASONS: &[&str] = &["bad-signature", "tampered"];

/// Leaf kinds after the state. `platform` and `developer` exist only under
/// `verified/`, where the vendor or Apple team is proven.
#[cfg(feature = "lint")]
pub(crate) const KINDS: &[&str] = &["signer", "subject", "id", "platform", "developer"];

/// Longest leaf kept from a claimed name.
const MAX_NAME_BYTES: usize = 64;

/// Code-signing CAs whose identity vetting a verified signature may rely on,
/// by SHA-256 certificate fingerprint. A chain in which one of them signed
/// the leaf makes the leaf's organization a fact, because the CA validated it
/// before issuing. filefacts proves only Microsoft's and Apple's own roots;
/// every other vendor's genuine signature is `CaSigned` and stays
/// `unverified/` unless its issuer is here.
///
/// Each entry was read from a genuine signed sample (`chain_sha256[1]`), then
/// matched against the CA certificate the CA publishes itself, which in turn
/// verifies under a root in the operating system's trust store. Pin an
/// issuing CA, never a root: a root vouches for every CA beneath it.
const PINNED_ISSUERS: &[(&str, &str)] = &[
    // Adobe's current Windows signatures (Creative Cloud Cleaner Tool, 2026).
    // Published at cacerts.digicert.com; issued by DigiCert Trusted Root G4
    // (552f7bdc…ac89988).
    (
        "46011ede1c147eb2bc731a539b7c047b7ee93e48b9d3c3ba710ce132bbdfac6b",
        "DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1",
    ),
    // Adobe's 2019-2021 signatures (Acrobat Reader DC 19.x-21.x). Published
    // at cacerts.digicert.com; issued by DigiCert High Assurance EV Root CA
    // (7431e5f4…b118cf).
    (
        "c7460b0edda1b44c8e2164b234ebecc3962a6a37a936b74a6e7d46682938f084",
        "DigiCert EV Code Signing CA (SHA2)",
    ),
    // Intel's oneAPI runtime DLLs (qkmalloc, 2025). Published at
    // crt.sectigo.com; issued by Sectigo Public Code Signing Root R46, whose
    // cross-certificate chains to USERTrust RSA Certification Authority.
    (
        "7fb0f58d71130abe724969f1cdc9b6a8d3274da18d059229b009a5b9b5557445",
        "Sectigo Public Code Signing CA R36",
    ),
];

/// The pinned CA that signed this signature's code-signing leaf, read from
/// the filefacts signature object. `chain_sha256` lists the leaf, then each
/// certificate whose key verifiably signed the one before; only its second
/// entry, the leaf's own issuer, can match a pin.
pub(crate) fn pinned_issuer(signature: &serde_json::Value) -> Option<&'static str> {
    if signature.get("eku_code_signing") != Some(&serde_json::Value::Bool(true)) {
        return None;
    }
    let issuer = signature.get("chain_sha256")?.get(1)?.as_str()?;
    PINNED_ISSUERS
        .iter()
        .find(|(pinned, _)| pinned.eq_ignore_ascii_case(issuer))
        .map(|&(_, name)| name)
}

/// How a file's signature failed, when it did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Failure {
    /// The signature's own cryptography fails.
    BadSignature,
    /// The file no longer hashes to what the signer signed.
    Tampered,
}

/// The signature path for `trust`, or `None` when there is no certificate
/// identity to report (unsigned, or ad-hoc, whose trait rules read the
/// code-signature flags directly). `issuer` is the pinned CA that signed the
/// leaf, if one did.
fn state_path(trust: Trust, failure: Option<Failure>, issuer: Option<&str>) -> Option<String> {
    let state = match (trust, failure) {
        (Trust::Unsigned | Trust::AdHoc, _) => return None,
        (_, Some(Failure::Tampered)) => "invalid/tampered",
        (_, Some(Failure::BadSignature)) => "invalid/bad-signature",
        (Trust::Platform | Trust::System | Trust::DeveloperId, None) => "verified",
        (Trust::SelfSigned, None) => "self-signed",
        (Trust::CaSigned, None) if issuer.is_some() => "verified",
        // `CaSigned` otherwise: a CA's key signed the leaf, but nothing here
        // vouches for that CA, and an attacker can mint a two-level chain.
        _ => "unverified",
    };
    Some(format!("metadata/signature/{state}"))
}

/// A claimed name as an identifier leaf: lowercased ASCII letters, digits
/// and `.`, with runs of anything else collapsed to one `-`, at most
/// [`MAX_NAME_BYTES`]. Commas, parentheses and quotes are dropped rather than
/// separated (`Postman, Inc.` is `postman-inc.`). A name that loses a
/// non-ASCII letter gains the first eight hex digits of its SHA-256, so names
/// stay distinct without letting a homoglyph (a Cyrillic `М` in `Microsoft`)
/// spell an identifier that reads like the real one. Rules reference these
/// leaves, and reference validation spells them through this same function.
pub(crate) fn normalize_name(name: &str) -> String {
    let mut out = String::with_capacity(name.len().min(MAX_NAME_BYTES));
    let mut lost_letters = false;
    for c in name.chars().flat_map(char::to_lowercase) {
        if c.is_ascii_lowercase() || c.is_ascii_digit() || c == '.' {
            out.push(c);
        } else if !matches!(c, ',' | '(' | ')' | '"' | '\'') {
            lost_letters |= c.is_alphanumeric();
            if !out.ends_with('-') {
                out.push('-');
            }
        }
    }
    let mut leaf: String = out.trim_matches('-').chars().take(MAX_NAME_BYTES).collect();
    if lost_letters {
        let digest = crate::analyzers::utils::calculate_sha256(name.as_bytes());
        leaf.truncate(MAX_NAME_BYTES - 9);
        let leaf = leaf.trim_end_matches('-');
        return if leaf.is_empty() {
            format!("x-{}", &digest[..8])
        } else {
            format!("{leaf}-{}", &digest[..8])
        };
    }
    let leaf = leaf.trim_end_matches('-');
    if leaf.is_empty() {
        "unknown".to_string()
    } else {
        leaf.to_string()
    }
}

/// The verified vendor of a platform signature: the leaf organization
/// filefacts matched exactly when it assigned `Platform`.
fn platform_vendor(identity: &Identity) -> &'static str {
    match identity
        .signer
        .as_ref()
        .and_then(|s| s.organization.as_deref())
    {
        Some("Microsoft Corporation") => "microsoft",
        _ => "apple",
    }
}

/// The signer findings for a file whose filefacts identity is `identity`.
/// `failure` is what the format's own integrity check found; `method` and
/// `location` anchor the evidence.
pub(crate) fn findings(
    identity: &Identity,
    failure: Option<Failure>,
    issuer: Option<&str>,
    method: &str,
    location: Option<&str>,
) -> Vec<Finding> {
    let Some(path) = state_path(identity.trust, failure, issuer) else {
        return Vec::new();
    };
    let signer = identity.signer.as_ref();
    let organization = signer.and_then(|s| s.organization.as_deref());
    let common_name = signer.and_then(|s| s.common_name.as_deref());
    let claimed = organization.or(common_name).unwrap_or("unknown");
    let state = path.trim_start_matches("metadata/signature/");
    let finding = |kind: &str, leaf: String, desc: String, value: String| Finding {
        precomputed_spans: None,
        src: None,
        kind: FindingKind::Capability,
        trait_refs: vec![],
        id: format!("{path}/{kind}::{leaf}").into(),
        desc: desc.into(),
        conf: 1.0,
        crit: Criticality::Notable,
        mbc: None,
        attack: None,
        evidence: vec![Evidence {
            method: method.to_string(),
            source: "filefacts".to_string(),
            value,
            location: location.map(str::to_string),
            ..Default::default()
        }],
        match_count: 1,
        source_file: None,
        downgraded: false,
    };

    let vouched = match issuer {
        Some(issuer) if state == "verified" => format!(" (issued by {issuer})"),
        _ => String::new(),
    };
    let mut out = vec![finding(
        "signer",
        normalize_name(claimed),
        format!("Signer ({state}): {claimed}{vouched}"),
        claimed.to_string(),
    )];
    if let Some(cn) = common_name
        && normalize_name(cn) != normalize_name(claimed)
    {
        out.push(finding(
            "subject",
            normalize_name(cn),
            format!("Certificate subject ({state}): {cn}"),
            cn.to_string(),
        ));
    }
    if failure.is_none() {
        match identity.trust {
            Trust::Platform | Trust::System => {
                let vendor = platform_vendor(identity);
                out.push(finding(
                    "platform",
                    vendor.to_string(),
                    format!("Verified platform signature: {vendor}"),
                    claimed.to_string(),
                ));
            }
            Trust::DeveloperId => {
                let team = identity
                    .team_id
                    .as_ref()
                    .map_or("unknown", |c| c.value.as_str());
                out.push(finding(
                    "developer",
                    normalize_name(team),
                    format!("Verified Apple Developer ID: {claimed} ({team})"),
                    team.to_string(),
                ));
            }
            _ => {}
        }
    }
    out
}

/// The bundle or executable identifier the code signature binds, filed under
/// the same trust state as its signer, or `None` when there is no signer
/// identity to file it under.
pub(crate) fn identifier_finding(
    identity: &Identity,
    failure: Option<Failure>,
    issuer: Option<&str>,
    identifier: &str,
    location: &str,
) -> Option<Finding> {
    let path = state_path(identity.trust, failure, issuer)?;
    Some(Finding {
        precomputed_spans: None,
        src: None,
        kind: FindingKind::Capability,
        trait_refs: vec![],
        id: format!("{path}/id::{}", normalize_name(identifier)).into(),
        desc: format!("Identifier: {identifier}").into(),
        conf: 1.0,
        crit: Criticality::Notable,
        mbc: None,
        attack: None,
        evidence: vec![Evidence {
            method: "code_directory".to_string(),
            source: "filefacts".to_string(),
            value: identifier.to_string(),
            location: Some(location.to_string()),
            ..Default::default()
        }],
        match_count: 1,
        source_file: None,
        downgraded: false,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    fn identity(trust: Trust, organization: &str, cn: &str) -> Identity {
        serde_json::from_value(serde_json::json!({
            "trust": trust,
            "signer": { "common_name": cn, "organization": organization, "source": "test" },
        }))
        .unwrap()
    }

    fn ids(findings: &[Finding]) -> Vec<String> {
        findings.iter().map(|f| f.id.to_string()).collect()
    }

    #[test]
    fn names_are_confined_to_a_small_alphabet() {
        assert_eq!(
            normalize_name("Microsoft Corporation"),
            "microsoft-corporation"
        );
        assert_eq!(normalize_name("Postman, Inc."), "postman-inc.");
        assert_eq!(normalize_name("Adobe Inc."), "adobe-inc.");
        assert_eq!(
            normalize_name("Tencent Technology(Shenzhen) Company Limited"),
            "tencent-technologyshenzhen-company-limited"
        );
        assert_eq!(
            normalize_name("Sectigo RSA Time Stamping Signer #3"),
            "sectigo-rsa-time-stamping-signer-3"
        );
        assert_eq!(normalize_name("a\u{1b}]52;c;x\u{7}b"), "a-52-c-x-b");
        assert_eq!(normalize_name("\u{202e}"), "unknown");
        assert_eq!(normalize_name(""), "unknown");
        assert_eq!(normalize_name(&"x".repeat(500)).len(), MAX_NAME_BYTES);
        // A homoglyph cannot pass for the real name, and non-ASCII names
        // stay distinct from each other.
        let homoglyph = normalize_name("\u{41c}icrosoft Corporation");
        assert!(
            homoglyph.starts_with("icrosoft-corporation-"),
            "{homoglyph}"
        );
        let yandex = normalize_name("ООО Яндекс");
        assert!(yandex.starts_with("x-") && yandex.len() == 10, "{yandex}");
        assert_ne!(yandex, normalize_name("ООО Ромашка"));
        // Normalized leaves are their own normal form; validation relies on it.
        for name in [
            "Microsoft Corporation",
            "Postman, Inc.",
            "ООО Яндекс",
            "\u{41c}icrosoft",
        ] {
            let leaf = normalize_name(name);
            assert_eq!(normalize_name(&leaf), leaf, "{name}");
        }
    }

    #[test]
    fn a_name_alone_never_reaches_verified() {
        // The certificate says Adobe; nothing vouches for it.
        for trust in [Trust::SelfSigned, Trust::CaSigned, Trust::Unverified] {
            let found = ids(&findings(
                &identity(trust, "Adobe Inc.", "Adobe Inc."),
                None,
                None,
                "t",
                None,
            ));
            assert!(
                found
                    .iter()
                    .all(|id| !id.starts_with("metadata/signature/verified/")),
                "{trust:?}: {found:?}"
            );
        }
        let self_signed = findings(
            &identity(Trust::SelfSigned, "Adobe Inc.", "Adobe Inc."),
            None,
            None,
            "t",
            None,
        );
        assert_eq!(
            ids(&self_signed),
            ["metadata/signature/self-signed/signer::adobe-inc."]
        );
    }

    #[test]
    fn a_failed_integrity_check_outranks_any_trust() {
        let microsoft = identity(
            Trust::Platform,
            "Microsoft Corporation",
            "Microsoft Windows",
        );
        let tampered = findings(&microsoft, Some(Failure::Tampered), None, "t", None);
        assert_eq!(
            ids(&tampered),
            [
                "metadata/signature/invalid/tampered/signer::microsoft-corporation",
                "metadata/signature/invalid/tampered/subject::microsoft-windows",
            ]
        );
        assert!(tampered.iter().all(|f| f.crit == Criticality::Notable));
    }

    #[test]
    fn verified_platform_and_developer_signatures_name_what_is_proven() {
        let microsoft = identity(
            Trust::Platform,
            "Microsoft Corporation",
            "Microsoft Windows",
        );
        assert!(
            ids(&findings(&microsoft, None, None, "t", None))
                .contains(&"metadata/signature/verified/platform::microsoft".to_string())
        );
        let mut developer = identity(
            Trust::DeveloperId,
            "Example Ltd",
            "Developer ID Application: Example Ltd (ABCDE12345)",
        );
        developer.team_id = Some(filefacts::Claim::claimed("ABCDE12345", "test"));
        assert!(
            ids(&findings(&developer, None, None, "t", None))
                .contains(&"metadata/signature/verified/developer::abcde12345".to_string())
        );
        assert!(findings(&identity(Trust::Unsigned, "x", "x"), None, None, "t", None).is_empty());
    }

    /// The signature object filefacts publishes for a genuine Adobe binary:
    /// the leaf, then the DigiCert G4 code-signing CA that signed it.
    fn adobe_signature(chain: &[&str], eku_code_signing: bool) -> serde_json::Value {
        serde_json::json!({
            "subject": "CN=Adobe Inc.,O=Adobe Inc.,C=US",
            "issuer": "CN=DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1,O=DigiCert\\, Inc.,C=US",
            "verified": true,
            "digest_matches": true,
            "eku_code_signing": eku_code_signing,
            "chain_sha256": chain,
        })
    }

    const ADOBE_LEAF: &str = "2c839993fadff6bfc5bbb02692abdf7b9305644b3794e4c68296d29f0142da24";
    const DIGICERT_G4_CS: &str = "46011ede1c147eb2bc731a539b7c047b7ee93e48b9d3c3ba710ce132bbdfac6b";

    #[test]
    fn a_pinned_issuing_ca_makes_a_ca_signed_signer_verified() {
        let signature = adobe_signature(&[ADOBE_LEAF, DIGICERT_G4_CS], true);
        let issuer = pinned_issuer(&signature);
        assert_eq!(
            issuer,
            Some("DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1")
        );
        let adobe = identity(Trust::CaSigned, "Adobe Inc.", "Adobe Inc.");
        let found = findings(&adobe, None, issuer, "t", None);
        assert_eq!(
            ids(&found),
            ["metadata/signature/verified/signer::adobe-inc."]
        );
        assert!(
            found[0].desc.contains("issued by DigiCert Trusted G4"),
            "{}",
            found[0].desc
        );
        // A pin cannot rescue a file changed after signing.
        let tampered = findings(&adobe, Some(Failure::Tampered), issuer, "t", None);
        assert_eq!(
            ids(&tampered),
            ["metadata/signature/invalid/tampered/signer::adobe-inc."]
        );
    }

    #[test]
    fn a_pin_counts_only_as_the_leaf_issuer_of_a_code_signing_leaf() {
        // Only the leaf's own issuer counts: not the leaf, not a certificate
        // further up, and not for a leaf without the code-signing EKU.
        assert_eq!(
            pinned_issuer(&adobe_signature(&[DIGICERT_G4_CS], true)),
            None
        );
        assert_eq!(
            pinned_issuer(&adobe_signature(
                &[ADOBE_LEAF, ADOBE_LEAF, DIGICERT_G4_CS],
                true
            )),
            None
        );
        assert_eq!(
            pinned_issuer(&adobe_signature(&[ADOBE_LEAF, DIGICERT_G4_CS], false)),
            None
        );
        assert_eq!(
            pinned_issuer(&adobe_signature(
                &[ADOBE_LEAF, "00".repeat(32).as_str()],
                true
            )),
            None
        );
        assert_eq!(pinned_issuer(&serde_json::json!({})), None);
        // A self-signed or unverifiable signature is not lifted by a pin.
        for trust in [Trust::SelfSigned, Trust::Unverified] {
            let found = findings(
                &identity(trust, "Adobe Inc.", "Adobe Inc."),
                None,
                Some("DigiCert Trusted G4 Code Signing RSA4096 SHA384 2021 CA1"),
                "t",
                None,
            );
            assert!(
                ids(&found)
                    .iter()
                    .all(|id| !id.starts_with("metadata/signature/verified/")),
                "{trust:?}"
            );
        }
    }
}
