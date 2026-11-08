//! Code-signature findings: the signer and the identity it vouches for.
//! Entitlements are traits over `macho.code_signature.entitlements`.

use super::AnalysisReport;

pub(super) fn emit_signature_findings(
    report: &mut AnalysisReport,
    sig_offset: u64,
    identifier_offset: Option<u64>,
    identity: &filefacts::Identity,
    failure: Option<crate::analyzers::signature::Failure>,
    issuer: Option<&str>,
) {
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
}
