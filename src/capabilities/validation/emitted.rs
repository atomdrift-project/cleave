//! Trait ids the analyzers synthesize at runtime rather than load from YAML.
//!
//! These never appear among the static trait ids, so reference validation
//! used to wave through every id under their namespaces by prefix. That hid
//! refs the engine can never emit: PE Authenticode stopped emitting
//! `metadata/signed/developer::<cn>` and `platform::<cn>` in 2026-05, and
//! ~150 YAML refs to those ids kept validating while matching nothing, or a
//! leg spelled `platform::authenticode-signed` that never existed. Each
//! namespace below is checked against what its emitter can actually produce;
//! the shared pieces (signer normalization, category and name sets) are the
//! emitters' own functions and constants, so the two cannot drift apart.

use crate::analyzers::embedded_code_detector::{EMBEDDED_LANG_NAMES, ENCODED_LAYER_NAMES};
use crate::analyzers::macho::{ENTITLEMENT_CATEGORIES, entitlement_category};
use crate::analyzers::pe::normalize_signer_name;

/// Exact ids emitted by the Mach-O and ELF analyzers.
const EXACT_IDS: &[&str] = &[
    "metadata/binary/linking::macho-install-name",
    "metadata/binary/linking::macho-dylib",
    "metadata/binary/linking::macho-rpath",
    "metadata/build/debug::elf-debuglink",
    "metadata/signed/integrity::macho-code-directory-invalid",
];

/// `metadata/signed/<category>::<leaf>` categories the analyzers emit.
/// `macho.rs` `emit_signature_findings`: developer (team id), platform
/// (`apple`), self-signed (signer org), unknown (`unknown`), id (bundle id);
/// `pe.rs`: unknown and leaf (normalized signer name).
const SIGNED_CATEGORIES: &[&str] = &[
    "developer",
    "platform",
    "self-signed",
    "unknown",
    "leaf",
    "id",
];

/// Validate a reference into a runtime-synthesized namespace.
///
/// `None`: not an engine-emitted namespace (or a shape the engine never
/// emits there), so the caller's static-id check decides. `Some(Ok)`: an id
/// or directory the engine can emit. `Some(Err(why))`: the namespace is the
/// engine's but this spelling can never be produced.
pub(crate) fn check_emitted_ref(id: &str) -> Option<Result<(), String>> {
    if id.starts_with("metadata/import/") {
        return crate::capabilities::mapper::imports::is_dynamic_import_ref(id).then_some(Ok(()));
    }
    if EXACT_IDS.contains(&id) {
        return Some(Ok(()));
    }
    let (path, leaf) = match id.split_once("::") {
        Some((path, leaf)) => (path, Some(leaf)),
        None => (id.trim_end_matches('/'), None),
    };
    match (path, leaf) {
        ("metadata/signed" | "metadata/entitlement" | "metadata/lang/embedded", None) => {
            Some(Ok(()))
        }
        ("metadata/lang/embedded", Some(lang)) => Some(if EMBEDDED_LANG_NAMES.contains(&lang) {
            Ok(())
        } else {
            Err(format!(
                "embedded languages are {}",
                EMBEDDED_LANG_NAMES.join(", ")
            ))
        }),
        _ => {
            if let Some(encoding) = path.strip_prefix("metadata/lang/encoded/") {
                // `metadata/lang/encoded/<encoding>` is itself the emitted id;
                // `<encoding>/…` subdirectories and `::` leaves are YAML.
                return (leaf.is_none() && ENCODED_LAYER_NAMES.contains(&encoding))
                    .then_some(Ok(()));
            }
            if let Some(category) = path.strip_prefix("metadata/signed/") {
                return check_signed(category, leaf);
            }
            if let Some(category) = path.strip_prefix("metadata/entitlement/") {
                return check_entitlement(category, leaf);
            }
            None
        }
    }
}

fn check_signed(category: &str, leaf: Option<&str>) -> Option<Result<(), String>> {
    if !SIGNED_CATEGORIES.contains(&category) {
        return None;
    }
    let Some(leaf) = leaf else {
        return Some(Ok(()));
    };
    let ok = match category {
        // Mach-O `developer::<team id>`: Apple team ids are ten uppercase
        // alphanumerics; `unknown` when the signature carries none.
        "developer" => {
            leaf == "unknown"
                || (leaf.len() == 10
                    && leaf
                        .bytes()
                        .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit()))
        }
        // Only Mach-O emits this category, and only for Apple platform
        // binaries. Other `platform::` ids are YAML traits, checked statically.
        "platform" => leaf == "apple",
        "unknown" | "leaf" => !leaf.is_empty() && normalize_signer_name(leaf) == leaf,
        _ => !leaf.is_empty(),
    };
    Some(if ok {
        Ok(())
    } else {
        Err(match category {
            "developer" => "the engine emits developer::<10-char Apple team id>; a PE signer is unknown::<name> or leaf::<name>".to_string(),
            "platform" => "the engine emits only platform::apple; other platform:: ids must be YAML traits".to_string(),
            _ => format!("{category}:: leaves are normalized: `{}`", normalize_signer_name(leaf)),
        })
    })
}

fn check_entitlement(category: &str, key: Option<&str>) -> Option<Result<(), String>> {
    if !ENTITLEMENT_CATEGORIES.contains(&category) {
        return None;
    }
    let Some(key) = key else {
        return Some(Ok(()));
    };
    let emitted = entitlement_category(key);
    Some(if emitted == category {
        Ok(())
    } else {
        Err(format!(
            "entitlement `{key}` is emitted under metadata/entitlement/{emitted}"
        ))
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn engine_emitted_ids_validate() {
        for id in [
            "metadata/signed/developer::ABCDE12345",
            "metadata/signed/developer::unknown",
            "metadata/signed/platform::apple",
            "metadata/signed/leaf::microsoft-corporation",
            "metadata/signed/leaf::valve-corp.",
            "metadata/signed/unknown::digicert-trusted-g4-code-signing-rsa4096-sha384-2021-ca1",
            "metadata/signed/id::com.apple.ls",
            "metadata/signed/integrity::macho-code-directory-invalid",
            "metadata/signed/developer/",
            "metadata/entitlement/security::com.apple.security.cs.debugger",
            "metadata/entitlement/security",
            "metadata/lang/embedded::shell",
            "metadata/lang/encoded/base64",
            "metadata/binary/linking::macho-rpath",
        ] {
            assert_eq!(check_emitted_ref(id), Some(Ok(())), "{id}");
        }
    }

    #[test]
    fn impossible_engine_ids_are_rejected() {
        for id in [
            // PE stopped emitting developer::<cn> / platform::<cn>.
            "metadata/signed/developer::mozilla-corporation",
            "metadata/signed/platform::authenticode-signed",
            "metadata/signed/leaf::Microsoft Corporation",
            "metadata/entitlement/network::com.apple.security.cs.debugger",
            "metadata/lang/embedded::ruby",
        ] {
            assert!(matches!(check_emitted_ref(id), Some(Err(_))), "{id}");
        }
    }

    #[test]
    fn yaml_namespaces_fall_through_to_static_validation() {
        for id in [
            "metadata/signed/trust-level::unsigned",
            "metadata/signed/certificate/identity::pe-signature-verified",
            "metadata/lang/encoded/unicode-escape::electron-js2c-marker",
            "metadata/lang/encoded/wide",
            "metadata/dylib::mscoree/dll.",
            "metadata/entitlement/bogus::com.apple.x",
        ] {
            assert_eq!(check_emitted_ref(id), None, "{id}");
        }
    }

    #[test]
    fn name_sets_cover_their_emitters() {
        use crate::analyzers::{FileType, embedded_code_detector::lang_name};
        for ft in [
            FileType::Python,
            FileType::JavaScript,
            FileType::Shell,
            FileType::Php,
            FileType::Elf,
        ] {
            assert!(EMBEDDED_LANG_NAMES.contains(&lang_name(&ft)));
        }
        for key in [
            "com.apple.security.device.camera",
            "com.apple.security.personal-information.photos-library",
            "com.apple.security.cs.allow-jit",
            "com.apple.security.network.client",
            "com.apple.security.files.user-selected.read-write",
            "keychain-access-groups",
            "com.apple.developer.icloud-services",
            "com.apple.private.tcc.allow",
            "com.apple.security.hypervisor",
            "com.apple.security.automation.apple-events",
            "com.example.unrelated",
        ] {
            assert!(
                ENTITLEMENT_CATEGORIES.contains(&entitlement_category(key)),
                "{key}"
            );
        }
    }
}
