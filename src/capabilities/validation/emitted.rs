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
use crate::analyzers::signature::{INVALID_REASONS, KINDS, STATES, normalize_name};

/// Fixed structural ids emitted by the analyzers.
const EXACT_IDS: &[&str] = &[
    crate::analyzers::embedded_code_detector::HEURISTIC_QUOTED_ORIGIN_ID,
    crate::analyzers::ci_secret_file_flow::FACT_ID,
    crate::analyzers::ci_secret_file_flow::COLLECTOR_FACT_ID,
    "objectives/anti-static/pack/upx::standard-unpack-refused",
    "metadata/binary/linking::macho-install-name",
    "metadata/binary/linking::macho-dylib",
    "metadata/binary/linking::macho-rpath",
    "metadata/build/debug::elf-debuglink",
    "metadata/signature/invalid/tampered::macho-code-directory",
];

/// Fixed ids emitted by the Chrome/WebExtension manifest analyzer.
const CHROME_EXACT_IDS: &[&str] = &[
    "metadata/permission/extension-api::external-connection-policy",
    "metadata/permission/extension-api::web-accessible-resource-entries",
    "metadata/permission/activation::persistent-background-declaration",
    "objectives/supply-chain/metadata-anomaly/update-url::external",
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
    if CHROME_EXACT_IDS.contains(&id) {
        return Some(Ok(()));
    }
    if let Some(rest) = id.strip_prefix("metadata/permission/host/") {
        return Some(check_chrome_host_ref(rest));
    }
    if let Some(rest) = id.strip_prefix("metadata/permission/extension-api/") {
        return Some(check_chrome_api_ref(rest));
    }
    if EXACT_IDS.contains(&id) {
        return Some(Ok(()));
    }
    let (path, leaf) = match id.split_once("::") {
        Some((path, leaf)) => (path, Some(leaf)),
        None => (id.trim_end_matches('/'), None),
    };
    match (path, leaf) {
        ("metadata/signed", _) => Some(Err(RETIRED_SIGNED.to_string())),
        ("metadata/signature" | "metadata/entitlement" | "metadata/lang/embedded", None) => {
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
            if path == "metadata/lang/encoding/layer" {
                return Some(match leaf {
                    Some(encoding) if ENCODED_LAYER_NAMES.contains(&encoding) => Ok(()),
                    Some(_) => Err(format!(
                        "decoded layer names are {}",
                        ENCODED_LAYER_NAMES.join(", ")
                    )),
                    None => Err("decoded layers require a named leaf".to_string()),
                });
            }
            if path.starts_with("metadata/signed/") {
                return Some(Err(RETIRED_SIGNED.to_string()));
            }
            if let Some(rest) = path.strip_prefix("metadata/signature/") {
                return check_signature(rest, leaf);
            }
            if let Some(category) = path.strip_prefix("metadata/entitlement/") {
                return check_entitlement(category, leaf);
            }
            None
        }
    }
}

fn check_chrome_host_ref(rest: &str) -> Result<(), String> {
    let Some((token, leaf)) = rest.split_once("::") else {
        return Err("Chrome host declarations use `<host>::declared`".into());
    };
    if leaf != "declared" {
        return Err("Chrome host declarations use the `declared` leaf".into());
    }
    let special = matches!(token, "all-urls" | "all-hosts" | "file-urls");
    let hostname = token.contains('.')
        && token.split('.').all(|label| {
            !label.is_empty()
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        });
    if special || hostname {
        Ok(())
    } else {
        Err(
            "Chrome host token must be a normalized dotted host or a supported wildcard token"
                .into(),
        )
    }
}

fn check_chrome_api_ref(rest: &str) -> Result<(), String> {
    let Some((token, leaf)) = rest.split_once("::") else {
        return Err("Chrome API declarations use `<permission>::declared`".into());
    };
    let kebab_token = !token.is_empty()
        && token.split('-').all(|part| {
            !part.is_empty()
                && part
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        });
    if leaf == "declared" && kebab_token {
        Ok(())
    } else {
        Err("Chrome API declarations use a normalized kebab token and the `declared` leaf".into())
    }
}

/// Why a `metadata/signed/` reference fails: the namespace said "signed"
/// whether or not the signature verified.
const RETIRED_SIGNED: &str = "metadata/signed/ is retired: signer findings live under \
     metadata/signature/<verified|self-signed|unverified|invalid/<reason>>/<kind>::<name>";

/// Check a reference under `metadata/signature/` (`rest` is the path after
/// it) against what `analyzers::signature` emits:
/// `<state>/<kind>::<normalized name>`, with `platform` and `developer` only
/// under `verified/`. `None` for any other shape, which is a YAML trait.
fn check_signature(rest: &str, leaf: Option<&str>) -> Option<Result<(), String>> {
    let (state, kind) = match rest.split_once('/') {
        Some(("invalid", rest)) => match rest.split_once('/') {
            Some((reason, kind)) => (reason, Some(kind)),
            None => (rest, None),
        },
        Some((state, kind)) => (state, Some(kind)),
        None => (rest, None),
    };
    let is_state = STATES.contains(&state) || INVALID_REASONS.contains(&state);
    let Some(kind) = kind else {
        // `<state>/` itself: a directory the engine fills.
        return (is_state && leaf.is_none()).then_some(Ok(()));
    };
    if !is_state || !KINDS.contains(&kind) {
        return None;
    }
    let Some(leaf) = leaf else {
        return Some(Ok(()));
    };
    let verified_only = matches!(kind, "platform" | "developer");
    Some(if verified_only && state != "verified" {
        Err(format!(
            "{kind}:: is emitted only under metadata/signature/verified/"
        ))
    } else if kind == "platform" && !matches!(leaf, "apple" | "microsoft") {
        Err("the engine emits verified/platform::apple and ::microsoft only".to_string())
    } else if leaf.is_empty() || normalize_name(leaf) != leaf {
        Err(format!(
            "{kind}:: leaves are normalized: `{}`",
            normalize_name(leaf)
        ))
    } else {
        Ok(())
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
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn engine_emitted_ids_validate() {
        for id in [
            "metadata/signature/verified/platform::apple",
            "metadata/signature/verified/platform::microsoft",
            "metadata/signature/verified/developer::abcde12345",
            "metadata/signature/verified/signer::microsoft-corporation",
            "metadata/signature/self-signed/signer::adobe-inc.",
            "metadata/signature/unverified/subject::digicert-trusted-g4-code-signing-rsa4096-sha384-2021-ca1",
            "metadata/signature/unverified/id::com.apple.ls",
            "metadata/signature/invalid/tampered/signer::microsoft-corporation",
            "metadata/signature/invalid/bad-signature/signer::valve-corp.",
            "metadata/signature/invalid/tampered::macho-code-directory",
            "metadata/signature/verified/",
            "metadata/signature/unverified/signer/",
            "metadata/signature/invalid/tampered/",
            "metadata/entitlement/security::com.apple.security.cs.debugger",
            "metadata/entitlement/security",
            "metadata/lang/embedded::shell",
            "metadata/lang/encoding/layer::base64",
            "metadata/lang/encoding/layer::wide",
            "metadata/binary/linking::macho-rpath",
        ] {
            assert_eq!(check_emitted_ref(id), Some(Ok(())), "{id}");
        }
    }

    #[test]
    fn impossible_engine_ids_are_rejected() {
        for id in [
            // Proven-identity kinds exist only under verified/.
            "metadata/signature/unverified/platform::microsoft",
            "metadata/signature/self-signed/developer::abcde12345",
            "metadata/signature/verified/platform::adobe",
            "metadata/signature/verified/signer::Microsoft Corporation",
            "metadata/entitlement/network::com.apple.security.cs.debugger",
            "metadata/lang/embedded::ruby",
        ] {
            assert!(matches!(check_emitted_ref(id), Some(Err(_))), "{id}");
        }
    }

    #[test]
    fn the_retired_signed_namespace_is_rejected() {
        for id in [
            "metadata/signed/platform::apple",
            "metadata/signed/leaf::microsoft-corporation",
            "metadata/signed/platform/",
            "metadata/signed",
        ] {
            let got = check_emitted_ref(id);
            assert!(
                matches!(&got, Some(Err(why)) if why.contains("metadata/signature/")),
                "{id}: {got:?}"
            );
        }
    }

    #[test]
    fn yaml_namespaces_fall_through_to_static_validation() {
        for id in [
            "metadata/signature/absent::unsigned-pe-executable",
            "metadata/signature/invalid/pe::pe-signature-digest-mismatch",
            "metadata/signature/verified/platform/microsoft::microsoft-nt-kernel-image",
            "metadata/lang/encoding/unicode-escape::electron-js2c-marker",
            "metadata/lang/encoding/wide::shell-interpreter-powershell",
            "metadata/dylib::mscoree/dll.",
            "metadata/entitlement/bogus::com.apple.x",
        ] {
            assert_eq!(check_emitted_ref(id), None, "{id}");
        }
    }

    #[test]
    fn signer_leaves_must_be_in_normalized_form() {
        for ok in ["acme", "acme-inc.", "sectigo-rsa-time-stamping-signer-3"] {
            for kind in ["signer", "subject", "id"] {
                assert_eq!(
                    check_emitted_ref(&format!("metadata/signature/unverified/{kind}::{ok}")),
                    Some(Ok(()))
                );
            }
        }
        for bad in [
            "Acme",
            "acme inc",
            "acme,inc",
            "acme(inc)",
            "ооо-яндекс",
            "",
        ] {
            let got = check_emitted_ref(&format!("metadata/signature/verified/signer::{bad}"));
            assert!(matches!(got, Some(Err(_))), "{bad}: {got:?}");
        }
        // The reason names the spelling the engine would have produced.
        let Some(Err(why)) = check_emitted_ref("metadata/signature/verified/signer::Acme Inc")
        else {
            panic!("expected a rejection");
        };
        assert!(why.contains("acme-inc"), "{why}");
    }

    #[test]
    fn directory_refs_into_engine_namespaces() {
        for dir in [
            "metadata/signature",
            "metadata/signature/",
            "metadata/signature/verified/",
            "metadata/signature/invalid/",
            "metadata/signature/invalid/tampered/",
            "metadata/signature/unverified/signer/",
            "metadata/signature/verified/platform",
            "metadata/entitlement/",
            "metadata/entitlement/keychain/",
            "metadata/lang/embedded",
        ] {
            assert_eq!(check_emitted_ref(dir), Some(Ok(())), "{dir}");
        }
        // YAML-only directories fall through.
        assert_eq!(check_emitted_ref("metadata/signature/absent/"), None);
        assert_eq!(check_emitted_ref("metadata/signature/claim/"), None);
        assert_eq!(check_emitted_ref("metadata/entitlement/nonsense/"), None);
    }

    #[test]
    fn every_encoded_layer_name_is_an_emitted_id() {
        for name in ENCODED_LAYER_NAMES {
            assert_eq!(
                check_emitted_ref(&format!("metadata/lang/encoding/layer::{name}")),
                Some(Ok(())),
                "{name}"
            );
        }
        assert!(matches!(
            check_emitted_ref("metadata/lang/encoding/layer::rot47"),
            Some(Err(_))
        ));
        assert_eq!(check_emitted_ref("metadata/lang/encoded/base64"), None);
        assert_eq!(check_emitted_ref("metadata/lang/encoding/base64"), None);
    }

    #[test]
    fn entitlement_rejection_names_the_emitted_category() {
        let Some(Err(why)) =
            check_emitted_ref("metadata/entitlement/network::com.apple.security.cs.allow-jit")
        else {
            panic!("expected a rejection");
        };
        assert!(why.contains("metadata/entitlement/security"), "{why}");
    }

    #[test]
    fn import_ids_keep_their_own_shape_check() {
        assert_eq!(
            check_emitted_ref("metadata/import/python/json::loads"),
            Some(Ok(()))
        );
        assert_eq!(check_emitted_ref("metadata/import/python/"), Some(Ok(())));
        // Not an import ecosystem: left to static validation.
        assert_eq!(check_emitted_ref("metadata/import/klingon/x::y"), None);
    }

    #[test]
    fn exact_engine_ids_validate() {
        for id in EXACT_IDS {
            assert_eq!(check_emitted_ref(id), Some(Ok(())), "{id}");
        }
    }

    #[test]
    fn chrome_manifest_emitted_ids_validate() {
        for id in [
            "metadata/permission/host/all-urls::declared",
            "metadata/permission/host/all-hosts::declared",
            "metadata/permission/host/file-urls::declared",
            "metadata/permission/host/example.org::declared",
            "metadata/permission/host/sub.example.co.uk::declared",
            "metadata/permission/extension-api/native-messaging::declared",
            "metadata/permission/extension-api/declarative-net-request::declared",
            "metadata/permission/extension-api/identity-2::declared",
            "metadata/permission/extension-api::external-connection-policy",
            "metadata/permission/extension-api::web-accessible-resource-entries",
            "metadata/permission/activation::persistent-background-declaration",
            "objectives/supply-chain/metadata-anomaly/update-url::external",
        ] {
            assert_eq!(check_emitted_ref(id), Some(Ok(())), "{id}");
        }
    }

    #[test]
    fn chrome_manifest_dynamic_ids_reject_malformed_near_misses() {
        for id in [
            "metadata/permission/host/Example.org::declared",
            "metadata/permission/host/.example.org::declared",
            "metadata/permission/host/example..org::declared",
            "metadata/permission/host/-example.org::declared",
            "metadata/permission/host/example.org::observed",
            "metadata/permission/host/example.org/extra::declared",
            "metadata/permission/extension-api/NativeMessaging::declared",
            "metadata/permission/extension-api/native--messaging::declared",
            "metadata/permission/extension-api/native-messaging::observed",
            "metadata/permission/extension-api/native/messaging::declared",
        ] {
            assert!(matches!(check_emitted_ref(id), Some(Err(_))), "{id}");
        }
        for id in [
            "metadata/permission/extension-api::unknown-policy",
            "metadata/permission/activation::content-script-run-at-start",
            "objectives/supply-chain/metadata-anomaly/update-url::first-party",
        ] {
            assert_eq!(check_emitted_ref(id), None, "{id}");
        }
    }

    #[test]
    fn chrome_yaml_traits_fall_through_to_static_validation() {
        for id in [
            // Aggregate host profile, not a per-host declaration.
            "metadata/permission/host::broad-host-access",
            // Canonical YAML API permission, not a dynamic fallback.
            "metadata/permission/extension-api::permission-proxy",
            // YAML activation behavior remains outside Chrome's fixed IDs.
            "metadata/permission/activation::content-script-run-at-start",
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
