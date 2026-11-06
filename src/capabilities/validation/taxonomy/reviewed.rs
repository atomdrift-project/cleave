//! Per-rule reviewed exemptions. Each is to become an `exempt:` entry on the rule it names.

// Split out of the parent module for size; it shares the parent's namespace.
#[allow(clippy::wildcard_imports)]
use super::*;

/// Named fields and resource labels are evidence of a claim, not a verified
/// identity. Like basename facts, low-tier observations do not become more
/// accurate merely because their carrier falls within a chosen size range.
pub(super) fn is_low_tier_named_binary_fact(t: &TraitDefinition) -> bool {
    if t.id.starts_with("well-known/malware/")
        || !matches!(t.crit, Criticality::Component | Criticality::Notable)
    {
        return false;
    }
    match &t.r#if {
        Condition::Kv(q) => {
            matches!(
                q.path.as_str(),
                "pe.version.company"
                    | "pe.version.product_name"
                    | "pe.version.original_filename"
                    | "pe.version.description"
                    | "pe.manifest.assembly_identity.name"
                    | "pe.manifest.description"
                    | "pe.signatures[0].subject"
                    | "pe.signatures[*].subject"
            ) && [q.exact.as_deref(), q.substr.as_deref(), q.regex.as_deref()]
                .iter()
                .any(|v| v.is_some_and(|s| !s.is_empty()))
        }
        Condition::Text(q) => {
            let resource_label = q.section.as_deref() == Some(".rsrc")
                && [q.exact.as_deref(), q.substr.as_deref(), q.regex.as_deref()]
                    .iter()
                    .any(|v| v.is_some_and(|s| !s.is_empty()));
            // Reviewed program-specific preference-name observation. Its
            // binary spelling can include accessor prefixes/suffixes and can
            // occur outside PE resources. It reports the name's presence,
            // not ownership or that the artifact is the Plex application.
            // Keep this allowance matcher- and identity-scoped; an arbitrary
            // binary signature still needs its normal relevance constraints.
            let plex_preference_name = t.id
                == "well-known/app/media/plex::plex-transcoder-h264-options-binary"
                && q.substr.as_deref() == Some("TranscoderH264Options")
                && q.exact.is_none()
                && q.regex.is_none()
                && q.word.is_none();
            // A named Schneider Electric product reference is an observed
            // string co-occurrence, not verified ownership of the binary.
            // Its meaning does not change with the containing file's size.
            let schneider_product_reference = t.id
                == "well-known/app/infrastructure/industrial-control/schneider-electric::industrial-product-reference"
                && q.regex.as_deref()
                    == Some(r"(?i)Schneider\s*Electric.{0,30}(Desal|Unity|SoMachine|EcoStruxure)")
                && q.exact.is_none()
                && q.substr.is_none()
                && q.word.is_none();
            // A Netscape name in a code section is a product reference, not
            // an identity claim about the binary that contains the text.
            let netscape_name_reference = t.id
                == "well-known/app/browser/netscape::netscape-name-text-reference"
                && q.regex.as_deref() == Some(r"(?i)(Netscape Navigator|Netscape Communicator)")
                && q.section.as_deref() == Some(".text")
                && q.exact.is_none()
                && q.substr.is_none()
                && q.word.is_none();
            // This product-specific route is a reference, not ownership of
            // the file, and is meaningful regardless of its size.
            let plex_network_route = t.id
                == "well-known/app/media/plex::plex-plugin-network-function-route"
                && q.regex.as_deref()
                    == Some(
                        r"com\.plexapp\.agents\.[\w.]+(/|%2[fF])function(/|%2[fF])GetResultFromNetwork",
                    )
                && q.exact.is_none()
                && q.substr.is_none()
                && q.word.is_none();
            // A name in read-only data is a reference to the utility, not
            // an ownership or execution claim, regardless of carrier size.
            let mshta_name_reference = t.id
                == "well-known/app/system/microsoft/mshta::mshta-exe-literal"
                && q.section.as_deref() == Some("rdata")
                && q.exact.as_deref() == Some("mshta.exe")
                && q.substr.is_none()
                && q.regex.is_none()
                && q.word.is_none();
            resource_label
                || plex_preference_name
                || plex_network_route
                || schneider_product_reference
                || netscape_name_reference
                || mshta_name_reference
        }
        _ => false,
    }
}

// These family-specific text observations have no evidence for a file-size
// range or section location. Keep the exception tied to both the ID and the
// exact matcher so that changes to either are reviewed again.
pub(super) fn is_reviewed_linfeng_marker(t: &TraitDefinition) -> bool {
    let expected = match t.id.as_str() {
        "well-known/malware/botnet/linfeng::linfeng-adb-bot-marker" => {
            (Criticality::Notable, ".linfengadbbotmasterchina")
        }
        "well-known/malware/botnet/linfeng::linfeng-bot-telegram-handle" => {
            (Criticality::Component, "t.me/mrrobot764linfengsudoopsec")
        }
        _ => return false,
    };
    t.crit == expected.0
        && matches!(&t.r#if, Condition::Text(q)
            if q.substr.as_deref() == Some(expected.1)
                && q.exact.is_none() && q.regex.is_none() && q.word.is_none())
}

// RedShell's paired operator commands are a named-family observation whose
// bytes may occur in any ELF section and whose meaning is independent of size.
// The exact ID, severity and matcher keep this exception narrowly reviewable.
pub(super) fn is_reviewed_redshell_injection_menu(t: &TraitDefinition) -> bool {
    t.id == "well-known/malware/backdoor/redc2::redshell-injection-menu"
        && t.crit == Criticality::Notable
        && matches!(&t.r#if, Condition::Text(q)
            if q.regex.as_deref() == Some(r"/redshell bin -inject <proc> <file\.bin>[\s\S]{0,220}/redshell elf -inject <pid> <file>")
                && !q.case_insensitive && q.exact.is_none() && q.substr.is_none() && q.word.is_none())
}

// These exact ShellObject markers identify encoded family strings wherever
// they occur in a PE. Their meaning does not depend on a section name.
pub(super) fn is_reviewed_shellobject_marker(t: &TraitDefinition) -> bool {
    let expected = match t.id.as_str() {
        "well-known/malware/trojan/shellobject/hijack::encoded-kvic-jpg-payload-url" => {
            "9/Pz76m8vPT09L349fYAvfnvvAP8APC8+AWvp7357wSf"
        }
        "well-known/malware/trojan/shellobject/hijack::encoded-kvic-probe-path" => {
            "vAP8APC87/H8AQK97/fvnw=="
        }
        "well-known/malware/trojan/shellobject/hijack::encoded-temp-res-file-template" => {
            "0u3+8evyy8Lenw=="
        }
        _ => return false,
    };
    t.crit == Criticality::Notable
        && matches!(&t.r#if, Condition::Text(q)
            if q.exact.as_deref() == Some(expected)
                && q.substr.is_none() && q.regex.is_none() && q.word.is_none())
}

// These distinctive Stagecomp references are observations independent of file size.
// Tie the exception to the reviewed ID, severity and complete matcher.
pub(super) fn is_reviewed_stagecomp_marker(t: &TraitDefinition) -> bool {
    let expected = match t.id.as_str() {
        "well-known/malware/backdoor/muddywater-darkcomp::stagecomp-moonzonet-domain" => {
            r"(?i)\bmoonzonet\.com\b"
        }
        "well-known/malware/backdoor/muddywater-darkcomp::stagecomp-visualwincomp-output" => {
            r"(?i)\bvisualwincomp\.txt\b"
        }
        _ => return false,
    };
    t.crit == Criticality::Notable
        && matches!(&t.r#if, Condition::Text(q)
            if q.regex.as_deref() == Some(expected)
                && q.exact.is_none() && q.substr.is_none() && q.word.is_none())
}

// These installer-tool observations are specific PE section, debug-path, or
// string facts. Their meaning does not change with the containing file size.
// Restrict the allowance to the reviewed ID, severity, and matcher.
pub(super) fn is_reviewed_installer_tool_fact(t: &TraitDefinition) -> bool {
    if t.crit != Criticality::Notable {
        return false;
    }
    let (kind, expected, section) = match t.id.as_str() {
        // This exact embedded product banner is a reference, not a claim
        // about the size or section layout of its containing binary.
        "well-known/lib/runtime/scripted/python-runtime::python-launcher-banner-marker" => {
            ("whole-exact", "Python Launcher for Windows Version %ls", "")
        }
        // These are embedded product references, not identity claims about
        // the containing binary; keep their original whole-file scope.
        "well-known/app/system/sshtty::sshtty-server-crate-marker" => {
            ("whole-substr", "sshtty::server", "")
        }
        "well-known/app/system/sshtty::sshtty-terminal-banner" => (
            "whole-substr",
            "Browser terminal with groups and tabs that keeps your shells running",
            "",
        ),
        // These are product-specific path references, not claims that the
        // containing binary is the product. Preserve whole-file matching.
        "well-known/app/security/eset::eset-update-manifest-path" => {
            ("whole-regex", r"/eset_upd/[\w./-]{0,64}update\.ver\b", "")
        }
        "well-known/app/security/globalprotect::globalprotect-sslvpn-login-esp" => {
            ("whole-substr", "/ssl-vpn/login.esp", "")
        }
        "well-known/app/development/code-forge/github::github-web-raw-msi-url" => (
            "whole-regex",
            r###"https://github\.com/.{1,40}/.{1,40}/raw/.{1,40}/.{1,80}\.msi"###,
            "",
        ),
        "well-known/app/development/code-forge/github::github-web-raw-url" => (
            "whole-regex",
            r###"https?://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/raw/(refs/heads/)?"###,
            "",
        ),
        "well-known/app/development/code-forge/github::raw-githubusercontent-web-file" => (
            "whole-regex",
            r###"raw\.githubusercontent\.com/.{1,100}\.(html|txt|php)"###,
            "",
        ),
        "well-known/app/development/code-forge/github::raw-githubusercontent-script-file" => (
            "whole-regex",
            r###"raw\.githubusercontent\.com/.{1,100}\.(sh|py|ps1|cmd)\b"###,
            "",
        ),
        "well-known/app/development/code-forge/github::raw-githubusercontent-scripting-lang" => (
            "whole-regex",
            r###"raw\.githubusercontent\.com/.{1,100}\.(rb|pl|js)\b"###,
            "",
        ),
        "well-known/app/development/code-forge/github::raw-githubusercontent-actions-url" => (
            "whole-regex",
            r###"(?i)raw\.githubusercontent\.com/actions/"###,
            "",
        ),
        "well-known/app/development/code-forge/github::raw-githubusercontent-native-library" => (
            "whole-regex",
            r###"raw\.githubusercontent\.com/.{1,140}\.(so(\.[0-9.]+)?|dylib|dll)\b"###,
            "",
        ),
        "well-known/app/development/code-forge/github::raw-githubusercontent-msbuild-project" => (
            "whole-regex",
            r###"raw\.githubusercontent\.com/.{1,160}\.(csproj|vbproj|fsproj|sln)\b"###,
            "",
        ),
        "well-known/app/development/code-forge/github::raw-githubusercontent-image-suffix" => (
            "whole-regex",
            r###"(?i)raw\.githubusercontent\.com/[^\s"'`]{1,120}\.(png|jpe?g|gif)\b"###,
            "",
        ),
        "well-known/app/development/code-forge/github::raw-githubusercontent-any" => (
            "whole-regex",
            r###"raw\.githubusercontent\.com/[a-zA-Z0-9._-]+/[a-zA-Z0-9._-]+/"###,
            "",
        ),
        "well-known/app/development/code-forge/github::raw-githubusercontent-refs" => (
            "whole-regex",
            r###"raw\.githubusercontent\.com/.{1,80}/refs/heads/"###,
            "",
        ),
        "well-known/app/development/code-forge/github::raw-githubusercontent-host-string" => {
            ("whole-exact", r###"raw.githubusercontent.com"###, "")
        }
        "well-known/app/development/code-forge/github::gist-githubusercontent-raw-binary-url" => (
            "whole-regex",
            r###"gist\.githubusercontent\.com/[^\s/]{1,80}/[^\s/]{1,80}/raw/"###,
            "",
        ),
        "well-known/lib/ai/tesseract::tesseract-upstream-model-url" => {
            ("whole-substr", "github.com/tesseract-ocr/tessdata", "")
        }
        "well-known/app/storage/mediafire::mediafire-download-url" => (
            "whole-regex",
            r###"mediafire\.com/(file|download)/[a-zA-Z0-9_-]{10,}"###,
            "",
        ),
        "well-known/app/productivity/zoho::zoho-service-url" => (
            "whole-regex",
            r###"https?://(www\.)?(zohoapis|workdrive\.zoho|accounts\.zoho)\.[a-z]{2,3}(\.[a-z]{2})?/"###,
            "",
        ),
        "well-known/app/productivity/zoho::zoho-service-host-reference" => (
            "whole-regex",
            r###"(?i)(^|[^\w.-])(zohoapis|(workdrive|accounts)\.zoho)\.[a-z]{2,3}(\.[a-z]{2})?([^\w.-]|$)"###,
            "",
        ),
        "well-known/app/productivity/zoho::zoho-oauth-token-url" => (
            "whole-regex",
            r###"(?i)(^|[^\w.-])accounts\.zoho\.[a-z]{2,3}(\.[a-z]{2})?/oauth/v2/token\b"###,
            "",
        ),
        "well-known/app/productivity/zoho::workdrive-zoho-host-url" => (
            "whole-regex",
            r###"https?://workdrive\.zoho\.(com|eu|in|jp|ca|sa|com\.[a-z]{2})/"###,
            "",
        ),
        "well-known/app/productivity/zoho::workdrive-zoho-api-url" => (
            "whole-regex",
            r###"https?://([a-z0-9-]+\.)?zohoapis\.(com|eu|in|jp|ca|sa|com\.[a-z]{2})/workdrive/"###,
            "",
        ),
        "well-known/app/storage/dropbox::dropbox-direct-share-url" => (
            "whole-regex",
            r###"(dl\.dropbox\.com|dl\.dropboxusercontent\.com)/s(cl)?/fi/[a-zA-Z0-9_-]{10,}"###,
            "",
        ),
        "well-known/app/storage/dropbox::dropbox-web-share-url" => (
            "whole-regex",
            r###"(www\.dropbox\.com)/s(cl)?/fi/[a-zA-Z0-9_-]{10,}"###,
            "",
        ),
        "well-known/app/storage/dropbox::dropboxusercontent-executable-url" => (
            "whole-regex",
            r###"dl\.dropboxusercontent\.com/[^\s"'<>]{1,240}\.(exe|dll|bat|ps1|msi)\b"###,
            "",
        ),
        "well-known/app/storage/dropbox::dropbox-share-executable-url" => (
            "whole-regex",
            r###"www\.dropbox\.com/s(cl)?/fi/[A-Za-z0-9_-]{10,}[^\s"'<>]{0,240}\.(exe|dll|bat|ps1|msi)\b"###,
            "",
        ),
        "well-known/app/storage/dropbox::dropbox-direct-executable-url" => (
            "whole-regex",
            r###"dl\.dropbox\.com/s(cl)?/fi/[A-Za-z0-9_-]{10,}[^\s"'<>]{0,240}\.(exe|dll|bat|ps1|msi)\b"###,
            "",
        ),
        "well-known/app/storage/dropbox::dropbox-share-url-bytecode" => (
            "whole-regex",
            r###"(dl\.dropbox|www\.dropbox)\.com/s(cl)?/fi/[a-zA-Z0-9_-]{10,}"###,
            "",
        ),
        "well-known/app/storage/google-drive::gdrive-export-download-url" => (
            "whole-regex",
            r###"(drive|docs)\.google\.com/uc\?export=download&id=[a-zA-Z0-9_-]{20,}"###,
            "",
        ),
        "well-known/app/storage/google-drive::gdrive-usercontent-download-reference" => (
            "whole-substr",
            r###"drive.usercontent.google.com/download"###,
            "",
        ),
        "well-known/app/storage/google-drive::gdrive-usercontent-host" => {
            ("whole-exact", r###"drive.usercontent.google.com"###, "")
        }
        "well-known/app/storage/google-drive::gdrive-pe-file-url" => (
            "whole-regex",
            r###"(drive|docs)\.google\.com/(uc|file/d)/[a-zA-Z0-9_-]{20,}[^\s,"'<>]{0,200}\.(exe|dll)\b"###,
            "",
        ),
        "well-known/app/storage/google-drive::gdrive-script-file-url" => (
            "whole-regex",
            r###"(drive|docs)\.google\.com/(uc|file/d)/[a-zA-Z0-9_-]{20,}[^\s,"'<>]{0,200}\.(bat|ps1)\b"###,
            "",
        ),
        "well-known/app/storage/alibaba-oss::oss-service-host-reference" => (
            "whole-regex",
            r###"(?i)([A-Za-z0-9-]{1,64}\.oss-(cn|ap|us|eu|me)-[A-Za-z0-9-]{1,32}|oss)\.aliyuncs\.com"###,
            "",
        ),
        "well-known/app/storage/alibaba-oss::oss-bucket-host-cn-ap" => (
            "whole-regex",
            r###"[a-z0-9-]{1,64}\.oss-(cn|ap)-[a-z0-9-]{1,32}\.aliyuncs\.com"###,
            "",
        ),
        "well-known/app/storage/alibaba-oss::oss-bucket-host-us-eu" => (
            "whole-regex",
            r###"[a-z0-9-]{1,64}\.oss-(us|eu)-[a-z0-9-]{1,32}\.aliyuncs\.com"###,
            "",
        ),
        "well-known/app/storage/alibaba-oss::oss-bucket-host-me" => (
            "whole-regex",
            r###"[a-z0-9-]{1,64}\.oss-(me)-[a-z0-9-]{1,32}\.aliyuncs\.com"###,
            "",
        ),
        "well-known/app/storage/alibaba-oss::oss-executable-url-cn-ap" => (
            "whole-regex",
            r###"\.oss-(cn|ap)-[a-z0-9-]{1,32}\.aliyuncs\.com/.{1,200}\.(exe|dll)\b"###,
            "",
        ),
        "well-known/app/storage/alibaba-oss::oss-script-url-cn-ap" => (
            "whole-regex",
            r###"\.oss-(cn|ap)-[a-z0-9-]{1,32}\.aliyuncs\.com/.{1,200}\.(bat|ps1)\b"###,
            "",
        ),
        "well-known/app/storage/alibaba-oss::oss-executable-url-us-eu" => (
            "whole-regex",
            r###"\.oss-(us|eu)-[a-z0-9-]{1,32}\.aliyuncs\.com/.{1,200}\.(exe|dll)\b"###,
            "",
        ),
        "well-known/app/storage/alibaba-oss::oss-script-url-us-eu" => (
            "whole-regex",
            r###"\.oss-(us|eu)-[a-z0-9-]{1,32}\.aliyuncs\.com/.{1,200}\.(bat|ps1)\b"###,
            "",
        ),
        "well-known/app/storage/alibaba-oss::oss-executable-url-me" => (
            "whole-regex",
            r###"\.oss-(me)-[a-z0-9-]{1,32}\.aliyuncs\.com/.{1,200}\.(exe|dll|bat|ps1)\b"###,
            "",
        ),
        "well-known/app/storage/tencent-cos::myqcloud-domain-reference" => {
            ("whole-regex", r###"(?i)myqcloud\.com"###, "")
        }
        "well-known/app/storage/tencent-cos::tencent-cos-url" => (
            "whole-regex",
            r###"[a-z0-9-]{1,64}\.cos\.ap-[a-z0-9-]{1,32}\.myqcloud\.com"###,
            "",
        ),
        "well-known/app/storage/tencent-cos::cos-pe-url" => (
            "whole-regex",
            r###"\.cos\.ap-[a-z0-9-]{1,32}\.myqcloud\.com/.{1,200}\.(exe|dll)\b"###,
            "",
        ),
        "well-known/app/storage/tencent-cos::cos-installer-batch-url" => (
            "whole-regex",
            r###"\.cos\.ap-[a-z0-9-]{1,32}\.myqcloud\.com/.{1,200}\.(msi|bat)\b"###,
            "",
        ),
        "well-known/app/storage/tencent-cos::cos-powershell-url" => (
            "whole-regex",
            r###"\.cos\.ap-[a-z0-9-]{1,32}\.myqcloud\.com/.{1,200}\.(ps1)\b"###,
            "",
        ),
        "well-known/app/storage/tencent-cos::tencent-cos-archive-url" => (
            "whole-regex",
            r###"\.cos\.ap-[a-z0-9-]{1,32}\.myqcloud\.com/.{1,200}\.(zip|7z|rar)\b"###,
            "",
        ),
        "well-known/app/storage/digitalocean-spaces::spaces-domain-reference" => {
            ("whole-regex", r###"(?i)digitaloceanspaces\.com"###, "")
        }
        "well-known/app/storage/filen::filen-domain-reference" => {
            ("whole-regex", r###"(?i)\bfilen\.(io|net)\b"###, "")
        }
        "well-known/app/storage/koofr::koofr-domain-reference" => {
            ("whole-regex", r###"(?i)\bkoofr\.(eu|com)\b"###, "")
        }
        "well-known/app/storage/amazon-s3::aws-s3-url" => (
            "whole-regex",
            r###"(?i)https?://([a-z0-9-]+\.)?s3([.-][a-z0-9-]+)?\.amazonaws\.com/"###,
            "",
        ),
        "well-known/app/storage/amazon-s3::s3-bucket-uri" => (
            "whole-regex",
            r###"(?i)\bs3://[a-z0-9][a-z0-9.-]{1,62}(/|$)"###,
            "",
        ),
        "well-known/app/storage/google-cloud-storage::gcs-url" => (
            "whole-regex",
            r###"https?://storage\.googleapis\.com/[a-z0-9-_]+(/|["']|$)"###,
            "",
        ),
        "well-known/app/storage/cloudflare-r2::r2-object-endpoint" => (
            "whole-regex",
            r###"(?i)(^|[^A-Za-z0-9.-])([a-z0-9-]+\.)?r2\.cloudflarestorage\.com([^A-Za-z0-9.-]|$)"###,
            "",
        ),
        "well-known/app/storage/cloudflare-r2::cloudflare-r2-url" => (
            "whole-regex",
            r###"https?://[a-z0-9-]+\.r2\.cloudflarestorage\.com(/|["']|$)"###,
            "",
        ),
        "well-known/app/storage/cloudflare-r2::cloudflare-r2-pub-url" => {
            ("whole-regex", r###"https?://pub-[a-f0-9]+\.r2\.dev/"###, "")
        }
        "well-known/app/storage/digitalocean-spaces::do-spaces-url" => (
            "whole-regex",
            r###"https?://[a-z0-9-]+\.[a-z0-9-]+\.digitaloceanspaces\.com/"###,
            "",
        ),
        "well-known/app/storage/vultr-object-storage::vultr-object-storage-url" => (
            "whole-regex",
            r###"https?://[a-z0-9-]+\.[a-z0-9-]+\.vultrobjects\.com/"###,
            "",
        ),
        "well-known/app/storage/backblaze-b2::backblaze-b2-url" => (
            "whole-regex",
            r###"https?://[a-z0-9-]+\.backblazeb2\.com/"###,
            "",
        ),
        "well-known/app/communication/discord::discord-cdn-shell-script-url" => (
            "whole-regex",
            r##"cdn\.discordapp\.com/attachments/\d+/\d+/[^\s"'<>]{1,80}\.sh\b"##,
            "",
        ),
        "well-known/app/communication/discord::discord-cdn-download-url" => (
            "whole-regex",
            r##"(cdn|media)\.discordapp\.(com|net)/attachments/\d+/\d+/"##,
            "",
        ),
        "well-known/app/communication/discord::discord-cdn-windows-executable-url" => (
            "whole-regex",
            r##"discordapp\.com/attachments/[0-9]{15,}/[0-9]{15,}/.{1,80}\.(exe|dll|bat|ps1)\b"##,
            "",
        ),
        "well-known/app/communication/discord::discord-cdn-archive-url" => (
            "whole-regex",
            r##"discordapp\.com/attachments/[0-9]{15,}/[0-9]{15,}/.{1,80}\.(zip|7z|rar)\b"##,
            "",
        ),
        "well-known/app/storage/mega::mega-file-share-url" => (
            "whole-regex",
            r##"mega\.nz/(file/[a-zA-Z0-9_-]{8,}|#![a-zA-Z0-9_-]{8,})"##,
            "",
        ),
        "well-known/app/infrastructure/content-delivery/jsdelivr::jsdelivr-npm-script-url" => (
            "whole-regex",
            r#"cdn\.jsdelivr\.net/npm/[^"'\s]{0,160}\.js([?#"'`\s<>)\]}]|$)"#,
            "",
        ),
        "well-known/lib/platform/windows-base-api::microsoft-kernel32-version-identity" => {
            ("internal-name-exact", "kernel32", "")
        }
        "well-known/lib/platform/windows-base-api::microsoft-kernelbase-version-identity" => {
            ("internal-name-regex", r"(?i)^kernelbase(\.dll)?$", "")
        }
        "well-known/app/system/microsoft/sync-center::syncmgr-registry-cluster" => {
            ("substr", r"SyncMgr\Handlers", "rdata")
        }
        "well-known/app/system/microsoft/sync-center::syncmgr-handler-clsid" => {
            ("exact", "{F897AA24-BDC3-11d1-B85B-00C04FB93981}", "rdata")
        }
        "well-known/app/system/microsoft/sync-center::mobsync-pdb-path" => {
            ("pdb-inline-regex", r"(?i)(^|[\\/])mobsync\.pdb$", "")
        }
        "well-known/app/system/microsoft/sync-center::mobsync-version-name" => {
            ("exact", "mobsync.exe", "rdata")
        }
        "well-known/app/security/microsoft-security-essentials::msse-product-name" => {
            ("exact", "Microsoft Security Essentials", "rdata")
        }
        "well-known/lib/native/madexcept::mad-except" => ("substr", "madExcept", "CODE"),
        "well-known/lib/development/halide::halide-hexagon-remote-profiler-symbol" => (
            "export-exact",
            "halide_hexagon_remote_profiler_get_global_instance",
            "",
        ),
        "well-known/lib/development/halide::halide-library-loader-symbol" => {
            ("export-exact", "halide_load_library", "")
        }
        "well-known/lib/runtime/native-platform/qualcomm-hexagon::qdsp6-start-symbol" => {
            ("export-exact", "qdsp6_start_main", "")
        }
        "well-known/lib/runtime/native-platform/qualcomm-hexagon::hexagon-hvx-lock-symbol" => {
            ("export-exact", "qurt_hvx_lock", "")
        }
        "well-known/app/system/drivers/nvidia::nvidia-nvapi-internal-name" => {
            ("internal-name-exact", "nvapi.dll", "")
        }
        "well-known/app/system/firmware/qualcomm-xbl::qcom-xbl-bootloader-marker" => {
            ("raw-substr", "XBL_SC_MINI_CTX", "")
        }
        "well-known/lib/platform/wine::wine-debug-channel-symbol" => {
            ("symbol-regex", r"^__wine_dbg_[a-z_]{3,30}$", "")
        }
        "well-known/lib/platform/wine::wine-builtin-header-text" => {
            ("text-offset-64", "Wine builtin DLL", "")
        }
        "well-known/tool/development/toolchain/edg::edg-modules-path-env" => {
            ("word", "EDG_MODULES_PATH", "rodata")
        }
        "well-known/tool/development/toolchain/edg::edg-front-end-daemon" => {
            ("word", "EDG_FRONT_END_DAEMON", "rodata")
        }
        "well-known/tool/development/toolchain/dotnet-sdk::dotnet-ilasm-coreclr-binary" => (
            "regex",
            r"src[/\\]runtime[/\\]src[/\\]coreclr[/\\]ilasm[/\\]main\.cpp|\.NET IL Assembler version",
            ".rodata",
        ),
        "well-known/lib/platform/atl::atl-module-rtti" => (
            "regex",
            "C(AtlModule|ComModule|AtlException)@ATL@@",
            ".data",
        ),
        "well-known/lib/platform/wtl::wtl-frame-rtti" => (
            "regex",
            "C(FrameWindowImpl|AppModule|AboutDlg|MainFrame).{0,50}WTL@@",
            ".data",
        ),
        "well-known/lib/platform/mfc::mfc-ccmdtarget" => ("exact", "CCmdTarget", ".rdata"),
        "well-known/lib/platform/mfc::mfc-cwinapp" => ("exact", "CWinApp", ".rdata"),
        "well-known/lib/platform/mfc::mfc-afx-window-classes" => (
            "regex",
            "Afx(ControlBar|MDIFrame|FrameOrView|OleControl)",
            ".rdata",
        ),
        "well-known/lib/platform/mfc::mfc-symbols" => ("symbol-substr", "AfxWinMain", ""),
        "well-known/lib/ui/qt::qt-core-runtime-dll" => ("regex", r"Qt\dCore\.dll", "rdata"),
        "well-known/lib/runtime/managed/dotnet-process::dotnet-system-diagnostics-process-resource" => {
            ("substr", "FxResources.System.Diagnostics.Process", "rdata")
        }
        "well-known/lib/runtime/managed/dotnet-process::dotnet-system-diagnostics-process-pdb" => (
            "pdb-inline-regex",
            r"(?i)(^|[\\/])System\.Diagnostics\.Process\.ni\.pdb$",
            "",
        ),
        "well-known/lib/runtime/managed/jvm::jli-launch" => ("symbol-exact", "JLI_Launch", ""),
        "well-known/lib/runtime/managed/jvm::jli-cmd-to-args" => {
            ("symbol-exact", "JLI_CmdToArgs", "")
        }
        "well-known/lib/runtime/managed/jvm::jli-get-std-args" => {
            ("symbol-exact", "JLI_GetStdArgs", "")
        }
        "well-known/lib/runtime/managed/jvm::jli-init-arg-processing" => {
            ("symbol-exact", "JLI_InitArgProcessing", "")
        }
        "well-known/lib/runtime/managed/jvm::jli-mem-alloc" => ("symbol-exact", "JLI_MemAlloc", ""),
        "well-known/lib/runtime/managed/jvm::jli-report-error" => {
            ("symbol-exact", "JLI_ReportErrorMessage", "")
        }
        "well-known/tool/packaging/jsmooth::jsmooth-vm-search-order-string" => (
            "whole-substr",
            "JSmooth will now try to use the VM in the following order:",
            "",
        ),
        "well-known/tool/packaging/jsmooth::jsmooth-native-class-string" => {
            ("whole-substr", "jsmooth.Native", "")
        }
        "well-known/lib/ui/flutter::flutter-windows-dll" => {
            ("exact", "flutter_windows.dll", "rdata")
        }
        "well-known/lib/ui/flutter::flutter-assets-path" => ("exact", r"\flutter_assets", "rdata"),
        "well-known/lib/ui/flutter::flutter-desktop-engine-symbols" => {
            ("symbol-regex", "^FlutterDesktop(Engine|ViewController)", "")
        }
        "well-known/lib/ui/flutter::flutter-linux-desktop-runner" => (
            "symbol-regex",
            "^fl_(dart_project_new|view_new|plugin_registry_get_type)$",
            "",
        ),
        "well-known/app/system/microsoft/core-utilities::bits-service-name-reference" => {
            ("substr", "Background Intelligent Transfer Service", "rdata")
        }
        "well-known/app/media/windows-media-player::windows-media-player-name-reference" => {
            ("substr", "Microsoft Windows Media Player", "rdata")
        }
        "well-known/app/system/huawei-pc-manager::pc-manager-uninstall-guide-reference" => (
            "substr",
            r"C:\Program Files\Huawei\PCManager\UninstallGuide.exe.FriendlyAppName",
            "rdata",
        ),
        "well-known/game/steam::steam-drivers-archive-title" => {
            ("exact", "Steam Drivers Archive", "rdata")
        }
        "well-known/game/steam::steam-driver-archive-path" => {
            ("substr", "drivers/Windows10/x64/Steam", "rdata")
        }
        "well-known/app/system/mobile/tencent-mobilegamepc::tencent-mobilegamepc-registry" => {
            ("exact", r"SOFTWARE\Tencent\MobileGamePC", "rdata")
        }
        "well-known/app/system/mobile/tencent-mobilegamepc::tencent-tmarketinst-version" => {
            ("exact", "TMarketInst", "rdata")
        }
        "well-known/app/system/mobile/tencent-mobilegamepc::tencent-txmobilegamepc-marker" => {
            ("exact", "TXMobileGamePC", "rdata")
        }
        "well-known/app/system/mobile/tencent-mobilegamepc::tencent-tgbdownloader-marker" => {
            ("exact", "TGBDownloader", "rdata")
        }
        "well-known/tool/packaging/qt-installer-framework::qt-installer-framework" => {
            ("substr", "Built with Qt Installer Framework", ".rdata")
        }
        "well-known/tool/packaging/installshield::installshield-setup-runtime-marker" => (
            "substr",
            "InstallShield setup.exe (Unicode) started",
            ".rdata",
        ),
        "well-known/tool/packaging/squirrel-windows::squirrel-windows-setup-marker" => {
            ("exact", "SquirrelInstall", "rdata")
        }
        "well-known/tool/packaging/squirrel-windows::squirrel-temp-marker" => {
            ("exact", "SQUIRREL_TEMP", "rdata")
        }
        "well-known/tool/packaging/smart-install-maker::smart-install-maker-description" => {
            ("whole-substr", "Smart Install Maker", "")
        }
        "well-known/tool/packaging/nsis::nsis-first-header-specific-build-sizes" => (
            "section-hex",
            "EF BE AD DE 4E 75 6C 6C 73 6F 66 74 49 6E 73 74 75 11 00 00 18 27 00 00 5D 00 00 80",
            "overlay",
        ),
        "well-known/lib/platform/advanced-installer::external-ui-started-marker" => (
            "substr",
            "Advanced Installer External UI started.",
            ".rdata",
        ),
        "well-known/lib/platform/advanced-installer::bootstrapper-flag" => {
            ("exact", "AI_BOOTSTRAPPER", ".rdata")
        }
        "well-known/lib/platform/advanced-installer::caphyon-registry-root" => {
            ("exact", r"Software\Caphyon\Advanced Installer\", ".rdata")
        }
        "well-known/lib/platform/advanced-installer::prerequisite-install-marker" => {
            ("substr", "AI_InstallPrerequisite", ".rdata")
        }
        "well-known/tool/packaging/nsis-inetc::inetc-user-agent" => {
            ("exact", "NSIS_Inetc (Mozilla)", "rdata")
        }
        "well-known/tool/packaging/izpack::izpack-package-path" => {
            ("path", r"com[/\\]izforge[/\\]izpack", "")
        }
        "well-known/tool/packaging/inno-setup-runtime::inno-setup-550-data-marker" => {
            ("exact", "Inno Setup Setup Data (5.5.0)", "rdata")
        }
        "well-known/tool/packaging/inno-setup-runtime::inno-password-canary" => {
            ("exact", "sccPasswordTest", "rdata")
        }
        "well-known/tool/packaging/inno-setup-runtime::inno-setup-header-670" => (
            "hex",
            "49 6E 6E 6F 20 53 65 74 75 70 20 53 65 74 75 70 20 44 61 74 61 20 28 36 2E 37 2E 30 29",
            "",
        ),
        "well-known/tool/packaging/nsis::nsis-manifest-identity" => {
            ("manifest-regex", "(?i)^Nullsoft Install System", "")
        }
        "well-known/tool/packaging/nsis::nullsoft-install-system-text" => {
            ("substr", "Nullsoft Install System", ".text")
        }
        "well-known/tool/packaging/nsis::nullsoft-install-system-rdata" => {
            ("substr", "Nullsoft Install System", ".rdata")
        }
        "well-known/tool/packaging/nsis::nsis-error-title-rdata" => {
            ("exact", "NSIS Error", ".rdata")
        }
        "well-known/tool/packaging/nsis::nsis-error-title-data" => ("exact", "NSIS Error", ".data"),
        "well-known/tool/packaging/nsis::nsis-error-url-rdata" => {
            ("substr", "nsis.sf.net/NSIS_Error", ".rdata")
        }
        "well-known/tool/packaging/nsis::nsis-error-url-data" => {
            ("substr", "nsis.sf.net/NSIS_Error", ".data")
        }
        "well-known/tool/packaging/nsis::nsis-uac-ipc" => ("exact", "NSISUACIPC", ".rdata"),
        "well-known/tool/packaging/nsis::nullsoftinst-marker" => {
            ("exact", "NullsoftInst", ".rdata")
        }
        "well-known/tool/packaging/inno-setup-loader::inno-manifest-description" => {
            ("manifest-regex", r"(?i)^Inno Setup\s*$", "")
        }
        "well-known/tool/packaging/inno-setup-loader::inno-setup-data-marker" => {
            ("substr", r"Inno Setup Setup Data (", "rdata")
        }
        "well-known/tool/packaging/inno-setup-loader::inno-setup-data-marker-overlay" => {
            ("substr", r"Inno Setup Setup Data (", "overlay")
        }
        "well-known/tool/packaging/inno-setup-loader::inno-setup-installer-marker" => (
            "substr",
            r"This installation was built with Inno Setup.",
            "rdata",
        ),
        "well-known/tool/packaging/inno-setup-loader::inno-setup-installer-text" => {
            ("substr", r"Inno Setup Setup Data (", ".text")
        }
        "well-known/tool/packaging/inno-setup-loader::inno-setup-installer-data" => {
            ("substr", r"Inno Setup Setup Data (", ".data")
        }
        "well-known/tool/packaging/inno-setup-loader::inno-setup-built-with-comment" => (
            "substr",
            r"This installation was built with Inno Setup",
            "rdata",
        ),
        "well-known/tool/packaging/inno-setup-loader::inno-uninstaller-marker" => {
            ("exact", r"ISUNINSTALLER", ".text")
        }
        "well-known/tool/packaging/embala::embala-banner-token" => (
            "section-hex",
            "45 4D 42 41 4C 41 5F 42 41 4E 4E 45 52",
            ".rdata",
        ),
        "well-known/tool/packaging/inno-setup-loader::inno-loader-magic-legacy-120" => (
            "section-hex",
            "72 44 6C 50 74 53 30 32 87 65 56 78",
            ".rsrc",
        ),
        "well-known/tool/packaging/inno-setup-loader::inno-loader-magic-legacy-400" => (
            "section-hex",
            "72 44 6C 50 74 53 30 34 87 65 56 78",
            ".rsrc",
        ),
        "well-known/tool/packaging/inno-setup-loader::inno-loader-magic-legacy-403" => (
            "section-hex",
            "72 44 6C 50 74 53 30 35 87 65 56 78",
            ".rsrc",
        ),
        "well-known/tool/packaging/inno-setup-loader::inno-loader-magic-legacy-410" => (
            "section-hex",
            "72 44 6C 50 74 53 30 36 87 65 56 78",
            ".rsrc",
        ),
        "well-known/tool/packaging/inno-setup-loader::inno-loader-magic-legacy-416" => (
            "section-hex",
            "72 44 6C 50 74 53 30 37 87 65 56 78",
            ".rsrc",
        ),
        "well-known/tool/packaging/inno-setup-loader::inno-loader-magic-515" => (
            "section-hex",
            "72 44 6C 50 74 53 CD E6 D7 7B 0B 2A",
            ".rsrc",
        ),
        "well-known/tool/packaging/installaware::installaware-version-comment" => {
            ("version-comment-regex", r"(?i)\bInstallAware\b", "")
        }
        "well-known/tool/packaging/installaware::installaware-sfx-builder-pdb" => (
            "pdb-inline-regex",
            r"(?i)\\InstallAware\\.*\\SFXSetup\.pdb$",
            "",
        ),
        "well-known/tool/packaging/qsetup::qsetup-extraction-banner" => (
            "exact",
            "QSetup will extract files to your Temp Drive (<DRIVE>)<P>",
            "CODE",
        ),
        "well-known/tool/packaging/iexpress::wextract-assembly-name" => {
            ("substr", "Microsoft.Windows.Wextract", "rsrc")
        }
        "well-known/tool/packaging/iexpress::wextract-manifest-description" => (
            "substr",
            "<description>IExpress extraction tool</description>",
            "rsrc",
        ),
        "well-known/tool/packaging/iexpress::wextract-product-description" => {
            ("exact", "Win32 Cabinet Self-Extractor", "rsrc")
        }
        "well-known/tool/packaging/iexpress::wextract-pdb-path" => {
            ("exact", "wextract.pdb", ".rdata")
        }
        "well-known/tool/packaging/iexpress::wextract-cleanup-string" => {
            ("whole-substr", "wextract_cleanup%", "")
        }
        "well-known/tool/packaging/iexpress::wextract-internal-name" => {
            ("internal-name-regex", r"(?i)^wextract(\.exe)?$", "")
        }
        "well-known/tool/sysadmin/winrar-sfx::winrar-sfx-registry-text" => {
            ("exact", r"Software\WinRAR SFX", ".rdata")
        }
        "well-known/tool/sysadmin/7zip::7zip-fm-app-path" => (
            "exact-offset",
            r"Software\Microsoft\Windows\CurrentVersion\App Paths\7zFM.exe",
            ".rdata",
        ),
        "well-known/tool/sysadmin/7zip::7zip-installer-setup-banner" => (
            "regex",
            r"7-Zip [0-9]{1,2}\.[0-9]{2}( \(x(64|86)\))? Setup",
            ".rdata",
        ),
        "well-known/tool/sysadmin/7zip::7zip-registry-key" => {
            ("exact", r"Software\7-Zip", ".rdata")
        }
        "well-known/tool/sysadmin/7zip::7zip-shell-extension-clsid" => (
            "exact",
            r"CLSID\{23170F69-40C1-278A-1000-000100020000}",
            ".rdata",
        ),
        "well-known/tool/sysadmin/7zip::7zip-uninstall-registry-path" => (
            "exact",
            r"Software\Microsoft\Windows\CurrentVersion\Uninstall\7-Zip",
            ".rdata",
        ),
        "well-known/tool/sysadmin/7zip::7zip32-runtime-dll" => {
            ("exact-offset", r"7-zip32.dll", ".rdata")
        }
        "well-known/tool/sysadmin/7zip::7zsfx-runtime-stub" => {
            ("exact-offset", r"7zS.sfx.exe", ".rdata")
        }
        "well-known/tool/packaging/wix::wixburn-section-name" => ("section", ".wixburn", ""),
        "well-known/tool/packaging/wix::wix-bundle-provider-key" => {
            ("exact", "WixBundleProviderKey", "rdata")
        }
        "well-known/tool/packaging/wix::wix-burn-runonce-token" => {
            ("exact", "burn.runonce", "rdata")
        }
        "well-known/tool/sysadmin/alzip::alzip-self-extractor-banner" => {
            ("substr", "ALZip Self-Extractor", "rsrc")
        }
        "well-known/tool/sysadmin/alzip::alzip-self-extractor-banner-packed" => {
            ("substr", "ALZip Self-Extractor", "UPX1")
        }
        "well-known/tool/sysadmin/alzip::alzip-zipsfx-marker" => ("exact", "ZIPSFX", "UPX1"),
        "well-known/tool/sysadmin/alzip::alzip-eggsfx-marker" => {
            ("regex", r"^EGGSFX(\.sfx)?$", "rsrc")
        }
        "well-known/tool/sysadmin/alzip::alzip-eggsfx-pdb" => {
            ("pdb", r"alzip-windows.*EGGSFX\.pdb$", "")
        }
        "well-known/tool/sysadmin/alzip::alzip-egg-format-class" => {
            ("substr", "EggFormatImpr", "UPX1")
        }
        "well-known/tool/sysadmin/alzip::alzip-upgrade-prompt" => (
            "substr",
            "Please upgrade ALZip to the latest version",
            "UPX1",
        ),
        _ => return false,
    };
    match &t.r#if {
        Condition::Symbol(q) => {
            (kind == "export-exact"
                && q.exact.as_deref() == Some(expected)
                && q.regex.is_none()
                && q.substr.is_none()
                && q.kind == Some(crate::composite_rules::condition::SymbolKind::Export)
                && q.is_check.is_none()
                && q.not.is_none())
                || ((kind == "symbol-regex"
                    && q.regex.as_deref() == Some(expected)
                    && q.exact.is_none()
                    && q.substr.is_none())
                    || (kind == "symbol-exact"
                        && q.exact.as_deref() == Some(expected)
                        && q.regex.is_none()
                        && q.substr.is_none())
                    || (kind == "symbol-substr"
                        && q.substr.as_deref() == Some(expected)
                        && q.exact.is_none()
                        && q.regex.is_none()))
                    && q.kind.is_none()
                    && q.is_check.is_none()
                    && q.not.is_none()
        }
        Condition::Raw(q) => {
            kind == "raw-substr"
                && q.substr.as_deref() == Some(expected)
                && q.exact.is_none()
                && q.regex.is_none()
                && q.word.is_none()
                && q.section.is_none()
                && q.offset.is_none()
                && q.offset_range == Some((0, None))
                && q.section_offset.is_none()
                && q.section_offset_range.is_none()
                && !q.case_insensitive
                && q.is_check.is_none()
                && q.not.is_none()
        }
        Condition::Path(q) => {
            kind == "path"
                && q.regex.as_deref() == Some(expected)
                && !q.case_insensitive
                && !q.basename
                && !q.dirname
                && q.exact.is_none()
                && q.substr.is_none()
                && q.is_check.is_none()
        }
        Condition::Hex(q) => {
            q.pattern == expected
                && q.offset.is_none()
                && q.not.is_none()
                && ((kind == "hex"
                    && q.offset_range == Some((800000, None))
                    && q.section.is_none())
                    || (kind == "section-hex"
                        && q.offset_range.is_none()
                        && q.section.as_deref() == Some(section)))
        }
        Condition::Section(q) => {
            kind == "section"
                && !q.case_insensitive
                && q.exact.as_deref() == Some(expected)
                && q.substr.is_none()
                && q.regex.is_none()
                && q.word.is_none()
        }
        Condition::Kv(q) => {
            if kind == "internal-name-exact" {
                return q.path == "pe.version.internal_name"
                    && q.exact.as_deref() == Some(expected)
                    && q.substr.is_none()
                    && q.regex.is_none()
                    && !q.case_insensitive;
            }
            ((kind == "pdb" && q.path == "pe.debug.pdb.path" && q.case_insensitive)
                || (kind == "manifest-regex"
                    && q.path == "pe.manifest.description"
                    && !q.case_insensitive)
                || (kind == "internal-name-regex"
                    && q.path == "pe.version.internal_name"
                    && !q.case_insensitive)
                || (kind == "version-comment-regex"
                    && q.path == "pe.version.comments"
                    && !q.case_insensitive)
                || (kind == "pdb-inline-regex"
                    && q.path == "pe.debug.pdb.path"
                    && !q.case_insensitive))
                && q.regex.as_deref() == Some(expected)
                && q.exact.is_none()
                && q.substr.is_none()
        }
        Condition::Text(q) => {
            ((matches!(
                kind,
                "whole-substr" | "whole-regex" | "whole-exact" | "text-offset-64"
            ) && q.section.is_none())
                || (!matches!(
                    kind,
                    "whole-substr" | "whole-regex" | "whole-exact" | "text-offset-64"
                ) && q.section.as_deref() == Some(section)))
                && !q.case_insensitive
                && (kind == "word" || q.word.is_none())
                && match kind {
                    "word" => {
                        q.word.as_deref() == Some(expected)
                            && q.exact.is_none()
                            && q.substr.is_none()
                            && q.regex.is_none()
                    }
                    "text-offset-64" => {
                        q.offset == Some(64)
                            && q.offset_range.is_none()
                            && q.exact.as_deref() == Some(expected)
                            && q.substr.is_none()
                            && q.regex.is_none()
                    }
                    "exact-offset" => {
                        q.offset_range == Some((6291456, None))
                            && q.offset.is_none()
                            && q.exact.as_deref() == Some(expected)
                            && q.substr.is_none()
                            && q.regex.is_none()
                    }
                    "exact" | "whole-exact" => {
                        q.exact.as_deref() == Some(expected)
                            && q.substr.is_none()
                            && q.regex.is_none()
                    }
                    "substr" | "whole-substr" => {
                        q.substr.as_deref() == Some(expected)
                            && q.exact.is_none()
                            && q.regex.is_none()
                    }
                    "regex" | "whole-regex" => {
                        q.regex.as_deref() == Some(expected)
                            && q.exact.is_none()
                            && q.substr.is_none()
                    }
                    _ => false,
                }
        }
        _ => false,
    }
}

// Reviewed product-name and tool-reference observations. These exact matchers
// report the cited name, path, API or diagnostic, not the identity or size of
// their containing binary. Pin the matchers so changes do not inherit an allowance.
// Tool-name references identify mentioned software, not the containing file.
// Their evidence can occur at any size or in debug data outside PE sections.
pub(super) fn is_migrated_tool_name_reference(t: &TraitDefinition) -> bool {
    if matches!(
        t.id.as_str(),
        "well-known/lib/crypto/ledger-live::ledger-live-product-at-least-four"
            | "well-known/app/finance/monero-gui::monero-gui-name-at-least-four"
    ) && !t.count_min.is_some_and(|n| n >= 4)
    {
        return false;
    }
    let (mode, expected, crit) = match t.id.as_str() {
        "well-known/app/browser/internet-explorer::internet-explorer-product-name" => {
            ("exact", "Internet Explorer", Criticality::Notable)
        }
        "well-known/tool/sysadmin/nping::nping" => ("word", "nping", Criticality::Notable),
        "well-known/tool/packaging/msi2exe::msi2exe-stub-pdb" => {
            ("regex", r"(?i)msi2exe(stub)?\.pdb", Criticality::Notable)
        }
        "well-known/tool/packaging/msi2exe::msi2exe-tool-token" => {
            ("substr", "msi2exe", Criticality::Component)
        }
        "well-known/tool/packaging/themida::themida-name-reference" => {
            ("substr", "Themida", Criticality::Notable)
        }
        "well-known/tool/sysadmin/winrar::winrar-name-reference" => {
            ("regex", "(?i)WinRAR", Criticality::Notable)
        }
        "well-known/app/infrastructure/runc::runc-oci-str" => {
            ("substr", "opencontainers/runc", Criticality::Notable)
        }
        "well-known/lib/platform/libcontainer::libcontainer-str" => {
            ("substr", "libcontainer", Criticality::Notable)
        }
        "well-known/tool/sysadmin/network::netstat-source-marker" => {
            ("exact", "netstat.c", Criticality::Notable)
        }
        "well-known/tool/sysadmin/network::netstat-usage-banner" => {
            ("regex", r"^usage:\s+netstat\b", Criticality::Notable)
        }
        "well-known/lib/crypto/ledger-live::ledger-live-product-at-least-four" => {
            ("substr", "Ledger Live", Criticality::Notable)
        }
        "well-known/app/finance/monero-gui::monero-gui-name-at-least-four" => {
            ("substr", "Monero GUI Wallet", Criticality::Notable)
        }
        "well-known/lib/platform/atl::atl-library-reference" => {
            ("word", "ATL.DLL", Criticality::Notable)
        }
        "well-known/lib/platform/atl::atlax-get-control" => {
            ("word", "AtlAxGetControl", Criticality::Notable)
        }
        "well-known/lib/platform/atl::atlax-win-init" => {
            ("word", "AtlAxWinInit", Criticality::Notable)
        }
        _ => return false,
    };
    t.crit == crit
        && matches!(&t.r#if, Condition::Text(q)
        if !q.case_insensitive && q.section.is_none() && match mode {
            "exact" => q.exact.as_deref() == Some(expected) && q.substr.is_none() && q.regex.is_none() && q.word.is_none(),
            "substr" => q.substr.as_deref() == Some(expected) && q.exact.is_none() && q.regex.is_none() && q.word.is_none(),
            "regex" => q.regex.as_deref() == Some(expected) && q.exact.is_none() && q.substr.is_none() && q.word.is_none(),
            "word" => q.word.as_deref() == Some(expected) && q.exact.is_none() && q.substr.is_none() && q.regex.is_none(),
            _ => false,
        })
}

pub(super) fn reviewed_unbounded_reference(t: &TraitDefinition, for_section: bool) -> bool {
    if is_migrated_tool_name_reference(t) {
        return true;
    }
    if t.id == "well-known/lib/platform/atl::atlax-get-control-import"
        && t.crit == Criticality::Notable
        && matches!(&t.r#if, Condition::Symbol(q)
            if q.exact.as_deref() == Some("AtlAxGetControl")
                && q.substr.is_none() && q.regex.is_none() && q.kind.is_none())
    {
        return true;
    }
    if !for_section
        && t.id == "well-known/lib/platform/microsoft-ado::rds-dataspace-clsid"
        && t.crit == Criticality::Notable
        && let Condition::Yara { source, .. } = &t.r#if
    {
        use sha2::{Digest, Sha256};
        return hex::encode(Sha256::digest(source.as_bytes()))
            == "a06362a186ced6d31b08e033950647ba55e595aaf1dd9fd74b73522c62871f51";
    }
    // ProgID references identify mentioned components, not the containing
    // file. Preserve cross-section and unbounded scope only for these matchers.
    let progid = match t.id.as_str() {
        "well-known/app/browser/internet-explorer::shell-explorer-progid" => {
            Some(("word", "Shell.Explorer.1", false))
        }
        "well-known/app/productivity/microsoft-outlook::outlook-application-progid" => {
            Some(("regex", r"(?i)\bOutlook\.Application(\.\d+)?\b", false))
        }
        "well-known/app/system/microsoft/platform::shell-application-progid" => {
            Some(("word", "Shell.Application", true))
        }
        "well-known/app/system/microsoft/remote-desktop::msrdp-client-progid"
            if t.count_min.is_some_and(|n| n >= 2) =>
        {
            Some(("regex", r"MsRdpClient[0-9a-zA-Z]{0,4}", false))
        }
        "well-known/lib/platform/microsoft-ado::adodb-connection-progid" => {
            Some(("regex", r"(?i)\bADODB\.Connection\b", false))
        }
        "well-known/lib/platform/microsoft-ado::adox-catalog-progid" => {
            Some(("regex", r"(?i)\bADOX\.Catalog\b", false))
        }
        "well-known/lib/platform/mozilla-activex::mozilla-browser-progid" => {
            Some(("word", "Mozilla.Browser.1", false))
        }
        "well-known/lib/platform/msxml::msxml2-prefix-text" => Some(("substr", "MSXml2", false)),
        "well-known/lib/runtime/scripted/windows-script-host::filesystemobject-progid" => {
            Some(("regex", r"\bScripting\.FileSystemObject\b", false))
        }
        "well-known/lib/runtime/scripted/windows-script-host::wscript-shell-literal" => {
            Some(("regex", r"WScript\.Shell(\.1)?", true))
        }
        "well-known/tool/packaging/windows-installer::windows-installer-progid" => Some((
            "regex",
            r"(?i)\bWindowsInstaller\.(Installer|Database|Record)\b",
            false,
        )),
        _ => None,
    };
    if let Some((mode, expected, case_insensitive)) = progid {
        return t.crit == Criticality::Notable
            && matches!(&t.r#if, Condition::Text(q)
            if q.case_insensitive == case_insensitive && q.section.is_none()
                && q.exact.is_none() && match mode {
                    "word" => q.word.as_deref() == Some(expected) && q.substr.is_none() && q.regex.is_none(),
                    "substr" => q.substr.as_deref() == Some(expected) && q.word.is_none() && q.regex.is_none(),
                    "regex" => q.regex.as_deref() == Some(expected) && q.word.is_none() && q.substr.is_none(),
                    _ => false,
                });
    }
    let class_reference = match t.id.as_str() {
        "well-known/app/browser/internet-explorer::web-browser-control-clsid" => {
            Some(("substr", "{EAB22AC0-30C1-11CF-A7EB-0000C05BAE0B}"))
        }
        "well-known/app/browser/internet-explorer::webbrowser-activex-clsid" => {
            Some(("exact", "{8856F961-340A-11D0-A96B-00C04FD705A2}"))
        }
        "well-known/app/system/microsoft/platform::cmstplua-clsid" => {
            Some(("substr", "{3E5FC7F9-9A51-4367-9063-A120244FBEC7}"))
        }
        "well-known/lib/runtime/scripted/vbscript::vbscript-engine-clsid-binary" => Some((
            "raw",
            r"(?-u)\x41\x37\x4F\xB5\x07\x5B\xCF\x11\xA4\xB0\x00\xAA\x00\x4A\x55\xE8",
        )),
        _ => None,
    };
    if let Some((mode, expected)) = class_reference {
        return t.crit == Criticality::Notable
            && match &t.r#if {
                Condition::Text(q) => {
                    !q.case_insensitive
                        && q.section.is_none()
                        && q.regex.is_none()
                        && q.word.is_none()
                        && match mode {
                            "exact" => q.exact.as_deref() == Some(expected) && q.substr.is_none(),
                            "substr" => q.substr.as_deref() == Some(expected) && q.exact.is_none(),
                            _ => false,
                        }
                }
                Condition::Raw(q) => {
                    mode == "raw"
                        && q.regex.as_deref() == Some(expected)
                        && q.section.is_none()
                        && q.exact.is_none()
                        && q.substr.is_none()
                        && q.word.is_none()
                        && !q.case_insensitive
                }
                _ => false,
            };
    }
    // Named COM identifiers and component references can appear in clients
    // of any size; text references need not reside in one binary section.
    let com_reference = match t.id.as_str() {
        "well-known/app/browser/microsoft-edge::edge-ielevator-interface-guid" => {
            Some(("text", "{c9c2b807-7731-4f34-81b7-44ff7779522b}", ""))
        }
        "well-known/app/browser/microsoft-edge::edge-ielevator-interface-guid-readonly" => Some((
            "hex",
            "07 B8 C2 C9 31 77 34 4F 81 B7 44 FF 77 79 52 2B",
            ".rdata",
        )),
        "well-known/app/system/microsoft/remote-desktop::mstscax-dll-literal" => {
            Some(("text", "mstscax.dll", ""))
        }
        "well-known/app/system/microsoft/remote-desktop::mstsclib-ctl-namespace" => {
            Some(("text", "MSTSCLibCtl", ""))
        }
        "well-known/lib/platform/mfc::mfc-cwebbrowser2-class" => Some(("text", "CWebBrowser2", "")),
        "well-known/lib/runtime/native-platform/chromium-helpers::chromium-ielevator-service-guid" => {
            Some((
                "hex",
                "CF BE 3A 46 0D 41 7F 40 8A F5 0D F3 5A 00 5C C8",
                "any",
            ))
        }
        "well-known/lib/runtime/native-platform/chromium-helpers::chromium-ielevator-service-guid-readonly" => {
            Some((
                "hex",
                "CF BE 3A 46 0D 41 7F 40 8A F5 0D F3 5A 00 5C C8",
                ".rdata",
            ))
        }
        "well-known/lib/runtime/native-platform/chromium-helpers::ielevator-decrypt-data-diagnostic" => {
            Some((
                "hex",
                "49 45 6C 65 76 61 74 6F 72 3A 3A 44 65 63 72 79 70 74 44 61 74 61 3A",
                ".rdata",
            ))
        }
        "well-known/lib/runtime/native-platform/chromium-helpers::ielevator-vtbl-type-name" => {
            Some(("hex", "49 45 6C 65 76 61 74 6F 72 56 74 62 6C", "any"))
        }
        _ => None,
    };
    if let Some((kind, expected, section)) = com_reference {
        return t.crit == Criticality::Notable
            && match &t.r#if {
                Condition::Text(q) => {
                    kind == "text"
                        && q.exact.as_deref() == Some(expected)
                        && q.substr.is_none()
                        && q.regex.is_none()
                        && q.word.is_none()
                        && !q.case_insensitive
                        && q.section.is_none()
                }
                Condition::Hex(q) => {
                    kind == "hex"
                        && q.pattern == expected
                        && q.section.as_deref() == Some(section)
                        && q.offset.is_none()
                        && q.offset_range.is_none()
                }
                _ => false,
            };
    }
    let (kind, mode, expected, section, path, size_ok, section_ok, crit) = match t.id.as_str() {
        r###"well-known/app/communication/aol-desktop::registry-path-aol"### => (
            r###"text"###,
            r###"regex"###,
            r###"(?i)Software\\AOL\\Desktop"###,
            r###".text"###,
            r###""###,
            true,
            false,
            Criticality::Notable,
        ),
        r###"well-known/app/communication/compuserve::registry-path-compuserve"### => (
            r###"text"###,
            r###"regex"###,
            r###"(?i)Software\\Compuserve"###,
            r###".text"###,
            r###""###,
            true,
            false,
            Criticality::Notable,
        ),
        r###"well-known/app/development/code-forge/gitlab::gitlab-generic-package-upload"### => (
            r###"text"###,
            r###"regex"###,
            r###"/api/v4/projects/.{0,160}/packages/generic/"###,
            r###""###,
            r###""###,
            true,
            false,
            Criticality::Notable,
        ),
        r###"well-known/app/enterprise/symantec-act::registry-path-symantec-act"### => (
            r###"text"###,
            r###"regex"###,
            r###"(?i)Software\\Symantec\\ACT!"###,
            r###".text"###,
            r###""###,
            true,
            false,
            Criticality::Notable,
        ),
        r###"well-known/app/productivity/lotus-approach::lotus-approach-name-reference"### => (
            r###"text"###,
            r###"regex"###,
            r###"(?i)Lotus Approach"###,
            r###".text"###,
            r###""###,
            true,
            false,
            Criticality::Notable,
        ),
        r###"well-known/app/productivity/lotus-approach::registry-path-lotus"### => (
            r###"text"###,
            r###"regex"###,
            r###"(?i)Software\\Lotus\\Approach"###,
            r###".text"###,
            r###""###,
            true,
            false,
            Criticality::Notable,
        ),
        r###"well-known/app/productivity/microsoft-office::ensure-vsto-component-text"### => (
            r###"text"###,
            r###"exact"###,
            r###"EnsureVSTOComponent"###,
            r###""###,
            r###""###,
            true,
            true,
            Criticality::Notable,
        ),
        r###"well-known/app/productivity/microsoft-office::msoxmled-pdb"### => (
            r###"text"###,
            r###"substr"###,
            r###"msoxmled.pdb"###,
            r###""###,
            r###""###,
            true,
            true,
            Criticality::Notable,
        ),
        r###"well-known/app/productivity/microsoft-office::office-help-path"### => (
            r###"text"###,
            r###"exact"###,
            r###"/MsOfficeHelp16/"###,
            r###""###,
            r###""###,
            true,
            true,
            Criticality::Notable,
        ),
        r###"well-known/app/productivity/microsoft-office::office-help-user-agent-text"### => (
            r###"text"###,
            r###"exact"###,
            r###"User-Agent: %s%sX-OfApp: %s%sX-OfVer: %s%sX-Office-Version: %d.%d.%04d.0%sX-OfHelpLcid: %s%sX-OfUILcid: %s%sX-OfSysLcid: %s%s"###,
            r###""###,
            r###""###,
            true,
            true,
            Criticality::Notable,
        ),
        r###"well-known/app/productivity/microsoft-office::office-help-viewer-name"### => (
            r###"text"###,
            r###"exact"###,
            r###"Microsoft Office Help Viewer"###,
            r###""###,
            r###""###,
            true,
            true,
            Criticality::Notable,
        ),
        r###"well-known/app/productivity/microsoft-office::officecompleted-text"### => (
            r###"text"###,
            r###"exact"###,
            r###"OfficeCompleted"###,
            r###""###,
            r###""###,
            true,
            true,
            Criticality::Component,
        ),
        r###"well-known/app/productivity/microsoft-office::vsto-installer-pdb-reference"### => (
            r###"text"###,
            r###"exact"###,
            r###"VSTOInstaller.pdb"###,
            r###""###,
            r###""###,
            true,
            true,
            Criticality::Notable,
        ),
        r###"well-known/app/productivity/sumatrapdf::sumatrapdf-encryption-sentinel"### => (
            r###"text"###,
            r###"regex"###,
            r###"This document is encrypted with sumatrapdf reader!{4,}"###,
            r###""###,
            r###""###,
            true,
            false,
            Criticality::Notable,
        ),
        r###"well-known/app/security/defender::defender-mpservice-alpc"### => (
            r###"text"###,
            r###"substr"###,
            r###"IMpService77BDAF73-B396-481F-9042-AD358843EC24"###,
            r###""###,
            r###""###,
            true,
            false,
            Criticality::Notable,
        ),
        r###"well-known/app/security/defender::defender-rpc-uuid"### => (
            r###"text"###,
            r###"regex"###,
            r###"(?i)c503f532-443a-4c69-8300-ccd1fbdb3839"###,
            r###""###,
            r###""###,
            true,
            false,
            Criticality::Notable,
        ),
        r###"well-known/app/system/apple/launch-services::apple-like-cache-service-name"### => (
            r###"text"###,
            r###"regex"###,
            r###"(?i)(com\.apple\.(verified|homeenergyd)|/com\.apple\.softwareupdate/SoftwareUpdate)\b"###,
            r###""###,
            r###""###,
            true,
            false,
            Criticality::Notable,
        ),
        r###"well-known/app/system/microsoft/platform::appinfo-elevation-interface-uuid"### => (
            r###"text"###,
            r###"regex"###,
            r###"(?i)\{?201ef99a[-, ]+7fa0[-, ]+444c[-, ]+9399[-, ]+19ba84f12a1a\}?"###,
            r###""###,
            r###""###,
            true,
            false,
            Criticality::Notable,
        ),
        r###"well-known/app/system/microsoft/telemetry::diagtrack-dll-name"### => (
            r###"text"###,
            r###"exact"###,
            r###"diagtrack.dll"###,
            r###""###,
            r###""###,
            true,
            true,
            Criticality::Notable,
        ),
        r###"well-known/app/system/microsoft/telemetry::diagtrackrunner-pdb"### => (
            r###"text"###,
            r###"exact"###,
            r###"diagtrackrunner.pdb"###,
            r###""###,
            r###""###,
            true,
            true,
            Criticality::Notable,
        ),
        r###"well-known/app/utility/getrighttogo::getrighttogo-manifest"### => (
            r###"value"###,
            r###"exact"###,
            r###"GetRightToGo.com Downloader"###,
            r###""###,
            r###"pe.manifest.description"###,
            true,
            false,
            Criticality::Notable,
        ),
        r###"well-known/dual-use/tunnel/localtunnel::localtunnel-client-error-text"### => (
            r###"text"###,
            r###"regex"###,
            r###"Localtunnel (exited|timeout)|localtunnel server returned an error"###,
            r###""###,
            r###""###,
            true,
            false,
            Criticality::Notable,
        ),
        r###"well-known/dual-use/tunnel/localtunnel::localtunnel-debug-namespace"### => (
            r###"text"###,
            r###"substr"###,
            r###"localtunnel:client"###,
            r###""###,
            r###""###,
            true,
            false,
            Criticality::Notable,
        ),
        r###"well-known/dual-use/tunnel/ngrok::go-ngrok-agent-type--rx-7"### => (
            r###"text"###,
            r###"regex"###,
            r###"\*ngrok\.(Agent|Dialer)\b"###,
            r###""###,
            r###""###,
            true,
            false,
            Criticality::Notable,
        ),
        r###"well-known/dual-use/tunnel/ngrok::go-ngrok-agent-type--rx-8"### => (
            r###"text"###,
            r###"regex"###,
            r###"\*ngrok\.(Endpoint|Upstream)\b"###,
            r###""###,
            r###""###,
            true,
            false,
            Criticality::Notable,
        ),
        r###"well-known/dual-use/tunnel/ngrok::go-ngrok-agent-type--rx-9"### => (
            r###"text"###,
            r###"regex"###,
            r###"\*ngrok\.(AgentSession|EndpointListener)\b"###,
            r###""###,
            r###""###,
            true,
            false,
            Criticality::Notable,
        ),
        r###"well-known/dual-use/tunnel/ngrok::go-ngrok-config-name"### => (
            r###"text"###,
            r###"regex"###,
            r###"\bNgrok(Config|Account)\b"###,
            r###""###,
            r###""###,
            true,
            false,
            Criticality::Notable,
        ),
        r###"well-known/dual-use/tunnel/ngrok::go-ngrok-config-type"### => (
            r###"text"###,
            r###"regex"###,
            r###"\*config\.Ngrok(Config|Account)\b"###,
            r###""###,
            r###""###,
            true,
            false,
            Criticality::Notable,
        ),
        r###"well-known/dual-use/tunnel/openconnect::openconnect-fortinet-command"### => (
            r###"text"###,
            r###"regex"###,
            r###"(?s)\bopenconnect\b.{0,160}--protocol[= '"]+fortinet([\s,'";)]|$)"###,
            r###""###,
            r###""###,
            true,
            false,
            Criticality::Notable,
        ),
        r###"well-known/dual-use/tunnel/tailscale::go-tsnet-vpn-startup-reference"### => (
            r###"text"###,
            r###"exact"###,
            r###"tailscale.com/tsnet.(*Server).Up"###,
            r###""###,
            r###""###,
            true,
            true,
            Criticality::Notable,
        ),
        r###"well-known/lib/crypto/jose-jwt::jwt-jwe-context--rx-6"### => (
            r###"text"###,
            r###"substr"###,
            r###"jose-jwt"###,
            r###""###,
            r###""###,
            true,
            true,
            Criticality::Notable,
        ),
        r###"well-known/lib/development/borland-delphi::borland-delphi-name-reference"### => (
            r###"text"###,
            r###"regex"###,
            r###"(?i)Borland Delphi"###,
            r###".text"###,
            r###""###,
            true,
            false,
            Criticality::Notable,
        ),
        r###"well-known/lib/network/proxy/go-socks5::armon-go-socks5"### => (
            r###"text"###,
            r###"substr"###,
            r###"github.com/armon/go-socks5"###,
            r###""###,
            r###""###,
            true,
            false,
            Criticality::Notable,
        ),
        r###"well-known/lib/network/proxy/go-socks5::armon-go-socks5-listen-and-serve"### => (
            r###"text"###,
            r###"substr"###,
            r###"github.com/armon/go-socks5.(*Server).ListenAndServe"###,
            r###""###,
            r###""###,
            true,
            true,
            Criticality::Notable,
        ),
        r###"well-known/lib/network/proxy/go-socks5::armon-go-socks5-serve-conn"### => (
            r###"text"###,
            r###"substr"###,
            r###"github.com/armon/go-socks5.(*Server).ServeConn"###,
            r###""###,
            r###""###,
            true,
            true,
            Criticality::Notable,
        ),
        r###"well-known/lib/network/yamux::go-yamux-multiplexed-transport"### => (
            r###"text"###,
            r###"substr"###,
            r###"github.com/hashicorp/yamux"###,
            r###""###,
            r###""###,
            true,
            false,
            Criticality::Notable,
        ),
        r###"well-known/lib/runtime/managed/dotnet-runtime::jwt-jwe-context--rx-2"### => (
            r###"text"###,
            r###"substr"###,
            r###"System.Security.Cryptography.Pkcs"###,
            r###""###,
            r###""###,
            true,
            true,
            Criticality::Notable,
        ),
        r###"well-known/lib/runtime/scripted/gentee::gentee-runtime-call"### => (
            r###"text"###,
            r###"exact"###,
            r###"gentee_call"###,
            r###""###,
            r###""###,
            true,
            true,
            Criticality::Notable,
        ),
        r###"well-known/lib/runtime/scripted/gentee::gentee-runtime-deinit"### => (
            r###"text"###,
            r###"exact"###,
            r###"gentee_deinit"###,
            r###""###,
            r###""###,
            true,
            true,
            Criticality::Notable,
        ),
        r###"well-known/lib/runtime/scripted/gentee::gentee-runtime-dll-name"### => (
            r###"text"###,
            r###"substr"###,
            r###"genteert.dll"###,
            r###""###,
            r###""###,
            true,
            true,
            Criticality::Notable,
        ),
        r###"well-known/lib/runtime/scripted/gentee::gentee-runtime-init"### => (
            r###"text"###,
            r###"exact"###,
            r###"gentee_init"###,
            r###""###,
            r###""###,
            true,
            true,
            Criticality::Notable,
        ),
        r###"well-known/lib/runtime/scripted/gentee::gentee-runtime-load"### => (
            r###"text"###,
            r###"exact"###,
            r###"gentee_load"###,
            r###""###,
            r###""###,
            true,
            true,
            Criticality::Notable,
        ),
        r###"well-known/lib/runtime/scripted/gentee::gentee-runtime-set"### => (
            r###"text"###,
            r###"exact"###,
            r###"gentee_set"###,
            r###""###,
            r###""###,
            true,
            true,
            Criticality::Notable,
        ),
        r###"well-known/tool/packaging/crypter::dotnet-named-builder-token"### => (
            r###"text"###,
            r###"regex"###,
            r###"MORPHEOUS|#KILLAMUVZ#"###,
            r###""###,
            r###""###,
            true,
            true,
            Criticality::Component,
        ),
        r###"well-known/tool/packaging/crypter::dotnet-named-crypter-title-text"### => (
            r###"text"###,
            r###"regex"###,
            r###"(?i)\b(Morpheous|Morpheus|Eladitos)\s+Crypter\b|Morpheous Crypter Cracked"###,
            r###""###,
            r###""###,
            true,
            true,
            Criticality::Notable,
        ),
        r###"well-known/app/system/microsoft/error-reporting::windows-error-reporter-manifest-reference"### => {
            (
                r###"text"###,
                r###"exact"###,
                r###"name="Microsoft.Windows.ErrorReporter""###,
                r###""###,
                r###""###,
                false,
                true,
                Criticality::Notable,
            )
        }
        r###"well-known/game/mahjong-titans::mahjong-titans-name-reference"### => (
            r###"text"###,
            r###"substr"###,
            r###"Mahjong Titans"###,
            r###""###,
            r###""###,
            false,
            true,
            Criticality::Notable,
        ),
        _ => return false,
    };
    if t.crit != crit || if for_section { !section_ok } else { !size_ok } {
        return false;
    }
    match &t.r#if {
        Condition::Text(q) if kind == "text" => {
            let value_matches = match mode {
                "exact" => {
                    q.exact.as_deref() == Some(expected) && q.substr.is_none() && q.regex.is_none()
                }
                "substr" => {
                    q.substr.as_deref() == Some(expected) && q.exact.is_none() && q.regex.is_none()
                }
                "regex" => {
                    q.regex.as_deref() == Some(expected) && q.exact.is_none() && q.substr.is_none()
                }
                _ => false,
            };
            value_matches
                && q.word.is_none()
                && !q.case_insensitive
                && q.section.as_deref().unwrap_or("") == section
        }
        Condition::Kv(q) if kind == "value" => {
            q.path == path
                && mode == "exact"
                && q.exact.as_deref() == Some(expected)
                && q.substr.is_none()
                && q.regex.is_none()
                && !q.case_insensitive
        }
        _ => false,
    }
}

/// Find well-known/ atomic traits targeting binaries without any file size filter.
///
/// Binary identity signatures normally need a size bound. Low-tier basename,
/// named version-field, signer-subject, and section-scoped resource facts are
/// observations, not verified identity, and need no arbitrary size range.
/// Malware, higher-criticality and unscoped binary signatures remain checked.
///
/// Returns `Vec<(trait_id, source_file)>` for violations.
#[must_use]
pub(super) fn is_go_socks5_library_reference(t: &TraitDefinition) -> bool {
    let expected = match t.id.as_str() {
        "well-known/lib/network/proxy/go-socks5::armon-go-socks5" => "github.com/armon/go-socks5",
        "well-known/lib/network/proxy/go-socks5::armon-go-socks5-listen-and-serve" => {
            "github.com/armon/go-socks5.(*Server).ListenAndServe"
        }
        "well-known/lib/network/proxy/go-socks5::armon-go-socks5-serve-conn" => {
            "github.com/armon/go-socks5.(*Server).ServeConn"
        }
        _ => return false,
    };
    t.crit == Criticality::Notable
        && matches!(&t.r#if, Condition::Text(q)
            if q.substr.as_deref() == Some(expected)
                && q.exact.is_none() && q.regex.is_none() && q.word.is_none())
}

// These named builder labels are references, not identity claims about the
// containing binary. Preserve their whole-file scope and original size range.
pub(super) fn is_named_crypter_label_reference(t: &TraitDefinition) -> bool {
    let (expected, crit) = match t.id.as_str() {
        "well-known/tool/packaging/crypter::dotnet-named-crypter-title-text" => (
            r"(?i)\b(Morpheous|Morpheus|Eladitos)\s+Crypter\b|Morpheous Crypter Cracked",
            Criticality::Notable,
        ),
        "well-known/tool/packaging/crypter::dotnet-named-builder-token" => {
            (r"MORPHEOUS|#KILLAMUVZ#", Criticality::Component)
        }
        _ => return false,
    };
    t.crit == crit
        && matches!(&t.r#if, Condition::Text(q)
        if q.regex.as_deref() == Some(expected)
            && q.exact.is_none() && q.substr.is_none() && q.word.is_none())
}

// Go ngrok type-name references can occur in any section and do not identify
// the containing binary; keep these reviewed matchers at whole-file scope.
pub(super) fn is_ngrok_go_type_reference(t: &TraitDefinition) -> bool {
    let expected = match t.id.as_str() {
        "well-known/dual-use/tunnel/ngrok::go-ngrok-agent-type--rx-7" => {
            r"\*ngrok\.(Agent|Dialer)\b"
        }
        "well-known/dual-use/tunnel/ngrok::go-ngrok-agent-type--rx-8" => {
            r"\*ngrok\.(Endpoint|Upstream)\b"
        }
        "well-known/dual-use/tunnel/ngrok::go-ngrok-agent-type--rx-9" => {
            r"\*ngrok\.(AgentSession|EndpointListener)\b"
        }
        "well-known/dual-use/tunnel/ngrok::go-ngrok-config-type" => {
            r"\*config\.Ngrok(Config|Account)\b"
        }
        "well-known/dual-use/tunnel/ngrok::go-ngrok-config-name" => r"\bNgrok(Config|Account)\b",
        _ => return false,
    };
    t.crit == Criticality::Notable
        && matches!(&t.r#if, Condition::Text(q)
        if q.regex.as_deref() == Some(expected)
            && q.exact.is_none() && q.substr.is_none() && q.word.is_none())
}

// Named client and runtime references need no assumptions about the size or
// section layout of a binary that happens to contain them.
pub(super) fn is_tunnel_client_reference(t: &TraitDefinition) -> bool {
    let (kind, expected) = match t.id.as_str() {
        "well-known/dual-use/tunnel/tailscale::go-tsnet-vpn-startup-reference" => {
            ("exact", "tailscale.com/tsnet.(*Server).Up")
        }
        "well-known/dual-use/tunnel/localtunnel::localtunnel-client-error-text" => (
            "regex",
            "Localtunnel (exited|timeout)|localtunnel server returned an error",
        ),
        "well-known/dual-use/tunnel/localtunnel::localtunnel-debug-namespace" => {
            ("substr", "localtunnel:client")
        }
        _ => return false,
    };
    t.crit == Criticality::Notable
        && matches!(&t.r#if, Condition::Text(q)
        if q.word.is_none() && match kind {
            "exact" => q.exact.as_deref() == Some(expected) && q.substr.is_none() && q.regex.is_none(),
            "regex" => q.regex.as_deref() == Some(expected) && q.exact.is_none() && q.substr.is_none(),
            "substr" => q.substr.as_deref() == Some(expected) && q.exact.is_none() && q.regex.is_none(),
            _ => false,
        })
}

// A yamux package-path reference does not describe the containing binary's
// size or section layout.
pub(super) fn is_yamux_library_reference(t: &TraitDefinition) -> bool {
    t.id == "well-known/lib/network/yamux::go-yamux-multiplexed-transport"
        && t.crit == Criticality::Notable
        && matches!(&t.r#if, Condition::Text(q)
            if q.substr.as_deref() == Some("github.com/hashicorp/yamux")
                && q.exact.is_none() && q.regex.is_none() && q.word.is_none())
}

// A named OpenConnect command can appear in binaries of arbitrary size; the
// command text is a reference, not an identity claim about the containing file.
pub(super) fn is_openconnect_command_reference(t: &TraitDefinition) -> bool {
    t.id == "well-known/dual-use/tunnel/openconnect::openconnect-fortinet-command"
        && t.crit == Criticality::Notable
        && matches!(&t.r#if, Condition::Text(q)
            if q.regex.as_deref() == Some(r#"(?s)\bopenconnect\b.{0,160}--protocol[= '"]+fortinet([\s,'";)]|$)"#)
                && q.exact.is_none() && q.substr.is_none() && q.word.is_none())
}

// Gentee API and DLL names can occur in any PE section and in binaries of
// any size; these are references to the runtime, not whole-file identity.
pub(super) fn is_gentee_runtime_reference(t: &TraitDefinition) -> bool {
    let (expected, exact) = match t.id.as_str() {
        "well-known/lib/runtime/scripted/gentee::gentee-runtime-init" => ("gentee_init", true),
        "well-known/lib/runtime/scripted/gentee::gentee-runtime-deinit" => ("gentee_deinit", true),
        "well-known/lib/runtime/scripted/gentee::gentee-runtime-load" => ("gentee_load", true),
        "well-known/lib/runtime/scripted/gentee::gentee-runtime-set" => ("gentee_set", true),
        "well-known/lib/runtime/scripted/gentee::gentee-runtime-call" => ("gentee_call", true),
        "well-known/lib/runtime/scripted/gentee::gentee-runtime-dll-name" => {
            ("genteert.dll", false)
        }
        _ => return false,
    };
    t.crit == Criticality::Notable
        && matches!(&t.r#if, Condition::Text(q)
            if q.regex.is_none() && q.word.is_none()
                && if exact { q.exact.as_deref() == Some(expected) && q.substr.is_none() }
                   else { q.substr.as_deref() == Some(expected) && q.exact.is_none() })
}

// These RPC interface references identify named Windows services, not the
// file containing them; their presence is independent of the file's size.
pub(super) fn is_windows_rpc_service_reference(t: &TraitDefinition) -> bool {
    let (expected, regex) = match t.id.as_str() {
        "well-known/app/security/defender::defender-rpc-uuid" => {
            ("(?i)c503f532-443a-4c69-8300-ccd1fbdb3839", true)
        }
        "well-known/app/security/defender::defender-mpservice-alpc" => {
            ("IMpService77BDAF73-B396-481F-9042-AD358843EC24", false)
        }
        "well-known/app/system/microsoft/platform::appinfo-elevation-interface-uuid" => (
            r"(?i)\{?201ef99a[-, ]+7fa0[-, ]+444c[-, ]+9399[-, ]+19ba84f12a1a\}?",
            true,
        ),
        _ => return false,
    };
    t.crit == Criticality::Notable
        && matches!(&t.r#if, Condition::Text(q)
            if q.exact.is_none() && q.word.is_none()
                && if regex { q.regex.as_deref() == Some(expected) && q.substr.is_none() }
                   else { q.substr.as_deref() == Some(expected) && q.regex.is_none() })
}

// This is a quoted claim about SumatraPDF, not a whole-file identity.
pub(super) fn is_sumatrapdf_encryption_claim(t: &TraitDefinition) -> bool {
    t.id == "well-known/app/productivity/sumatrapdf::sumatrapdf-encryption-sentinel"
        && t.crit == Criticality::Notable
        && matches!(&t.r#if, Condition::Text(q)
            if q.regex.as_deref() == Some("This document is encrypted with sumatrapdf reader!{4,}")
                && q.exact.is_none() && q.substr.is_none() && q.word.is_none())
}

// Managed library names may be embedded in any section of any sized binary.
pub(super) fn is_jwe_library_reference(t: &TraitDefinition) -> bool {
    let expected = match t.id.as_str() {
        "well-known/lib/runtime/managed/dotnet-runtime::jwt-jwe-context--rx-2" => {
            "System.Security.Cryptography.Pkcs"
        }
        "well-known/lib/crypto/jose-jwt::jwt-jwe-context--rx-6" => "jose-jwt",
        _ => return false,
    };
    t.crit == Criticality::Notable
        && matches!(&t.r#if, Condition::Text(q)
            if q.substr.as_deref() == Some(expected)
                && q.exact.is_none() && q.regex.is_none() && q.word.is_none())
}

// Apple service/path references can occur in containing files of any size.
pub(super) fn is_apple_cache_service_reference(t: &TraitDefinition) -> bool {
    t.id == "well-known/app/system/apple/launch-services::apple-like-cache-service-name"
        && t.crit == Criticality::Notable
        && matches!(&t.r#if, Condition::Text(q)
            if q.regex.as_deref() == Some(r"(?i)(com\.apple\.(verified|homeenergyd)|/com\.apple\.softwareupdate/SoftwareUpdate)\b")
                && q.exact.is_none() && q.substr.is_none() && q.word.is_none())
}

// These product and debug-name strings describe references in the containing
// file. Their meaning does not depend on the file's size or PE section.
pub(super) fn is_windows_product_name_reference(t: &TraitDefinition) -> bool {
    let (expected, kind, crit) = match t.id.as_str() {
        "well-known/app/system/microsoft/error-reporting::windows-error-reporter-manifest-reference" => {
            (
                "name=\"Microsoft.Windows.ErrorReporter\"",
                "exact",
                Criticality::Notable,
            )
        }
        "well-known/game/mahjong-titans::mahjong-titans-name-reference" => {
            ("Mahjong Titans", "substr", Criticality::Notable)
        }
        "well-known/app/productivity/microsoft-office::officecompleted-text" => {
            ("OfficeCompleted", "exact", Criticality::Component)
        }
        "well-known/app/productivity/microsoft-office::office-help-viewer-name" => (
            "Microsoft Office Help Viewer",
            "exact",
            Criticality::Notable,
        ),
        "well-known/app/productivity/microsoft-office::office-help-path" => {
            ("/MsOfficeHelp16/", "exact", Criticality::Notable)
        }
        "well-known/app/productivity/microsoft-office::msoxmled-pdb" => {
            ("msoxmled.pdb", "substr", Criticality::Notable)
        }
        "well-known/app/productivity/microsoft-office::vsto-installer-pdb-reference" => {
            ("VSTOInstaller.pdb", "exact", Criticality::Notable)
        }
        "well-known/app/productivity/microsoft-office::ensure-vsto-component-text" => {
            ("EnsureVSTOComponent", "exact", Criticality::Notable)
        }
        "well-known/app/productivity/microsoft-office::office-help-user-agent-text" => (
            "User-Agent: %s%sX-OfApp: %s%sX-OfVer: %s%sX-Office-Version: %d.%d.%04d.0%sX-OfHelpLcid: %s%sX-OfUILcid: %s%sX-OfSysLcid: %s%s",
            "exact",
            Criticality::Notable,
        ),
        "well-known/app/system/microsoft/telemetry::diagtrackrunner-pdb" => {
            ("diagtrackrunner.pdb", "exact", Criticality::Notable)
        }
        "well-known/app/system/microsoft/telemetry::diagtrack-dll-name" => {
            ("diagtrack.dll", "exact", Criticality::Notable)
        }
        _ => return false,
    };
    t.crit == crit
        && matches!(&t.r#if, Condition::Text(q)
        if q.regex.is_none() && q.word.is_none()
            && match kind {
                "exact" => q.exact.as_deref() == Some(expected) && q.substr.is_none(),
                "substr" => q.substr.as_deref() == Some(expected) && q.exact.is_none(),
                _ => false,
            })
}

// These are product-name references, not whole-file product identities.
pub(super) fn is_legacy_product_name_reference(t: &TraitDefinition) -> bool {
    let expected = match t.id.as_str() {
        "well-known/app/productivity/lotus-approach::lotus-approach-name-reference" => {
            "(?i)Lotus Approach"
        }
        "well-known/lib/development/borland-delphi::borland-delphi-name-reference" => {
            "(?i)Borland Delphi"
        }
        _ => return false,
    };
    t.crit == Criticality::Notable
        && matches!(&t.r#if, Condition::Text(q)
            if q.regex.as_deref() == Some(expected)
                && q.exact.is_none() && q.substr.is_none() && q.word.is_none())
}

// Repeated product-name text is a reference, not the containing file's identity.
pub(super) fn is_trezor_name_reference(t: &TraitDefinition) -> bool {
    t.id == "well-known/app/finance/trezor::repeated-trezor-token"
        && t.crit == Criticality::Notable
        && t.count_min.is_some_and(|n| n >= 4)
        && matches!(&t.r#if, Condition::Text(q)
            if q.substr.as_deref() == Some("trezor")
                && q.exact.is_none() && q.regex.is_none() && q.word.is_none())
}

pub(super) fn is_nvidia_nvml_reference(t: &TraitDefinition) -> bool {
    if t.crit != Criticality::Notable {
        return false;
    }
    let expected = match t.id.as_str() {
        "well-known/lib/runtime/native-platform/nvidia-nvml::nvml-wrapper-rust-crate" => {
            "nvml-wrapper-sys"
        }
        "well-known/lib/runtime/native-platform/nvidia-nvml::nvidia-gpu-classifier-token" => {
            "NvidiaQuadroTeslaNVSGRIDGeForceTitanV"
        }
        _ => return false,
    };
    matches!(&t.r#if, Condition::Text(q)
        if q.substr.as_deref() == Some(expected)
            && q.section.as_deref() == Some("rdata")
            && q.word.is_none() && q.exact.is_none() && q.regex.is_none())
}

// These provider URL references can appear in binaries of any size.
pub(super) fn is_sms_provider_endpoint_reference(t: &TraitDefinition) -> bool {
    if t.crit != Criticality::Notable {
        return false;
    }
    let expected = match t.id.as_str() {
        "well-known/app/communication/weimi::weimi-cc-api" => "api.weimi.cc/",
        "well-known/app/communication/weimi::weimi-cc-admin" => "www.weimi.cc/sms.html",
        "well-known/app/communication/juhe::juhe-cn-sms-send" => "v.juhe.cn/sms/",
        _ => return false,
    };
    matches!(&t.r#if, Condition::Text(q)
        if q.substr.as_deref() == Some(expected)
            && q.word.is_none() && q.exact.is_none() && q.regex.is_none())
}

// A literal tool-name reference does not identify or bound the enclosing binary.
pub(super) fn is_poolpartybof_reference(t: &TraitDefinition) -> bool {
    t.id == "well-known/tool/offensive/poolpartybof::poolparty-bof-name"
        && t.crit == Criticality::Notable
        && matches!(&t.r#if, Condition::Text(q)
            if q.substr.as_deref() == Some("PoolPartyBof")
                && q.word.is_none() && q.exact.is_none() && q.regex.is_none())
}

// A staged minicap path is a tool reference, not an identity or file-size claim.
pub(super) fn is_minicap_path_reference(t: &TraitDefinition) -> bool {
    t.id == "well-known/tool/development/automation/minicap::android-staged-minicap-path"
        && t.crit == Criticality::Notable
        && matches!(&t.r#if, Condition::Text(q)
            if q.regex.as_deref() == Some(r"/data/local/tmp/minicap\b")
                && q.word.is_none() && q.exact.is_none() && q.substr.is_none())
}

// A quoted Mixcloud warning is product-related text, not a size-bounded identity.
pub(super) fn is_mixcloud_warning_reference(t: &TraitDefinition) -> bool {
    t.id == "well-known/app/media/mixcloud::mixcloud-download-warning"
        && t.crit == Criticality::Notable
        && matches!(&t.r#if, Condition::Text(q)
            if q.substr.as_deref() == Some("IFYOUWANTTHEARTISTSTOGETPAIDDONOTDOWNLOADFROMMIXCLOUD")
                && q.word.is_none() && q.exact.is_none() && q.regex.is_none())
}

// Registry key text refers to another product, not the containing binary.
// Preserve whole-file coverage without arbitrary size or section limits.
pub(super) fn is_reviewed_product_registry_reference(t: &TraitDefinition) -> bool {
    if t.crit != Criticality::Notable {
        return false;
    }
    let (kind, expected) = match t.id.as_str() {
        "well-known/lib/runtime/managed/java-runtime::java-runtime-home-key-reference" => {
            ("exact", r"SOFTWARE\JavaSoft\Java Runtime Environment")
        }
        "well-known/game/roblox::roblox-studio-registry-key" => (
            "regex",
            r"(?i)SOFTWARE[\\/]Roblox[\\/]RobloxStudioBrowser[\\/]roblox\.com",
        ),
        "well-known/game/steam-registry::steam-path-string" => ("substr", r"Software\Valve\Steam"),
        "well-known/app/productivity/onenote::onenote-options-other-policy-path" => (
            "exact",
            r"Software\Policies\Microsoft\Office\16.0\OneNote\Options\Other",
        ),
        "well-known/app/system/pcanywhere::pcanywhere-data-port-reference" => (
            "substr",
            r"Symantec\pcAnywhere\CurrentVersion\System\TCPIPDataPort",
        ),
        "well-known/app/productivity/lotus-approach::registry-path-lotus" => {
            ("regex", r"(?i)Software\\Lotus\\Approach")
        }
        "well-known/app/communication/aol-desktop::registry-path-aol" => {
            ("regex", r"(?i)Software\\AOL\\Desktop")
        }
        "well-known/app/enterprise/symantec-act::registry-path-symantec-act" => {
            ("regex", r"(?i)Software\\Symantec\\ACT!")
        }
        "well-known/app/communication/compuserve::registry-path-compuserve" => {
            ("regex", r"(?i)Software\\Compuserve")
        }
        _ => return false,
    };
    matches!(&t.r#if, Condition::Text(q)
    if q.word.is_none() && match kind {
        "exact" => q.exact.as_deref() == Some(expected) && q.substr.is_none() && q.regex.is_none(),
        "substr" => q.substr.as_deref() == Some(expected) && q.exact.is_none() && q.regex.is_none(),
        "regex" => q.regex.as_deref() == Some(expected) && q.exact.is_none() && q.substr.is_none(),
        _ => false,
    })
}

// These exact Nping command references describe text inside another file.
// They do not identify the containing binary or imply a meaningful size bound.
pub(super) fn is_reviewed_nping_command_reference(t: &TraitDefinition) -> bool {
    if t.crit != Criticality::Notable {
        return false;
    }
    let (kind, expected) = match t.id.as_str() {
        "well-known/tool/offensive/reconnaissance/nping::nping" => ("word", "nping"),
        "well-known/tool/offensive/reconnaissance/nping::source-port" => {
            ("regex", r"(?i)\bnping\b[^\r\n]{0,300}--source-port")
        }
        "well-known/tool/offensive/reconnaissance/nping::payload-data" => {
            ("regex", r"(?i)\bnping\b[^\r\n]{0,300}--data=")
        }
        _ => return false,
    };
    matches!(&t.r#if, Condition::Text(q)
    if q.exact.is_none() && q.substr.is_none()
        && match kind {
            "word" => q.word.as_deref() == Some(expected) && q.regex.is_none(),
            "regex" => q.regex.as_deref() == Some(expected) && q.word.is_none(),
            _ => false,
        })
}

// These are command and script references within another file, not claims
// about that file's own identity or size. Keep the exception matcher-specific.
pub(super) fn is_reviewed_remote_tool_reference(t: &TraitDefinition) -> bool {
    if t.crit != Criticality::Notable {
        return false;
    }
    let expected = match t.id.as_str() {
        "well-known/tool/offensive/impacket::impacket-psexec-script-reference" => {
            r"(?i)\bpsexec\.py\b"
        }
        "well-known/tool/offensive/impacket::impacket-wmiexec-script-reference" => {
            r"(?i)(impacket[\\/]examples[\\/]wmiexec\.py|wmiexec\.py)\b"
        }
        "well-known/tool/offensive/impacket::impacket-wmiexec-target" => {
            r"(?i)\bwmiexec\.py\b[^\r\n]{0,180}@(\[[^\]\r\n]{1,40}\]|[A-Za-z0-9_.-]+)"
        }
        "well-known/tool/sysadmin/sysinternals::psexec-remote-invocation" => {
            r#"(?i)\bpsexec(64)?(\.exe)?\b[^\r\n]{0,160}\s+["']?\\\\[\w.%${}<>-]{1,80}(\s|["']|$)"#
        }
        _ => return false,
    };
    matches!(&t.r#if, Condition::Text(q)
        if q.regex.as_deref() == Some(expected)
            && q.exact.is_none() && q.substr.is_none() && q.word.is_none())
}

// These low-tier observations report named .NET Framework tools in another
// file; they do not claim that the containing binary is that tool. Restrict
// the exception to the reviewed IDs and matchers, without a file-size cutoff.
pub(super) fn is_reviewed_dotnet_tool_name_reference(t: &TraitDefinition) -> bool {
    if t.crit != Criticality::Notable {
        return false;
    }
    let (kind, expected) = match t.id.as_str() {
        "well-known/lib/runtime/managed/dotnet-runtime::servicemodelreg-exe-name" => {
            ("regex", r"(?i)\bServiceModelReg\.exe\b")
        }
        "well-known/lib/runtime/managed/dotnet-runtime::addinprocess32-exe-name" => {
            ("regex", r"(?i)\bAddInProcess32\.exe\b")
        }
        "well-known/lib/runtime/managed/dotnet-runtime::regasm-exe-name" => {
            ("regex", r"(?i)\bRegAsm\.exe\b")
        }
        "well-known/lib/runtime/managed/dotnet-runtime::installutil-exe-name" => {
            ("regex", r"(?i)\bInstallUtil\.exe\b")
        }
        "well-known/lib/runtime/managed/dotnet-runtime::mscorsvw-exe-name" => {
            ("regex", r"(?i)\bmscorsvw\.exe\b")
        }
        "well-known/lib/runtime/managed/dotnet-runtime::msbuild-exe-name" => {
            ("word", "MSBuild.exe")
        }
        "well-known/lib/runtime/managed/dotnet-runtime::aspnet-tool-exe-name" => {
            ("regex", r"aspnet_(compiler|regiis|state|wp)\.exe")
        }
        _ => return false,
    };
    matches!(&t.r#if, Condition::Text(q)
    if q.exact.is_none() && q.substr.is_none()
        && match kind {
            "regex" => q.regex.as_deref() == Some(expected) && q.word.is_none(),
            "word" => q.word.as_deref() == Some(expected) && q.regex.is_none(),
            _ => false,
        })
}

pub(super) fn is_reviewed_utility_reference(t: &TraitDefinition) -> bool {
    let (crit, kind, expected) = match t.id.as_str() {
        "well-known/app/utility/hwinfo::hwinfo-name-reference" => {
            (Criticality::Component, "regex", r"(?i)HWiNFO")
        }
        "well-known/app/network/filezilla::filezilla-name-reference" => {
            (Criticality::Component, "regex", r"(?i)FileZilla")
        }
        "well-known/tool/detection/wireshark::wireshark-name-reference" => {
            (Criticality::Component, "regex", r"(?i)Wireshark")
        }
        "well-known/app/productivity/notepad-plus-plus::notepad-plus-plus-name-reference" => {
            (Criticality::Component, "regex", r"(?i)Notepad\+\+")
        }
        "well-known/tool/sysadmin/7zip::sevenzip-setup-label-reference" => (
            Criticality::Notable,
            "regex",
            r"(?i)7-Zip\s+(Setup|Installer)",
        ),
        "well-known/tool/sysadmin/7zip::sevenzip-file-manager-label-reference" => (
            Criticality::Notable,
            "regex",
            r"(?i)7-Zip\s+(File Manager|Standalone)",
        ),
        "well-known/tool/sysadmin/7zip::sevenzip-console-label-reference" => (
            Criticality::Notable,
            "regex",
            r"(?i)7-Zip\s+(Console|Archiver)",
        ),
        "well-known/tool/sysadmin/7zip::sevenzip-extension-label-reference" => {
            (Criticality::Component, "regex", r"(?i)7-Zip\s+(Extension)")
        }
        "well-known/lib/data/sevenzipjbinding::sevenzipjbinding-package-path-reference" => {
            (Criticality::Notable, "substr", r"net/sf/sevenzipjbinding")
        }
        _ => return false,
    };
    t.crit == crit
        && matches!(&t.r#if, Condition::Text(q)
        if q.exact.is_none() && q.word.is_none()
            && match kind {
                "regex" => q.regex.as_deref() == Some(expected) && q.substr.is_none(),
                "substr" => q.substr.as_deref() == Some(expected) && q.regex.is_none(),
                _ => false,
            })
}

// Preserve whole-file matching only for these two specific star references.
pub(super) fn is_reviewed_star_reference(t: &TraitDefinition) -> bool {
    let expected = match t.id.as_str() {
        "well-known/tool/sysadmin/star::star-archive-format-marker" => {
            "Extended standard tar (star 1994)"
        }
        "well-known/tool/sysadmin/star::star-default-config-marker" => "/etc/default/star",
        _ => return false,
    };
    t.crit == Criticality::Notable
        && matches!(&t.r#if, Condition::Text(q)
            if q.exact.as_deref() == Some(expected)
                && q.substr.is_none() && q.regex.is_none() && q.word.is_none())
}
