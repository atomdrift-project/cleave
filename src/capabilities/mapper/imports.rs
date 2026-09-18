//! Runtime import findings: metadata/import/<ecosystem>/<target>::<local-name>.
//!
//! Read typed filefacts imports, never the report's mixed import/call list.

use crate::types::{AnalysisReport, Criticality, Evidence, Finding, FindingKind};
use rustc_hash::FxHashSet;

/// A small, shared, case-insensitive set of capability-bearing import names.
/// Match complete namespace components, so e.g. `socket` matches but
/// `socket_helpers` does not. This classifies the imported target, never an
/// attacker-controlled local alias. Notable says capability, not maliciousness.
fn import_criticality(ecosystem: &str, target: &str) -> Criticality {
    // Swift's os.log is the logging module, not Python/Go's OS interface.
    // Keep this exact and ecosystem-scoped; other os imports remain notable.
    if ecosystem == "swift"
        && (target.eq_ignore_ascii_case("os.log") || target.eq_ignore_ascii_case("os/log"))
    {
        return Criticality::Baseline;
    }
    use std::sync::LazyLock;
    static NOTABLE: LazyLock<Option<regex::RegexSet>> = LazyLock::new(|| {
        regex::RegexSetBuilder::new([
            // Networking, download, exfiltration and remote control.
            r"(?:^|[./:])(socket|socketserver|requests|httpx|aiohttp|urllib3?|http|https|http2|httplib|net|dns|ftplib|smtplib|paramiko|asyncssh|websockets?|scapy|pycurl|curl|libcurl|axios|node-fetch|got|undici|needle|superagent|request|reqwest|ureq|hyper|tonic|tungstenite|tokio-tungstenite|grpc|grpcio|ssh2|net-ssh|net-http|faraday|httparty|rest-client|okhttp3?|retrofit2?|guzzlehttp|sockets|winsock2?|winhttp|wininet|network|cfnetwork|networkextension|urlsession)(?:$|[./:])",
            // Encryption, hashing, encoded payloads and byte encodings.
            r"(?:^|[./:])(crypto|cryptography|cryptodome|cryptopp|openssl|ssl|tls|hashlib|hmac|bcrypt|argon2|scrypt|aes|rsa|chacha20poly1305|ring|rustls|sodium|libsodium|nacl|pynacl|base64|base32|binascii|codecs|encoding|hex|atob|btoa|buffer|textencoder|textdecoder|cryptokit|commoncrypto)(?:$|[./:])",
            // Process execution, OS/native interfaces and dynamic code loading.
            r"(?:^|[./:])(os|ctypes|cffi|ffi|ffi-napi|ref-napi|child_process|subprocess|multiprocessing|pty|pexpect|popen2|commands|execa|shelljs|node-pty|cross-spawn|process|processbuilder|syscall|libc|nix|winapi|windows-sys|windows|unistd|dlfcn|win32api|win32process|win32con|win32com|pythonnet|psutil|koffi|open3|open4|fiddle|libloading|importlib|reflect|reflection|vm|marshal|pickle|dill|cloudpickle)(?:$|[./:])",
            // Payload staging, filesystem traversal and archive unpacking.
            r"(?:^|[./:])(shutil|fs|fs-extra|pathlib|glob|walkdir|tempfile|zipfile|tarfile|gzip|zlib|bz2|lzma|zip|tar|flate2|xz2|archiver|adm-zip|jszip|extract-zip|unzipper|compress|compression|fileutils|filemanager|filesystem)(?:$|[./:])",
            // Credentials, browser stores, host discovery, input/screen capture.
            r"(?:^|[./:])(keyring|keytar|keychain|keychaindb|keyutils|secretstorage|win32cred|win32crypt|browser_cookie3|browsercookie|sqlite3|rusqlite|better-sqlite3|sqlcipher|pynput|keyboard|pyautogui|pyperclip|mss|pyscreenshot|screenshot|screenshots|clipboard|robotjs|iohook|uiohook-napi|rdev|enigo|arboard|device_query|screenshot-desktop|node-machine-id|wmi|winreg|win32security|security-framework)(?:$|[./:])",
            // Cloud/CI credentials and service APIs usable for exfiltration/C2.
            r"(?:^|[./:])(boto3|botocore|azure|aws-sdk|@aws-sdk|aws-sdk-go|aws-sdk-go-v2|@google-cloud|octokit|@octokit|pygithub|github3|go-github|gitlab|docker|kubernetes|client-go|discord|discordjs|telegram|telebot|slack_sdk|@slack|twilio|sendgrid|nodemailer|telethon|msal|jwt|jsonwebtoken|jose)(?:$|[./:])",
            // Persistence and job/service management.
            r"(?:^|[./:])(cron|crontab|node-cron|node-schedule|schedule|apscheduler|daemon|pywin32|pyroute2|dbus|dbus_next|servicemanager|node-windows|win32service|win32serviceutil|systemd|launchd)(?:$|[./:])",
            // Browser/session access, wallet signing, secret loading, host
            // reconnaissance and additional code/payload execution helpers.
            r"(?:^|[./:])(getpass|platform|dotenv|dotenvy|godotenv|playwright|puppeteer|selenium|chromedp|webdriver|eth_account|web3|ethers|@solana|solana|bitcoin|bip32|bip39|vm2|isolated-vm|wasmtime|wasmer|scriptengine|scriptenginemanager|classloader|urlclassloader|@modelcontextprotocol|mcp|fastmcp|impacket|pwn|pwntools|frida|win32clipboard|win32gui|win32ui|base58|base85|bs58|pbkdf2|md5|sha1|sha2|sha3|tar-fs|tar-stream|py7zr|pako|lz-string|sudo-prompt|node-cmd|powershell|duct)(?:$|[./:])",
            // Additional networking and cryptographic library variants.
            r"(?:^|[./:])(ws|crypto-js|tweetnacl|node-forge|sjcl|elliptic|openssl-sys|https-proxy-agent|http-proxy-agent|socks-proxy-agent|proxy-agent|socks|socks5|lwp|mechanize|node-telegram-bot-api)(?:$|[./:])",
            // Qualified platform APIs whose generic leaf names are ambiguous.
            r"(?:^|[./:])(java[./:]lang[./:]Runtime|System[./:](IO|Management|Diagnostics[./:]Process|Runtime[./:]InteropServices)|Microsoft[./:]Win32|golang[./:]org/x/sys|google[./:]cloud|google[./:]auth)(?:$|[./:])",
        ])
        .case_insensitive(true)
        .build()
        .ok()
    });
    // A relative module named requests is not evidence of importing requests.
    let Some(notable) = NOTABLE.as_ref() else {
        return Criticality::Baseline;
    };
    let target = target.replace("::", "/").replace('\\', "/");
    if !target.starts_with('.') && notable.is_match(&target) {
        Criticality::Notable
    } else {
        Criticality::Baseline
    }
}

/// Dynamic imports and directory references share the emitted ecosystem list.
/// Static YAML namespaces such as package, builtin and framework are not exempt.
pub(crate) fn is_dynamic_import_ref(id: &str) -> bool {
    let Some(rest) = id.strip_prefix("metadata/import/") else {
        return false;
    };
    let (path, local) = match rest.split_once("::") {
        Some((path, local)) => (path, Some(local)),
        None => (rest.trim_end_matches('/'), None),
    };
    let mut parts = path.split('/');
    let ecosystem = parts.next().unwrap_or("");
    if !matches!(
        ecosystem,
        "python"
            | "npm"
            | "ruby"
            | "java"
            | "go"
            | "rust"
            | "c"
            | "php"
            | "perl"
            | "lua"
            | "shell"
            | "powershell"
            | "swift"
            | "objc"
            | "dotnet"
            | "scala"
            | "groovy"
            | "elixir"
            | "zig"
            | "applescript"
    ) {
        return false;
    }
    let modules: Vec<_> = parts.collect();
    if modules.iter().any(|p| p.is_empty() || p.contains(':')) {
        return false;
    }
    local.is_none_or(|local| !modules.is_empty() && !local.is_empty() && !local.contains(':'))
}

impl super::CapabilityMapper {
    pub(crate) fn generate_import_findings(
        report: &mut AnalysisReport,
        parsed: &filefacts::ParsedFile<'_>,
    ) {
        let ecosystem = Self::detect_import_ecosystem(&report.target.file_type.to_lowercase(), "");
        // Binary library findings are a separate namespace. Only source imports
        // participate in this hierarchy.
        if !is_dynamic_import_ref(&format!("metadata/import/{ecosystem}")) {
            return;
        }
        let mut seen: FxHashSet<String> =
            report.findings.iter().map(|f| f.id.to_string()).collect();
        for symbol in parsed.symbols().iter_kind(filefacts::SymbolKind::Import) {
            let filefacts::Symbol::Import {
                name,
                library,
                alias,
                offset,
                ..
            } = symbol
            else {
                continue;
            };
            let module = library.as_deref().filter(|s| !s.is_empty()).unwrap_or(name);
            // Source from-import members carry their owner separately. Relative
            // Python members are already qualified by filefacts.
            let target = if library.is_some() && !name.starts_with('.') {
                format!("{}.{}", module.trim_end_matches('.'), name)
            } else {
                name.clone()
            };
            let target = if ecosystem == "npm" {
                target.strip_prefix("node:").unwrap_or(&target).to_string()
            } else {
                target
            };
            // `from . import name` also has a module capture of just `.`.
            // It names no imported target; the qualified member is the fact.
            if Self::normalize_import_name(&target).is_empty() {
                continue;
            }
            let normalized = Self::normalize_source_module(&target);
            let local = alias
                .as_deref()
                .filter(|s| !s.is_empty())
                .map(str::to_string)
                .unwrap_or_else(|| {
                    if library.is_none() {
                        return normalized.clone();
                    }
                    Self::normalize_import_name(if library.is_some() && name.starts_with('.') {
                        name.rsplit('.').next().unwrap_or(name)
                    } else {
                        name
                    })
                });
            if normalized.is_empty() || local.is_empty() {
                continue;
            }
            let id = format!("metadata/import/{ecosystem}/{normalized}::{local}");
            if !seen.insert(id.clone()) {
                continue;
            }
            let mut desc = if library.is_some() {
                format!("imports {name} from {module}")
            } else {
                format!("imports {name}")
            };
            if let Some(alias) = alias {
                desc.push_str(&format!(" as {alias}"));
            }
            report.push_finding_capped(Finding {
                id: id.into(),
                kind: FindingKind::Structural,
                desc: desc.into(),
                conf: 0.95,
                crit: import_criticality(ecosystem, &target),
                evidence: vec![Evidence {
                    method: "import".to_string(),
                    source: "filefacts".to_string(),
                    value: name.clone(),
                    location: offset.map(|offset| format!("0x{offset:x}")),
                    ..Default::default()
                }],
                ..Default::default()
            });
        }
    }

    /// Keep local relative imports distinct from external packages.
    fn normalize_source_module(module: &str) -> String {
        let relative = module.bytes().take_while(|b| *b == b'.').count();
        let normalized = Self::normalize_import_name(module);
        if relative == 0 {
            normalized
        } else if normalized.is_empty() {
            format!("relative/{relative}")
        } else {
            format!("relative/{relative}/{normalized}")
        }
    }

    /// Detect the ecosystem for an import based on file type and source.
    pub(crate) fn detect_import_ecosystem(file_type: &str, source: &str) -> &'static str {
        // First check source for explicit ecosystem markers
        match source {
            "npm" | "package.json" => return "npm",
            "pip" | "pypi" | "requirements.txt" => return "pypi",
            "gem" | "rubygems" | "gemfile" => return "rubygems",
            "cargo" | "crates.io" => return "cargo",
            "go" | "go.mod" => return "gomod",
            "maven" | "gradle" | "pom.xml" => return "maven",
            "composer" => return "composer",
            _ => {}
        }

        // For binary formats, use the binary type as ecosystem
        match file_type {
            "elf" | "so" => return "elf",
            "macho" | "dylib" => return "macho",
            "pe" | "exe" | "dll" => return "pe",
            _ => {}
        }

        // For source code, detect language from file type
        match file_type {
            "python" | "python_script" => "python",
            "javascript" | "js" | "typescript" | "ts" => "npm",
            "ruby" | "rb" => "ruby",
            "java" | "class" => "java",
            "go" => "go",
            "rust" | "rs" => "rust",
            "c" | "cpp" | "h" | "hpp" => "c",
            "php" => "php",
            "perl" | "pl" => "perl",
            "lua" => "lua",
            "shell" | "shellscript" | "shell_script" | "bash" | "sh" => "shell",
            "powershell" | "ps1" => "powershell",
            "swift" => "swift",
            "objectivec" | "objc" | "m" => "objc",
            "csharp" | "cs" => "dotnet",
            "scala" | "sc" => "scala",
            "groovy" | "gradle" => "groovy",
            "elixir" | "ex" | "exs" => "elixir",
            "zig" => "zig",
            "applescript" | "scpt" => "applescript",
            _ => "unknown",
        }
    }

    /// Normalize an import name for use in a finding ID.
    ///
    /// - Converts to lowercase
    /// - Converts dots and slashes to path separators (/)
    /// - Replaces other special characters with hyphens
    /// - Removes leading/trailing separators
    /// - Collapses multiple separators
    pub(crate) fn normalize_import_name(name: &str) -> String {
        // Convert dots and slashes to path separators for consistent hierarchical naming:
        // - Python: os.path.join -> os/path/join
        // - Ruby: net/http -> net/http
        // Replace other special chars with hyphens, collapse consecutive separators
        let mut result = String::with_capacity(name.len());
        let mut prev_sep = true; // Skip leading separators

        for c in name
            .replace("::", "/")
            .replace('\\', "/")
            .to_lowercase()
            .chars()
        {
            match c {
                c if c.is_ascii_alphanumeric() || c == '_' => {
                    result.push(c);
                    prev_sep = false;
                }
                '.' | '/' => {
                    // Both dots and slashes become path separators
                    if !prev_sep {
                        result.push('/');
                        prev_sep = true;
                    }
                }
                _ => {
                    if !prev_sep {
                        result.push('-');
                        prev_sep = true;
                    }
                }
            }
        }

        // Trim trailing separator
        if result.ends_with('/') || result.ends_with('-') {
            result.pop();
        }

        result
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use crate::capabilities::CapabilityMapper;
    use crate::composite_rules::{EvaluationContext, FileType};
    use crate::types::TargetInfo;

    #[test]
    fn dynamic_import_criticality_covers_major_language_capabilities() {
        for target in [
            "socket",
            "requests",
            "httpx.Client",
            "urllib.request",
            "Crypto.Cipher.AES",
            "hashlib",
            "base64",
            "os",
            "ctypes",
            "subprocess",
            "pickle",
            "zipfile",
            "keyring",
            "browser_cookie3",
            "sqlite3",
            "pynput",
            "pyautogui",
            "winreg",
            "boto3",
            "node:child_process",
            "node:fs/promises",
            "node-fetch",
            "@aws-sdk/client-s3",
            "@octokit/rest",
            "discord.js",
            "ffi-napi",
            "robotjs",
            "node-cron",
            "net/http",
            "os/exec",
            "encoding/base64",
            "crypto/tls",
            "golang.org/x/sys/unix",
            "std::process::Command",
            "reqwest::blocking",
            "libloading",
            "rustls",
            "arboard",
            "java.net.Socket",
            "java.lang.Runtime",
            "java.lang.ProcessBuilder",
            "javax.crypto.Cipher",
            "System.Net.Http",
            "System.Security.Cryptography",
            "System.Runtime.InteropServices",
            "System.IO",
            "Microsoft.Win32",
            "NET::HTTP",
            "Open3",
            "OpenSSL",
            "Fiddle",
            "GuzzleHttp\\Client",
            "IO::Socket::SSL",
            "MIME::Base64",
            "sys/socket.h",
            "unistd.h",
            "openssl/evp.h",
            "WinSock2.h",
            "CryptoKit",
            "Network",
            "socket.http",
            "getpass",
            "platform",
            "dotenv",
            "playwright",
            "puppeteer",
            "eth_account",
            "ethers",
            "@solana/web3.js",
            "vm2",
            "wasmtime",
            "@modelcontextprotocol/sdk",
            "impacket",
            "win32clipboard",
            "bs58",
            "ws",
            "crypto-js",
            "tweetnacl",
            "node-forge",
            "https-proxy-agent",
            "LWP::UserAgent",
            "node-telegram-bot-api",
        ] {
            assert_eq!(
                import_criticality("python", target),
                Criticality::Notable,
                "{target}"
            );
        }
        for target in [
            "math",
            "json",
            "sys",
            "collections",
            "typing",
            "io",
            "mmap",
            "stdio.h",
            "stddef.h",
            "fmt",
            "strings",
            "std::collections",
            "java.util.List",
            "System.Collections.Generic",
            "serde",
            "react",
            "lodash",
            "date",
            "unknown_package",
            "myrequests",
            "requests_helper",
            "socketio_helpers",
            "cryptography_utils",
            "custom_os",
            "oscar",
            "http_tools",
            "processes",
            ".requests",
            "..socket",
            "./node_modules/axios",
        ] {
            assert_eq!(
                import_criticality("python", target),
                Criticality::Baseline,
                "{target}"
            );
        }
    }

    #[test]
    fn dynamic_import_swift_logging_exception_is_narrow() {
        for target in ["os.log", "OS.LOG", "os/log"] {
            assert_eq!(import_criticality("swift", target), Criticality::Baseline);
            assert_eq!(import_criticality("python", target), Criticality::Notable);
            assert_eq!(import_criticality("go", target), Criticality::Notable);
        }
        for target in ["os", "os.loggable", "os.log.socket", "Network", "CryptoKit"] {
            assert_eq!(import_criticality("swift", target), Criticality::Notable);
        }
    }

    #[test]
    fn dynamic_import_alias_does_not_change_criticality() {
        let source = b"import math as socket\nimport SoCkEt as math\n";
        let mut report = AnalysisReport::new(TargetInfo {
            path: "aliases.py".into(),
            file_type: "python".into(),
            size_bytes: source.len() as u64,
            sha256: "test".into(),
            architectures: None,
        });
        CapabilityMapper::empty().evaluate_and_merge_findings(&mut report, source, None, None);
        for (id, criticality) in [
            ("metadata/import/python/math::socket", Criticality::Baseline),
            ("metadata/import/python/socket::math", Criticality::Notable),
        ] {
            assert_eq!(
                report.findings.iter().find(|f| f.id == id).unwrap().crit,
                criticality
            );
        }
    }

    #[test]
    fn dynamic_imports_are_emitted_for_major_source_languages() {
        for (path, file_type, source, expected, criticality) in [
            (
                "imports.swift",
                "swift",
                "import Foundation\nimport os.log\n",
                "metadata/import/swift/os/log::os/log",
                Criticality::Baseline,
            ),
            (
                "imports.js",
                "javascript",
                "import 'node:fs/promises';\n",
                "metadata/import/npm/fs/promises::fs/promises",
                Criticality::Notable,
            ),
            (
                "imports.go",
                "go",
                "package main\nimport \"net/http\"\nfunc main() {}\n",
                "metadata/import/go/net/http::net/http",
                Criticality::Notable,
            ),
            (
                "imports.rb",
                "ruby",
                "require 'net/http'\n",
                "metadata/import/ruby/net/http::net/http",
                Criticality::Notable,
            ),
            (
                "imports.rs",
                "rust",
                "use std::process::Command;\nfn main() {}\n",
                "metadata/import/rust/std/process/command::std/process/command",
                Criticality::Notable,
            ),
            (
                "imports.c",
                "c",
                "#include <stdio.h>\nint main(void) { return 0; }\n",
                "metadata/import/c/stdio/h::stdio/h",
                Criticality::Baseline,
            ),
        ] {
            let mut report = AnalysisReport::new(TargetInfo {
                path: path.into(),
                file_type: file_type.into(),
                size_bytes: source.len() as u64,
                sha256: "test".into(),
                architectures: None,
            });
            CapabilityMapper::empty().evaluate_and_merge_findings(
                &mut report,
                source.as_bytes(),
                None,
                None,
            );
            let finding = report.findings.iter().find(|f| f.id == expected);
            assert!(
                finding.is_some(),
                "{path}: missing {expected}; got {:?}",
                report.findings.iter().map(|f| &f.id).collect::<Vec<_>>()
            );
            assert_eq!(finding.unwrap().crit, criticality, "{path}");
        }
    }

    #[test]
    fn dynamic_imports_reach_evaluation_with_library_and_alias() {
        let source = b"import os\nimport requests as R\nfrom os import path\nfrom os import path as p\nfrom sys import path as p\nfrom . import requests as local\nprint('not an import')\n";
        let mut report = AnalysisReport::new(TargetInfo {
            path: "imports.py".into(),
            file_type: "python".into(),
            size_bytes: source.len() as u64,
            sha256: "test".into(),
            architectures: None,
        });
        let mapper = CapabilityMapper::empty();
        mapper.evaluate_and_merge_findings(&mut report, source, None, None);
        let ids: Vec<&str> = report.findings.iter().map(|f| f.id.as_str()).collect();
        for expected in [
            "metadata/import/python/os::os",
            "metadata/import/python/requests::R",
            "metadata/import/python/os/path::path",
            "metadata/import/python/os/path::p",
            "metadata/import/python/sys/path::p",
            "metadata/import/python/relative/1/requests::local",
        ] {
            assert!(ids.contains(&expected), "missing {expected}: {ids:?}");
        }
        assert!(!ids.iter().any(|id| id.contains("print")));
        assert!(!ids.contains(&"metadata/import/python/requests::local"));
        assert!(!ids.contains(&"metadata/import/python/relative/1::relative/1"));
        assert!(
            report
                .findings
                .iter()
                .all(|f| f.evidence.iter().all(|e| e.location.is_some()))
        );

        // Existing directory semantics match every alias, but an exact local
        // name remains exact. These results also feed hierarchy-based ML.
        let ctx = EvaluationContext::test_only_new(&report, source, FileType::Python);
        for reference in [
            "metadata/import/python/requests",
            "metadata/import/python/os/path::p",
        ] {
            assert!(
                crate::composite_rules::evaluators::eval_trait(reference, &ctx).matched,
                "{reference}"
            );
        }
        let before = report.findings.len();
        mapper.evaluate_and_merge_findings(&mut report, source, None, None);
        assert_eq!(
            before,
            report.findings.len(),
            "re-evaluation must not duplicate imports"
        );
        assert_eq!(
            report
                .findings
                .iter()
                .find(|f| f.id == "metadata/import/python/requests::R")
                .unwrap()
                .crit,
            Criticality::Notable
        );
        assert_eq!(
            report
                .findings
                .iter()
                .find(|f| f.id == "metadata/import/python/sys/path::p")
                .unwrap()
                .crit,
            Criticality::Baseline
        );
        assert_eq!(report.strip_unmatched_traits(), (0, 0));
        assert_eq!(
            report.findings.len(),
            before,
            "unreferenced imports must survive JSON/diff filtering"
        );
    }

    #[test]
    fn dynamic_import_refs_reject_old_and_static_namespaces() {
        for valid in [
            "metadata/import/python",
            "metadata/import/python/os/",
            "metadata/import/python/os::p",
            "metadata/import/npm/fs-extra::fs",
        ] {
            assert!(is_dynamic_import_ref(valid), "{valid}");
        }
        for invalid in [
            "metadata/import/python::os",
            "metadata/import/package::typo",
            "metadata/import/package/fs",
            "metadata/import/python/os::",
            "metadata/import/python//os::os",
        ] {
            assert!(!is_dynamic_import_ref(invalid), "{invalid}");
        }
    }

    #[test]
    fn dynamic_import_alias_cannot_impersonate_a_member() {
        for (source, expected, imports_system) in [
            (
                "import os as system\n",
                "metadata/import/python/os::system",
                false,
            ),
            (
                "from os import path as system\n",
                "metadata/import/python/os/path::system",
                false,
            ),
            (
                "from os import system\n",
                "metadata/import/python/os/system::system",
                true,
            ),
            (
                "from os import system as run\n",
                "metadata/import/python/os/system::run",
                true,
            ),
        ] {
            let mut report = AnalysisReport::new(TargetInfo {
                path: "imports.py".into(),
                file_type: "python".into(),
                size_bytes: source.len() as u64,
                sha256: "test".into(),
                architectures: None,
            });
            let mut mapper = CapabilityMapper::empty();
            mapper
                .composite_rules
                .push(crate::composite_rules::CompositeTrait {
                    id: "objectives/test::system-import".into(),
                    desc: "Imports the system member".into(),
                    crit: Criticality::Notable,
                    conf: 0.9,
                    r#for: vec![FileType::Python],
                    platforms: vec![crate::composite_rules::Platform::All],
                    all: Some(vec![crate::composite_rules::Condition::Trait {
                        id: "metadata/import/python/os/system".into(),
                    }]),
                    ..Default::default()
                });
            mapper.evaluate_and_merge_findings(&mut report, source.as_bytes(), None, None);
            assert!(report.findings.iter().any(|f| f.id == expected), "{source}");
            assert_eq!(
                report
                    .findings
                    .iter()
                    .any(|f| f.id == "objectives/test::system-import"),
                imports_system,
                "{source}"
            );
        }
    }
}
