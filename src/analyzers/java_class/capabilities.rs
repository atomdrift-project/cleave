//! Capability detection for Java bytecode.

use super::parsing::ClassInfo;
use crate::types::*;

impl super::JavaClassAnalyzer {
    pub(super) fn detect_capabilities(&self, class_info: &ClassInfo, report: &mut AnalysisReport) {
        // Detect suspicious class references
        let suspicious_classes = [
            (
                "java/lang/Runtime",
                "execution/process",
                "Process execution capability",
            ),
            (
                "java/lang/ProcessBuilder",
                "execution/process",
                "Process execution via ProcessBuilder",
            ),
            ("java/net/Socket", "net/socket", "Network socket operations"),
            (
                "java/net/ServerSocket",
                "net/server",
                "Network server socket",
            ),
            ("java/net/URL", "net/http", "URL/HTTP operations"),
            ("java/net/URLConnection", "net/http", "HTTP connection"),
            ("java/net/HttpURLConnection", "net/http", "HTTP operations"),
            ("javax/net/ssl", "net/ssl", "SSL/TLS operations"),
            ("java/io/File", "fs/file", "File system operations"),
            ("java/nio/file", "fs/file", "NIO file operations"),
            (
                "java/lang/reflect",
                "reflect/invoke",
                "Reflection capabilities",
            ),
            (
                "java/lang/ClassLoader",
                "reflect/classloader",
                "Dynamic class loading",
            ),
            ("javax/crypto", "crypto/cipher", "Cryptographic operations"),
            ("java/security", "crypto/security", "Security operations"),
            ("java/util/zip", "archive/zip", "ZIP archive operations"),
            ("java/util/jar", "archive/jar", "JAR archive operations"),
            ("java/sql", "data/sql", "SQL database operations"),
            (
                "javax/naming",
                "net/jndi",
                "JNDI operations (potential for injection)",
            ),
            ("java/rmi", "net/rmi", "Remote Method Invocation"),
            (
                "java/awt/Robot",
                "ui/automation",
                "UI automation (keylogger potential)",
            ),
            (
                "java/lang/System",
                "intel/system",
                "System information access",
            ),
            (
                "java/lang/Thread",
                "execution/thread",
                "Thread manipulation",
            ),
            ("sun/misc/Unsafe", "mem/unsafe", "Unsafe memory operations"),
        ];

        for class_ref in &class_info.class_refs {
            for (pattern, cap_id, description) in &suspicious_classes {
                // Use exact match or proper prefix match (pattern must match up to a / or end of string)
                // to avoid e.g. "java/lang/Runtime" matching "java/lang/RuntimeException"
                if class_ref == *pattern
                    || (class_ref.starts_with(pattern)
                        && class_ref
                            .as_bytes()
                            .get(pattern.len())
                            .map_or(true, |&b| b == b'/'))
                {
                    if !report.findings.iter().any(|c| c.id == *cap_id) {
                        report.findings.push(Finding {
                            kind: FindingKind::Capability,
                            trait_refs: vec![],
                            id: cap_id.to_string(),
                            desc: description.to_string(),
                            conf: 0.9,
                            crit: if cap_id.contains("unsafe") {
                                Criticality::Hostile
                            } else if *cap_id == "net/jndi" || *cap_id == "net/rmi" {
                                Criticality::Suspicious
                            } else {
                                Criticality::Notable
                            },
                            mbc: None,
                            attack: None,
                            evidence: vec![Evidence {
                                method: "class_reference".to_string(),
                                source: "constant_pool".to_string(),
                                value: class_ref.clone(),
                                location: None,
                                ..Default::default()
                            }],

                            match_count: 0,
                            source_file: None,
                        });
                    }
                    break;
                }
            }
        }

        // Detect suspicious method names
        for method in &class_info.methods {
            let method_lower = method.name.to_lowercase();
            if method_lower.contains("decrypt") || method_lower.contains("encrypt") {
                self.add_capability(
                    report,
                    "crypto/operation",
                    "Encryption/decryption operation",
                    &method.name,
                    Criticality::Notable,
                );
            }
            if method_lower.contains("exec")
                || method_lower.contains("command")
                || method_lower.contains("shell")
            {
                self.add_capability(
                    report,
                    "execution/command",
                    "Command execution method",
                    &method.name,
                    Criticality::Notable,
                );
            }
            if method_lower.contains("download") || method_lower.contains("upload") {
                self.add_capability(
                    report,
                    "net/transfer",
                    "File transfer operation",
                    &method.name,
                    Criticality::Suspicious,
                );
            }
            if method_lower.contains("inject") || method_lower.contains("hook") {
                self.add_capability(
                    report,
                    "execution/inject",
                    "Code injection method",
                    &method.name,
                    Criticality::Hostile,
                );
            }
            if method_lower.contains("keylog") || method_lower.contains("capture") {
                self.add_capability(
                    report,
                    "credential/keylogger",
                    "Potential keylogging",
                    &method.name,
                    Criticality::Hostile,
                );
            }
        }

        // Detect suspicious strings (RAT commands, malware indicators)
        for s in &class_info.strings {
            let s_lower = s.to_lowercase();

            // Shell/command execution - shell path references are common in legitimate
            // Java applications (build tools, IDE launchers). Only hostile when combined
            // with other indicators; standalone references are notable.
            if s_lower.contains("cmd.exe")
                || s_lower.contains("powershell")
                || s_lower.contains("power-shell")
                || s_lower.contains("pwsh")
                || s_lower.contains("/bin/sh")
                || s_lower.contains("/bin/bash")
            {
                self.add_capability(
                    report,
                    "execution/shell",
                    "Shell command string",
                    s,
                    Criticality::Notable,
                );
            }

            // URL references
            if s.contains("http://") || s.contains("https://") {
                self.add_capability(report, "net/url", "URL reference", s, Criticality::Notable);
            }

            // Credential/password stealing — high-confidence patterns are hostile,
            // bare "password" in strings is only notable (common in crypto libs, validators)
            if s_lower.contains("chrome-pass")
                || s_lower.contains("fox-pass")
                || s_lower.contains("browser") && s_lower.contains("pass")
            {
                self.add_capability(
                    report,
                    "credential/password",
                    "Credential stealing indicator",
                    s,
                    Criticality::Hostile,
                );
            } else if s_lower.contains("credential")
                || s_lower.contains("steal") && s_lower.contains("pass")
                || s_lower.contains("dump") && s_lower.contains("pass")
                || s_lower.contains("grab") && s_lower.contains("pass")
                || s_lower.contains("harvest") && s_lower.contains("pass")
            {
                self.add_capability(
                    report,
                    "credential/password",
                    "Credential stealing indicator",
                    s,
                    Criticality::Suspicious,
                );
            } else if Self::contains_word(&s_lower, "password")
                || s_lower.contains("-pass")
                || s_lower.contains("_pass")
            {
                // Bare "password" references are common in crypto libraries, validators,
                // config files — notable but not hostile without additional context
                self.add_capability(
                    report,
                    "credential/password",
                    "Password reference",
                    s,
                    Criticality::Notable,
                );
            }

            // Keylogging
            if s_lower.contains("keylog")
                || s_lower.contains("key-log")
                || s_lower.contains("o-keylogger")
                || (Self::contains_word(&s_lower, "keystroke")
                    && !s_lower.contains("javax/swing")
                    && !s_lower.contains("javax.swing"))
            {
                self.add_capability(
                    report,
                    "credential/keylogger",
                    "Keylogger indicator",
                    s,
                    Criticality::Hostile,
                );
            }

            // Encryption/decryption - common in legitimate Java apps for data protection.
            // Only suspicious when combined with other RAT indicators.
            if s_lower.contains("decrypt")
                || s_lower.contains("encrypt")
                || s_lower.contains("rw-decrypt")
                || s_lower.contains("rw-encrypt")
            {
                self.add_capability(
                    report,
                    "crypto/operation",
                    "Encryption/decryption operation",
                    s,
                    Criticality::Notable,
                );
            }

            // Download and execute
            if s_lower.contains("up-n-exec")
                || s_lower.contains("download") && s_lower.contains("exec")
                || Self::contains_word(&s_lower, "dropper")
            {
                self.add_capability(
                    report,
                    "command-and-control/dropper",
                    "Download and execute capability",
                    s,
                    Criticality::Hostile,
                );
            }

            // System control - use word boundaries to avoid false positives like
            // "textureBoots" containing "reboot"
            if Self::contains_word(&s_lower, "reboot")
                || Self::contains_word(&s_lower, "shutdown")
                || Self::contains_word(&s_lower, "uninstall")
                || s_lower.contains("self-destruct")
            {
                self.add_capability(
                    report,
                    "impact/control",
                    "System control capability",
                    s,
                    Criticality::Suspicious,
                );
            }

            // Privilege escalation
            if s_lower.contains("priv")
                && (s_lower.contains("req") || s_lower.contains("chk") || s_lower.contains("esc"))
                || s_lower.contains("elevate")
                || s_lower.contains("admin")
            {
                self.add_capability(
                    report,
                    "privilege-escalation/indicator",
                    "Privilege escalation indicator",
                    s,
                    Criticality::Suspicious,
                );
            }

            // Remote access indicators. Keep this conservative: short standalone tokens like
            // "rat" or "c2" occur in benign identifiers and decompiler output.
            let rat_context = Self::contains_word(&s_lower, "rat")
                && (s_lower.contains("remote")
                    || s_lower.contains("trojan")
                    || s_lower.contains("access")
                    || s_lower.contains("client")
                    || s_lower.contains("server")
                    || s_lower.contains("panel"));
            let c2_context = (Self::contains_word(&s_lower, "c2") || s_lower.contains("c&c"))
                && (s_lower.contains("server")
                    || s_lower.contains("channel")
                    || s_lower.contains("config")
                    || s_lower.contains("endpoint")
                    || s_lower.contains("panel"));
            let beacon_context = Self::contains_word(&s_lower, "beacon")
                && !s_lower.contains("color")
                && !s_lower.contains("texture")
                && !s_lower.contains("minecraft")
                && (s_lower.contains("http")
                    || s_lower.contains("dns")
                    || s_lower.contains("sleep")
                    || s_lower.contains("interval")
                    || s_lower.contains("callback"));
            let implant_context = Self::contains_word(&s_lower, "implant")
                && (s_lower.contains("payload")
                    || s_lower.contains("loader")
                    || s_lower.contains("session")
                    || s_lower.contains("agent"));
            if rat_context
                || c2_context
                || beacon_context
                || implant_context
                || Self::contains_word(&s_lower, "backdoor")
                || s_lower.contains("reverse") && s_lower.contains("shell")
            {
                self.add_capability(
                    report,
                    "impact/remote-access",
                    "Remote access trojan indicator",
                    s,
                    Criticality::Suspicious,
                );
            }

            // File operations
            if s_lower.contains("file-manager")
                || s_lower.contains("browse-file")
                || s_lower.contains("upload")
                || s_lower.contains("exfil")
            {
                self.add_capability(
                    report,
                    "exfiltration/data",
                    "Data exfiltration capability",
                    s,
                    Criticality::Suspicious,
                );
            }

            // Screen capture
            if s_lower.contains("screenshot")
                || s_lower.contains("screen-cap")
                || s_lower.contains("desktop") && s_lower.contains("capture")
            {
                self.add_capability(
                    report,
                    "exfiltration/screenshot",
                    "Screenshot capability",
                    s,
                    Criticality::Hostile,
                );
            }

            // Webcam/microphone
            if s_lower.contains("webcam")
                || s_lower.contains("camera")
                || s_lower.contains("microphone")
                || s_lower.contains("audio-record")
            {
                self.add_capability(
                    report,
                    "exfiltration/av-capture",
                    "Audio/video capture capability",
                    s,
                    Criticality::Hostile,
                );
            }
        }
    }

    /// Check if `haystack` contains `needle` as a whole word (surrounded by non-alphanumeric
    /// characters or string boundaries). This avoids false positives from substring matches
    /// like "rat" in "charAt" or "Generated".
    fn contains_word(haystack: &str, needle: &str) -> bool {
        let hay = haystack.as_bytes();
        let ndl = needle.as_bytes();
        if ndl.len() > hay.len() {
            return false;
        }
        for i in 0..=(hay.len() - ndl.len()) {
            if &hay[i..i + ndl.len()] == ndl {
                let before_ok = i == 0 || !hay[i - 1].is_ascii_alphanumeric();
                let after_ok =
                    i + ndl.len() == hay.len() || !hay[i + ndl.len()].is_ascii_alphanumeric();
                if before_ok && after_ok {
                    return true;
                }
            }
        }
        false
    }

    fn add_capability(
        &self,
        report: &mut AnalysisReport,
        id: &str,
        desc: &str,
        evidence_value: &str,
        crit: Criticality,
    ) {
        if !report.findings.iter().any(|c| c.id == id) {
            report.findings.push(Finding {
                kind: FindingKind::Capability,
                trait_refs: vec![],
                id: id.to_string(),
                desc: desc.to_string(),
                conf: 0.85,
                crit,
                mbc: None,
                attack: None,
                evidence: vec![Evidence {
                    method: "string_analysis".to_string(),
                    source: "constant_pool".to_string(),
                    value: evidence_value.to_string(),
                    location: None,
                    ..Default::default()
                }],

                match_count: 0,
                source_file: None,
            });
        }
    }
}
