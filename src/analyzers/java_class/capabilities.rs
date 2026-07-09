//! Capability detection for Java bytecode.

use crate::analysis_context::AnalysisContext;
use crate::types::{AnalysisReport, Criticality, Evidence, Finding, FindingKind};

/// Collect a filefacts values array (e.g. `class.class_refs`) into owned strings.
fn ctx_values_array(ctx: Option<&AnalysisContext<'_>>, key: &str) -> Vec<String> {
    let Some(ctx) = ctx else {
        return Vec::new();
    };
    ctx.parsed
        .values()
        .get(key)
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

impl super::JavaClassAnalyzer {
    /// Read the constant-pool facts filefacts surfaces — the complete
    /// `CONSTANT_Class` set and `CONSTANT_Utf8` string table — and run the
    /// capability heuristics over them. cleave applies its own
    /// interesting-string policy; the parsing itself lives in filefacts.
    pub(super) fn detect_capabilities(
        &self,
        ctx: Option<&AnalysisContext<'_>>,
        report: &mut AnalysisReport,
    ) {
        let class_refs = ctx_values_array(ctx, "class.class_refs");
        let strings: Vec<String> = ctx_values_array(ctx, "class.strings")
            .into_iter()
            .filter(|s| self.is_interesting_string(s))
            .collect();
        self.detect_capabilities_from_facts(&class_refs, &strings, report);
    }

    /// Capability heuristics over already-resolved constant-pool facts.
    /// `strings` are expected to have passed [`Self::is_interesting_string`].
    pub(super) fn detect_capabilities_from_facts(
        &self,
        _class_refs: &[String],
        strings: &[String],
        report: &mut AnalysisReport,
    ) {
        let target_path = report.target.path.to_lowercase();
        let is_sig_stub = target_path.ends_with(".sig") || target_path.contains("ct.sym");
        let is_demo_artifact = target_path.contains("/demo/") || target_path.contains("j2ddemo");
        let is_plantuml_brotli_dictionary =
            target_path.contains("net/sourceforge/plantuml/brotli/dictionarydata.class");

        // Detect suspicious strings (RAT commands, malware indicators)
        for s in strings {
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
            if is_sig_stub || is_plantuml_brotli_dictionary || s_lower == "credentials_expired" {
                continue;
            }
            if s_lower.contains("chrome-pass")
                || s_lower.contains("fox-pass")
                || (s_lower.contains("browser") && s_lower.contains("password"))
            {
                self.add_capability(
                    report,
                    "credential/password",
                    "Credential stealing indicator",
                    s,
                    Criticality::Suspicious,
                );
            } else if s_lower.contains("steal") && s_lower.contains("pass")
                || s_lower.contains("dump") && s_lower.contains("pass")
                || s_lower.contains("grab") && s_lower.contains("pass")
                || s_lower.contains("harvest") && s_lower.contains("pass")
            {
                self.add_capability(
                    report,
                    "credential/password",
                    "Credential stealing indicator",
                    s,
                    Criticality::Notable,
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
            let is_java_keystroke_api = s_lower.contains("javax/swing")
                || s_lower.contains("javax.swing")
                || s_lower.contains("java/awt/awtkeystroke")
                || s_lower.contains("java.awt.awtkeystroke")
                || s_lower.contains("awtkeystroke")
                || s_lower.contains("javax/swing/keystroke")
                || s_lower.contains("javax.swing.keystroke")
                || s_lower == "app_context_keystroke_key"
                || s_lower == "getkeystroke"
                || s_lower == "getkeystrokeforevent"
                || s_lower == "keystroke.java"
                || s_lower == "awtkeystroke.java"
                || s_lower == "keystroke.class"
                || s_lower == "awtkeystroke.class"
                || s_lower == "keystroke"
                || s_lower == "keystroke: ";

            if s_lower.contains("keylog")
                || s_lower.contains("key-log")
                || s_lower.contains("o-keylogger")
                || (Self::contains_word(&s_lower, "keystroke")
                    && !is_java_keystroke_api
                    && !s_lower.contains("jline/console")
                    && !s_lower.contains("ljline/console"))
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

            // System control - use word boundaries to avoid false positives like
            // "textureBoots" containing "reboot"
            if !is_demo_artifact && Self::is_system_control_string(&s_lower) {
                self.add_capability(
                    report,
                    "impact/control",
                    "System control capability",
                    s,
                    Criticality::Notable,
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
                    Criticality::Notable,
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
                    Criticality::Notable,
                );
            }

            // File operations. Skip strings that look like Java class refs / type
            // descriptors (e.g. "org/apache/tomcat/util/http/fileupload/...") — these
            // are framework package paths, not exfiltration intent.
            let looks_like_class_path = s.contains('/') || s.starts_with('L') && s.ends_with(';');
            if !looks_like_class_path
                && (s_lower.contains("file-manager")
                    || s_lower.contains("browse-file")
                    || s_lower.contains("upload")
                    || s_lower.contains("exfiltrate")
                    || Self::contains_word(&s_lower, "exfil"))
            {
                self.add_capability(
                    report,
                    "exfiltration/data",
                    "Data exfiltration capability",
                    s,
                    Criticality::Notable,
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
                    Criticality::Notable,
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
                    Criticality::Notable,
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
        if ndl.is_empty() || ndl.len() > hay.len() {
            return false;
        }
        // SIMD-accelerated candidate search (built once per needle, then cached);
        // the boundary rule below is byte-identical to the former naive scan.
        let finder = crate::composite_rules::condition::cached_finder(needle);
        let mut from = 0;
        while let Some(rel) = finder.find(&hay[from..]) {
            let i = from + rel;
            let before_ok = i == 0 || !hay[i - 1].is_ascii_alphanumeric();
            let after_ok =
                i + ndl.len() == hay.len() || !hay[i + ndl.len()].is_ascii_alphanumeric();
            if before_ok && after_ok {
                return true;
            }
            from = i + 1;
        }
        false
    }

    fn is_system_control_string(s: &str) -> bool {
        let shell_ctx = s.contains("cmd.exe")
            || s.contains("/bin/sh")
            || s.contains("/bin/bash")
            || s.contains("powershell");
        let shutdown_flags = s.contains("/s")
            || s.contains("/r")
            || s.contains("/f")
            || s.contains("/t")
            || s.contains("-r")
            || s.contains("-f");
        let shutdown_cmd = (Self::contains_word(s, "shutdown")
            || Self::contains_word(s, "reboot")
            || s.contains("shutdown.exe"))
            && (shell_ctx || shutdown_flags);
        let uninstall_cmd = Self::contains_word(s, "uninstall")
            && (s.contains("msiexec")
                || s.contains("/quiet")
                || s.contains("/qn")
                || s.contains("remove"));

        shutdown_cmd || uninstall_cmd || s.contains("self-destruct")
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
                src: None,
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
