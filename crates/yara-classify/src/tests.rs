use super::*;

fn split_rules(source: &str) -> Vec<(String, bool, &str)> {
    let mut starts: Vec<(usize, String, bool)> = Vec::new();
    let mut offset = 0usize;

    for line in source.split_inclusive('\n') {
        let line_no_nl = line.strip_suffix('\n').unwrap_or(line);
        let trimmed = line_no_nl.trim_start();
        let is_private = trimmed.starts_with("private rule ");
        let rest = if is_private {
            trimmed.strip_prefix("private rule ")
        } else {
            trimmed.strip_prefix("rule ")
        };
        if let Some(rest) = rest
            && let Some(name) = rest.split_whitespace().next()
        {
            starts.push((offset, name.trim_end_matches('{').to_string(), is_private));
        }
        offset += line.len();
    }

    let mut rules = Vec::new();
    for (idx, (start, name, is_private)) in starts.iter().enumerate() {
        let end = starts
            .get(idx + 1)
            .map(|next| next.0)
            .unwrap_or(source.len());
        rules.push((name.clone(), *is_private, &source[*start..end]));
    }

    rules
}

#[test]
fn test_infer_doc_and_script_override_platform_hints() {
    assert_eq!(
        infer_filetypes("PDF_Something", Some("windows")),
        vec!["pdf"]
    );
    assert_eq!(
        infer_filetypes("RTF_Bad_Doc", Some("linux")),
        vec!["rtf", "doc"]
    );
    assert_eq!(
        infer_filetypes("Linux_Backdoor_Bash_e427876d", None),
        vec!["sh", "bash", "zsh"]
    );
    assert_eq!(
        infer_filetypes("Win_PS1_Malware", None),
        vec!["ps1", "psm1", "psd1"]
    );
}

#[test]
fn test_infer_metadata_text_and_tags() {
    assert_eq!(
        infer_filetypes_from_metadata_text(
            "Presence of Windows Script Encoding Header in a OneNote file with embedded files",
        ),
        vec!["one", "onepkg"]
    );
    assert_eq!(
        infer_filetypes_from_tags(&["PowerShell".to_string()]),
        vec!["ps1", "psm1", "psd1"]
    );
    assert_eq!(infer_filetypes_from_tags(&["LOG".to_string()]), vec!["log"]);
    assert_eq!(
        infer_filetypes_from_tags(&["LINUXMALWARE".to_string()]),
        vec!["elf", "so"]
    );
    assert_eq!(
        infer_filetypes_from_tags(&["WINMALWARE".to_string()]),
        vec!["pe", "dll"]
    );
    assert_eq!(
        infer_filetypes_from_metadata_text("Detects malicious RDP files"),
        vec!["rdp"]
    );
    assert_eq!(
        infer_filetypes_from_metadata_text("Detects some kind of HTMLSmuggling used by APT28"),
        vec!["html"]
    );
    assert_eq!(
        infer_filetypes_from_metadata_text("Detects APT28 Phishing page"),
        vec!["html"]
    );
    assert_eq!(
        infer_filetypes_from_metadata_text(
            "https://example.invalid/yara_rules/apt_lazarus_backdoored_jslib.yar"
        ),
        vec!["js", "mjs", "cjs"]
    );
    assert_eq!(
        infer_filetypes_from_metadata_text(
            "https://example.invalid/yara_rules/apt_luckymouse_compromised_electronapp.yar"
        ),
        vec!["js", "mjs", "cjs"]
    );
    assert_eq!(
        infer_filetypes_from_metadata_text("Detects clean version of PowerShower"),
        vec!["ps1", "psm1", "psd1"]
    );
    assert_eq!(
        infer_filetypes_from_metadata_text("Auto-generated rule - file README.cup.NOPEN"),
        vec!["txt"]
    );
    assert_eq!(
        infer_filetypes_from_metadata_text("OpenVPN configuration artifact"),
        vec!["ovpn"]
    );
}

#[test]
fn test_namespace_filename_inference() {
    assert_eq!(
        infer_filetypes_from_namespace("3p.RussianPanda95.VanillaTempest.win_mal_TextShell", None),
        vec!["pe", "dll"]
    );
    assert!(infer_filetypes_from_namespace("3p.huntress.ScreenConnect", None).is_empty());
}

#[test]
fn test_magic_and_module_detection() {
    assert_eq!(filetype_from_magic("uint16(0) == 0x5A4D"), Some("pe"));
    assert_eq!(filetype_from_magic("uint32be(0) == 0x5A4D"), Some("pe"));
    assert_eq!(filetype_from_magic("uint32(0) == 0x464c457f"), Some("elf"));
    assert_eq!(filetype_from_magic("uint16(0) == 0x457f"), Some("elf"));
    assert_eq!(filetype_from_magic("int16(0) == 0x5A4D"), Some("pe"));
    assert_eq!(filetype_from_magic("int32be(0) == 0x7f454c46"), Some("elf"));
    assert_eq!(
        filetype_from_magic("uint32be(0x0) == 0x7F454C46"),
        Some("elf")
    );
    assert_eq!(
        filetype_from_magic("uint32be(0) == 0xcffaedfe"),
        Some("macho")
    );
    assert_eq!(
        filetype_from_magic("uint32be(0) == 0xcafebabe"),
        Some("macho")
    );
    assert_eq!(
        filetype_from_magic("uint32be(0) == 0x504B0304"),
        Some("zip")
    );
    assert_eq!(
        filetype_from_magic("uint32be(0) == 0xD0CF11E0"),
        Some("ole")
    );
    assert_eq!(
        filetype_from_magic("uint32be(0) == 0x6465780A"),
        Some("dex")
    );
    assert!(has_module_reference("pe.number_of_sections > 3", "pe."));
    assert!(!has_module_reference("recipe.format", "pe."));
}

#[test]
fn test_inject_condition_filetype_hints() {
    let source = r#"rule Demo {
    meta:
        description = "PE rule"
    condition:
        uint16(0) == 0x5A4D
}"#;
    let output = inject_condition_filetype_hints(source);
    assert!(output.contains("filetype = \"pe\""));
}

#[test]
fn test_canonical_binary_filetype() {
    // Single-token aliases.
    assert_eq!(canonical_binary_filetype("exe"), "pe");
    assert_eq!(canonical_binary_filetype("dll"), "pe");
    assert_eq!(canonical_binary_filetype("so"), "elf");
    assert_eq!(canonical_binary_filetype("dylib"), "macho");

    // VirusTotal's free-text vocabulary, as copied into upstream rule meta.
    // Left unresolved these become buckets no scan ever selects.
    assert_eq!(canonical_binary_filetype("win32 exe"), "pe");
    assert_eq!(canonical_binary_filetype("win64 dll"), "pe");
    assert_eq!(canonical_binary_filetype("mach-o"), "macho");
    assert_eq!(canonical_binary_filetype("elf executable"), "elf");

    // Already canonical, and unrelated types, pass through untouched.
    assert_eq!(canonical_binary_filetype("pe"), "pe");
    assert_eq!(canonical_binary_filetype("ps1"), "ps1");
    assert_eq!(
        canonical_binary_filetype("ms word document"),
        "ms word document"
    );

    // Ambiguous: words naming two different formats are not guessed at.
    assert_eq!(canonical_binary_filetype("elf and exe"), "elf and exe");
}

#[test]
fn test_inject_condition_filetype_hints_multibyte_comment() {
    // Regression: a multi-byte character (em-dash) before the rule keyword
    // used to panic find_rule_start's byte-position slicing.
    let source = "// header — with an em-dash before the rule\nrule Demo {\n    condition:\n        uint16(0) == 0x5A4D\n}";
    let output = inject_condition_filetype_hints(source);
    assert!(output.contains("filetype = \"pe\""));
    assert!(output.contains("— with an em-dash"));
}

#[test]
fn test_classify_rule_metadata_hints() {
    let source = r#"
rule DELIVRTO_SUSP_Onenote_Win_Script_Encoding_Feb23 : FILE
{
    meta:
        description = "Presence of Windows Script Encoding Header in a OneNote file with embedded files"
        source_url = "https://github.com/delivr-to/detections/blob/main/yara-rules/onenote_windows_script_encoding_file.yar"
    condition:
        true
}
"#;
    assert_eq!(
        YaraTier::classify_rule(
            "DELIVRTO_SUSP_Onenote_Win_Script_Encoding_Feb23",
            source,
            "3p.YARAForge.delivrto"
        ),
        YaraTier::Doc
    );

    let js_source = r#"
rule suspicious_node_implant : FILE
{
    meta:
        description = "JavaScript credential stealer for Electron and Node.js applications"
    condition:
        true
}
"#;
    assert_eq!(
        YaraTier::classify_rule("suspicious_node_implant", js_source, "3p.test.javascript"),
        YaraTier::ScriptJs
    );

    let rdp_source = r#"
rule SEKOIA_Apt_Apt29_Malicious_Rdp_File : FILE
{
    meta:
        description = "Detects malicious RDP files"
        source_url = "https://example.invalid/apt_apt29_malicious_rdp_file.yar"
    condition:
        true
}
"#;
    assert_eq!(
        YaraTier::classify_rule(
            "SEKOIA_Apt_Apt29_Malicious_Rdp_File",
            rdp_source,
            "3p.test.rdp"
        ),
        YaraTier::Doc
    );

    let html_smuggling_source = r#"
rule SEKOIA_Apt_Apt28_Htmlsmuggling : FILE
{
    meta:
        description = "Detects some kind of HTMLSmuggling used by APT28"
        source_url = "https://example.invalid/apt_apt28_htmlsmuggling.yar"
    condition:
        true
}
"#;
    assert_eq!(
        YaraTier::classify_rule(
            "SEKOIA_Apt_Apt28_Htmlsmuggling",
            html_smuggling_source,
            "3p.test.html"
        ),
        YaraTier::Doc
    );

    let jslib_source = r#"
rule SEKOIA_Apt_Lazarus_Backdoored_Jslib : FILE
{
    meta:
        description = "Detects InvisibleFerret based on common ressource."
        source_url = "https://example.invalid/apt_lazarus_backdoored_jslib.yar"
    condition:
        true
}
"#;
    assert_eq!(
        YaraTier::classify_rule(
            "SEKOIA_Apt_Lazarus_Backdoored_Jslib",
            jslib_source,
            "3p.test.jslib"
        ),
        YaraTier::ScriptJs
    );

    let electron_source = r#"
rule SEKOIA_Apt_Luckymouse_Compromised_Electronapp : FILE
{
    meta:
        description = "Detects compromised ElectronApp"
        source_url = "https://example.invalid/apt_luckymouse_compromised_electronapp.yar"
    condition:
        true
}
"#;
    assert_eq!(
        YaraTier::classify_rule(
            "SEKOIA_Apt_Luckymouse_Compromised_Electronapp",
            electron_source,
            "3p.test.electron"
        ),
        YaraTier::ScriptJs
    );

    let powershower_source = r#"
rule SEKOIA_Apt_Cloudatlas_Powershower_Clean : FILE
{
    meta:
        description = "Detects clean version of PowerShower"
        source_url = "https://example.invalid/apt_cloudatlas_powershower_clean.yar"
    condition:
        true
}
"#;
    assert_eq!(
        YaraTier::classify_rule(
            "SEKOIA_Apt_Cloudatlas_Powershower_Clean",
            powershower_source,
            "3p.test.ps1"
        ),
        YaraTier::Script
    );

    let readme_source = r#"
rule SIGNATURE_BASE_FVEY_Shadowbroker_README_Cup
{
    meta:
        description = "Auto-generated rule - file README.cup.NOPEN"
    condition:
        true
}
"#;
    assert_eq!(
        YaraTier::classify_rule(
            "SIGNATURE_BASE_FVEY_Shadowbroker_README_Cup",
            readme_source,
            "3p.test.readme"
        ),
        YaraTier::Doc
    );

    let log_source = r#"
rule SIGNATURE_BASE_LOG_F5_BIGIP_Exploitation_Artefacts_CVE_2021_22986_Mar21_1 : LOG
{
    meta:
        description = "Detects forensic artefacts indicating successful exploitation of F5 BIG IP appliances"
    condition:
        true
}
"#;
    assert_eq!(
        YaraTier::classify_rule(
            "SIGNATURE_BASE_LOG_F5_BIGIP_Exploitation_Artefacts_CVE_2021_22986_Mar21_1",
            log_source,
            "3p.test.log"
        ),
        YaraTier::Doc
    );
}

#[test]
fn test_classify_rule_content_hints_for_scripts_and_configs() {
    let js_source = r#"
rule SEKOIA_Apt_Tortoiseshell_Wateringhole_Script : FILE
{
    strings:
        $ = "btoa(document.referrer)"
        $ = "navigator.language"
        $ = "window.RTCPeerConnection"
        $ = "sha256(canvas.toDataURL("
    condition:
        3 of them
}
"#;
    assert_eq!(
        YaraTier::classify_rule(
            "SEKOIA_Apt_Tortoiseshell_Wateringhole_Script",
            js_source,
            "3p.test.browserjs"
        ),
        YaraTier::ScriptJs
    );

    let ps_source = r#"
rule SEKOIA_Apt_Cloudatlas_Powershower_Clean : FILE
{
    strings:
        $ = "[io.file]::WriteAllBytes($zipfile"
        $ = "System.IO.File]::Exists($p_t"
    condition:
        all of them
}
"#;
    assert_eq!(
        YaraTier::classify_rule(
            "SEKOIA_Apt_Cloudatlas_Powershower_Clean",
            ps_source,
            "3p.test.ps-body"
        ),
        YaraTier::Script
    );

    let tomcat_source = r#"
rule SIGNATURE_BASE_VUL_Tomcat_Catalina_CVE_2020_1938 : FILE
{
    strings:
        $h1 = "<?xml "
        $a1 = "<Service name=\"Catalina\">"
        $v1 = "<Connector port=\"8009\" protocol=\"AJP/1.3\" redirectPort=\"8443\"/>"
    condition:
        all of them
}
"#;
    assert_eq!(
        YaraTier::classify_rule(
            "SIGNATURE_BASE_VUL_Tomcat_Catalina_CVE_2020_1938",
            tomcat_source,
            "3p.test.tomcat"
        ),
        YaraTier::Doc
    );
}

#[test]
fn test_classify_rule_additional_magic_and_tag_variants() {
    let linux_tag_source = r#"
rule DEADBITS_Watchdog_Botnet : BOTNET LINUXMALWARE EXPLOITATION CVE_2019_11581
{
    condition:
        true
}
"#;
    assert_eq!(
        YaraTier::classify_rule(
            "DEADBITS_Watchdog_Botnet",
            linux_tag_source,
            "3p.test.deadbits"
        ),
        YaraTier::Elf
    );

    let signed_elf_source = r#"
rule SEKOIA_Apt_Apt31_Pakdoor : FILE
{
    condition:
        int32be ( 0 ) == 0x7f454c46 and true
}
"#;
    assert_eq!(
        YaraTier::classify_rule(
            "SEKOIA_Apt_Apt31_Pakdoor",
            signed_elf_source,
            "3p.test.pakdoor"
        ),
        YaraTier::Elf
    );

    let offset_elf_source = r#"
rule SECUINFRA_RANSOM_Esxiargs_Ransomware_Encryptor_Feb23
{
    condition:
        uint32be( 0x0 ) == 0x7F454C46 and true
}
"#;
    assert_eq!(
        YaraTier::classify_rule(
            "SECUINFRA_RANSOM_Esxiargs_Ransomware_Encryptor_Feb23",
            offset_elf_source,
            "3p.test.esxiargs"
        ),
        YaraTier::Elf
    );

    let fat_macho_source = r#"
rule SEKOIA_Apt_Cloudmensis_Spyagent_Strings : FILE
{
    condition:
        uint32be( 0 ) == 0xcafebabe and true
}
"#;
    assert_eq!(
        YaraTier::classify_rule(
            "SEKOIA_Apt_Cloudmensis_Spyagent_Strings",
            fat_macho_source,
            "3p.test.cloudmensis"
        ),
        YaraTier::MachO
    );

    let signed_pe_source = r#"
rule SIGNATURE_BASE_APT_NK_Lazarus_RC4_Loop : FILE
{
    condition:
        int16 ( 0 ) == 0x5a4d and true
}
"#;
    assert_eq!(
        YaraTier::classify_rule(
            "SIGNATURE_BASE_APT_NK_Lazarus_RC4_Loop",
            signed_pe_source,
            "3p.test.lazarus"
        ),
        YaraTier::Pe
    );
}

#[test]
fn test_binary_rule_name_overrides_misleading_script_metadata() {
    let source = r#"
rule ARKBIRD_SOLG_MAL_OSX_Wizardupdate_Oct_2021_2 : FILE
{
    meta:
        description = "Detect a structure like the bash of WizardUpdate installer on OSX system"
        source_url = "https://example.invalid/MAL_OSX_WizardUpdate_Oct_2021_2.yara"
    condition:
        true
}
"#;

    assert_eq!(
        YaraTier::classify_rule(
            "ARKBIRD_SOLG_MAL_OSX_Wizardupdate_Oct_2021_2",
            source,
            "3p.test.macos"
        ),
        YaraTier::MachO
    );
}

#[test]
fn test_binary_namespace_overrides_misleading_doc_metadata() {
    let source = r#"
rule TRELLIX_ARC_Pwnlnx_Backdoor_Variant_1 : BACKDOOR FILE
{
    meta:
        description = "Rule to detect the backdoor pwnlnx variant 1"
        reference = "https://example.invalid/report.pdf"
    condition:
        true
}
"#;

    assert_eq!(
        YaraTier::classify_rule(
            "TRELLIX_ARC_Pwnlnx_Backdoor_Variant_1",
            source,
            "3p.test.linux"
        ),
        YaraTier::Elf
    );
}

#[test]
fn test_os_metadata_does_not_force_binary_tier_when_namespace_has_no_signal() {
    let source = r#"
rule VOLEXITY_Susp_Php_Fileinput_Eval : FILE
{
    meta:
        description = "Rule designed to detect PHP files which use file_get_contents() and then shortly afterwards use an eval statement."
        os = "win,linux"
    condition:
        true
}
"#;

    assert_eq!(
        YaraTier::classify_rule("VOLEXITY_Susp_Php_Fileinput_Eval", source, "3p.test.any"),
        YaraTier::Script
    );
}

#[test]
fn test_scan_order() {
    assert_eq!(
        YaraTier::scan_order(Some(&["ts", "tsx", "js"])),
        vec![YaraTier::ScriptJs, YaraTier::CrossFormat]
    );
    assert_eq!(
        YaraTier::scan_order(Some(&["ps1"])),
        vec![YaraTier::Script, YaraTier::CrossFormat]
    );
    assert_eq!(
        YaraTier::scan_order(Some(&["jar", "zip"])),
        vec![YaraTier::Archive, YaraTier::CrossFormat]
    );
    assert_eq!(
        YaraTier::scan_order(None),
        vec![YaraTier::CrossFormat, YaraTier::Raw, YaraTier::Unknown]
    );
}

#[test]
fn test_cross_format_and_unknown_classification() {
    let cross_format = r#"
rule mixed_windows_linux_payload {
    meta:
        filetypes = "pe,elf"
    condition:
        true
}
"#;
    assert_eq!(
        YaraTier::classify_rule("mixed_windows_linux_payload", cross_format, "3p.test.multi"),
        YaraTier::CrossFormat
    );

    let unknown = r#"
rule opaque_family_name {
    condition:
        true
}
"#;
    assert_eq!(
        YaraTier::classify_rule("opaque_family_name", unknown, "3p.test.unknown"),
        YaraTier::Unknown
    );
}

#[test]
fn test_additional_filetype_aliases_and_name_heuristics() {
    assert_eq!(YaraTier::from_filetypes(&["apk"]), YaraTier::Archive);
    assert_eq!(YaraTier::from_filetypes(&["vhd"]), YaraTier::Archive);
    assert_eq!(YaraTier::from_filetypes(&["mach"]), YaraTier::MachO);
    assert_eq!(YaraTier::from_filetypes(&["hta"]), YaraTier::Script);
    assert_eq!(YaraTier::from_filetypes(&["au3"]), YaraTier::Script);
    assert_eq!(YaraTier::from_filetypes(&["sct"]), YaraTier::Script);
    assert_eq!(YaraTier::from_filetypes(&["svg"]), YaraTier::Doc);

    assert_eq!(
        infer_filetypes("kimsuky_downloader_pe", None),
        vec!["pe", "dll"]
    );
    assert_eq!(
        infer_filetypes("APT29_wellmess_elf", None),
        vec!["elf", "so"]
    );
    assert_eq!(
        infer_filetypes("malware_unknown_machOdownloader", None),
        vec!["macho", "dylib"]
    );
    assert_eq!(
        infer_filetypes("RUSSIANPANDA_Solarmarker_Loader_PS2EXE", None),
        vec!["pe", "dll"]
    );
    assert_eq!(
        infer_filetypes("SEKOIA_Downloader_Mac_Smooth_Operator", None),
        vec!["macho", "dylib"]
    );
}

#[test]
fn test_metadata_text_handles_android_and_containers() {
    assert_eq!(
        infer_filetypes_from_metadata_text("Detects Dex files containing GuardZoo strings."),
        vec!["apk", "dex"]
    );
    assert_eq!(
        infer_filetypes_from_metadata_text("fake gzip provided by CC"),
        vec!["gzip"]
    );
    assert_eq!(
        infer_filetypes_from_metadata_text(
            "Detect suspicious VHD file with APT28 artefacts inside"
        ),
        vec!["vhd"]
    );
    assert_eq!(
        infer_filetypes_from_metadata_text(
            "Detects Embedded PDFs which can start malicious content"
        ),
        vec!["pdf"]
    );
    assert_eq!(
        infer_filetypes_from_metadata_text("Detects DarkGate AutoIT script"),
        vec!["au3"]
    );
    assert_eq!(
        infer_filetypes_from_metadata_text("Detect IronPython script used by Turla group"),
        vec!["py", "pyc"]
    );
    assert_eq!(
        infer_filetypes_from_metadata_text("Cobalt Strike resources/template.sct signature"),
        vec!["sct", "wsf"]
    );
    assert_eq!(
        infer_filetypes_from_metadata_text("Detect samples of the Android banking trojan BRATA"),
        vec!["apk", "dex"]
    );
    assert_eq!(
        infer_filetypes_from_metadata_text("Suspicious SVG foreignObject smuggling document"),
        vec!["svg"]
    );
    assert_eq!(
        infer_filetypes_from_metadata_text("Outlook reminder exploit message"),
        vec!["msg"]
    );
    assert!(
        infer_filetypes_from_metadata_text(
            "Detects code found in report on exploits against CVE-2020-5902 F5 BIG-IP vulnerability by NCC group"
        )
        .is_empty()
    );
    assert_eq!(
        infer_filetypes_from_metadata_text("Suspicious bash script downloader"),
        vec!["sh", "bash", "zsh"]
    );
}

#[test]
fn test_classify_rule_additional_filetype_examples() {
    let apk_rule = r#"
rule SEKOIA_Apt_Yemen_Apk_Guardzoo : FILE
{
    meta:
        description = "Detects Dex files containing GuardZoo strings."
    condition:
        true
}
"#;
    assert_eq!(
        YaraTier::classify_rule("SEKOIA_Apt_Yemen_Apk_Guardzoo", apk_rule, "3p.test.android"),
        YaraTier::Archive
    );

    let vhd_rule = r#"
rule ARKBIRD_SOLG_APT_APT28_VHD_Nov_2020_1 : FILE
{
    meta:
        description = "Detect suspicious VHD file with APT28 artefacts inside"
    condition:
        true
}
"#;
    assert_eq!(
        YaraTier::classify_rule(
            "ARKBIRD_SOLG_APT_APT28_VHD_Nov_2020_1",
            vhd_rule,
            "3p.test.container"
        ),
        YaraTier::Archive
    );

    let broad_rule = r#"
rule VOLEXITY_Susp_Any_Jarischf_User_Path : FILE MEMORY
{
    meta:
        description = "Detects paths embedded in released projects."
        os = "all"
    condition:
        true
}
"#;
    assert_eq!(
        YaraTier::classify_rule(
            "VOLEXITY_Susp_Any_Jarischf_User_Path",
            broad_rule,
            "3p.test.any"
        ),
        YaraTier::CrossFormat
    );

    let multi_rule = r#"
rule BINARYALERT_Hacktool_Multi_Bloodhound_Owned : FILE
{
    condition:
        true
}
"#;
    assert_eq!(
        YaraTier::classify_rule(
            "BINARYALERT_Hacktool_Multi_Bloodhound_Owned",
            multi_rule,
            "3p.test.multi"
        ),
        YaraTier::CrossFormat
    );

    let autoit_rule = r#"
rule RUSSIANPANDA_Darkgate_Autoit
{
    meta:
        description = "Detects DarkGate AutoIT script"
    strings:
        $h = "AU3!EA06"
    condition:
        $h
}
"#;
    assert_eq!(
        YaraTier::classify_rule(
            "RUSSIANPANDA_Darkgate_Autoit",
            autoit_rule,
            "3p.test.autoit"
        ),
        YaraTier::Script
    );

    let powgoop_decoded_rule = r#"
rule SEKOIA_Apt_Muddywater_Powgoop_Decoded : FILE
{
    strings:
        $h1 = "[System.Net.WebRequest]::Create(" ascii wide
        $h2 = "Headers.Add('Authorization'" ascii wide
        $h3 = "Headers.Add('Cookie',('value=' + $ec + ';')" ascii wide
        $h4 = "GetResponseStream()" ascii wide
        $c1 = "return (65..90) + (97..122) | Get-Random -Count" ascii wide
    condition:
        3 of them
}
"#;
    assert_eq!(
        YaraTier::classify_rule(
            "SEKOIA_Apt_Muddywater_Powgoop_Decoded",
            powgoop_decoded_rule,
            "3p.test.powgoop"
        ),
        YaraTier::Script
    );

    let sysrvbot_tomcat_rule = r#"
rule backdoor_SysrvBot_tomcat {
    strings:
        $s1 = "&echo ----file ROOT good----" ascii
        $s2 = "application.getRealPath(\"tomcat.jsp\").split(\"\\\\tomcat.jsp\");" ascii
        $s3 = "ldr.sh?tomcat)|bash" ascii
    condition:
        all of them
}
"#;
    assert_eq!(
        YaraTier::classify_rule(
            "backdoor_SysrvBot_tomcat",
            sysrvbot_tomcat_rule,
            "3p.JPCERT.sysrvbot"
        ),
        YaraTier::Script
    );

    let mimipenguin_rule = r#"
rule SIGNATURE_BASE_Mimipenguin_1 : FILE
{
    strings:
        $x1 = "def _dump_target_processes(self):" fullword ascii
    condition:
        uint16( 0 ) == 0x2123 and $x1
}
"#;
    assert_eq!(
        YaraTier::classify_rule(
            "SIGNATURE_BASE_Mimipenguin_1",
            mimipenguin_rule,
            "3p.YARAForge.yara-rules-full"
        ),
        YaraTier::Script
    );

    let waterpamola_js_rule = r#"
rule WaterPamola_stealjs_str {
    strings:
        $str1 = "eval(function(p,a,c,k,"
        $str2 = "XMLHttpRequest"
        $str3 = "application/x-www-form-urlencoded"
    condition:
        all of them
}
"#;
    assert_eq!(
        YaraTier::classify_rule(
            "WaterPamola_stealjs_str",
            waterpamola_js_rule,
            "3p.JPCERT.waterpamola"
        ),
        YaraTier::ScriptJs
    );

    let batcopier_rule = r#"
rule SEKOIA_Apt_Unk_Batcopier_Strings : FILE
{
    strings:
        $ = "@echo off"
        $ = "echo F|xcopy"
        $ = "attrib +r +s +h"
    condition:
        all of them
}
"#;
    assert_eq!(
        YaraTier::classify_rule(
            "SEKOIA_Apt_Unk_Batcopier_Strings",
            batcopier_rule,
            "3p.YARAForge.yara-rules-full"
        ),
        YaraTier::Script
    );

    let bypassgodzilla_rule = r#"
rule SEKOIA_Tool_Bypassgodzilla : FILE
{
    strings:
        $jsp_1a = "response.getWriter().write(\""
        $asp_1 = "[\"payload\"]).CreateInstance(\"LY\");"
        $php_1 = "=(\"!\"^\"@\").'ss'.Chr(\"101\").'rs';"
        $php_3 = "*/isset($_SESSION/*"
        $php_4 = "@set_time_limit(Chr(\"48\"))"
    condition:
        all of them
}
"#;
    assert_eq!(
        YaraTier::classify_rule(
            "SEKOIA_Tool_Bypassgodzilla",
            bypassgodzilla_rule,
            "3p.YARAForge.yara-rules-full"
        ),
        YaraTier::Script
    );

    let pivotnacci_webshell_rule = r#"
rule SEKOIA_Tool_Pivotnacci_Webshell : FILE
{
    strings:
        $ = "Response.BinaryWrite(newBuff)"
        $ = "Request.Headers.Get(ID_HEADER)"
        $ = "extract_session_readbuf($conn_id"
    condition:
        all of them
}
"#;
    assert_eq!(
        YaraTier::classify_rule(
            "SEKOIA_Tool_Pivotnacci_Webshell",
            pivotnacci_webshell_rule,
            "3p.YARAForge.yara-rules-full"
        ),
        YaraTier::Script
    );

    let proxynotshell_log_rule = r#"
rule SIGNATURE_BASE_EXPL_Exchange_Proxynotshell_Patterns_CVE_2022_41040_Oct22_1 : SCRIPT
{
    meta:
        description = "Detects successful ProxyNotShell exploitation attempts in log files"
    condition:
        true
}
"#;
    assert_eq!(
        YaraTier::classify_rule(
            "SIGNATURE_BASE_EXPL_Exchange_Proxynotshell_Patterns_CVE_2022_41040_Oct22_1",
            proxynotshell_log_rule,
            "3p.YARAForge.yara-rules-full"
        ),
        YaraTier::Doc
    );

    let barracuda_forensics_rule = r#"
rule SIGNATURE_BASE_APT_UNC4841_ESG_Barracuda_CVE_2023_2868_Forensic_Artifacts_Jun23_1 : SCRIPT
{
    meta:
        description = "Detects forensic artifacts found in the exploitation of CVE-2023-2868 in Barracuda ESG devices by UNC4841"
    condition:
        true
}
"#;
    assert_eq!(
        YaraTier::classify_rule(
            "SIGNATURE_BASE_APT_UNC4841_ESG_Barracuda_CVE_2023_2868_Forensic_Artifacts_Jun23_1",
            barracuda_forensics_rule,
            "3p.YARAForge.yara-rules-full"
        ),
        YaraTier::Doc
    );

    let casper_output_rule = r#"
rule SIGNATURE_BASE_Casper_Systeminformation_Output
{
    meta:
        description = "Casper French Espionage Malware - System Info Output"
    condition:
        true
}
"#;
    assert_eq!(
        YaraTier::classify_rule(
            "SIGNATURE_BASE_Casper_Systeminformation_Output",
            casper_output_rule,
            "3p.YARAForge.yara-rules-full"
        ),
        YaraTier::Doc
    );

    let gsecdump_output_rule = r#"
rule SIGNATURE_BASE_Gsecdump_Password_Dump_File : FILE
{
    meta:
        description = "Detects a gsecdump output file"
    condition:
        true
}
"#;
    assert_eq!(
        YaraTier::classify_rule(
            "SIGNATURE_BASE_Gsecdump_Password_Dump_File",
            gsecdump_output_rule,
            "3p.YARAForge.yara-rules-full"
        ),
        YaraTier::Doc
    );

    let ntlm_output_rule = r#"
rule SIGNATURE_BASE_NTLM_Dump_Output
{
    meta:
        description = "NTML Hash Dump output file - John/LC format"
    condition:
        true
}
"#;
    assert_eq!(
        YaraTier::classify_rule(
            "SIGNATURE_BASE_NTLM_Dump_Output",
            ntlm_output_rule,
            "3p.YARAForge.yara-rules-full"
        ),
        YaraTier::Doc
    );

    let recon_outputs_rule = r#"
rule SIGNATURE_BASE_SUSP_Recon_Outputs_Jun20_1 : FILE
{
    meta:
        description = "Detects outputs of many different commands often used for reconnaissance purposes"
    condition:
        true
}
"#;
    assert_eq!(
        YaraTier::classify_rule(
            "SIGNATURE_BASE_SUSP_Recon_Outputs_Jun20_1",
            recon_outputs_rule,
            "3p.YARAForge.yara-rules-full"
        ),
        YaraTier::Doc
    );

    let scanbox_rule = r#"
rule SEKOIA_Apt_Scanbox_Framework_Not_Obfuscated : FILE
{
    strings:
        $ = ".fun.split_data = function"
        $ = "loadjs ="
        $ = "info.color = screen.colorDepth"
    condition:
        all of them
}
"#;
    assert_eq!(
        YaraTier::classify_rule(
            "SEKOIA_Apt_Scanbox_Framework_Not_Obfuscated",
            scanbox_rule,
            "3p.YARAForge.yara-rules-full"
        ),
        YaraTier::ScriptJs
    );

    let sharpext_rule = r#"
rule SEKOIA_Apt_Kimsuky_Sharpext_Devtoolmodule_Strings : FILE
{
    strings:
        $ = "packetProc = function"
        $ = "var url = request.request.url"
        $ = "https://mail"
    condition:
        all of them
}
"#;
    assert_eq!(
        YaraTier::classify_rule(
            "SEKOIA_Apt_Kimsuky_Sharpext_Devtoolmodule_Strings",
            sharpext_rule,
            "3p.YARAForge.yara-rules-full"
        ),
        YaraTier::ScriptJs
    );

    let powerexchange_rule = r#"
rule SEKOIA_Apt_Oilrig_Powerexchange : FILE
{
    strings:
        $ = "($h.value).PadRight((($h.value).Length+($h.value).Length%4),'=')"
        $ = "[Environment]::NewLine+$_.Exception.Message | Out-File -FilePath"
    condition:
        all of them
}
"#;
    assert_eq!(
        YaraTier::classify_rule(
            "SEKOIA_Apt_Oilrig_Powerexchange",
            powerexchange_rule,
            "3p.YARAForge.yara-rules-full"
        ),
        YaraTier::Script
    );

    let securepreferences_rule = r#"
rule SEKOIA_Apt_Kimsuky_Sharpext_Compromised_Securepreferences
{
    meta:
        description = "Detects compromised Chrome SecurePreferences file"
    condition:
        true
}
"#;
    assert_eq!(
        YaraTier::classify_rule(
            "SEKOIA_Apt_Kimsuky_Sharpext_Compromised_Securepreferences",
            securepreferences_rule,
            "3p.YARAForge.yara-rules-full"
        ),
        YaraTier::Doc
    );

    let guloader_unpacker_rule = r#"
rule SEKOIA_Guloader_Unpacker : FILE
{
    strings:
        $p1 = "([Parameter(Position = 0)] [Type[]] $" base64
        $p2 = "}else {" base64
    condition:
        all of them
}
"#;
    assert_eq!(
        YaraTier::classify_rule(
            "SEKOIA_Guloader_Unpacker",
            guloader_unpacker_rule,
            "3p.YARAForge.yara-rules-full"
        ),
        YaraTier::Script
    );

    let guloader_unpacker_decoded_rule = r#"
rule SEKOIA_Guloader_Unpacker_Decoded : FILE
{
    strings:
        $s1 = "([String]$"
        $s2 = "For($"
        $s3 = ",[Parameter(Position = 1)] [Type] $"
    condition:
        all of them
}
"#;
    assert_eq!(
        YaraTier::classify_rule(
            "SEKOIA_Guloader_Unpacker_Decoded",
            guloader_unpacker_decoded_rule,
            "3p.YARAForge.yara-rules-full"
        ),
        YaraTier::Script
    );

    let scriptlet_rule = r#"
rule GCTI_Cobaltstrike_Resources_Template_Sct_V3_3_To_V4_X
{
    meta:
        description = "Cobalt Strike's resources/template.sct signature"
    strings:
        $a = "<scriptlet>"
        $b = "<script language=\"vbscript\">"
    condition:
        all of them
}
"#;
    assert_eq!(
        YaraTier::classify_rule(
            "GCTI_Cobaltstrike_Resources_Template_Sct_V3_3_To_V4_X",
            scriptlet_rule,
            "3p.test.sct"
        ),
        YaraTier::Script
    );

    let native_iis_rule = r#"
rule ESET_IIS_Group14
{
    meta:
        description = "Detects Group 14 native IIS malware family"
    condition:
        true
}
"#;
    assert_eq!(
        YaraTier::classify_rule("ESET_IIS_Group14", native_iis_rule, "3p.test.iis"),
        YaraTier::Pe
    );

    let shortcut_rule = r#"
rule suspicious_shortcut
{
    meta:
        description = "Suspicious shortcut with remote URL"
    condition:
        true
}
"#;
    assert_eq!(
        YaraTier::classify_rule("suspicious_shortcut", shortcut_rule, "3p.test.shortcut"),
        YaraTier::Doc
    );

    let raw32_rule = r#"
rule FIREEYE_RT_APT_Loader_Raw32_REDFLARE_1 : FILE
{
    meta:
        description = "No description has been set in the source file - FireEye-RT"
    condition:
        ( uint16( 0 ) != 0x5A4D ) and true
}
"#;
    assert_eq!(
        YaraTier::classify_rule(
            "FIREEYE_RT_APT_Loader_Raw32_REDFLARE_1",
            raw32_rule,
            "3p.test.raw"
        ),
        YaraTier::Raw
    );

    let octowave_support_rule = r#"
rule SIGNATURE_BASE_Octowave_Loader_Supporting_File_03_2025 : FILE
{
    meta:
        description = "Detects supporting file used by Octowave loader containing hardcoded values"
    condition:
        uint16( 0 ) != 0x5a4d and true
}
"#;
    assert_eq!(
        YaraTier::classify_rule(
            "SIGNATURE_BASE_Octowave_Loader_Supporting_File_03_2025",
            octowave_support_rule,
            "3p.test.raw"
        ),
        YaraTier::Raw
    );

    let sliver_implant_rule = r#"
rule GCTI_Sliver_Implant_32Bit
{
    meta:
        description = "Sliver 32-bit implant (with and without --debug flag at compile)"
    condition:
        true
}
"#;
    assert_eq!(
        YaraTier::classify_rule(
            "GCTI_Sliver_Implant_32Bit",
            sliver_implant_rule,
            "3p.test.unknown"
        ),
        YaraTier::Unknown
    );

    let smooth_operator_rule = r#"
rule SEKOIA_Downloader_Mac_Smooth_Operator : FILE
{
    meta:
        description = "Detect the Smooth_Operator malware"
        source_url = "https://example.invalid/yara_rules/downloader_mac_smooth_operator.yar"
    condition:
        uint32be( 0 ) == 0xcafebabe and true
}
"#;
    assert_eq!(
        YaraTier::classify_rule(
            "SEKOIA_Downloader_Mac_Smooth_Operator",
            smooth_operator_rule,
            "3p.test.macos"
        ),
        YaraTier::MachO
    );

    let sharpnbtscan_rule = r#"
rule SEKOIA_Tool_Sharpnbtscan_Strings : FILE
{
    condition:
        uint32be( 0 ) == 0x5A4D and true
}
"#;
    assert_eq!(
        YaraTier::classify_rule(
            "SEKOIA_Tool_Sharpnbtscan_Strings",
            sharpnbtscan_rule,
            "3p.YARAForge.yara-rules-full"
        ),
        YaraTier::Pe
    );

    let malscript_rule = r#"
rule MalScript_Tricks
{
    strings:
        $s1 = "window.moveTo -"
        $s2 = "window.resizeTo 0"
    condition:
        all of them
}
"#;
    assert_eq!(
        YaraTier::classify_rule(
            "MalScript_Tricks",
            malscript_rule,
            "3p.bartblaze.generic.MalScript_Tricks"
        ),
        YaraTier::ScriptJs
    );

    let jupyter_rule = r#"
rule Jupyter
{
    strings:
        $ = "var __addr__="
        $ = "var __hwid__="
        $ = "var __xkey__="
    condition:
        all of them
}
"#;
    assert_eq!(
        YaraTier::classify_rule("Jupyter", jupyter_rule, "3p.bartblaze.crimeware.Jupyter"),
        YaraTier::ScriptJs
    );

    let systembc_config_rule = r#"
rule SystemBC_Config
{
    strings:
        $ = "BEGINDATA"
        $ = "HOST1:"
        $ = "PORT1:"
        $ = "TOR:"
    condition:
        3 of them
}
"#;
    assert_eq!(
        YaraTier::classify_rule(
            "SystemBC_Config",
            systembc_config_rule,
            "3p.bartblaze.crimeware.SystemBC"
        ),
        YaraTier::Doc
    );

    let ta18_scripts_rule = r#"
rule SIGNATURE_BASE_TA18_074A_Scripts : FILE
{
    condition:
        true
}
"#;
    assert_eq!(
        YaraTier::classify_rule(
            "SIGNATURE_BASE_TA18_074A_Scripts",
            ta18_scripts_rule,
            "3p.YARAForge.yara-rules-full"
        ),
        YaraTier::Script
    );

    let moveit_log_rule = r#"
rule SIGNATURE_BASE_LOG_EXPL_Moveit_Exploitation_Indicator_Jun23_1
{
    condition:
        true
}
"#;
    assert_eq!(
        YaraTier::classify_rule(
            "SIGNATURE_BASE_LOG_EXPL_Moveit_Exploitation_Indicator_Jun23_1",
            moveit_log_rule,
            "3p.YARAForge.yara-rules-full"
        ),
        YaraTier::Doc
    );

    let fourelementsword_config_rule = r#"
rule SIGNATURE_BASE_Fourelementsword_Config_File
{
    strings:
        $s1 = "RegisterDlls=OurDll"
        $s2 = "[DefaultInstall]"
        $s3 = "Signature=\"$Windows NT$\""
    condition:
        all of them
}
"#;
    assert_eq!(
        YaraTier::classify_rule(
            "SIGNATURE_BASE_Fourelementsword_Config_File",
            fourelementsword_config_rule,
            "3p.YARAForge.yara-rules-full"
        ),
        YaraTier::Doc
    );

    let ares_pydoor_rule = r#"
rule BlackTech_AresPYDoor_str
{
    condition:
        true
}
"#;
    assert_eq!(
        YaraTier::classify_rule(
            "BlackTech_AresPYDoor_str",
            ares_pydoor_rule,
            "3p.JPCERT.blacktech"
        ),
        YaraTier::Script
    );

    let p0wned_rule = r#"
rule SIGNATURE_BASE_Hacktool_Strings_P0Wnedshell : FILE
{
    condition:
        true
}
"#;
    assert_eq!(
        YaraTier::classify_rule(
            "SIGNATURE_BASE_Hacktool_Strings_P0Wnedshell",
            p0wned_rule,
            "3p.YARAForge.yara-rules-full"
        ),
        YaraTier::Script
    );

    let forensic_name_rule = r#"
rule SIGNATURE_BASE_Nautilus_Forensic_Artificats
{
    condition:
        true
}
"#;
    assert_eq!(
        YaraTier::classify_rule(
            "SIGNATURE_BASE_Nautilus_Forensic_Artificats",
            forensic_name_rule,
            "3p.YARAForge.yara-rules-full"
        ),
        YaraTier::Doc
    );
}

#[test]
fn test_classify_rule_pe_magic_and_module_examples() {
    let cert_rule = r#"
rule REVERSINGLABS_Cert_Blocklist_0332D5C942869Bdcabf5A8266197Cd14 : INFO FILE
{
    meta:
        description = "Certificate used for digitally signing malware."
        tags = "INFO, FILE"
    condition:
        uint16( 0 ) == 0x5A4D and for any i in ( 0 .. pe.number_of_signatures ) : (
            pe.signatures [ i ] . subject contains "JAWRO SP Z O O"
        )
}
"#;
    assert_eq!(
        YaraTier::classify_rule(
            "REVERSINGLABS_Cert_Blocklist_0332D5C942869Bdcabf5A8266197Cd14",
            cert_rule,
            "3p.test.reversinglabs"
        ),
        YaraTier::Pe
    );

    let indicator_rule = r#"
rule DITEKSHEN_INDICATOR_KB_CERT_066276Af2F2C7E246D3B1Cab1B4Aa42E : FILE
{
    meta:
        description = "Detects executables signed with stolen, revoked or invalid certificates"
    condition:
        uint16( 0 ) == 0x5a4d and for any i in ( 0 .. pe.number_of_signatures ) : (
            pe.signatures [ i ] . subject contains "IQ Trade ApS"
        )
}
"#;
    assert_eq!(
        YaraTier::classify_rule(
            "DITEKSHEN_INDICATOR_KB_CERT_066276Af2F2C7E246D3B1Cab1B4Aa42E",
            indicator_rule,
            "3p.test.ditekshen"
        ),
        YaraTier::Pe
    );
}

/// Pins two real YARAForge cert rules whose only PE signal is a
/// `pe.signatures[...]` reference — the shape that used to classify as
/// `Unknown`. The rule text lives in-repo (extracted verbatim from the
/// third-party bundle) rather than being read out of a sibling traits
/// checkout, so this asserts on every host instead of silently skipping
/// wherever that checkout is absent.
#[test]
fn test_exact_third_party_cert_examples_classify_as_pe() {
    let source = include_str!("../tests/fixtures/yaraforge_cert_rules.yar");
    for target in [
        "REVERSINGLABS_Cert_Blocklist_0332D5C942869Bdcabf5A8266197Cd14",
        "DITEKSHEN_INDICATOR_KB_CERT_066276Af2F2C7E246D3B1Cab1B4Aa42E",
    ] {
        let (_, _, rule_text) = split_rules(source)
            .into_iter()
            .find(|(name, is_private, _)| !*is_private && name == target)
            .expect("target rule present");
        let lower = rule_text.to_lowercase();
        assert!(
            filetype_from_magic(rule_text).is_some() || has_module_reference(&lower, "pe."),
            "missing PE signal for {target}: {rule_text}"
        );
        assert_eq!(
            YaraTier::classify_rule(target, rule_text, "3p.YARAForge.yara-rules-full"),
            YaraTier::Pe,
            "failed for {target}: filetype_from_magic={:?} has_pe_module={} source={rule_text}",
            filetype_from_magic(rule_text),
            has_module_reference(&lower, "pe.")
        );
    }
}

#[test]
fn test_tier_classification_fixtures() {
    let fixtures_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("tests")
        .join("yara_tier_fixtures");

    if !fixtures_dir.exists() {
        return;
    }

    let mut tested = 0;
    let mut failures: Vec<String> = Vec::new();

    for platform_entry in std::fs::read_dir(&fixtures_dir).expect("fixtures directory readable") {
        let platform_entry = platform_entry.expect("platform entry readable");
        if !platform_entry
            .file_type()
            .expect("platform file type readable")
            .is_dir()
        {
            continue;
        }
        let platform_dir = platform_entry.file_name().to_string_lossy().to_string();

        for filetype_entry in
            std::fs::read_dir(platform_entry.path()).expect("filetype directory readable")
        {
            let filetype_entry = filetype_entry.expect("filetype entry readable");
            if !filetype_entry
                .file_type()
                .expect("filetype kind readable")
                .is_dir()
            {
                continue;
            }
            let filetype_dir = filetype_entry.file_name().to_string_lossy().to_string();

            let expected_tier = match filetype_dir.split(',').next().unwrap_or("") {
                "pe" | "dll" | "exe" => YaraTier::Pe,
                "elf" | "so" => YaraTier::Elf,
                "macho" | "dylib" => YaraTier::MachO,
                "js" | "ts" | "script-js" => YaraTier::ScriptJs,
                "script" => YaraTier::Script,
                "doc" => YaraTier::Doc,
                "generic" => YaraTier::CrossFormat,
                other => {
                    failures.push(format!(
                        "Unknown filetype directory: {}/{}",
                        platform_dir, other
                    ));
                    continue;
                }
            };

            for rule_file in
                std::fs::read_dir(filetype_entry.path()).expect("rule fixture directory readable")
            {
                let rule_file = rule_file.expect("rule fixture readable");
                let path = rule_file.path();
                if path.extension().and_then(|e| e.to_str()) != Some("yar") {
                    continue;
                }

                let source = std::fs::read_to_string(&path).expect("rule fixture source readable");
                let rule_name = extract_rule_name(&source).unwrap_or_else(|| {
                    path.file_stem()
                        .expect("fixture stem")
                        .to_string_lossy()
                        .to_string()
                });

                let ns = format!("3p.test.{}", platform_dir);
                let actual_tier = YaraTier::classify_rule(&rule_name, &source, &ns);

                if actual_tier != expected_tier {
                    failures.push(format!(
                        "FAIL: {}/{}/{} — rule '{}': expected {:?}, got {:?}",
                        platform_dir,
                        filetype_dir,
                        path.file_name()
                            .expect("fixture filename")
                            .to_string_lossy(),
                        rule_name,
                        expected_tier,
                        actual_tier,
                    ));
                }
                tested += 1;
            }
        }
    }

    if !failures.is_empty() {
        panic!(
            "{} of {} tier classification tests failed:\n{}",
            failures.len(),
            tested,
            failures.join("\n"),
        );
    }
    assert!(tested > 0, "No fixture files found");
}

fn extract_rule_name(source: &str) -> Option<String> {
    for line in source.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("rule ") {
            let name = rest.split_whitespace().next()?.trim_end_matches('{');
            return Some(name.to_string());
        }
    }
    None
}

/// Opt-in diagnostic sweep over an entire third-party rule corpus, reporting
/// how the classifier tiers it. Permanently `#[ignore]`d: it needs the full
/// bundle (tens of thousands of rules, far too large to vendor), and it
/// prints a census rather than asserting a fixed expectation. Point it at a
/// traits checkout with `CLEAVE_TRAITS_DIR=/path/to/traits cargo test -p
/// yara-classify -- --ignored --nocapture audit_third_party`. The
/// classification behaviour this inspects is asserted for real by
/// `test_tier_classification_fixtures` and
/// `test_exact_third_party_cert_examples_classify_as_pe`, both of which run
/// off in-repo fixtures.
#[test]
#[ignore]
fn test_audit_third_party_residual_tiers() {
    fn collect_rule_files(dir: &std::path::Path, files: &mut Vec<std::path::PathBuf>) {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                collect_rule_files(&path, files);
            } else if path
                .extension()
                .and_then(|ext| ext.to_str())
                .map(|ext| ext == "yar" || ext == "yara")
                .unwrap_or(false)
            {
                files.push(path);
            }
        }
    }

    let Some(traits_dir) = std::env::var_os("CLEAVE_TRAITS_DIR")
        .map(|d| std::path::PathBuf::from(d).join("third-party"))
        .filter(|d| d.exists())
    else {
        eprintln!(
            "SKIP: audit_third_party_residual_tiers — set CLEAVE_TRAITS_DIR to a traits \
                 checkout containing third-party/"
        );
        return;
    };

    let mut files = Vec::new();
    collect_rule_files(&traits_dir, &mut files);
    files.sort();

    let mut counts: std::collections::HashMap<YaraTier, usize> = std::collections::HashMap::new();
    let mut cross_format = Vec::new();
    let mut raw = Vec::new();
    let mut unknown = Vec::new();

    for path in files {
        let Ok(source) = std::fs::read_to_string(&path) else {
            continue;
        };
        let rel = path.strip_prefix(&traits_dir).unwrap_or(&path);
        let ns = format!(
            "3p.{}",
            rel.with_extension("").to_string_lossy().replace('/', ".")
        );
        for (name, is_private, rule_text) in split_rules(&source) {
            if is_private {
                continue;
            }
            let tier = YaraTier::classify_rule(&name, rule_text, &ns);
            *counts.entry(tier).or_default() += 1;
            match tier {
                YaraTier::CrossFormat => cross_format.push(format!("{} (ns={})", name, ns)),
                YaraTier::Raw => raw.push(format!("{} (ns={})", name, ns)),
                YaraTier::Unknown => unknown.push(format!("{} (ns={})", name, ns)),
                _ => {}
            }
        }
    }

    cross_format.sort();
    raw.sort();
    unknown.sort();

    eprintln!("\n=== Residual Tier Audit ===");
    for tier in YaraTier::ALL {
        let count = counts.get(tier).copied().unwrap_or(0);
        eprintln!("  {:12}: {}", tier.label(), count);
    }
    eprintln!("\n=== Cross-Format Rules ({}) ===", cross_format.len());
    for name in &cross_format {
        eprintln!("  {name}");
    }
    eprintln!("\n=== Raw Rules ({}) ===", raw.len());
    for name in &raw {
        eprintln!("  {name}");
    }
    eprintln!("\n=== Unknown Rules ({}) ===", unknown.len());
    for name in &unknown {
        eprintln!("  {name}");
    }
}
