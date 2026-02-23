//! Test module.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! Tests for string extraction and classification
//!
//! Comprehensive test coverage for:
//! - String type classification (URL, IP, Email, Path, Base64)
//! - IP address validation (excluding version strings)
//! - Path detection (Unix, Windows, relative)
//! - Go binary detection
//! - Symbol normalization
//! - Edge cases and malware indicators

use super::strings::StringExtractor;
use crate::types::StringType;
use std::collections::HashMap;

/// Helper: Create extractor with defaults
fn create_extractor() -> StringExtractor {
    StringExtractor::new()
}

// ==================== String Classification Tests ====================

#[test]
fn test_classify_url_http() {
    let extractor = create_extractor();
    assert_eq!(
        extractor.classify_string_type("http://example.com"),
        StringType::Url
    );
}

#[test]
fn test_classify_url_https() {
    let extractor = create_extractor();
    assert_eq!(
        extractor.classify_string_type("https://malware.example.com/payload.exe"),
        StringType::Url
    );
}

#[test]
fn test_classify_url_ftp() {
    let extractor = create_extractor();
    assert_eq!(
        extractor.classify_string_type("ftp://ftp.example.com/files/"),
        StringType::Url
    );
}

#[test]
fn test_classify_url_with_port() {
    let extractor = create_extractor();
    assert_eq!(
        extractor.classify_string_type("https://c2server.com:8443/beacon"),
        StringType::Url
    );
}

#[test]
fn test_classify_url_with_params() {
    let extractor = create_extractor();
    assert_eq!(
        extractor.classify_string_type("https://api.example.com/data?key=value&id=123"),
        StringType::Url
    );
}

#[test]
fn test_classify_ip_valid() {
    let extractor = create_extractor();
    assert_eq!(
        extractor.classify_string_type("192.168.1.1"),
        StringType::Ip
    );
}

#[test]
fn test_classify_ip_loopback() {
    let extractor = create_extractor();
    assert_eq!(
        extractor.classify_string_type("127.0.0.1"),
        StringType::Ip
    );
}

#[test]
fn test_classify_ip_public() {
    let extractor = create_extractor();
    assert_eq!(
        extractor.classify_string_type("8.8.8.8"),
        StringType::Ip
    );
}

#[test]
fn test_classify_ip_with_text() {
    let extractor = create_extractor();
    assert_eq!(
        extractor.classify_string_type("Connect to 10.0.0.5 for C2"),
        StringType::Ip
    );
}

#[test]
fn test_classify_version_not_ip() {
    let extractor = create_extractor();
    // Version strings should NOT be classified as IPs
    assert_eq!(
        extractor.classify_string_type("Chrome/100.0.0.0"),
        StringType::Const
    );
}

#[test]
fn test_classify_safari_version_not_ip() {
    let extractor = create_extractor();
    assert_eq!(
        extractor.classify_string_type("Safari/537.36.0.0"),
        StringType::Const
    );
}

#[test]
fn test_classify_invalid_ip_out_of_range() {
    let extractor = create_extractor();
    // Octets > 255 should not be IPs
    assert_eq!(
        extractor.classify_string_type("999.999.999.999"),
        StringType::Const
    );
}

#[test]
fn test_classify_email_simple() {
    let extractor = create_extractor();
    assert_eq!(
        extractor.classify_string_type("user@example.com"),
        StringType::Email
    );
}

#[test]
fn test_classify_email_with_subdomain() {
    let extractor = create_extractor();
    assert_eq!(
        extractor.classify_string_type("contact@mail.company.com"),
        StringType::Email
    );
}

#[test]
fn test_classify_email_with_plus() {
    let extractor = create_extractor();
    assert_eq!(
        extractor.classify_string_type("user+tag@example.com"),
        StringType::Email
    );
}

#[test]
fn test_classify_path_unix_absolute() {
    let extractor = create_extractor();
    assert_eq!(
        extractor.classify_string_type("/usr/bin/bash"),
        StringType::Path
    );
}

#[test]
fn test_classify_path_unix_etc() {
    let extractor = create_extractor();
    assert_eq!(
        extractor.classify_string_type("/etc/passwd"),
        StringType::Path
    );
}

#[test]
fn test_classify_path_unix_tmp() {
    let extractor = create_extractor();
    assert_eq!(
        extractor.classify_string_type("/tmp/malware.sh"),
        StringType::Path
    );
}

#[test]
fn test_classify_path_windows() {
    let extractor = create_extractor();
    assert_eq!(
        extractor.classify_string_type(r"C:\Windows\System32\cmd.exe"),
        StringType::Path
    );
}

#[test]
fn test_classify_path_windows_program_files() {
    let extractor = create_extractor();
    assert_eq!(
        extractor.classify_string_type(r"C:\Program Files\App\binary.exe"),
        StringType::Path
    );
}

#[test]
fn test_classify_base64_valid() {
    let extractor = create_extractor();
    // 16+ chars of valid base64
    assert_eq!(
        extractor.classify_string_type("SGVsbG8gV29ybGQh"),
        StringType::Base64
    );
}

#[test]
fn test_classify_base64_with_padding() {
    let extractor = create_extractor();
    assert_eq!(
        extractor.classify_string_type("VGhpcyBpcyBhIHRlc3Q="),
        StringType::Base64
    );
}

#[test]
fn test_classify_base64_long() {
    let extractor = create_extractor();
    // Malware often uses long base64 strings
    let long_base64 = "VGhpcyBpcyBhIHZlcnkgbG9uZyBiYXNlNjQgZW5jb2RlZCBzdHJpbmcgdGhhdCBtaWdodCBjb250YWluIG1hbGljaW91cyBwYXlsb2Fk";
    assert_eq!(
        extractor.classify_string_type(long_base64),
        StringType::Base64
    );
}

#[test]
fn test_classify_base64_too_short() {
    let extractor = create_extractor();
    // Less than 16 chars should not be classified as base64
    assert_eq!(
        extractor.classify_string_type("SGVsbG8="),
        StringType::Const
    );
}

#[test]
fn test_classify_plain_text() {
    let extractor = create_extractor();
    assert_eq!(
        extractor.classify_string_type("Hello World"),
        StringType::Const
    );
}

#[test]
fn test_classify_plain_with_numbers() {
    let extractor = create_extractor();
    assert_eq!(
        extractor.classify_string_type("Build version 1.2.3"),
        StringType::Const
    );
}

// ==================== Symbol Classification Tests ====================

#[test]
fn test_classify_import_symbol() {
    let mut extractor = create_extractor();
    let mut imports = std::collections::HashSet::new();
    imports.insert("CreateRemoteThread".to_string());
    extractor = extractor.with_imports(&imports);

    assert_eq!(
        extractor.classify_string_type("CreateRemoteThread"),
        StringType::Import
    );
}

#[test]
fn test_classify_export_symbol() {
    let mut extractor = create_extractor();
    let mut exports = std::collections::HashSet::new();
    exports.insert("DllMain".to_string());
    extractor = extractor.with_exports(&exports);

    assert_eq!(
        extractor.classify_string_type("DllMain"),
        StringType::Export
    );
}

#[test]
fn test_classify_function_symbol() {
    let mut extractor = create_extractor();
    let mut functions = std::collections::HashSet::new();
    functions.insert("main".to_string());
    extractor = extractor.with_functions(&functions);

    assert_eq!(
        extractor.classify_string_type("main"),
        StringType::FuncName
    );
}

#[test]
fn test_classify_import_with_library() {
    let mut extractor = create_extractor();
    let mut import_libs = HashMap::new();
    import_libs.insert("socket".to_string(), "libc.so".to_string());
    extractor = extractor.with_import_libraries(import_libs);

    assert_eq!(
        extractor.classify_string_type("socket"),
        StringType::Import
    );
}

// ==================== IP Validation Tests ====================

#[test]
fn test_is_real_ip_valid() {
    let extractor = create_extractor();
    assert!(extractor.classify_string_type("192.168.1.1") == StringType::Ip);
}

#[test]
fn test_is_real_ip_localhost() {
    let extractor = create_extractor();
    assert!(extractor.classify_string_type("127.0.0.1") == StringType::Ip);
}

#[test]
fn test_is_real_ip_zeros() {
    let extractor = create_extractor();
    assert!(extractor.classify_string_type("0.0.0.0") == StringType::Ip);
}

#[test]
fn test_is_real_ip_max_octets() {
    let extractor = create_extractor();
    assert!(extractor.classify_string_type("255.255.255.255") == StringType::Ip);
}

#[test]
fn test_is_real_ip_chrome_version() {
    let extractor = create_extractor();
    // Should NOT be classified as IP
    assert!(extractor.classify_string_type("Chrome/100.0.0.0") != StringType::Ip);
}

#[test]
fn test_is_real_ip_firefox_version() {
    let extractor = create_extractor();
    assert!(extractor.classify_string_type("Firefox/90.0.0.0") != StringType::Ip);
}

#[test]
fn test_is_real_ip_webkit_version() {
    let extractor = create_extractor();
    assert!(extractor.classify_string_type("AppleWebKit/537.36.0.0") != StringType::Ip);
}

#[test]
fn test_is_real_ip_out_of_range() {
    let extractor = create_extractor();
    // 256 is out of range for an octet
    assert!(extractor.classify_string_type("192.168.256.1") != StringType::Ip);
}

#[test]
fn test_is_real_ip_way_out_of_range() {
    let extractor = create_extractor();
    assert!(extractor.classify_string_type("999.888.777.666") != StringType::Ip);
}

// ==================== Path Detection Tests ====================

#[test]
fn test_is_path_unix_bin() {
    let extractor = create_extractor();
    assert_eq!(
        extractor.classify_string_type("/bin/sh"),
        StringType::Path
    );
}

#[test]
fn test_is_path_unix_usr_bin() {
    let extractor = create_extractor();
    assert_eq!(
        extractor.classify_string_type("/usr/bin/python"),
        StringType::Path
    );
}

#[test]
fn test_is_path_unix_etc() {
    let extractor = create_extractor();
    assert_eq!(
        extractor.classify_string_type("/etc/shadow"),
        StringType::Path
    );
}

#[test]
fn test_is_path_unix_tmp() {
    let extractor = create_extractor();
    assert_eq!(
        extractor.classify_string_type("/tmp/exploit.sh"),
        StringType::Path
    );
}

#[test]
fn test_is_path_unix_var() {
    let extractor = create_extractor();
    assert_eq!(
        extractor.classify_string_type("/var/log/messages"),
        StringType::Path
    );
}

#[test]
fn test_is_path_windows_c_drive() {
    let extractor = create_extractor();
    assert_eq!(
        extractor.classify_string_type(r"C:\Windows\system.ini"),
        StringType::Path
    );
}

#[test]
fn test_is_path_windows_d_drive() {
    let extractor = create_extractor();
    assert_eq!(
        extractor.classify_string_type(r"D:\Data\file.txt"),
        StringType::Path
    );
}

#[test]
fn test_is_path_relative_with_bin() {
    let extractor = create_extractor();
    assert_eq!(
        extractor.classify_string_type("local/bin/tool"),
        StringType::Path
    );
}

#[test]
fn test_is_path_not_url() {
    let extractor = create_extractor();
    // URLs with slashes should not be paths
    assert_eq!(
        extractor.classify_string_type("http://example.com/path"),
        StringType::Url
    );
}

#[test]
fn test_is_path_with_spaces_not_path() {
    let extractor = create_extractor();
    // Strings with slashes AND spaces are probably not paths (unless specific keywords)
    assert_eq!(
        extractor.classify_string_type("some text / with slashes"),
        StringType::Const
    );
}

// ==================== Go Binary Detection Tests ====================
// Note: is_go_binary delegates to stng::is_go_binary which has its own tests.
// We just verify the method is callable.

#[test]
fn test_is_go_binary_without_magic() {
    let extractor = create_extractor();
    let data = vec![0u8; 1024];

    // Non-Go binaries should return false
    assert!(!extractor.is_go_binary(&data));
}

#[test]
fn test_is_go_binary_empty() {
    let extractor = create_extractor();
    let data = vec![];

    // Empty data should return false
    assert!(!extractor.is_go_binary(&data));
}

// ==================== Edge Cases and Malware Indicators ====================

#[test]
fn test_classify_powershell_encoded_command() {
    let extractor = create_extractor();
    // PowerShell -EncodedCommand uses base64
    let encoded = "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHA";
    assert_eq!(
        extractor.classify_string_type(encoded),
        StringType::Base64
    );
}

#[test]
fn test_classify_c2_domain() {
    let extractor = create_extractor();
    assert_eq!(
        extractor.classify_string_type("https://evil-c2-server.onion/beacon"),
        StringType::Url
    );
}

#[test]
fn test_classify_pastebin_url() {
    let extractor = create_extractor();
    // Malware often uses pastebin for C2
    assert_eq!(
        extractor.classify_string_type("https://pastebin.com/raw/ABC123"),
        StringType::Url
    );
}

#[test]
fn test_classify_discord_webhook() {
    let extractor = create_extractor();
    // Malware uses Discord webhooks for exfiltration
    assert_eq!(
        extractor.classify_string_type("https://discord.com/api/webhooks/123/token"),
        StringType::Url
    );
}

#[test]
fn test_classify_suspicious_registry_path() {
    let extractor = create_extractor();
    assert_eq!(
        extractor.classify_string_type(r"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run"),
        StringType::Const // Registry paths don't have drive letters
    );
}

#[test]
fn test_classify_linux_persistence_path() {
    let extractor = create_extractor();
    assert_eq!(
        extractor.classify_string_type("/etc/crontab"),
        StringType::Path
    );
}

#[test]
fn test_classify_empty_string() {
    let extractor = create_extractor();
    assert_eq!(
        extractor.classify_string_type(""),
        StringType::Const
    );
}

#[test]
fn test_classify_very_long_url() {
    let extractor = create_extractor();
    let long_url = format!("https://example.com/{}", "A".repeat(2000));
    assert_eq!(
        extractor.classify_string_type(&long_url),
        StringType::Url
    );
}

#[test]
fn test_classify_ipv4_in_url() {
    let extractor = create_extractor();
    // IP in URL should be classified as URL, not IP
    assert_eq!(
        extractor.classify_string_type("http://192.168.1.1:8080/admin"),
        StringType::Url
    );
}

#[test]
fn test_classify_mixed_case_url() {
    let extractor = create_extractor();
    // URLs with mixed case
    assert_eq!(
        extractor.classify_string_type("HtTpS://ExAmPlE.CoM/PaTh"),
        StringType::Url
    );
}

#[test]
fn test_min_length_filter() {
    let extractor = StringExtractor::new().with_min_length(10);
    // Short strings should still be classified but extraction might filter them
    assert_eq!(
        extractor.classify_string_type("test"),
        StringType::Const
    );
}

// ==================== Symbol Normalization Tests ====================

#[test]
fn test_normalize_import_with_underscore() {
    let mut extractor = create_extractor();
    let mut imports = std::collections::HashSet::new();
    imports.insert("malloc".to_string());
    extractor = extractor.with_imports(&imports);

    // _malloc should match malloc (underscore prefix stripped)
    assert_eq!(
        extractor.classify_string_type("_malloc"),
        StringType::Import
    );
}

#[test]
fn test_normalize_import_with_double_underscore() {
    let mut extractor = create_extractor();
    let mut imports = std::collections::HashSet::new();
    imports.insert("init".to_string());
    extractor = extractor.with_imports(&imports);

    // __init should match init
    assert_eq!(
        extractor.classify_string_type("__init"),
        StringType::Import
    );
}
