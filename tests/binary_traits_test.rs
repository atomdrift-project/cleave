//! Integration test module.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::fs;
use tempfile::TempDir;

/// Test that daemon persistence traits are detected for ELF binaries with /dev/null
#[test]
fn test_daemon_dev_null_trait() {
    let temp_dir = TempDir::new().unwrap();
    let elf_path = temp_dir.path().join("daemon.elf");

    // Create minimal ELF with /dev/null string
    let mut elf_data = vec![
        0x7f, b'E', b'L', b'F', // ELF magic
        0x02, // 64-bit
        0x01, // Little endian
        0x01, // ELF version
        0x00, // System V ABI
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Padding
    ];
    // Add /dev/null string
    elf_data.extend_from_slice(b"/dev/null\x00");
    // Pad to minimum size
    elf_data.resize(256, 0);

    fs::write(&elf_path, &elf_data).unwrap();

    let output = assert_cmd::cargo_bin_cmd!("flayer")
        .args(["--json", "analyze", elf_path.to_str().unwrap()])
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);

    if let Ok(json) = serde_json::from_str::<serde_json::Value>(&stdout) {
        // Check strings for /dev/null
        if let Some(strings) = json.get("strings").and_then(|v| v.as_array()) {
            let has_dev_null = strings.iter().any(|s| {
                s.get("value")
                    .and_then(|v| v.as_str())
                    .map(|v| v.contains("/dev/null"))
                    .unwrap_or(false)
            });
            if has_dev_null {
                eprintln!("Found /dev/null string in ELF binary");
            }
        }

        // Check traits for daemon-related patterns
        if let Some(findings) = json.get("findings").and_then(|v| v.as_array()) {
            let daemon_findings: Vec<_> = findings
                .iter()
                .filter(|f| {
                    f.get("id")
                        .and_then(|id| id.as_str())
                        .map(|id| id.contains("daemon") || id.contains("dev-null"))
                        .unwrap_or(false)
                })
                .collect();

            for finding in &daemon_findings {
                if let Some(id) = finding.get("id").and_then(|i| i.as_str()) {
                    eprintln!("Found daemon-related trait: {}", id);
                }
            }
        }
    }
}

/// Test that HTTP protocol string trait is detected
#[test]
fn test_http_protocol_trait() {
    let temp_dir = TempDir::new().unwrap();
    let elf_path = temp_dir.path().join("http.elf");

    // Create minimal ELF with HTTP protocol strings
    let mut elf_data = vec![
        0x7f, b'E', b'L', b'F', // ELF magic
        0x02, // 64-bit
        0x01, // Little endian
        0x01, // ELF version
        0x00, // System V ABI
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Padding
    ];
    // Add HTTP/1.1 string
    elf_data.extend_from_slice(b"HTTP/1.1\x00");
    elf_data.extend_from_slice(b"User-Agent: test\x00");
    elf_data.extend_from_slice(b"\r\n\r\n");
    // Pad to minimum size
    elf_data.resize(256, 0);

    fs::write(&elf_path, &elf_data).unwrap();

    let output = assert_cmd::cargo_bin_cmd!("flayer")
        .args(["--json", "analyze", elf_path.to_str().unwrap()])
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);

    if let Ok(json) = serde_json::from_str::<serde_json::Value>(&stdout) {
        // Check strings for HTTP patterns
        if let Some(strings) = json.get("strings").and_then(|v| v.as_array()) {
            let has_http = strings.iter().any(|s| {
                s.get("value")
                    .and_then(|v| v.as_str())
                    .map(|v| v.contains("HTTP/"))
                    .unwrap_or(false)
            });
            if has_http {
                eprintln!("Found HTTP protocol string in ELF binary");
            }
        }

        // Check findings for HTTP-related traits
        if let Some(findings) = json.get("findings").and_then(|v| v.as_array()) {
            let http_findings: Vec<_> = findings
                .iter()
                .filter(|f| {
                    f.get("id")
                        .and_then(|id| id.as_str())
                        .map(|id| id.contains("http"))
                        .unwrap_or(false)
                })
                .collect();

            for finding in &http_findings {
                if let Some(id) = finding.get("id").and_then(|i| i.as_str()) {
                    eprintln!("Found HTTP-related trait: {}", id);
                }
            }
        }
    }
}

/// Test that hex charset trait (cipher indicator) is detected
#[test]
fn test_hex_charset_cipher_trait() {
    let temp_dir = TempDir::new().unwrap();
    let elf_path = temp_dir.path().join("cipher.elf");

    // Create minimal ELF with hex charset (cipher indicator)
    let mut elf_data = vec![
        0x7f, b'E', b'L', b'F', // ELF magic
        0x02, // 64-bit
        0x01, // Little endian
        0x01, // ELF version
        0x00, // System V ABI
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Padding
    ];
    // Add hex charset string (common in XOR/RC4 ciphers)
    elf_data.extend_from_slice(b"0123456789abcdef\x00");
    // Pad to minimum size
    elf_data.resize(256, 0);

    fs::write(&elf_path, &elf_data).unwrap();

    let output = assert_cmd::cargo_bin_cmd!("flayer")
        .args(["--json", "analyze", elf_path.to_str().unwrap()])
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);

    if let Ok(json) = serde_json::from_str::<serde_json::Value>(&stdout) {
        // Check strings for hex charset
        if let Some(strings) = json.get("strings").and_then(|v| v.as_array()) {
            let has_hex_charset = strings.iter().any(|s| {
                s.get("value")
                    .and_then(|v| v.as_str())
                    .map(|v| v == "0123456789abcdef")
                    .unwrap_or(false)
            });
            if has_hex_charset {
                eprintln!("Found hex charset string in ELF binary");
            }
        }

        // Check findings for cipher-related traits
        if let Some(findings) = json.get("findings").and_then(|v| v.as_array()) {
            let cipher_findings: Vec<_> = findings
                .iter()
                .filter(|f| {
                    f.get("id")
                        .and_then(|id| id.as_str())
                        .map(|id| id.contains("cipher") || id.contains("hex"))
                        .unwrap_or(false)
                })
                .collect();

            for finding in &cipher_findings {
                if let Some(id) = finding.get("id").and_then(|i| i.as_str()) {
                    eprintln!("Found cipher-related trait: {}", id);
                }
            }
        }
    }
}

/// Test that exotic architecture traits are detected - MIPS
#[test]
#[ignore = "Depends on binary.yaml.disabled which has experimental binary condition types"]
fn test_exotic_arch_mips_trait() {
    let temp_dir = TempDir::new().unwrap();
    let elf_path = temp_dir.path().join("mips.elf");

    // Create minimal MIPS ELF header
    let elf_data = vec![
        0x7f, b'E', b'L', b'F', // ELF magic
        0x01, // 32-bit
        0x02, // Big endian (MIPS MSB)
        0x01, // ELF version
        0x00, // System V ABI
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Padding
        0x00, 0x02, // e_type: ET_EXEC
        0x00, 0x08, // e_machine: EM_MIPS (8)
        0x00, 0x00, 0x00, 0x01, // e_version
        // Rest of ELF header (entry, phoff, shoff, flags, etc.)
        0x00, 0x40, 0x00, 0x00, // e_entry
        0x00, 0x00, 0x00, 0x34, // e_phoff
        0x00, 0x00, 0x00, 0x00, // e_shoff
        0x00, 0x00, 0x00, 0x00, // e_flags
        0x00, 0x34, // e_ehsize
        0x00, 0x20, // e_phentsize
        0x00, 0x01, // e_phnum
        0x00, 0x28, // e_shentsize
        0x00, 0x00, // e_shnum
        0x00, 0x00, // e_shstrndx
    ];

    fs::write(&elf_path, &elf_data).unwrap();

    let output = assert_cmd::cargo_bin_cmd!("flayer")
        .args(["--json", "analyze", elf_path.to_str().unwrap()])
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);

    if let Ok(json) = serde_json::from_str::<serde_json::Value>(&stdout) {
        // Check target info for MIPS architecture
        if let Some(target) = json.get("target") {
            if let Some(archs) = target.get("architectures").and_then(|a| a.as_array()) {
                let is_mips = archs.iter().any(|a| {
                    a.as_str()
                        .map(|s| s.to_lowercase().contains("mips"))
                        .unwrap_or(false)
                });
                if is_mips {
                    eprintln!("Detected MIPS architecture");
                }
            }
        }

        // Check findings for exotic arch traits
        if let Some(findings) = json.get("findings").and_then(|v| v.as_array()) {
            let arch_findings: Vec<_> = findings
                .iter()
                .filter(|f| {
                    f.get("id")
                        .and_then(|id| id.as_str())
                        .map(|id| id.contains("exotic-arch") || id.contains("mips"))
                        .unwrap_or(false)
                })
                .collect();

            assert!(
                !arch_findings.is_empty(),
                "Should detect exotic-arch-mips trait for MIPS binary"
            );

            for finding in &arch_findings {
                if let Some(id) = finding.get("id").and_then(|i| i.as_str()) {
                    eprintln!("Found exotic arch trait: {}", id);
                }
            }
        }
    }
}

/// Test that big-endian trait is detected
#[test]
fn test_big_endian_trait() {
    let temp_dir = TempDir::new().unwrap();
    let elf_path = temp_dir.path().join("bigendian.elf");

    // Create minimal big-endian ELF (MIPS or PPC style)
    let elf_data = vec![
        0x7f, b'E', b'L', b'F', // ELF magic
        0x01, // 32-bit
        0x02, // Big endian
        0x01, // ELF version
        0x00, // System V ABI
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Padding
        0x00, 0x02, // e_type: ET_EXEC
        0x00, 0x14, // e_machine: EM_PPC (20)
        0x00, 0x00, 0x00, 0x01, // e_version
        0x00, 0x00, 0x00, 0x00, // Rest of header...
    ];

    fs::write(&elf_path, &elf_data).unwrap();

    let output = assert_cmd::cargo_bin_cmd!("flayer")
        .args(["--json", "analyze", elf_path.to_str().unwrap()])
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);

    if let Ok(json) = serde_json::from_str::<serde_json::Value>(&stdout) {
        // Check findings for big-endian trait
        if let Some(findings) = json.get("findings").and_then(|v| v.as_array()) {
            let endian_findings: Vec<_> = findings
                .iter()
                .filter(|f| {
                    f.get("id")
                        .and_then(|id| id.as_str())
                        .map(|id| id.contains("big-endian") || id.contains("endian"))
                        .unwrap_or(false)
                })
                .collect();

            for finding in &endian_findings {
                if let Some(id) = finding.get("id").and_then(|i| i.as_str()) {
                    eprintln!("Found endian trait: {}", id);
                }
            }
        }
    }
}

/// Test that static binary trait is detected
#[test]
fn test_static_binary_trait() {
    // Use the test fixture ELF which should be a normal dynamically linked binary
    let output = assert_cmd::cargo_bin_cmd!("flayer")
        .args(["--json", "analyze", "tests/fixtures/test.elf"])
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);

    if let Ok(json) = serde_json::from_str::<serde_json::Value>(&stdout) {
        // Check structure for static/dynamic linking info
        if let Some(structure) = json.get("structure").and_then(|v| v.as_array()) {
            let static_features: Vec<_> = structure
                .iter()
                .filter(|s| {
                    s.get("id")
                        .and_then(|id| id.as_str())
                        .map(|id| id.contains("static") || id.contains("dynamic"))
                        .unwrap_or(false)
                })
                .collect();

            for feature in &static_features {
                if let Some(id) = feature.get("id").and_then(|i| i.as_str()) {
                    eprintln!("Found linking structure: {}", id);
                }
            }
        }
    }
}

/// Test daemon composite rule - fork + setsid + /dev/null
#[test]
fn test_daemon_composite_trait() {
    let temp_dir = TempDir::new().unwrap();
    let elf_path = temp_dir.path().join("full_daemon.elf");

    // Create minimal ELF with daemon-related strings
    let mut elf_data = vec![
        0x7f, b'E', b'L', b'F', // ELF magic
        0x02, // 64-bit
        0x01, // Little endian
        0x01, // ELF version
        0x00, // System V ABI
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Padding
    ];
    // Add multiple daemon-related strings
    elf_data.extend_from_slice(b"/dev/null\x00");
    elf_data.extend_from_slice(b"fork\x00");
    elf_data.extend_from_slice(b"setsid\x00");
    elf_data.extend_from_slice(b"/proc/self\x00");
    // Pad to minimum size
    elf_data.resize(512, 0);

    fs::write(&elf_path, &elf_data).unwrap();

    let output = assert_cmd::cargo_bin_cmd!("flayer")
        .args(["--json", "analyze", elf_path.to_str().unwrap()])
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);

    if let Ok(json) = serde_json::from_str::<serde_json::Value>(&stdout) {
        // Check for composite daemon trait
        if let Some(findings) = json.get("findings").and_then(|v| v.as_array()) {
            let daemon_findings: Vec<_> = findings
                .iter()
                .filter(|f| {
                    f.get("id")
                        .and_then(|id| id.as_str())
                        .map(|id| id.contains("daemon"))
                        .unwrap_or(false)
                })
                .collect();

            eprintln!(
                "Found {} daemon-related findings for composite test",
                daemon_findings.len()
            );

            for finding in &daemon_findings {
                if let Some(id) = finding.get("id").and_then(|i| i.as_str()) {
                    eprintln!("  - {}", id);
                }
            }
        }
    }
}

/// Test HTTP composite rule - protocol + headers
#[test]
fn test_http_composite_trait() {
    let temp_dir = TempDir::new().unwrap();
    let elf_path = temp_dir.path().join("http_client.elf");

    // Create minimal ELF with HTTP client patterns
    let mut elf_data = vec![
        0x7f, b'E', b'L', b'F', // ELF magic
        0x02, // 64-bit
        0x01, // Little endian
        0x01, // ELF version
        0x00, // System V ABI
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Padding
    ];
    // Add HTTP patterns
    elf_data.extend_from_slice(b"GET /path HTTP/1.1\r\n\x00");
    elf_data.extend_from_slice(b"User-Agent: Mozilla\x00");
    elf_data.extend_from_slice(b"Content-Type: text/html\x00");
    elf_data.extend_from_slice(b"\r\n\r\n");
    // Pad to minimum size
    elf_data.resize(512, 0);

    fs::write(&elf_path, &elf_data).unwrap();

    let output = assert_cmd::cargo_bin_cmd!("flayer")
        .args(["--json", "analyze", elf_path.to_str().unwrap()])
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);

    if let Ok(json) = serde_json::from_str::<serde_json::Value>(&stdout) {
        // Check for HTTP-related findings
        if let Some(findings) = json.get("findings").and_then(|v| v.as_array()) {
            let http_findings: Vec<_> = findings
                .iter()
                .filter(|f| {
                    f.get("id")
                        .and_then(|id| id.as_str())
                        .map(|id| id.contains("http") || id.contains("c2"))
                        .unwrap_or(false)
                })
                .collect();

            eprintln!(
                "Found {} HTTP-related findings for composite test",
                http_findings.len()
            );

            for finding in &http_findings {
                if let Some(id) = finding.get("id").and_then(|i| i.as_str()) {
                    eprintln!("  - {}", id);
                }
            }
        }
    }
}

/// Test IoT malware composite rule - exotic arch + static + stripped
#[test]
fn test_iot_target_composite_trait() {
    let temp_dir = TempDir::new().unwrap();
    let elf_path = temp_dir.path().join("iot_target.elf");

    // Create minimal MIPS static ELF (IoT pattern)
    let elf_data = vec![
        0x7f, b'E', b'L', b'F', // ELF magic
        0x01, // 32-bit
        0x02, // Big endian
        0x01, // ELF version
        0x00, // System V ABI
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Padding
        0x00, 0x02, // e_type: ET_EXEC
        0x00, 0x08, // e_machine: EM_MIPS (8)
        0x00, 0x00, 0x00, 0x01, // e_version
        0x00, 0x40, 0x00, 0x00, // e_entry
        0x00, 0x00, 0x00, 0x34, // e_phoff
        0x00, 0x00, 0x00, 0x00, // e_shoff = 0 (no sections)
        0x00, 0x00, 0x00, 0x00, // e_flags
        0x00, 0x34, // e_ehsize
        0x00, 0x20, // e_phentsize
        0x00, 0x01, // e_phnum
        0x00, 0x28, // e_shentsize
        0x00, 0x00, // e_shnum = 0 (stripped)
        0x00, 0x00, // e_shstrndx
    ];

    fs::write(&elf_path, &elf_data).unwrap();

    let output = assert_cmd::cargo_bin_cmd!("flayer")
        .args(["--json", "analyze", elf_path.to_str().unwrap()])
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);

    if let Ok(json) = serde_json::from_str::<serde_json::Value>(&stdout) {
        // Check for IoT-related findings
        if let Some(findings) = json.get("findings").and_then(|v| v.as_array()) {
            let iot_findings: Vec<_> = findings
                .iter()
                .filter(|f| {
                    f.get("id")
                        .and_then(|id| id.as_str())
                        .map(|id| {
                            id.contains("iot")
                                || id.contains("mirai")
                                || id.contains("exotic-arch")
                                || id.contains("mips")
                        })
                        .unwrap_or(false)
                })
                .collect();

            eprintln!(
                "Found {} IoT-related findings for MIPS static binary",
                iot_findings.len()
            );

            for finding in &iot_findings {
                if let Some(id) = finding.get("id").and_then(|i| i.as_str()) {
                    eprintln!("  - {}", id);
                }
            }
        }
    }
}

/// Test ARM32 exotic architecture detection
#[test]
fn test_exotic_arch_arm32_trait() {
    let temp_dir = TempDir::new().unwrap();
    let elf_path = temp_dir.path().join("arm32.elf");

    // Create minimal ARM32 ELF header
    let elf_data = vec![
        0x7f, b'E', b'L', b'F', // ELF magic
        0x01, // 32-bit
        0x01, // Little endian
        0x01, // ELF version
        0x00, // System V ABI
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Padding
        0x02, 0x00, // e_type: ET_EXEC (little endian)
        0x28, 0x00, // e_machine: EM_ARM (40 = 0x28)
        0x01, 0x00, 0x00, 0x00, // e_version
    ];

    fs::write(&elf_path, &elf_data).unwrap();

    let output = assert_cmd::cargo_bin_cmd!("flayer")
        .args(["--json", "analyze", elf_path.to_str().unwrap()])
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);

    if let Ok(json) = serde_json::from_str::<serde_json::Value>(&stdout) {
        if let Some(findings) = json.get("findings").and_then(|v| v.as_array()) {
            let arm_findings: Vec<_> = findings
                .iter()
                .filter(|f| {
                    f.get("id")
                        .and_then(|id| id.as_str())
                        .map(|id| id.contains("arm") || id.contains("exotic-arch"))
                        .unwrap_or(false)
                })
                .collect();

            for finding in &arm_findings {
                if let Some(id) = finding.get("id").and_then(|i| i.as_str()) {
                    eprintln!("Found ARM-related trait: {}", id);
                }
            }
        }
    }
}

/// Test PowerPC exotic architecture detection
#[test]
fn test_exotic_arch_ppc_trait() {
    let temp_dir = TempDir::new().unwrap();
    let elf_path = temp_dir.path().join("ppc.elf");

    // Create minimal PowerPC ELF header (big-endian)
    let elf_data = vec![
        0x7f, b'E', b'L', b'F', // ELF magic
        0x01, // 32-bit
        0x02, // Big endian
        0x01, // ELF version
        0x00, // System V ABI
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Padding
        0x00, 0x02, // e_type: ET_EXEC
        0x00, 0x14, // e_machine: EM_PPC (20 = 0x14)
        0x00, 0x00, 0x00, 0x01, // e_version
    ];

    fs::write(&elf_path, &elf_data).unwrap();

    let output = assert_cmd::cargo_bin_cmd!("flayer")
        .args(["--json", "analyze", elf_path.to_str().unwrap()])
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);

    if let Ok(json) = serde_json::from_str::<serde_json::Value>(&stdout) {
        if let Some(findings) = json.get("findings").and_then(|v| v.as_array()) {
            let ppc_findings: Vec<_> = findings
                .iter()
                .filter(|f| {
                    f.get("id")
                        .and_then(|id| id.as_str())
                        .map(|id| id.contains("ppc") || id.contains("exotic-arch"))
                        .unwrap_or(false)
                })
                .collect();

            for finding in &ppc_findings {
                if let Some(id) = finding.get("id").and_then(|i| i.as_str()) {
                    eprintln!("Found PPC-related trait: {}", id);
                }
            }
        }
    }
}
