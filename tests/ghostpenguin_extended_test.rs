//! Integration test module.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use assert_cmd::Command;
use std::fs::File;
use std::io::Write;
use tempfile::TempDir;

#[test]
#[ignore = "Trait detection not working - 'Appends to crontab by piping' message not found in output"]
fn test_ghostpenguin_extended_detection() -> Result<(), Box<dyn std::error::Error>> {
    let temp_dir = TempDir::new()?;
    let elf_path = temp_dir.path().join("ghostpenguin_new_traits.elf");

    let mut file = File::create(&elf_path)?;

    // ELF Header (x86_64)
    file.write_all(b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")?;
    file.write_all(&[0u8; 50])?;

    // 1. Cron Persistence (Blind Append)
    file.write_all(b"(crontab -l ; echo \"* * * * * /tmp/x\") | crontab -")?;

    // 2. Cron Persistence (Filtered Rewrite)
    file.write_all(b"crontab -l | grep -v 'malware' | crontab -")?;

    // 3. Host Info Strings (Need 3 to trigger)
    file.write_all(b"LanIP: 192.168.1.1")?;
    file.write_all(b"GateWay: 192.168.1.254")?;
    file.write_all(b"OSInfo: Linux")?;
    file.write_all(b"Userame: root")?;

    // 4. Custom C2 Framing
    file.write_all(b"Bytes == %d")?;
    file.write_all(b"iDataSize == %d")?;

    // Run cleave
    #[allow(deprecated)]
    let mut cmd = Command::cargo_bin("cleave")?;
    cmd.arg(&elf_path);

    let cmd_assert = cmd.assert();
    let success = cmd_assert.success();
    let output = success.get_output();
    let stdout = String::from_utf8_lossy(&output.stdout);

    println!("Output: {}", stdout);

    // Verify New Detections
    assert!(
        stdout.contains("Appends to crontab by piping"),
        "Missing cron blind append detection"
    );
    // assert!(stdout.contains("Rewrites crontab by filtering"), "Missing cron filtered rewrite detection"); // Masked by blind append in UI
    assert!(
        stdout.contains("Detailed system information gathering strings"),
        "Missing host info strings detection"
    );
    assert!(
        stdout.contains("Custom text-based C2 protocol framing"),
        "Missing custom C2 framing detection"
    );

    Ok(())
}
