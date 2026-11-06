use super::*;
use std::path::PathBuf;
use tempfile::TempDir;

#[test]
fn test_validate_actual_traits_directory() {
    // Test against actual traits directory
    let traits_path = PathBuf::from("traits");
    if traits_path.exists() {
        let result = validate_directory_structure(&traits_path);
        assert!(
            result.is_ok(),
            "Directory validation failed:\n{}",
            result.unwrap_err().join("\n")
        );
    }
}

#[test]
fn test_allowed_objectives_constants() {
    // Verify all MBC objectives are present
    assert!(ALLOWED_OBJECTIVES.contains(&"anti-analysis"));
    assert!(ALLOWED_OBJECTIVES.contains(&"anti-static"));
    assert!(ALLOWED_OBJECTIVES.contains(&"evasion"));
    assert!(ALLOWED_OBJECTIVES.contains(&"execution"));
    assert!(ALLOWED_OBJECTIVES.contains(&"persistence"));
    assert!(ALLOWED_OBJECTIVES.contains(&"privilege-escalation"));
}

#[test]
fn test_no_objective_abbreviations_allowed() {
    // Ensure abbreviated/aliased names aren't in the whitelist
    // c2 should be command-and-control, collect should be collection
    assert!(!ALLOWED_OBJECTIVES.contains(&"c2"));
    assert!(!ALLOWED_OBJECTIVES.contains(&"collect"));
    assert!(!ALLOWED_OBJECTIVES.contains(&"cred"));
    assert!(!ALLOWED_OBJECTIVES.contains(&"privesc"));
    assert!(!ALLOWED_OBJECTIVES.contains(&"lat-move"));
}

#[test]
fn test_catches_invalid_objectives_subdirectory() {
    // Create temp directory with invalid structure
    let temp_dir = TempDir::new().unwrap();
    let traits_path = temp_dir.path();

    // Create objectives/ with valid and invalid subdirectories
    std::fs::create_dir_all(traits_path.join("objectives/command-and-control")).unwrap();
    std::fs::create_dir_all(traits_path.join("objectives/c2")).unwrap(); // Invalid!
    std::fs::create_dir_all(traits_path.join("objectives/collect")).unwrap(); // Invalid!

    let result = validate_directory_structure(traits_path);
    assert!(result.is_err(), "Should catch invalid directories");

    let errors = result.unwrap_err();
    assert!(
        errors.iter().any(|e| e.contains("'c2'")),
        "Should flag 'c2' as invalid: {:?}",
        errors
    );
    assert!(
        errors.iter().any(|e| e.contains("'collect'")),
        "Should flag 'collect' as invalid: {:?}",
        errors
    );
}

#[test]
fn test_catches_invalid_micro_behaviors_subdirectory() {
    // Create temp directory with invalid structure
    let temp_dir = TempDir::new().unwrap();
    let traits_path = temp_dir.path();

    // Create micro-behaviors/ with valid and invalid subdirectories
    std::fs::create_dir_all(traits_path.join("micro-behaviors/communications")).unwrap();
    std::fs::create_dir_all(traits_path.join("micro-behaviors/communications/smb")).unwrap();
    std::fs::create_dir_all(traits_path.join("micro-behaviors/communications/transfer")).unwrap();
    std::fs::create_dir_all(traits_path.join("micro-behaviors/network/interface")).unwrap();
    std::fs::create_dir_all(traits_path.join("micro-behaviors/c2")).unwrap(); // Invalid!
    std::fs::create_dir_all(traits_path.join("micro-behaviors/persist")).unwrap(); // Invalid!

    let result = validate_directory_structure(traits_path);
    assert!(result.is_err(), "Should catch invalid directories");

    let errors = result.unwrap_err();
    assert!(
        errors.iter().any(|e| e.contains("'c2'")),
        "Should flag 'c2' as invalid: {:?}",
        errors
    );
    assert!(
        errors.iter().any(|e| e.contains("'persist'")),
        "Should flag 'persist' as invalid: {:?}",
        errors
    );
    assert!(
        errors.iter().all(|e| !e.contains("'network'")),
        "Should accept the network/interface taxonomy path: {:?}",
        errors
    );
}

#[test]
fn test_valid_structure_passes() {
    // Create temp directory with valid structure
    let temp_dir = TempDir::new().unwrap();
    let traits_path = temp_dir.path();

    // Create valid directories
    std::fs::create_dir_all(traits_path.join("objectives/command-and-control")).unwrap();
    std::fs::create_dir_all(traits_path.join("objectives/collection")).unwrap();
    std::fs::create_dir_all(traits_path.join("micro-behaviors/communications")).unwrap();
    std::fs::create_dir_all(traits_path.join("micro-behaviors/communications/adb")).unwrap();
    std::fs::create_dir_all(traits_path.join("micro-behaviors/communications/finger")).unwrap();
    std::fs::create_dir_all(traits_path.join("micro-behaviors/process")).unwrap();
    std::fs::create_dir_all(traits_path.join("micro-behaviors/os/command/lookup")).unwrap();
    std::fs::create_dir_all(traits_path.join("micro-behaviors/data/property/access")).unwrap();
    std::fs::create_dir_all(traits_path.join("micro-behaviors/data/retrieve")).unwrap();
    std::fs::create_dir_all(traits_path.join("well-known/malware")).unwrap();
    std::fs::create_dir_all(traits_path.join("metadata/binary")).unwrap();
    std::fs::create_dir_all(traits_path.join("metadata/lang/source/attribution")).unwrap();
    std::fs::create_dir_all(traits_path.join("metadata/installer/layout")).unwrap();
    std::fs::create_dir_all(traits_path.join("metadata/lang/charset/alphabet")).unwrap();
    std::fs::create_dir_all(traits_path.join("metadata/vendor")).unwrap();

    let result = validate_directory_structure(traits_path);
    assert!(result.is_ok(), "Valid structure should pass: {:?}", result);
}

#[test]
fn test_retired_os_network_is_rejected() {
    let temp_dir = TempDir::new().unwrap();
    std::fs::create_dir_all(temp_dir.path().join("micro-behaviors/os/network/interface")).unwrap();
    let errors = validate_directory_structure(temp_dir.path()).unwrap_err();
    assert!(
        errors
            .iter()
            .any(|e| e.contains("micro-behaviors/os/network")),
        "Retired os/network must be rejected: {:?}",
        errors
    );
}

#[test]
fn retired_encoding_directories_are_rejected() {
    for retired in ["metadata/file/encoded", "metadata/lang/encoded"] {
        let temp = TempDir::new().unwrap();
        std::fs::create_dir_all(temp.path().join(retired)).unwrap();
        let errors = validate_directory_structure(temp.path()).unwrap_err();
        assert!(
            errors.iter().any(|error| error.contains("encoded")),
            "{retired}: {errors:?}"
        );
    }
}

#[test]
fn retired_taxonomy_subtrees_are_rejected() {
    for retired in RETIRED_TAXONOMY_PATHS {
        let temp = TempDir::new().unwrap();
        std::fs::create_dir_all(temp.path().join(retired).join("nested")).unwrap();
        let errors = validate_directory_structure(temp.path()).unwrap_err();
        assert!(
            errors.iter().any(|error| error.contains(retired)),
            "{retired}: {errors:?}"
        );
    }
}

#[test]
fn migrated_taxonomy_target_homes_are_valid() {
    let temp_dir = TempDir::new().unwrap();
    let traits_path = temp_dir.path();
    for new in [
        "micro-behaviors/communications/irc",
        "micro-behaviors/crypto/decrypt",
        "micro-behaviors/crypto/key",
        "micro-behaviors/crypto/asymmetric/signature",
        "micro-behaviors/data/checksum",
        "objectives/execution/staging",
        "objectives/collection/email",
        "objectives/credential-access/registry",
        "objectives/impact/spam",
        "micro-behaviors/crypto/encrypt",
        "micro-behaviors/crypto/sign",
        "micro-behaviors/crypto/verify",
        "micro-behaviors/dylib/unload",
        "micro-behaviors/mem/heap-spray",
        "micro-behaviors/mem/overflow",
        "micro-behaviors/mem/stack-pivot",
        "micro-behaviors/process/deploy",
        "micro-behaviors/process/fiber",
        "objectives/credential-access/memory",
        "metadata/file/entropy",
        "metadata/file/text-distribution",
        "metadata/signature/script",
    ] {
        std::fs::create_dir_all(traits_path.join(new)).unwrap();
    }
    let result = validate_directory_structure(traits_path);
    assert!(result.is_ok(), "Migration homes should pass: {:?}", result);

    // The new names do not open the parent to arbitrary siblings.
    std::fs::create_dir_all(traits_path.join("micro-behaviors/network/misc")).unwrap();
    let errors = validate_directory_structure(traits_path).unwrap_err();
    assert!(errors.iter().any(|e| e.contains("misc")));
}

#[test]
fn retired_process_subtrees_are_rejected_and_resource_homes_are_allowed() {
    for retired in RETIRED_PROCESS_PATHS {
        let temp = TempDir::new().unwrap();
        std::fs::create_dir_all(temp.path().join(retired).join("nested")).unwrap();
        let errors = validate_directory_structure(temp.path()).unwrap_err();
        assert!(errors.iter().any(|e| e.contains(retired)), "{errors:?}");
    }
    let temp = TempDir::new().unwrap();
    for path in [
        "micro-behaviors/process/stdio/relay",
        "micro-behaviors/process/config",
        "micro-behaviors/process/hook/interception",
        "micro-behaviors/process/create/fork",
        "micro-behaviors/process/interpreter/eval/direct",
        "micro-behaviors/process/sync/condition",
        "micro-behaviors/data/stream/write",
        "micro-behaviors/data/document/open",
        "micro-behaviors/mem/local-storage",
        "micro-behaviors/revision-control/repository",
        "micro-behaviors/communications/http/intercept",
    ] {
        std::fs::create_dir_all(temp.path().join(path)).unwrap();
    }
    let result = validate_directory_structure(temp.path());
    assert!(result.is_ok(), "{result:?}");
}

#[test]
fn retired_crypto_library_and_native_homes_are_rejected() {
    for retired in ["library", "native"] {
        let temp = TempDir::new().unwrap();
        std::fs::create_dir_all(temp.path().join("micro-behaviors/crypto").join(retired)).unwrap();
        let errors = validate_directory_structure(temp.path()).unwrap_err();
        assert!(
            errors.iter().any(|error| error.contains(retired)),
            "{errors:?}"
        );
    }
}

#[test]
fn test_catches_invalid_metadata_subdirectory() {
    let temp_dir = TempDir::new().unwrap();
    let traits_path = temp_dir.path();

    std::fs::create_dir_all(traits_path.join("metadata/binary")).unwrap();
    std::fs::create_dir_all(traits_path.join("metadata/purpose")).unwrap(); // Invalid!
    std::fs::create_dir_all(traits_path.join("metadata/intent")).unwrap(); // Invalid!

    let result = validate_directory_structure(traits_path);
    assert!(result.is_err(), "Should catch invalid metadata directories");

    let errors = result.unwrap_err();
    assert!(
        errors.iter().any(|e| e.contains("'purpose'")),
        "Should flag 'purpose' as invalid: {:?}",
        errors
    );
    assert!(
        errors.iter().any(|e| e.contains("'intent'")),
        "Should flag 'intent' as invalid: {:?}",
        errors
    );
}

#[test]
fn test_catches_invalid_anti_analysis_subdirectory() {
    let temp_dir = TempDir::new().unwrap();
    let traits_path = temp_dir.path();

    // Create valid and invalid anti-analysis subdirectories
    std::fs::create_dir_all(traits_path.join("objectives/anti-analysis/debugger-detect")).unwrap();
    std::fs::create_dir_all(traits_path.join("objectives/anti-analysis/vm-detect")).unwrap();
    // Invalid - these belong elsewhere
    std::fs::create_dir_all(traits_path.join("objectives/anti-analysis/obfuscation")).unwrap();
    std::fs::create_dir_all(traits_path.join("objectives/anti-analysis/kernel-hide")).unwrap();

    let result = validate_directory_structure(traits_path);
    assert!(
        result.is_err(),
        "Should catch invalid anti-analysis directories"
    );

    let errors = result.unwrap_err();
    assert!(
        errors.iter().any(|e| e.contains("'obfuscation'")),
        "Should flag 'obfuscation' as invalid: {:?}",
        errors
    );
    assert!(
        errors.iter().any(|e| e.contains("'kernel-hide'")),
        "Should flag 'kernel-hide' as invalid: {:?}",
        errors
    );
}

#[test]
fn test_catches_invalid_persistence_subdirectory() {
    let temp_dir = TempDir::new().unwrap();
    let traits_path = temp_dir.path();

    // Valid persistence subdirectories
    std::fs::create_dir_all(traits_path.join("objectives/persistence/firmware")).unwrap();
    std::fs::create_dir_all(traits_path.join("objectives/persistence/system")).unwrap();
    std::fs::create_dir_all(traits_path.join("objectives/persistence/login")).unwrap();
    // Invalid - hiding belongs in evasion, not persistence
    std::fs::create_dir_all(traits_path.join("objectives/persistence/hidden-files")).unwrap();
    // Invalid - flat structure without trigger event
    std::fs::create_dir_all(traits_path.join("objectives/persistence/registry")).unwrap();

    let result = validate_directory_structure(traits_path);
    assert!(
        result.is_err(),
        "Should catch invalid persistence directories"
    );

    let errors = result.unwrap_err();
    assert!(
        errors.iter().any(|e| e.contains("'hidden-files'")),
        "Should flag 'hidden-files' as invalid: {:?}",
        errors
    );
    assert!(
        errors.iter().any(|e| e.contains("'registry'")),
        "Should flag flat 'registry' as invalid: {:?}",
        errors
    );
}

#[test]
fn test_catches_invalid_impact_subdirectory() {
    let temp_dir = TempDir::new().unwrap();
    let traits_path = temp_dir.path();

    // Valid impact subdirectories
    std::fs::create_dir_all(traits_path.join("objectives/impact/ransom")).unwrap();
    std::fs::create_dir_all(traits_path.join("objectives/impact/degrade")).unwrap();
    std::fs::create_dir_all(traits_path.join("objectives/impact/dos")).unwrap();
    // Invalid - exploits belong in privilege-escalation
    std::fs::create_dir_all(traits_path.join("objectives/impact/exploit")).unwrap();
    // Invalid - stealer belongs in credential-access
    std::fs::create_dir_all(traits_path.join("objectives/impact/stealer")).unwrap();

    let result = validate_directory_structure(traits_path);
    assert!(result.is_err(), "Should catch invalid impact directories");

    let errors = result.unwrap_err();
    assert!(
        errors.iter().any(|e| e.contains("'exploit'")),
        "Should flag 'exploit' as invalid: {:?}",
        errors
    );
    assert!(
        errors.iter().any(|e| e.contains("'stealer'")),
        "Should flag 'stealer' as invalid: {:?}",
        errors
    );
}

#[test]
fn test_catches_invalid_anti_static_subdirectory() {
    let temp_dir = TempDir::new().unwrap();
    let traits_path = temp_dir.path();

    std::fs::create_dir_all(traits_path.join("objectives/anti-static/obfuscation")).unwrap();
    std::fs::create_dir_all(traits_path.join("objectives/anti-static/pack")).unwrap();
    // Invalid - these don't belong in anti-static
    std::fs::create_dir_all(traits_path.join("objectives/anti-static/hardening")).unwrap();
    std::fs::create_dir_all(traits_path.join("objectives/anti-static/masquerade")).unwrap();

    let result = validate_directory_structure(traits_path);
    assert!(
        result.is_err(),
        "Should catch invalid anti-static directories"
    );

    let errors = result.unwrap_err();
    assert!(
        errors.iter().any(|e| e.contains("'hardening'")),
        "Should flag 'hardening' as invalid: {:?}",
        errors
    );
    assert!(
        errors.iter().any(|e| e.contains("'masquerade'")),
        "Should flag 'masquerade' as invalid: {:?}",
        errors
    );
}

#[test]
fn test_catches_invalid_execution_subdirectory() {
    let temp_dir = TempDir::new().unwrap();
    let traits_path = temp_dir.path();

    // Valid execution subdirectories
    std::fs::create_dir_all(traits_path.join("objectives/execution/interpreter")).unwrap();
    std::fs::create_dir_all(traits_path.join("objectives/execution/wmi")).unwrap();
    // Invalid - these were historically misplaced
    std::fs::create_dir_all(traits_path.join("objectives/execution/setup")).unwrap();
    std::fs::create_dir_all(traits_path.join("objectives/execution/tty")).unwrap();
    std::fs::create_dir_all(traits_path.join("objectives/execution/reflective-load")).unwrap();

    let result = validate_directory_structure(traits_path);
    assert!(
        result.is_err(),
        "Should catch invalid execution directories"
    );

    let errors = result.unwrap_err();
    assert!(
        errors.iter().any(|e| e.contains("'setup'")),
        "Should flag 'setup' as invalid (hooks → micro-behaviors/build/setup/): {:?}",
        errors
    );
    assert!(
        errors.iter().any(|e| e.contains("'tty'")),
        "Should flag 'tty' as invalid (neutral capability → micro-behaviors/): {:?}",
        errors
    );
    assert!(
        errors.iter().any(|e| e.contains("'reflective-load'")),
        "Should flag 'reflective-load' as invalid (evasive → evasion/ or c2/implant/): {:?}",
        errors
    );
}

#[test]
fn test_catches_invalid_c2_subdirectory() {
    let temp_dir = TempDir::new().unwrap();
    let traits_path = temp_dir.path();

    // Valid C2 subdirectories
    std::fs::create_dir_all(traits_path.join("objectives/command-and-control/backdoor")).unwrap();
    std::fs::create_dir_all(traits_path.join("objectives/command-and-control/dropper")).unwrap();
    std::fs::create_dir_all(traits_path.join("objectives/command-and-control/beacon")).unwrap();
    // Invalid - these were historically misplaced
    std::fs::create_dir_all(traits_path.join("objectives/command-and-control/ddos")).unwrap();
    std::fs::create_dir_all(traits_path.join("objectives/command-and-control/exfil")).unwrap();
    std::fs::create_dir_all(traits_path.join("objectives/command-and-control/phishing")).unwrap();

    let result = validate_directory_structure(traits_path);
    assert!(result.is_err(), "Should catch invalid C2 directories");

    let errors = result.unwrap_err();
    assert!(
        errors.iter().any(|e| e.contains("'ddos'")),
        "Should flag 'ddos' as invalid (belongs in impact/dos/): {:?}",
        errors
    );
    assert!(
        errors.iter().any(|e| e.contains("'exfil'")),
        "Should flag 'exfil' as invalid (belongs in exfiltration/): {:?}",
        errors
    );
    assert!(
        errors.iter().any(|e| e.contains("'phishing'")),
        "Should flag 'phishing' as invalid (belongs in credential-access/): {:?}",
        errors
    );
}

#[test]
fn test_catches_invalid_lateral_movement_subdirectory() {
    let temp_dir = TempDir::new().unwrap();
    let traits_path = temp_dir.path();

    // Valid lateral-movement subdirectories
    std::fs::create_dir_all(traits_path.join("objectives/lateral-movement/worm")).unwrap();
    std::fs::create_dir_all(traits_path.join("objectives/lateral-movement/ssh")).unwrap();
    std::fs::create_dir_all(traits_path.join("objectives/lateral-movement/brute-force")).unwrap();
    // Invalid - these were historically misplaced and moved elsewhere
    std::fs::create_dir_all(traits_path.join("objectives/lateral-movement/scan")).unwrap();
    std::fs::create_dir_all(traits_path.join("objectives/lateral-movement/evasion")).unwrap();
    std::fs::create_dir_all(traits_path.join("objectives/lateral-movement/phishing")).unwrap();

    let result = validate_directory_structure(traits_path);
    assert!(
        result.is_err(),
        "Should catch invalid lateral-movement directories"
    );

    let errors = result.unwrap_err();
    assert!(
        errors.iter().any(|e| e.contains("'scan'")),
        "Should flag 'scan' as invalid (belongs in discovery/): {:?}",
        errors
    );
    assert!(
        errors.iter().any(|e| e.contains("'evasion'")),
        "Should flag 'evasion' as invalid (belongs in objectives/evasion/): {:?}",
        errors
    );
    assert!(
        errors.iter().any(|e| e.contains("'phishing'")),
        "Should flag 'phishing' as invalid (belongs in credential-access/): {:?}",
        errors
    );
}

#[test]
fn test_metadata_no_vendor_specific_toplevel() {
    // Vendor-specific directories belong under metadata/vendor/, not at top level
    let temp_dir = TempDir::new().unwrap();
    let traits_path = temp_dir.path();

    std::fs::create_dir_all(traits_path.join("metadata/apple")).unwrap(); // Invalid!
    std::fs::create_dir_all(traits_path.join("metadata/microsoft")).unwrap(); // Invalid!

    let result = validate_directory_structure(traits_path);
    assert!(result.is_err(), "Vendor dirs at top level should fail");

    let errors = result.unwrap_err();
    assert!(
        errors.iter().any(|e| e.contains("'apple'")),
        "Should flag 'apple' as invalid: {:?}",
        errors
    );
}

#[test]
fn test_catches_invalid_metadata_level2_subdirectory() {
    let temp_dir = TempDir::new().unwrap();
    let traits_path = temp_dir.path();

    // Valid level-2 subdirectories
    std::fs::create_dir_all(traits_path.join("metadata/binary/metrics")).unwrap();
    std::fs::create_dir_all(traits_path.join("metadata/binary/anomaly")).unwrap();
    // Invalid level-2 subdirectory
    std::fs::create_dir_all(traits_path.join("metadata/binary/pe")).unwrap();

    let result = validate_directory_structure(traits_path);
    assert!(
        result.is_err(),
        "Should catch invalid metadata level-2 directories"
    );

    let errors = result.unwrap_err();
    assert!(
        errors.iter().any(|e| e.contains("metadata/binary/pe")),
        "Should flag 'pe' as invalid under binary/: {:?}",
        errors
    );
}

#[test]
fn test_allows_image_measurements_but_not_file_identity() {
    let temp_dir = TempDir::new().unwrap();
    let traits_path = temp_dir.path();

    // `metrics` was replaced by the three things it actually held: pixel
    // statistics, container metadata segments, and bytes past the image.
    std::fs::create_dir_all(traits_path.join("metadata/image/pixel")).unwrap();
    assert!(
        validate_directory_structure(traits_path).is_ok(),
        "metadata/image/pixel should be allowed for neutral image measurements"
    );

    std::fs::create_dir_all(traits_path.join("metadata/image/magic")).unwrap();
    let result = validate_directory_structure(traits_path);
    assert!(
        result.is_err(),
        "metadata/image/magic should not duplicate metadata/file/magic"
    );

    let errors = result.unwrap_err();
    assert!(
        errors.iter().any(|e| e.contains("metadata/image/magic")),
        "Should flag 'magic' as invalid under image/: {:?}",
        errors
    );
}

#[test]
fn test_catches_invalid_metadata_package_subdirectory() {
    let temp_dir = TempDir::new().unwrap();
    let traits_path = temp_dir.path();

    std::fs::create_dir_all(traits_path.join("metadata/package/testing")).unwrap();
    std::fs::create_dir_all(traits_path.join("metadata/package/npm")).unwrap(); // Invalid!

    let result = validate_directory_structure(traits_path);
    assert!(
        result.is_err(),
        "Should catch invalid metadata/package/ directories"
    );

    let errors = result.unwrap_err();
    assert!(
        errors.iter().any(|e| e.contains("metadata/package/npm")),
        "Should flag 'npm' as invalid under package/: {:?}",
        errors
    );
}
#[test]
fn security_hold_policy_directory_is_explicitly_admitted() {
    let temp_dir = TempDir::new().unwrap();
    let traits_path = temp_dir.path();
    std::fs::create_dir_all(traits_path.join("objectives/supply-chain/security-hold")).unwrap();
    assert!(validate_directory_structure(traits_path).is_ok());
    std::fs::create_dir_all(traits_path.join("objectives/supply-chain/security-hold-impostor"))
        .unwrap();
    let errors = validate_directory_structure(traits_path).unwrap_err();
    assert!(
        errors
            .iter()
            .any(|error| error.contains("security-hold-impostor"))
    );
}
