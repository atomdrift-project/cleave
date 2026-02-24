// Directory whitelist validation
//
// Validates that only known subdirectories exist in top-level taxonomy tiers.
// This prevents taxonomy drift and ensures consistency with TAXONOMY.md.

use std::path::Path;

/// Allowed top-level subdirectories in objectives/
///
/// These correspond to MBC objectives and cleave-specific extensions.
/// Update this list when adding new objectives to TAXONOMY.md.
const ALLOWED_OBJECTIVES: &[&str] = &[
    "anti-analysis",       // MBC: Anti-Behavioral Analysis
    "anti-static",         // MBC: Anti-Static Analysis
    "evasion",            // MBC: Defense Evasion (extended)
    "command-and-control", // MBC: Command and Control
    "collection",         // MBC: Collection
    "credential-access",  // MBC: Credential Access
    "discovery",          // MBC: Discovery
    "execution",          // MBC: Execution
    "exfiltration",       // MBC: Exfiltration
    "impact",             // MBC: Impact
    "lateral-movement",   // MBC: Lateral Movement
    "persistence",        // MBC: Persistence
    "privilege-escalation", // MBC: Privilege Escalation
    // Meta categories
    "false-positives",    // Special: downgrade rules for reducing FPs
];

/// Allowed top-level subdirectories in micro-behaviors/
///
/// These represent capability categories (what code can do).
/// Must not use objective names (no c2, persist, evasion, etc.).
const ALLOWED_MICRO_BEHAVIORS: &[&str] = &[
    "build",
    "cli",
    "communications",
    "config",
    "crypto",
    "data",
    "dylib",
    "env",
    "fs",
    "graphics",
    "hardware",
    "host",
    "interface",
    "interop",
    "io",
    "mem",
    "os",
    "process",
    "software",
    "time",
    "ui",
    "vm",
];

/// Allowed top-level subdirectories in well-known/
///
/// These represent specific malware families and tools.
const ALLOWED_WELL_KNOWN: &[&str] = &[
    "malware",
    "tools",
];

/// Validates that only known subdirectories exist in taxonomy tiers.
///
/// Returns Ok(()) if all directories are whitelisted, or Err with a list
/// of unknown directories that should be reviewed.
pub fn validate_directory_structure(traits_path: &Path) -> Result<(), Vec<String>> {
    let mut errors = Vec::new();

    // Check objectives/
    if let Ok(entries) = std::fs::read_dir(traits_path.join("objectives")) {
        for entry in entries.flatten() {
            if entry.file_type().map(|ft| ft.is_dir()).unwrap_or(false) {
                let dir_name = entry.file_name().to_string_lossy().to_string();
                if !ALLOWED_OBJECTIVES.contains(&dir_name.as_str()) {
                    errors.push(format!(
                        "Unknown objectives/ subdirectory: '{}'\n  \
                         If this is a valid MBC objective, add it to ALLOWED_OBJECTIVES in \
                         src/capabilities/validation/directory_whitelist.rs",
                        dir_name
                    ));
                }
            }
        }
    }

    // Check micro-behaviors/
    if let Ok(entries) = std::fs::read_dir(traits_path.join("micro-behaviors")) {
        for entry in entries.flatten() {
            if entry.file_type().map(|ft| ft.is_dir()).unwrap_or(false) {
                let dir_name = entry.file_name().to_string_lossy().to_string();
                if !ALLOWED_MICRO_BEHAVIORS.contains(&dir_name.as_str()) {
                    errors.push(format!(
                        "Unknown micro-behaviors/ subdirectory: '{}'\n  \
                         Micro-behaviors must describe capabilities, not objectives.\n  \
                         If valid, add to ALLOWED_MICRO_BEHAVIORS in \
                         src/capabilities/validation/directory_whitelist.rs",
                        dir_name
                    ));
                }
            }
        }
    }

    // Check well-known/
    if let Ok(entries) = std::fs::read_dir(traits_path.join("well-known")) {
        for entry in entries.flatten() {
            if entry.file_type().map(|ft| ft.is_dir()).unwrap_or(false) {
                let dir_name = entry.file_name().to_string_lossy().to_string();
                if !ALLOWED_WELL_KNOWN.contains(&dir_name.as_str()) {
                    errors.push(format!(
                        "Unknown well-known/ subdirectory: '{}'\n  \
                         well-known/ should only contain 'malware' and 'tools'.\n  \
                         If adding a new category, update ALLOWED_WELL_KNOWN in \
                         src/capabilities/validation/directory_whitelist.rs",
                        dir_name
                    ));
                }
            }
        }
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

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
    fn test_no_objective_names_in_micro_behaviors() {
        // Ensure micro-behaviors doesn't contain objective names
        assert!(!ALLOWED_MICRO_BEHAVIORS.contains(&"c2"));
        assert!(!ALLOWED_MICRO_BEHAVIORS.contains(&"persist"));
        assert!(!ALLOWED_MICRO_BEHAVIORS.contains(&"evasion"));
        assert!(!ALLOWED_MICRO_BEHAVIORS.contains(&"anti-static"));
    }
}
