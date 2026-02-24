//! Test the scpt crate in isolation, simulating how cleave would use it

use scpt::{ScptParser, SymbolKind};

const SHELL_SCRIPT_SCPT: &[u8] = include_bytes!("fixtures/shell_script.scpt");
const TELL_APP_SCPT: &[u8] = include_bytes!("fixtures/tell_app.scpt");

/// Simulate how cleave's AppleScriptAnalyzer extracts imports
fn extract_imports(data: &[u8]) -> Vec<(String, Option<String>, String)> {
    let mut imports = Vec::new();

    if let Ok(parser) = ScptParser::new(data) {
        for symbol in parser.symbols() {
            let (source, library) = match symbol.kind {
                SymbolKind::Variable => ("scpt_variable", None),
                SymbolKind::AppleEvent => ("scpt_event", Some("AppleEvents")),
                SymbolKind::FourCharCode => ("scpt_fourcc", Some("OSType")),
                SymbolKind::Application => ("scpt_app", Some("Applications")),
                SymbolKind::Handler => ("scpt_handler", None),
                SymbolKind::StringLiteral => continue,
            };

            imports.push((symbol.name, library.map(String::from), source.to_string()));
        }

        for event in parser.apple_events() {
            imports.push((
                format!("{}.{}", event.class_code, event.event_code),
                Some("AppleEvents".to_string()),
                "scpt_event".to_string(),
            ));

            if event.desc != "unknown" {
                imports.push((
                    event.desc.to_string(),
                    Some("AppleScript".to_string()),
                    "scpt_command".to_string(),
                ));
            }
        }
    }

    imports
}

#[test]
fn test_cleave_integration_shell_script() {
    let imports = extract_imports(SHELL_SCRIPT_SCPT);

    // Check variables are extracted
    assert!(imports
        .iter()
        .any(|(name, _, source)| name == "userName" && source == "scpt_variable"));
    assert!(imports
        .iter()
        .any(|(name, _, source)| name == "hostName" && source == "scpt_variable"));
    assert!(imports
        .iter()
        .any(|(name, _, source)| name == "currentDir" && source == "scpt_variable"));

    // Check Apple Events are extracted
    assert!(imports.iter().any(|(name, lib, source)| name == "syso.exec"
        && lib.as_deref() == Some("AppleEvents")
        && source == "scpt_event"));
    assert!(imports.iter().any(|(name, lib, source)| name == "syso.dela"
        && lib.as_deref() == Some("AppleEvents")
        && source == "scpt_event"));

    // Check command descriptions are extracted
    assert!(imports
        .iter()
        .any(|(name, lib, source)| name == "do shell script"
            && lib.as_deref() == Some("AppleScript")
            && source == "scpt_command"));
    assert!(imports.iter().any(|(name, lib, source)| name == "delay"
        && lib.as_deref() == Some("AppleScript")
        && source == "scpt_command"));
}

#[test]
fn test_cleave_integration_tell_app() {
    let imports = extract_imports(TELL_APP_SCPT);

    // Check variables
    assert!(imports
        .iter()
        .any(|(name, _, source)| name == "desktopFolder" && source == "scpt_variable"));
    assert!(imports
        .iter()
        .any(|(name, _, source)| name == "processCount" && source == "scpt_variable"));

    // Check applications
    assert!(imports.iter().any(|(name, lib, source)| name == "Finder"
        && lib.as_deref() == Some("Applications")
        && source == "scpt_app"));
    assert!(imports
        .iter()
        .any(|(name, lib, source)| name == "System Events"
            && lib.as_deref() == Some("Applications")
            && source == "scpt_app"));

    // Check Apple Events
    assert!(imports.iter().any(|(name, _, _)| name == "misc.actv"));
    assert!(imports.iter().any(|(name, _, _)| name == "core.cnte"));

    // Check command descriptions
    assert!(imports.iter().any(|(name, _, _)| name == "activate"));
    assert!(imports.iter().any(|(name, _, _)| name == "count"));
}

#[test]
fn test_import_count() {
    let imports = extract_imports(SHELL_SCRIPT_SCPT);

    // Should have a reasonable number of imports
    assert!(
        imports.len() >= 10,
        "Expected at least 10 imports, got {}",
        imports.len()
    );

    // Print all imports for debugging
    for (name, lib, source) in &imports {
        println!(
            "{}: {} ({})",
            source,
            name,
            lib.as_deref().unwrap_or("none")
        );
    }
}
