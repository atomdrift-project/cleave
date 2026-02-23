//! Integration tests for scpt parser.
#![allow(clippy::unwrap_used)] // Tests use unwrap for simplicity

use scpt::{is_scpt, ScptParser, SymbolKind};

const SHELL_SCRIPT_SCPT: &[u8] = include_bytes!("fixtures/shell_script.scpt");
const TELL_APP_SCPT: &[u8] = include_bytes!("fixtures/tell_app.scpt");
const SIMPLE_SCPT: &[u8] = include_bytes!("fixtures/simple.scpt");

#[test]
fn test_is_scpt_magic() {
    assert!(is_scpt(SHELL_SCRIPT_SCPT));
    assert!(is_scpt(TELL_APP_SCPT));
    assert!(is_scpt(SIMPLE_SCPT));
    assert!(!is_scpt(b"not a scpt file"));
}

#[test]
fn test_parser_version() {
    let parser = ScptParser::new(SHELL_SCRIPT_SCPT).unwrap();
    assert!(parser.version().starts_with("1."));
}

#[test]
fn test_parser_validity() {
    let parser = ScptParser::new(SHELL_SCRIPT_SCPT).unwrap();
    assert!(parser.is_valid());

    let parser = ScptParser::new(TELL_APP_SCPT).unwrap();
    assert!(parser.is_valid());
}

#[test]
fn test_shell_script_detection() {
    let parser = ScptParser::new(SHELL_SCRIPT_SCPT).unwrap();
    assert!(parser.uses_shell_script());
    assert!(parser.uses_delay());

    let parser = ScptParser::new(TELL_APP_SCPT).unwrap();
    assert!(!parser.uses_shell_script());
    assert!(parser.uses_delay());
}

#[test]
fn test_shell_script_variables() {
    let parser = ScptParser::new(SHELL_SCRIPT_SCPT).unwrap();
    let vars = parser.variables();

    assert!(vars.contains(&"userName".to_string()));
    assert!(vars.contains(&"hostName".to_string()));
    assert!(vars.contains(&"currentDir".to_string()));
}

#[test]
fn test_shell_script_events() {
    let parser = ScptParser::new(SHELL_SCRIPT_SCPT).unwrap();

    assert!(parser.has_apple_event("syso", "exec"));
    assert!(parser.has_apple_event("syso", "dela"));
}

#[test]
fn test_tell_app_variables() {
    let parser = ScptParser::new(TELL_APP_SCPT).unwrap();
    let vars = parser.variables();

    assert!(vars.contains(&"desktopFolder".to_string()));
    assert!(vars.contains(&"processCount".to_string()));
}

#[test]
fn test_tell_app_events() {
    let parser = ScptParser::new(TELL_APP_SCPT).unwrap();
    let events = parser.apple_events();

    // Check for activate event
    assert!(events
        .iter()
        .any(|e| e.class_code == "misc" && e.event_code == "actv"));

    // Check for count event
    assert!(events
        .iter()
        .any(|e| e.class_code == "core" && e.event_code == "cnte"));

    // Check for folder reference
    assert!(events
        .iter()
        .any(|e| e.class_code == "ears" && e.event_code == "ffdr"));
}

#[test]
fn test_tell_app_applications() {
    let parser = ScptParser::new(TELL_APP_SCPT).unwrap();
    let symbols = parser.symbols();

    let apps: Vec<_> = symbols
        .iter()
        .filter(|s| s.kind == SymbolKind::Application)
        .collect();

    assert!(apps.iter().any(|s| s.name == "Finder"));
    assert!(apps.iter().any(|s| s.name == "System Events"));
}

#[test]
fn test_simple_variables() {
    let parser = ScptParser::new(SIMPLE_SCPT).unwrap();
    let vars = parser.variables();

    assert!(vars.contains(&"myVariable".to_string()));
    assert!(vars.contains(&"anotherVar".to_string()));
    assert!(vars.contains(&"resultPath".to_string()));
}

#[test]
fn test_apple_event_descriptions() {
    let parser = ScptParser::new(SHELL_SCRIPT_SCPT).unwrap();
    let events = parser.apple_events();

    let exec_event = events
        .iter()
        .find(|e| e.class_code == "syso" && e.event_code == "exec")
        .unwrap();
    assert_eq!(exec_event.desc, "do shell script");

    let delay_event = events
        .iter()
        .find(|e| e.class_code == "syso" && e.event_code == "dela")
        .unwrap();
    assert_eq!(delay_event.desc, "delay");
}

#[test]
fn test_four_char_codes() {
    let parser = ScptParser::new(TELL_APP_SCPT).unwrap();
    let symbols = parser.symbols();

    let fourccs: Vec<_> = symbols
        .iter()
        .filter(|s| s.kind == SymbolKind::FourCharCode)
        .collect();

    // "desk" (desktop) and "prcs" (processes) should be present
    assert!(fourccs.iter().any(|s| s.name == "desk"));
    assert!(fourccs.iter().any(|s| s.name == "prcs"));
}

#[test]
fn test_symbol_offsets() {
    let parser = ScptParser::new(SHELL_SCRIPT_SCPT).unwrap();
    let symbols = parser.symbols();

    // All symbols should have valid offsets within the file
    for sym in &symbols {
        assert!(sym.offset < SHELL_SCRIPT_SCPT.len());
    }
}

#[test]
fn test_no_duplicate_symbols() {
    let parser = ScptParser::new(TELL_APP_SCPT).unwrap();
    let symbols = parser.symbols();

    // Check for no exact duplicates (same name + kind)
    let mut seen = std::collections::HashSet::new();
    for sym in &symbols {
        let key = (sym.name.clone(), sym.kind.clone());
        assert!(
            seen.insert(key.clone()),
            "Duplicate symbol found: {:?}",
            key
        );
    }
}
