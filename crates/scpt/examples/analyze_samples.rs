//! Example: analyze sample scpt files.
#![allow(clippy::unwrap_used)] // Examples use unwrap for simplicity

use std::collections::{HashMap, HashSet};
use std::fs;

fn main() {
    let dir = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "/Users/t/src/mbdl/scpt".to_string());
    let mut all_symbols: HashMap<String, Vec<String>> = HashMap::new();
    let mut all_events: HashMap<String, Vec<String>> = HashMap::new();
    let mut all_apps: HashSet<String> = HashSet::new();
    let mut all_strings: HashSet<String> = HashSet::new();

    for entry in fs::read_dir(&dir).unwrap() {
        let entry = entry.unwrap();
        let path = entry.path();
        if path.extension().is_some_and(|e| e == "scpt") {
            let filename = path.file_name().unwrap().to_string_lossy().to_string();
            let short_name = &filename[..8];
            let data = fs::read(&path).unwrap();

            if let Ok(parser) = scpt::ScptParser::new(&data) {
                println!("\n=== {} ({} bytes) ===", short_name, data.len());

                for sym in parser.symbols() {
                    let kind_str = match sym.kind {
                        scpt::SymbolKind::Variable => "var",
                        scpt::SymbolKind::AppleEvent => "event",
                        scpt::SymbolKind::FourCharCode => "4cc",
                        scpt::SymbolKind::Application => "app",
                        scpt::SymbolKind::StringLiteral => "str",
                        scpt::SymbolKind::Handler => "handler",
                    };
                    println!("  {:8} {}", kind_str, sym.name);

                    match sym.kind {
                        scpt::SymbolKind::Variable => {
                            all_symbols
                                .entry(sym.name.clone())
                                .or_default()
                                .push(short_name.to_string());
                        }
                        scpt::SymbolKind::AppleEvent => {
                            all_events
                                .entry(sym.name.clone())
                                .or_default()
                                .push(short_name.to_string());
                        }
                        scpt::SymbolKind::Application => {
                            all_apps.insert(sym.name.clone());
                        }
                        scpt::SymbolKind::StringLiteral => {
                            if sym.name.len() > 5 {
                                all_strings.insert(sym.name.clone());
                            }
                        }
                        _ => {}
                    }
                }
            }
        }
    }

    println!("\n\n========== SUMMARY ==========\n");

    println!("--- Unique Apple Events ---");
    let mut events: Vec<_> = all_events.keys().collect();
    events.sort();
    for e in events {
        println!("  {} (in {} files)", e, all_events[e].len());
    }

    println!("\n--- Variables (appearing in 2+ files) ---");
    let mut vars: Vec<_> = all_symbols.iter().filter(|(_, v)| v.len() >= 2).collect();
    vars.sort_by_key(|(k, _)| *k);
    for (v, files) in vars {
        println!("  {} ({})", v, files.len());
    }

    println!("\n--- All Unique Variables ---");
    let mut all_vars: Vec<_> = all_symbols.keys().collect();
    all_vars.sort();
    for v in all_vars {
        println!("  {}", v);
    }

    println!("\n--- Applications ---");
    let mut apps: Vec<_> = all_apps.iter().collect();
    apps.sort();
    for a in apps {
        println!("  {}", a);
    }

    println!("\n--- Interesting Strings ---");
    let mut strings: Vec<_> = all_strings.iter().collect();
    strings.sort();
    for s in strings {
        println!("  {}", s);
    }
}
