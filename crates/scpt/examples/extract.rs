use scpt::{ScptParser, SymbolKind};
use std::env;
use std::fs;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        eprintln!("Usage: {} <scpt_file>", args[0]);
        std::process::exit(1);
    }

    let path = &args[1];
    let data = match fs::read(path) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("Error reading file: {}", e);
            std::process::exit(1);
        }
    };

    let parser = match ScptParser::new(&data) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("Error parsing scpt: {}", e);
            std::process::exit(1);
        }
    };

    println!("AppleScript Version: {}", parser.version());
    println!("Valid: {}", parser.is_valid());
    println!("Uses shell script: {}", parser.uses_shell_script());
    println!("Uses delay: {}", parser.uses_delay());
    println!();

    println!("=== Apple Events ===");
    for event in parser.apple_events() {
        println!(
            "  {}.{} - {}",
            event.class_code, event.event_code, event.desc
        );
    }
    println!();

    println!("=== Variables ===");
    for var in parser.variables() {
        println!("  {}", var);
    }
    println!();

    println!("=== All Symbols ===");
    let symbols = parser.symbols();

    // Group by kind
    for kind in [
        SymbolKind::Variable,
        SymbolKind::AppleEvent,
        SymbolKind::FourCharCode,
        SymbolKind::Application,
        SymbolKind::StringLiteral,
    ] {
        let filtered: Vec<_> = symbols.iter().filter(|s| s.kind == kind).collect();
        if !filtered.is_empty() {
            println!("\n{:?}s ({}):", kind, filtered.len());
            for sym in filtered.iter().take(20) {
                println!("  [0x{:06x}] {}", sym.offset, sym.name);
            }
            if filtered.len() > 20 {
                println!("  ... and {} more", filtered.len() - 20);
            }
        }
    }
}
