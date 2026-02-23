//! Symbol extraction command.
//!
//! Extracts symbols (imports, exports, functions) from binary files and source code.
//! Supports ELF, PE, Mach-O binaries as well as various script languages.

use crate::analyzers::{
    self, detect_file_type, elf::ElfAnalyzer, macho::MachOAnalyzer, pe::PEAnalyzer, Analyzer,
    FileType,
};
use crate::cli;
use crate::commands::shared::SymbolInfo;
use crate::radare2::Radare2Analyzer;
use anyhow::Result;
use std::path::Path;

pub(crate) fn run(target: &str, format: &cli::OutputFormat) -> Result<String> {
    let path = Path::new(target);
    if !path.exists() {
        anyhow::bail!("File does not exist: {}", target);
    }

    let mut symbols: Vec<SymbolInfo> = Vec::new();

    // Detect file type
    if let Ok(file_type) = detect_file_type(path) {
        match file_type {
            FileType::Elf | FileType::MachO | FileType::Pe => {
                // Binary file - extract symbols with addresses

                // Use radare2 for comprehensive symbol extraction
                if Radare2Analyzer::is_available() {
                    let r2 = Radare2Analyzer::new();
                    if let Ok((r2_imports, r2_exports, r2_symbols)) = r2.extract_all_symbols(path) {
                        // Add imports
                        for imp in r2_imports {
                            symbols.push(SymbolInfo {
                                name: imp.name.trim_start_matches('_').to_string(),
                                address: None,
                                library: imp.lib_name,
                                symbol_type: "import".to_string(),
                                source: "radare2".to_string(),
                            });
                        }

                        // Add exports
                        for exp in r2_exports {
                            symbols.push(SymbolInfo {
                                name: exp.name.trim_start_matches('_').to_string(),
                                address: Some(format!("0x{:x}", exp.vaddr)),
                                library: None,
                                symbol_type: "export".to_string(),
                                source: "radare2".to_string(),
                            });
                        }

                        // Add other symbols (functions, etc.)
                        for sym in r2_symbols {
                            let sym_type = if sym.symbol_type == "FUNC" || sym.symbol_type == "func"
                            {
                                "function"
                            } else {
                                &sym.symbol_type
                            };

                            let clean_name = sym.name.trim_start_matches('_').to_string();

                            // Skip if already added as import or export
                            let already_added = symbols.iter().any(|s| s.name == clean_name);
                            if !already_added {
                                symbols.push(SymbolInfo {
                                    name: clean_name,
                                    address: Some(format!("0x{:x}", sym.vaddr)),
                                    library: None,
                                    symbol_type: sym_type.to_lowercase(),
                                    source: "radare2".to_string(),
                                });
                            }
                        }
                    }
                } else {
                    // Fallback to goblin-based analysis
                    let capability_mapper = crate::capabilities::CapabilityMapper::empty();
                    let report = match file_type {
                        FileType::Elf => ElfAnalyzer::new()
                            .with_capability_mapper(capability_mapper)
                            .analyze(path)?,
                        FileType::MachO => MachOAnalyzer::new()
                            .with_capability_mapper(capability_mapper)
                            .analyze(path)?,
                        FileType::Pe => PEAnalyzer::new()
                            .with_capability_mapper(capability_mapper)
                            .analyze(path)?,
                        _ => anyhow::bail!("unsupported binary file type for symbol extraction"),
                    };

                    // Add imports
                    for import in report.imports {
                        symbols.push(SymbolInfo {
                            name: import.symbol.clone(),
                            address: None,
                            library: import.library,
                            symbol_type: "import".to_string(),
                            source: import.source,
                        });
                    }

                    // Add exports
                    for export in report.exports {
                        symbols.push(SymbolInfo {
                            name: export.symbol,
                            address: export.offset,
                            library: None,
                            symbol_type: "export".to_string(),
                            source: export.source,
                        });
                    }

                    // Add functions
                    for func in report.functions {
                        symbols.push(SymbolInfo {
                            name: func.name,
                            address: func.offset,
                            library: None,
                            symbol_type: "function".to_string(),
                            source: func.source,
                        });
                    }
                }
            }
            _ => {
                // Source file or script - analyze for symbols using unified analyzer
                let report =
                    if let Some(analyzer) = analyzers::analyzer_for_file_type(&file_type, None) {
                        analyzer.analyze(path)?
                    } else {
                        anyhow::bail!(
                            "Unsupported file type for symbol extraction: {:?}",
                            file_type
                        );
                    };

                // Add imports (function calls from source code)
                for import in report.imports {
                    symbols.push(SymbolInfo {
                        name: import.symbol.clone(),
                        address: None,
                        library: import.library,
                        symbol_type: "import".to_string(),
                        source: import.source,
                    });
                }

                // Add exports (defined functions)
                for export in report.exports {
                    symbols.push(SymbolInfo {
                        name: export.symbol,
                        address: export.offset,
                        library: None,
                        symbol_type: "export".to_string(),
                        source: export.source,
                    });
                }

                // Add functions
                for func in report.functions {
                    symbols.push(SymbolInfo {
                        name: func.name,
                        address: func.offset,
                        library: None,
                        symbol_type: "function".to_string(),
                        source: func.source,
                    });
                }
            }
        }
    } else {
        anyhow::bail!("Unable to detect file type for: {}", target);
    }

    // Sort symbols by address (if available), then by name
    symbols.sort_by(|a, b| {
        match (&a.address, &b.address) {
            (Some(addr_a), Some(addr_b)) => {
                // Parse hex addresses for proper numeric sorting
                let parse_addr =
                    |s: &str| -> u64 { s.trim_start_matches("0x").parse::<u64>().unwrap_or(0) };
                let num_a = parse_addr(addr_a);
                let num_b = parse_addr(addr_b);
                num_a.cmp(&num_b)
            }
            (Some(_), None) => std::cmp::Ordering::Less,
            (None, Some(_)) => std::cmp::Ordering::Greater,
            (None, None) => a.name.cmp(&b.name),
        }
    });

    // Format output
    match format {
        cli::OutputFormat::Jsonl => Ok(serde_json::to_string_pretty(&symbols)?),
        cli::OutputFormat::Terminal => {
            let mut output = String::new();
            output.push_str(&format!(
                "Extracted {} symbols from {}\n\n",
                symbols.len(),
                target
            ));
            output.push_str(&format!(
                "{:<18} {:<12} {:<20} {}\n",
                "ADDRESS", "TYPE", "LIBRARY", "NAME"
            ));
            output.push_str(&format!(
                "{:-<18} {:-<12} {:-<20} {:-<30}\n",
                "", "", "", ""
            ));

            for sym in symbols {
                let addr = sym.address.unwrap_or_else(|| "-".to_string());
                let lib = sym.library.as_deref().unwrap_or("-");
                output.push_str(&format!(
                    "{:<18} {:<12} {:<20} {}\n",
                    addr, sym.symbol_type, lib, sym.name
                ));
            }

            Ok(output)
        }
    }
}
