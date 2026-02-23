//! String extraction command.
//!
//! Extracts strings from binary files and source code, with support for:
//! - Binary string extraction (imports, exports, functions, stack strings, etc.)
//! - AST-based extraction for source files
//! - Multiple encoding detection (UTF-8, UTF-16, base64, etc.)
//! - String classification (URLs, IPs, emails, paths, shell commands)

use crate::analyzers::{
    detect_file_type, elf::ElfAnalyzer, macho::MachOAnalyzer, pe::PEAnalyzer, Analyzer, FileType,
};
use crate::cli;
use crate::commands::shared::extract_strings_from_ast;
use crate::radare2::Radare2Analyzer;
use crate::strings;
use anyhow::Result;
use std::fs;
use std::path::Path;

pub(crate) fn run(target: &str, min_length: usize, format: &cli::OutputFormat) -> Result<String> {
    let path = Path::new(target);
    if !path.exists() {
        anyhow::bail!("File does not exist: {}", target);
    }

    let data = fs::read(path)?;

    // For source code files with AST support, extract strings via AST parsing
    if let Ok(file_type) = detect_file_type(path) {
        if file_type.is_source_code() {
            return extract_strings_from_ast(path, &file_type, min_length, format);
        }
    }

    let mut imports = std::collections::HashSet::new();
    let mut import_libraries = std::collections::HashMap::new();
    let mut exports = std::collections::HashSet::new();
    let mut functions = std::collections::HashSet::new();

    // Try to extract symbols if it's a binary file
    if let Ok(file_type) = detect_file_type(path) {
        match file_type {
            FileType::Elf | FileType::MachO | FileType::Pe => {
                // macOS specific optimization: use nm -u -m for highly accurate import library mappings
                #[cfg(target_os = "macos")]
                {
                    if file_type == FileType::MachO {
                        if let Ok(nm_output) = std::process::Command::new("nm")
                            .args(["-u", "-m", &*path.to_string_lossy()])
                            .output()
                        {
                            let nm_str = String::from_utf8_lossy(&nm_output.stdout);
                            for line in nm_str.lines() {
                                let trimmed = line.trim();
                                if let Some(sym_start) = trimmed.find("external ") {
                                    let sym_part = &trimmed[sym_start + 9..];
                                    if let Some(lib_start) = sym_part.find(" (from ") {
                                        let mut sym = sym_part[..lib_start].trim().to_string();
                                        // Strip leading underscore for consistency
                                        if sym.starts_with('_') {
                                            sym = sym[1..].to_string();
                                        }
                                        let lib_part = &sym_part[lib_start + 7..];
                                        let lib = lib_part.trim_end_matches(')').to_string();
                                        imports.insert(sym.clone());
                                        import_libraries.insert(sym, lib);
                                    }
                                }
                            }
                        }
                    }
                }

                // Use radare2 directly for fast symbol/function extraction in ONE batch
                if Radare2Analyzer::is_available() {
                    let r2 = Radare2Analyzer::new();
                    if let Ok((r2_imports, _, r2_symbols)) = r2.extract_all_symbols(path) {
                        for imp in r2_imports {
                            let name = imp.name.trim_start_matches('_');
                            imports.insert(name.to_string());
                            if let Some(lib) = imp.lib_name {
                                import_libraries.insert(name.to_string(), lib);
                            }
                        }
                        for sym in r2_symbols {
                            if sym.name.starts_with("imp.") || sym.name.starts_with("sym.imp.") {
                                let clean = sym
                                    .name
                                    .trim_start_matches("sym.imp.")
                                    .trim_start_matches("imp.")
                                    .trim_start_matches('_');
                                imports.insert(clean.to_string());
                            } else if sym.symbol_type == "FUNC"
                                || sym.symbol_type == "func"
                                || sym.name.starts_with("fcn.")
                            {
                                let name = sym.name.trim_start_matches('_').to_string();
                                // Exports are GLOBAL in MachO symbols
                                if sym.symbol_type == "FUNC"
                                    && (sym.name.starts_with("__mh_") || !sym.name.starts_with('_'))
                                {
                                    exports.insert(name.clone());
                                }
                                if !imports.contains(&name) && !exports.contains(&name) {
                                    functions.insert(name);
                                }
                            }
                        }
                    }
                } else {
                    // Fallback to minimal goblin analysis
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

                    for import in report.imports {
                        imports.insert(import.symbol.clone());
                        if let Some(lib) = import.library {
                            import_libraries.insert(import.symbol, lib);
                        }
                    }
                    for export in report.exports {
                        exports.insert(export.symbol);
                    }
                    for func in report.functions {
                        if func.name.starts_with("sym.imp.") {
                            let clean = func.name.trim_start_matches("sym.imp.");
                            imports.insert(clean.to_string());
                        } else if !imports.contains(&func.name) && !exports.contains(&func.name) {
                            functions.insert(func.name);
                        }
                    }
                }
            }
            _ => {}
        }
    }

    let extractor = strings::StringExtractor::new()
        .with_min_length(min_length)
        .with_imports(&imports)
        .with_import_libraries(import_libraries)
        .with_exports(&exports)
        .with_functions(&functions);

    let strings = extractor.extract_smart(&data, None);

    match format {
        cli::OutputFormat::Jsonl => Ok(serde_json::to_string_pretty(&strings)?),
        cli::OutputFormat::Terminal => {
            let mut output = String::new();

            // Sort strings by offset to show them in file order
            let mut strings = strings;
            strings.sort_by_key(|s| s.offset);

            let mut current_section: Option<&str> = None;

            for s in &strings {
                let section = s.section.as_deref();

                // Print section header when section changes
                if section != current_section {
                    if current_section.is_some() {
                        output.push('\n');
                    }
                    let section_name = section.unwrap_or("(unknown)");
                    output.push_str(&format!("── {} ──\n", section_name));
                    current_section = section;
                }

                let offset = s
                    .offset
                    .map(|o| format!("{}", o))
                    .unwrap_or_else(|| "-".to_string());

                // Use stng-style type labels
                let stype_str = match s.string_type {
                    crate::types::StringType::Import => "import",
                    crate::types::StringType::Export => "export",
                    crate::types::StringType::FuncName => "func",
                    crate::types::StringType::StackString => "stack",
                    crate::types::StringType::Url => "url",
                    crate::types::StringType::IP => "ip",
                    crate::types::StringType::Email => "email",
                    crate::types::StringType::Path => "path",
                    crate::types::StringType::Base64 => "base64",
                    crate::types::StringType::ShellCmd => "shell",
                    _ => "-",
                };

                // Format encoding chain as a separate column
                let encoding_str = if s.encoding_chain.is_empty() {
                    "-".to_string()
                } else {
                    s.encoding_chain.join("+")
                };

                // Escape control characters for display
                let mut val_display = s
                    .value
                    .replace('\n', "\\n")
                    .replace('\r', "\\r")
                    .replace('\t', "\\t");

                if s.string_type == crate::types::StringType::Base64 {
                    use base64::{engine::general_purpose, Engine as _};

                    if let Ok(decoded) = general_purpose::STANDARD.decode(s.value.trim()) {
                        if !decoded.is_empty()
                            && decoded.iter().all(|&b| {
                                (0x20..=0x7e).contains(&b) || b == b'\n' || b == b'\r' || b == b'\t'
                            })
                        {
                            if let Ok(decoded_str) = String::from_utf8(decoded) {
                                let escaped = decoded_str
                                    .replace('\n', "\\n")
                                    .replace('\r', "\\r")
                                    .replace('\t', "\\t");

                                val_display = format!("{}  [{}]", val_display, escaped);
                            }
                        }
                    }
                }

                output.push_str(&format!(
                    "{:>10} {:<12} {:<10} {}\n",
                    offset, stype_str, encoding_str, val_display
                ));
            }
            Ok(output)
        }
    }
}
