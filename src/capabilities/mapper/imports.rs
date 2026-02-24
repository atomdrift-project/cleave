//! Import finding generation and ecosystem detection.
//!
//! This module handles the generation of capability findings from import data,
//! supporting both binary formats (ELF, Mach-O, PE) and source code (Python, JS, etc.).

use crate::types::{AnalysisReport, Criticality, Evidence, Finding, FindingKind};
use rustc_hash::FxHashSet;

/// Maximum number of metadata/internal/symbols:: findings to generate.
/// These are only used for ML, so we limit to avoid output explosion on large binaries.
const MAX_IMPORT_FINDINGS: usize = 1024;

impl super::CapabilityMapper {
    /// Generate capability findings from import data in analysis reports.
    ///
    /// Creates structured findings with hierarchical IDs that enable composite rules
    /// to reference imports as traits. For example:
    /// - `metadata/import/python/socket` for Python's socket module
    /// - `metadata/import/npm/axios` for npm's axios package
    /// - `metadata/import/elf/libcrypto.so` for ELF shared library imports
    pub(crate) fn generate_import_findings(report: &mut AnalysisReport) {
        // Collect existing finding IDs to avoid duplicates
        let mut seen_ids: FxHashSet<String> =
            report.findings.iter().map(|f| f.id.clone()).collect();

        let file_type = report.target.file_type.to_lowercase();
        let ecosystem = Self::detect_import_ecosystem(&file_type, "");
        let is_binary = matches!(ecosystem, "elf" | "macho" | "pe");

        let mut new_findings: Vec<Finding> = Vec::new();

        if is_binary {
            // For binaries: generate library-level and symbol-level findings
            // Library: metadata/dylib/{library} - linked libraries (for composite trait matching)
            // Symbol: metadata/internal/symbols/{symbol} - called/referenced symbols (for ML only, not composite traits)

            // Group symbols by library for dylib findings
            let mut libs_with_symbols: std::collections::HashMap<String, Vec<String>> =
                std::collections::HashMap::new();

            let mut import_finding_count = 0;

            for import in &report.imports {
                if let Some(lib) = &import.library {
                    if !lib.is_empty() {
                        libs_with_symbols
                            .entry(lib.clone())
                            .or_default()
                            .push(import.symbol.clone());
                    }
                }

                // Generate symbol-level finding for ML (not for composite trait matching)
                // Limited to MAX_IMPORT_FINDINGS to avoid output explosion
                if import_finding_count >= MAX_IMPORT_FINDINGS {
                    continue;
                }

                let normalized_symbol = Self::normalize_import_name(&import.symbol);
                if !normalized_symbol.is_empty() {
                    let symbol_id = format!("metadata/internal/symbols::{}", normalized_symbol);
                    if !seen_ids.contains(&symbol_id) {
                        seen_ids.insert(symbol_id.clone());
                        import_finding_count += 1;
                        new_findings.push(Finding {
                            id: symbol_id,
                            kind: FindingKind::Structural,
                            desc: String::new(), // Compact: desc is redundant (derivable from id)
                            conf: 0.95,
                            crit: Criticality::Baseline,
                            mbc: None,
                            attack: None,
                            trait_refs: Vec::new(),
                            evidence: Vec::new(), // Compact: evidence is redundant
                            source_file: None,
                        });
                    }
                }
            }

            // Generate a finding for each library
            for (library, symbols) in libs_with_symbols {
                let normalized_lib = Self::normalize_import_name(&library);
                if normalized_lib.is_empty() {
                    continue;
                }

                // No format prefix - we don't encode file types in trait IDs
                let id = format!("metadata/dylib::{}", normalized_lib);

                if seen_ids.contains(&id) {
                    continue;
                }
                seen_ids.insert(id.clone());

                // Limit symbols in description to first 5
                let symbol_preview: Vec<_> = symbols.iter().take(5).cloned().collect();
                let desc = if symbols.len() > 5 {
                    format!(
                        "links {} ({}, ... +{} more)",
                        library,
                        symbol_preview.join(", "),
                        symbols.len() - 5
                    )
                } else {
                    format!("links {} ({})", library, symbol_preview.join(", "))
                };

                new_findings.push(Finding {
                    id,
                    kind: FindingKind::Structural,
                    desc,
                    conf: 0.95,
                    crit: Criticality::Baseline,
                    mbc: None,
                    attack: None,
                    trait_refs: Vec::new(),
                    evidence: vec![Evidence {
                        method: "library".to_string(),
                        source: "goblin".to_string(),
                        value: library,
                        location: Some(format!("{} symbols", symbols.len())),
                    }],

                    source_file: None,
                });
            }
        } else {
            // For scripts: generate two types of findings:
            // 1. metadata/import/{lang}/{module} for actual imports (usable in composite traits)
            // 2. metadata/internal/symbols/{symbol} for function calls (ML only, not for composites)
            let mut import_finding_count = 0;

            for import in &report.imports {
                let normalized = Self::normalize_import_name(&import.symbol);
                if normalized.is_empty() {
                    continue;
                }

                if import.source == "ast" {
                    // Function calls go to metadata/internal/symbols/ for ML usage only
                    // Limited to MAX_IMPORT_FINDINGS
                    if import_finding_count >= MAX_IMPORT_FINDINGS {
                        continue;
                    }

                    let symbol_id = format!("metadata/internal/symbols::{}", normalized);
                    if !seen_ids.contains(&symbol_id) {
                        seen_ids.insert(symbol_id.clone());
                        import_finding_count += 1;
                        new_findings.push(Finding {
                            id: symbol_id,
                            kind: FindingKind::Structural,
                            desc: String::new(), // Compact: derivable from id
                            conf: 0.95,
                            crit: Criticality::Baseline,
                            mbc: None,
                            attack: None,
                            trait_refs: Vec::new(),
                            evidence: Vec::new(), // Compact: redundant
                            source_file: None,
                        });
                    }
                } else {
                    // Actual imports go to metadata/import/{lang}/{module} for composite traits
                    let source_ecosystem =
                        Self::detect_import_ecosystem(&file_type, &import.source);

                    let id = format!("metadata/import/{}::{}", source_ecosystem, normalized);

                    if seen_ids.contains(&id) {
                        continue;
                    }
                    seen_ids.insert(id.clone());

                    let desc = match &import.library {
                        Some(lib) if !lib.is_empty() => {
                            format!("imports {} from {}", import.symbol, lib)
                        }
                        _ => format!("imports {}", import.symbol),
                    };

                    new_findings.push(Finding {
                        id,
                        kind: FindingKind::Structural,
                        desc,
                        conf: 0.95,
                        crit: Criticality::Baseline,
                        mbc: None,
                        attack: None,
                        trait_refs: Vec::new(),
                        evidence: vec![Evidence {
                            method: "import".to_string(),
                            source: import.source.clone(),
                            value: import.symbol.clone(),
                            location: import.library.clone(),
                        }],

                        source_file: None,
                    });
                }
            }
        }

        report.findings.extend(new_findings);
    }

    /// Detect the ecosystem for an import based on file type and source.
    pub(crate) fn detect_import_ecosystem(file_type: &str, source: &str) -> &'static str {
        // First check source for explicit ecosystem markers
        match source {
            "npm" | "package.json" => return "npm",
            "pip" | "pypi" | "requirements.txt" => return "pypi",
            "gem" | "rubygems" | "gemfile" => return "rubygems",
            "cargo" | "crates.io" => return "cargo",
            "go" | "go.mod" => return "gomod",
            "maven" | "gradle" | "pom.xml" => return "maven",
            "composer" => return "composer",
            _ => {}
        }

        // For binary formats, use the binary type as ecosystem
        match file_type {
            "elf" | "so" => return "elf",
            "macho" | "dylib" => return "macho",
            "pe" | "exe" | "dll" => return "pe",
            _ => {}
        }

        // For source code, detect language from file type
        match file_type {
            "python" | "python_script" => "python",
            "javascript" | "js" | "typescript" | "ts" => "npm",
            "ruby" | "rb" => "ruby",
            "java" | "class" => "java",
            "go" => "go",
            "rust" | "rs" => "rust",
            "c" | "cpp" | "h" | "hpp" => "c",
            "php" => "php",
            "perl" | "pl" => "perl",
            "lua" => "lua",
            "shell" | "shellscript" | "shell_script" | "bash" | "sh" => "shell",
            "powershell" | "ps1" => "powershell",
            "swift" => "swift",
            "objectivec" | "objc" | "m" => "objc",
            "csharp" | "cs" => "dotnet",
            "scala" | "sc" => "scala",
            "groovy" | "gradle" => "groovy",
            "elixir" | "ex" | "exs" => "elixir",
            "zig" => "zig",
            "applescript" | "scpt" => "applescript",
            _ => "unknown",
        }
    }

    /// Normalize an import name for use in a finding ID.
    ///
    /// - Converts to lowercase
    /// - Converts dots and slashes to path separators (/)
    /// - Replaces other special characters with hyphens
    /// - Removes leading/trailing separators
    /// - Collapses multiple separators
    pub(crate) fn normalize_import_name(name: &str) -> String {
        // Convert dots and slashes to path separators for consistent hierarchical naming:
        // - Python: os.path.join -> os/path/join
        // - Ruby: net/http -> net/http
        // Replace other special chars with hyphens, collapse consecutive separators
        let mut result = String::with_capacity(name.len());
        let mut prev_sep = true; // Skip leading separators

        for c in name.to_lowercase().chars() {
            match c {
                c if c.is_ascii_alphanumeric() || c == '_' => {
                    result.push(c);
                    prev_sep = false;
                }
                '.' | '/' => {
                    // Both dots and slashes become path separators
                    if !prev_sep {
                        result.push('/');
                        prev_sep = true;
                    }
                }
                _ => {
                    if !prev_sep {
                        result.push('-');
                        prev_sep = true;
                    }
                }
            }
        }

        // Trim trailing separator
        if result.ends_with('/') || result.ends_with('-') {
            result.pop();
        }

        result
    }
}
