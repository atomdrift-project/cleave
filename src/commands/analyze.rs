//! Single file analysis command.
//!
//! This module implements the core file analysis functionality for cleave.
//! It performs comprehensive analysis of a single file or directory, including:
//!
//! - File type detection via magic bytes
//! - Format-specific structural analysis (ELF, PE, Mach-O, scripts, archives, etc.)
//! - YARA rule scanning with parallel loading
//! - Capability mapping and trait evaluation
//! - Composite rule evaluation
//! - Criticality assessment and filtering
//!
//! # Architecture
//!
//! The analysis process follows these steps:
//!
//! 1. **File Type Detection**: Fast magic byte inspection to determine file format
//! 2. **Parallel Initialization**: YARA rules and capability mapper load concurrently
//! 3. **Format Routing**: Files are routed to specialized analyzers based on type
//! 4. **Trait Evaluation**: Capability mapper processes findings and assigns traits
//! 5. **Output Formatting**: Results are formatted as Terminal or JSONL
//!
//! # Performance
//!
//! - YARA loading happens in parallel with capability mapper initialization
//! - Binary formats (ELF/PE/Mach-O) run structural analysis and YARA scans in parallel
//! - Archives support streaming JSONL output for progressive results
//! - Directory traversal loads YARA rules once and reuses for all files
//!
//! # Output Formats
//!
//! - **Terminal**: Human-readable summary with findings and metadata
//! - **JSONL**: Machine-readable JSON Lines format (one JSON object per line)

use crate::analyzers::{detect_file_type, FileType};
use crate::cli;
use crate::commands::shared::check_criticality_error;
use crate::composite_rules;
use crate::malecule_bridge;
use crate::output;
use crate::types;
use anyhow::{Context, Result};
use malecule::LayoutAlgorithm;
use std::fs;
use std::path::Path;

/// Build `AnalysisOptions` from CLI arguments.
fn build_options(
    enable_third_party: bool,
    zip_passwords: &[String],
    disabled: &crate::cli::DisabledComponents,
    sample_extraction: Option<&crate::types::SampleExtractionConfig>,
    max_memory_file_size: u64,
    platforms: &[crate::composite_rules::Platform],
    min_hostile_precision: f32,
    min_suspicious_precision: f32,
    enable_full_validation: bool,
) -> cleave::AnalysisOptions {
    // Convert binary crate Platform to library crate Platform
    // They're the same type structurally but Rust treats them as distinct
    // because main.rs re-declares the modules. Use serde round-trip.
    let platforms_lib: Vec<cleave::Platform> = if platforms.is_empty() {
        vec![cleave::Platform::All]
    } else {
        let json = serde_json::to_string(platforms).unwrap_or_default();
        serde_json::from_str(&json).unwrap_or_else(|_| vec![cleave::Platform::All])
    };
    let sample_lib: Option<cleave::SampleExtractionConfig> =
        sample_extraction.map(|s| cleave::SampleExtractionConfig {
            extract_dir: s.extract_dir.clone(),
            archive_sha256: s.archive_sha256.clone(),
        });
    cleave::AnalysisOptions {
        enable_third_party_yara: enable_third_party && !disabled.third_party,
        zip_passwords: zip_passwords.to_vec(),
        disable_yara: disabled.yara,
        disable_radare2: disabled.radare2,
        disable_upx: disabled.upx,
        all_files: false,
        platforms: platforms_lib,
        min_hostile_precision,
        min_suspicious_precision,
        enable_full_validation,
        max_memory_file_size,
        sample_extraction: sample_lib,
    }
}

/// Analyze a single file or directory with comprehensive malware detection.
#[allow(clippy::too_many_arguments)]
pub(crate) fn run(
    target: &str,
    enable_third_party: bool,
    format: &cli::OutputFormat,
    zip_passwords: &[String],
    disabled: &cli::DisabledComponents,
    error_if_levels: Option<&[types::Criticality]>,
    verbose: bool,
    all_files: bool,
    shuffle: bool,
    sample_extraction: Option<&types::SampleExtractionConfig>,
    platforms: &[composite_rules::Platform],
    min_hostile_precision: f32,
    min_suspicious_precision: f32,
    max_memory_file_size: u64,
    enable_full_validation: bool,
    mol_path: Option<&str>,
    mol_layout: cli::MolLayout,
) -> Result<String> {
    let path = Path::new(target);

    if !path.exists() {
        anyhow::bail!("Path does not exist: {}", target);
    }

    let options = build_options(
        enable_third_party,
        zip_passwords,
        disabled,
        sample_extraction,
        max_memory_file_size,
        platforms,
        min_hostile_precision,
        min_suspicious_precision,
        enable_full_validation,
    );

    // If target is a directory, process files recursively
    if path.is_dir() {
        // For JSONL mode, stream results immediately for progress tracking
        let streaming = matches!(format, cli::OutputFormat::Jsonl);
        // Collect all file analysis data for galaxy view
        let mut all_file_analyses: Vec<types::FileAnalysis> = Vec::new();

        // Collect all files first, filtering unknown types early
        let mut files: Vec<_> = walkdir::WalkDir::new(path)
            .follow_links(false)
            .into_iter()
            .filter_entry(|e| !e.file_name().to_string_lossy().starts_with(".git"))
            .filter_map(std::result::Result::ok)
            .filter(|e| e.file_type().is_file())
            .filter(|e| {
                if all_files {
                    return true;
                }
                let file_type = detect_file_type(e.path()).unwrap_or(FileType::Unknown);
                file_type.is_program()
            })
            .collect();

        // Shuffle files for random processing order when requested.
        if shuffle {
            use rand::seq::SliceRandom;
            files.shuffle(&mut rand::rng());
        }

        let results = if streaming {
            let results = Vec::new();
            for entry in &files {
                let file_path = entry.path().to_string_lossy().to_string();
                let result = analyze_and_format(
                    &file_path,
                    &options,
                    format,
                    error_if_levels,
                    verbose,
                    None,
                    mol_layout,
                    Some(&mut all_file_analyses),
                )?;
                tracing::info!(
                    path = %file_path,
                    jsonl_bytes = result.len(),
                    "JSONL output"
                );
                print!("{}", result);
                use std::io::Write;
                if let Err(e) = std::io::stdout().flush() {
                    if e.kind() == std::io::ErrorKind::BrokenPipe {
                        tracing::info!("stdout pipe closed, stopping analysis");
                        return Ok(String::new());
                    }
                }
            }
            results
        } else {
            use rayon::prelude::*;

            let file_paths: Vec<String> = files
                .iter()
                .map(|e| e.path().to_string_lossy().to_string())
                .collect();

            let par_results: Vec<(String, Result<String>)> = file_paths
                .par_iter()
                .map(|file_path| {
                    let result = analyze_and_format(
                        file_path,
                        &options,
                        format,
                        error_if_levels,
                        verbose,
                        None,
                        mol_layout,
                        None,
                    );
                    (file_path.clone(), result)
                })
                .collect();

            let mut results = Vec::with_capacity(par_results.len());
            for (_, result) in par_results {
                results.push(result?);
            }
            results
        };

        // Generate galaxy view from all collected files
        if let Some(base_path) = mol_path {
            if !all_file_analyses.is_empty() {
                let mut combined_report = types::AnalysisReport::new(types::TargetInfo {
                    path: target.to_string(),
                    file_type: "directory".to_string(),
                    size_bytes: 0,
                    sha256: String::new(),
                    architectures: None,
                });
                combined_report.files = all_file_analyses;
                write_malecule_files(&combined_report, base_path, mol_layout)?;
            }
        }

        return Ok(results.join(""));
    }

    // Single file analysis
    analyze_and_format(
        target,
        &options,
        format,
        error_if_levels,
        verbose,
        mol_path,
        mol_layout,
        None,
    )
}

/// Analyze a single file and format the output.
///
/// Uses `cleave::analyze_file()` for the core analysis pipeline (with caching),
/// then converts the result to binary-crate types via serde roundtrip (necessary
/// because main.rs re-declares library modules, creating parallel type hierarchies).
/// Finally applies CLI-specific post-processing (v2 conversion, encoding layer merging,
/// filtering, mol generation, output formatting).
#[allow(clippy::too_many_arguments)]
fn analyze_and_format(
    target: &str,
    options: &cleave::AnalysisOptions,
    format: &cli::OutputFormat,
    error_if_levels: Option<&[types::Criticality]>,
    verbose: bool,
    mol_path: Option<&str>,
    mol_layout: cli::MolLayout,
    file_collector: Option<&mut Vec<types::FileAnalysis>>,
) -> Result<String> {
    let path = Path::new(target);

    // Core analysis — single pipeline in lib.rs, with caching
    let lib_report = cleave::analyze_file(path, options)?;

    // Convert library types to binary-crate types via serde roundtrip.
    // The types are structurally identical but Rust treats them as distinct
    // because main.rs re-declares the library modules.
    let json = serde_json::to_vec(&lib_report)?;
    let mut report: types::AnalysisReport = serde_json::from_slice(&json)?;

    // CLI-specific post-processing
    check_criticality_error(&report, error_if_levels)?;
    report.shrink_to_fit();
    report.convert_to_v2(verbose);

    // Merge encoding layers and recalculate composites.
    // The mapper is only needed when encoding layers are actually merged (rare for single files),
    // so we defer its expensive initialization to avoid ~800ms overhead on the common path.
    let merged_indices = report.merge_encoding_layers();
    if !merged_indices.is_empty() {
        let capability_mapper =
            crate::capabilities::CapabilityMapper::new_with_precision_thresholds(
                options.min_hostile_precision,
                options.min_suspicious_precision,
                options.enable_full_validation,
            );
        for &idx in &merged_indices {
            let file = &report.files[idx];
            let mut temp_report = types::AnalysisReport::new(types::TargetInfo {
                path: file.path.clone(),
                file_type: file.file_type.clone(),
                sha256: file.sha256.clone(),
                size_bytes: file.size,
                architectures: None,
            });
            temp_report.findings = file.findings.clone();

            let new_composites = capability_mapper.evaluate_container_composites(
                &temp_report,
                &file.findings,
                &file.file_type,
            );
            if !new_composites.is_empty() {
                let file = &mut report.files[idx];
                for finding in new_composites {
                    if !file.findings.iter().any(|f| f.id == finding.id) {
                        file.findings.push(finding);
                    }
                }
                file.compute_summary();
            }
        }
        tracing::debug!(
            "Merged encoding layers into {} parent file(s)",
            merged_indices.len()
        );
    }

    // Filter unmatched component traits for terminal output
    if *format == cli::OutputFormat::Terminal {
        let removed = report.filter_unmatched_components();
        if removed > 0 {
            tracing::debug!(
                "Filtered {} unmatched component traits from terminal output",
                removed
            );
        }
    }

    // Collect files for galaxy view
    if let Some(collector) = file_collector {
        collector.extend(report.files.iter().cloned());
    }

    // Generate MOL file if requested
    if let Some(base_path) = mol_path {
        write_malecule_files(&report, base_path, mol_layout)?;
    }

    match format {
        cli::OutputFormat::Json => Ok(serde_json::to_string(&report)?),
        cli::OutputFormat::Jsonl => output::format_jsonl(&report),
        cli::OutputFormat::Terminal => Ok(output::format_terminal(&report)),
    }
}

/// Convert CLI MolLayout to malecule LayoutAlgorithm.
fn mol_layout_to_algorithm(layout: cli::MolLayout) -> LayoutAlgorithm {
    match layout {
        cli::MolLayout::Spherical => LayoutAlgorithm::LayeredSpherical,
        cli::MolLayout::Force => LayoutAlgorithm::ForceDirected,
        cli::MolLayout::Tree => LayoutAlgorithm::HierarchicalTree,
        cli::MolLayout::Spiral => LayoutAlgorithm::SpiralGalaxy,
    }
}

/// All layout algorithms in display order
const ALL_LAYOUTS: [(cli::MolLayout, &str); 4] = [
    (cli::MolLayout::Spherical, "Spherical"),
    (cli::MolLayout::Force, "Force"),
    (cli::MolLayout::Tree, "Tree"),
    (cli::MolLayout::Spiral, "Spiral"),
];

/// Write MOL, JSON sidecar, and HTML viewer files for the analysis report.
fn write_malecule_files(
    report: &types::AnalysisReport,
    base_path: &str,
    mol_layout: cli::MolLayout,
) -> Result<()> {
    let default_layout = mol_layout_to_algorithm(mol_layout);

    // Filter to files with meaningful findings
    let files_with_findings: Vec<&types::FileAnalysis> = report
        .files
        .iter()
        .filter(|f| !f.findings.is_empty())
        .collect();

    if files_with_findings.is_empty() {
        return Ok(());
    }

    // For multiple files, generate a galaxy view
    if files_with_findings.len() > 1 {
        return write_galaxy_view(&files_with_findings, base_path, default_layout);
    }

    // Single file: generate individual malecule
    let file = files_with_findings[0];
    let malecule = malecule_bridge::malecule_from_file_analysis(file, default_layout);

    // Skip if no meaningful structure
    if malecule.atoms.len() <= 1 {
        return Ok(());
    }

    let mol_file_path = format!("{}.mol", base_path);
    let json_file_path = format!("{}.json", base_path);
    let html_file_path = format!("{}.html", base_path);

    // Write MOL file (default layout)
    let mol_content = malecule::mol::generate_mol(&malecule);
    fs::write(&mol_file_path, &mol_content).context("Failed to write MOL file")?;

    // Write JSON sidecar
    let json_content =
        malecule::mol::generate_metadata_json(&malecule).context("Failed to generate JSON")?;
    fs::write(&json_file_path, &json_content).context("Failed to write JSON sidecar")?;

    // Generate MOL content for all layouts
    let all_mol_contents: Vec<(String, String)> = ALL_LAYOUTS
        .iter()
        .map(|(layout, name)| {
            let algo = mol_layout_to_algorithm(*layout);
            let m = malecule_bridge::malecule_from_file_analysis(file, algo);
            (name.to_string(), malecule::mol::generate_mol(&m))
        })
        .collect();

    // Write HTML viewer with all layouts
    let html_content = generate_html_viewer(&malecule.name, &all_mol_contents, &json_content);
    fs::write(&html_file_path, html_content).context("Failed to write HTML viewer")?;

    eprintln!(
        "Malecule: {} • formula={} • atoms={} • bonds={}",
        html_file_path,
        malecule.formula,
        malecule.atoms.len(),
        malecule.bonds.len()
    );

    tracing::info!(
        mol = %mol_file_path,
        json = %json_file_path,
        html = %html_file_path,
        formula = %malecule.formula,
        "Wrote malecule files"
    );

    Ok(())
}

/// Data for a single molecule in the galaxy view.
struct GalaxyMolecule {
    /// File basename (e.g., "init.js")
    name: String,
    /// Detected file type (e.g., "batch", "javascript", "png")
    file_type: String,
    /// File ID for parent-child relationship detection
    file_id: u32,
    /// Parent file ID (for layered content)
    parent_id: Option<u32>,
    /// All layout variants: (layout_name, malecule)
    layouts: Vec<(String, malecule::Malecule)>,
    /// All searchable text: strings + evidence (for inter-file reference detection)
    searchable_text: String,
}

/// Write a galaxy view for multiple files (directory scan).
fn write_galaxy_view(
    files: &[&types::FileAnalysis],
    base_path: &str,
    _layout: LayoutAlgorithm,
) -> Result<()> {
    // Generate malecules for each file
    let mut molecules: Vec<GalaxyMolecule> = Vec::new();

    for file in files {
        // Generate all layout variants
        let layouts: Vec<(String, malecule::Malecule)> = ALL_LAYOUTS
            .iter()
            .map(|(layout_enum, name)| {
                let algo = mol_layout_to_algorithm(*layout_enum);
                let m = malecule_bridge::malecule_from_file_analysis(file, algo);
                (name.to_string(), m)
            })
            .collect();

        // Skip files with no meaningful structure (check first layout)
        if layouts.first().map(|(_, m)| m.atoms.len()).unwrap_or(0) <= 1 {
            continue;
        }

        let name = file
            .path
            .rsplit('/')
            .next()
            .unwrap_or(&file.path)
            .to_string();

        // Build searchable text from strings + evidence
        let mut searchable_text = String::new();

        // Add extracted strings
        for s in &file.strings {
            searchable_text.push_str(&s.value);
            searchable_text.push('\n');
        }

        // Add evidence strings
        for finding in &file.findings {
            for ev in &finding.evidence {
                searchable_text.push_str(&ev.value);
                searchable_text.push('\n');
            }
        }

        molecules.push(GalaxyMolecule {
            name,
            file_type: file.file_type.clone(),
            file_id: file.id,
            parent_id: file.parent_id,
            layouts,
            searchable_text,
        });
    }

    if molecules.is_empty() {
        return Ok(());
    }

    // Detect inter-file references
    let inter_file_links = detect_inter_file_links(&molecules);

    // Generate the galaxy HTML
    let html_file_path = format!("{}.html", base_path);
    let html_content = generate_galaxy_html_viewer(&molecules, &inter_file_links);
    fs::write(&html_file_path, &html_content).context("Failed to write galaxy HTML viewer")?;

    let total_atoms: usize = molecules.iter().map(|m| m.layouts[0].1.atoms.len()).sum();
    let total_bonds: usize = molecules.iter().map(|m| m.layouts[0].1.bonds.len()).sum();

    eprintln!(
        "Galaxy: {} • {} molecules • {} atoms • {} bonds • {} inter-file links",
        html_file_path,
        molecules.len(),
        total_atoms,
        total_bonds,
        inter_file_links.len()
    );

    Ok(())
}

/// Inter-file link between two molecules.
struct InterFileLink {
    /// Index of source molecule
    from_mol: usize,
    /// Index of target molecule
    to_mol: usize,
}

/// Extract basename without extension (stem).
fn file_stem(name: &str) -> &str {
    // Find last dot that's not at the start
    if let Some(dot_pos) = name.rfind('.') {
        if dot_pos > 0 {
            return &name[..dot_pos];
        }
    }
    name
}

/// Check if two stems share a common root (for name-based linking).
/// Returns true if stems are identical OR share the same root before an underscore.
/// E.g., "packageloader" and "packageloader_decode" share root "packageloader".
fn stems_share_root(stem_a: &str, stem_b: &str) -> bool {
    if stem_a.len() < 4 || stem_b.len() < 4 {
        return false;
    }

    // Exact match
    if stem_a == stem_b {
        return true;
    }

    // Get root (part before first underscore, or whole stem if no underscore)
    let root_a = stem_a.split('_').next().unwrap_or(stem_a);
    let root_b = stem_b.split('_').next().unwrap_or(stem_b);

    // Roots must match and be substantial (>= 6 chars)
    root_a.len() >= 6 && root_a == root_b
}

/// Detect inter-file references by checking:
/// 1. If basename of one file appears in strings/evidence of another
/// 2. If filenames share a common stem prefix (name-based relationship)
/// 3. If files have a parent-child relationship (layered content)
fn detect_inter_file_links(molecules: &[GalaxyMolecule]) -> Vec<InterFileLink> {
    let mut links = Vec::new();

    for (i, mol_a) in molecules.iter().enumerate() {
        for (j, mol_b) in molecules.iter().enumerate() {
            if i >= j {
                continue; // Skip self and already-checked pairs
            }

            // Get stems (basename without extension) for name-based matching
            let stem_a = file_stem(&mol_a.name);
            let stem_b = file_stem(&mol_b.name);

            // Check 1: full basename references in strings/evidence
            let b_in_a = mol_a.searchable_text.contains(&mol_b.name);
            let a_in_b = mol_b.searchable_text.contains(&mol_a.name);

            // Check 2: filenames share a common root
            // E.g., "packageloader.bat" and "packageloader_decode.bat"
            let shared_root = stems_share_root(stem_a, stem_b);

            // Check 3: parent-child relationship (layered content)
            let parent_child =
                mol_a.parent_id == Some(mol_b.file_id) || mol_b.parent_id == Some(mol_a.file_id);

            if b_in_a || a_in_b || shared_root || parent_child {
                links.push(InterFileLink {
                    from_mol: i,
                    to_mol: j,
                });
            }
        }
    }

    links
}

/// Generate galaxy HTML viewer for multi-file analysis.
fn generate_galaxy_html_viewer(
    molecules: &[GalaxyMolecule],
    inter_file_links: &[InterFileLink],
) -> String {
    // Generate MOL content for all layouts of each molecule
    // Structure: [{ Spherical: `...`, Force: `...`, Tree: `...`, Spiral: `...` }, ...]
    let mol_layouts_js: String = molecules
        .iter()
        .map(|m| {
            let layout_entries: Vec<String> = m
                .layouts
                .iter()
                .map(|(name, malecule)| {
                    let mol = malecule::mol::generate_mol(malecule);
                    let escaped = mol.replace('`', "\\`").replace("${", "\\${");
                    format!("            {}: `{}`", name, escaped)
                })
                .collect();
            format!("        {{\n{}\n        }}", layout_entries.join(",\n"))
        })
        .collect::<Vec<_>>()
        .join(",\n");

    // Generate metadata JSON for each molecule (use first layout, metadata is layout-independent)
    let metadata_entries: Vec<String> = molecules
        .iter()
        .map(|m| {
            let meta = malecule::mol::generate_metadata(&m.layouts[0].1);
            serde_json::to_string(&meta).unwrap_or_else(|_| "{}".to_string())
        })
        .collect();

    let metadata_js = metadata_entries.join(",\n        ");

    let names_js = molecules
        .iter()
        .map(|m| format!("\"{}\"", m.name.replace('"', "\\\"")))
        .collect::<Vec<_>>()
        .join(", ");

    let file_types_js = molecules
        .iter()
        .map(|m| format!("\"{}\"", m.file_type.replace('"', "\\\"")))
        .collect::<Vec<_>>()
        .join(", ");

    let links_js = inter_file_links
        .iter()
        .map(|l| format!("[{}, {}]", l.from_mol, l.to_mol))
        .collect::<Vec<_>>()
        .join(", ");

    let total_molecules = molecules.len();

    format!(
        r##"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Galaxy View - {total_molecules} Molecules</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: #0a0a1a;
            color: #eee;
            overflow: hidden;
        }}
        #container {{ width: 100vw; height: 100vh; }}
        #info {{
            position: absolute;
            top: 10px;
            left: 10px;
            background: rgba(0,0,0,0.8);
            padding: 15px;
            border-radius: 8px;
            max-width: 350px;
            z-index: 100;
        }}
        #info h1 {{ font-size: 18px; margin-bottom: 8px; color: #ff79c6; }}
        #info p {{ font-size: 12px; margin: 4px 0; opacity: 0.8; }}
        .molecule-list {{ margin-top: 10px; max-height: 200px; overflow-y: auto; }}
        .molecule-item {{
            display: flex;
            align-items: center;
            padding: 4px 8px;
            margin: 2px 0;
            background: rgba(255,255,255,0.05);
            border-radius: 4px;
            cursor: pointer;
            font-size: 11px;
        }}
        .molecule-item:hover {{ background: rgba(255,255,255,0.1); }}
        .molecule-item.selected {{ background: rgba(255,121,198,0.3); border: 1px solid #ff79c6; }}
        .molecule-color {{ width: 10px; height: 10px; border-radius: 50%; margin-right: 8px; flex-shrink: 0; }}
        .molecule-info {{ display: flex; flex-direction: column; overflow: hidden; }}
        .molecule-name {{ white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }}
        .molecule-formula {{ font-size: 9px; color: #888; font-family: monospace; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }}
        .layout-switcher {{ margin-top: 10px; padding-top: 10px; border-top: 1px solid #333; }}
        .layout-switcher-title {{ font-size: 11px; color: #888; margin-bottom: 6px; }}
        .layout-btn {{
            padding: 4px 8px; margin: 2px; font-size: 10px;
            background: rgba(255,255,255,0.1); border: 1px solid #444;
            border-radius: 4px; color: #ccc; cursor: pointer;
        }}
        .layout-btn:hover {{ background: rgba(255,255,255,0.2); }}
        .layout-btn.active {{ background: rgba(255,121,198,0.3); border-color: #ff79c6; color: #fff; }}
        .legend {{ margin-top: 10px; padding-top: 10px; border-top: 1px solid #333; }}
        .legend-item {{ display: flex; align-items: center; margin: 4px 0; font-size: 11px; }}
        .legend-color {{ width: 12px; height: 12px; border-radius: 50%; margin-right: 8px; }}
        .hostile {{ background: #ff4444; }}
        .suspicious {{ background: #4488ff; }}
        .notable {{ background: #ffffff; }}
        .neutral {{ background: #888888; }}
        #tooltip {{
            position: absolute;
            bottom: 20px;
            right: 20px;
            background: rgba(0,0,0,0.9);
            padding: 15px;
            border-radius: 8px;
            max-width: 400px;
            z-index: 100;
            display: none;
            border: 1px solid #444;
        }}
        #tooltip.visible {{ display: block; }}
        #tooltip h2 {{ font-size: 14px; margin-bottom: 8px; color: #ff79c6; word-break: break-all; }}
        #tooltip .file-name {{ font-size: 11px; color: #888; margin-bottom: 8px; }}
        #tooltip .severity {{ font-size: 11px; padding: 2px 8px; border-radius: 4px; margin-bottom: 8px; display: inline-block; }}
        #tooltip .severity.hostile {{ background: #ff4444; color: #fff; }}
        #tooltip .severity.suspicious {{ background: #4488ff; color: #fff; }}
        #tooltip .severity.notable {{ background: #ffffff; color: #000; }}
        #tooltip .severity.neutral {{ background: #888888; color: #fff; }}
        #tooltip .description {{ font-size: 12px; margin: 8px 0; line-height: 1.4; color: #ccc; }}
        #tooltip .evidence {{ font-size: 11px; margin-top: 10px; }}
        #tooltip .evidence-title {{ color: #888; margin-bottom: 4px; }}
        #tooltip .evidence-item {{ font-family: monospace; font-size: 10px; background: #2a2a3e; padding: 4px 8px; margin: 2px 0; border-radius: 3px; word-break: break-all; }}
        #tooltip .close {{ position: absolute; top: 8px; right: 10px; cursor: pointer; color: #666; font-size: 16px; }}
        #tooltip .close:hover {{ color: #fff; }}
        #tooltip .category {{ font-size: 10px; color: #666; margin-bottom: 4px; }}
    </style>
</head>
<body>
    <div id="info">
        <h1>Galaxy View</h1>
        <p>{total_molecules} molecules • <span id="link-count"></span> links</p>
        <div class="molecule-list" id="molecule-list"></div>
        <div class="layout-switcher" id="layout-switcher"></div>
        <div class="legend">
            <div class="legend-item"><span class="legend-color hostile"></span>Hostile</div>
            <div class="legend-item"><span class="legend-color suspicious"></span>Suspicious</div>
            <div class="legend-item"><span class="legend-color notable"></span>Notable</div>
            <div class="legend-item"><span class="legend-color neutral"></span>Neutral</div>
        </div>
    </div>
    <div id="tooltip">
        <span class="close" onclick="hideTooltip()">&times;</span>
        <div class="file-name" id="tooltip-file"></div>
        <div class="category" id="tooltip-category"></div>
        <h2 id="tooltip-trait"></h2>
        <span class="severity" id="tooltip-severity"></span>
        <div class="description" id="tooltip-desc"></div>
        <div class="evidence" id="tooltip-evidence"></div>
    </div>
    <div id="container"></div>

    <script src="https://cdnjs.cloudflare.com/ajax/libs/three.js/r128/three.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/three@0.128.0/examples/js/controls/OrbitControls.js"></script>
    <script>
        // Galaxy data - each molecule has all layout variants
        const molLayouts = [
{mol_layouts_js}
        ];
        const metadataList = [
        {metadata_js}
        ];
        const moleculeNames = [{names_js}];
        const fileTypes = [{file_types_js}];
        const interFileLinks = [{links_js}];
        const layoutNames = ['Spherical', 'Force', 'Tree', 'Spiral'];
        let currentLayout = 'Spherical';

        document.getElementById('link-count').textContent = interFileLinks.length;

        // Molecule colors (distinct hues for each molecule)
        const moleculeColors = moleculeNames.map((_, i) => {{
            const hue = (i * 137.5) % 360; // Golden angle for good distribution
            return new THREE.Color().setHSL(hue / 360, 0.7, 0.5);
        }});

        // Three.js setup
        const container = document.getElementById('container');
        const scene = new THREE.Scene();
        scene.background = new THREE.Color(0x0a0a1a);

        const camera = new THREE.PerspectiveCamera(60, window.innerWidth / window.innerHeight, 0.1, 1000);
        camera.position.set(0, 10, 30);

        const renderer = new THREE.WebGLRenderer({{ antialias: true }});
        renderer.setSize(window.innerWidth, window.innerHeight);
        renderer.setPixelRatio(window.devicePixelRatio);
        container.appendChild(renderer.domElement);

        const controls = new THREE.OrbitControls(camera, renderer.domElement);
        controls.enableDamping = true;
        controls.dampingFactor = 0.05;

        // Lighting
        const ambientLight = new THREE.AmbientLight(0x404040, 0.5);
        scene.add(ambientLight);
        const directionalLight = new THREE.DirectionalLight(0xffffff, 1);
        directionalLight.position.set(10, 10, 10);
        scene.add(directionalLight);

        // Severity colors
        const severityColors = {{
            'hostile': 0xff4444,
            'suspicious': 0x4488ff,
            'notable': 0xffffff,
            'neutral': 0x888888
        }};

        // Parse MOL file
        function parseMol(molString) {{
            const lines = molString.trim().split('\n');
            const atoms = [];
            const bonds = [];

            if (lines.length < 5) return {{ atoms: [], bonds: [] }};

            const countsLine = lines[3];
            if (!countsLine || countsLine.length < 6) return {{ atoms: [], bonds: [] }};

            const numAtoms = parseInt(countsLine.substring(0, 3).trim()) || 0;
            const numBonds = parseInt(countsLine.substring(3, 6).trim()) || 0;

            for (let i = 4; i < 4 + numAtoms; i++) {{
                const line = lines[i];
                const x = parseFloat(line.substring(0, 10).trim());
                const y = parseFloat(line.substring(10, 20).trim());
                const z = parseFloat(line.substring(20, 30).trim());
                const symbol = line.substring(31, 34).trim();
                atoms.push({{ x, y, z, symbol }});
            }}

            const bondStart = 4 + numAtoms;
            for (let i = bondStart; i < bondStart + numBonds; i++) {{
                if (i >= lines.length) break;
                const line = lines[i];
                const atom1 = parseInt(line.substring(0, 3).trim()) - 1;
                const atom2 = parseInt(line.substring(3, 6).trim()) - 1;
                const bondType = parseInt(line.substring(6, 9).trim());
                bonds.push({{ atom1, atom2, bondType }});
            }}

            return {{ atoms, bonds }};
        }}

        // Group molecules by file type for tree-like clustering
        const typeGroups = {{}};
        fileTypes.forEach((type, idx) => {{
            if (!typeGroups[type]) typeGroups[type] = [];
            typeGroups[type].push(idx);
        }});
        const groupNames = Object.keys(typeGroups);
        const numGroups = groupNames.length;

        // Pre-compute positions: each type gets a cluster, molecules within are close together
        const moleculePositions = [];
        const groupRadius = Math.max(12, numGroups * 5); // Distance between type clusters
        const clusterRadius = 6; // Max spread within a cluster

        groupNames.forEach((typeName, groupIdx) => {{
            const groupAngle = (groupIdx / numGroups) * Math.PI * 2;
            const groupCenter = {{
                x: Math.cos(groupAngle) * groupRadius,
                y: 0,
                z: Math.sin(groupAngle) * groupRadius
            }};

            const members = typeGroups[typeName];
            members.forEach((molIdx, memberIdx) => {{
                // Position within cluster - spiral out from center
                const memberAngle = (memberIdx / Math.max(members.length, 1)) * Math.PI * 2;
                const memberDist = Math.min(clusterRadius, 2 + memberIdx * 1.5);
                moleculePositions[molIdx] = {{
                    x: groupCenter.x + Math.cos(memberAngle) * memberDist,
                    y: (memberIdx % 3 - 1) * 2, // Slight vertical spread
                    z: groupCenter.z + Math.sin(memberAngle) * memberDist
                }};
            }});
        }});

        // Get pre-computed position for a molecule
        function getMoleculeOffset(index, total) {{
            return moleculePositions[index] || {{ x: 0, y: 0, z: 0 }};
        }}

        // Storage for all meshes
        let allAtomMeshes = [];
        let allBondMeshes = [];
        let moleculeGroups = [];
        let atomToMolecule = []; // Map atom mesh index to molecule index
        const labelSprites = []; // Track label sprites

        // Build molecules for current layout
        function buildMolecules() {{
            // Clear existing molecules (but not labels - they stay)
            moleculeGroups.forEach(group => {{
                scene.remove(group);
                group.traverse(obj => {{
                    if (obj.geometry) obj.geometry.dispose();
                    if (obj.material) obj.material.dispose();
                }});
            }});
            allAtomMeshes = [];
            allBondMeshes = [];
            moleculeGroups = [];
            atomToMolecule = [];

            molLayouts.forEach((layouts, molIndex) => {{
                const molStr = layouts[currentLayout];
                const mol = parseMol(molStr);
                const metadata = metadataList[molIndex];
                const offset = getMoleculeOffset(molIndex, molLayouts.length);

                const group = new THREE.Group();
                group.position.set(offset.x, offset.y, offset.z);
                scene.add(group);
                moleculeGroups.push(group);

                // Create atoms
                mol.atoms.forEach((atom, atomIndex) => {{
                    const atomMeta = metadata.atoms[atomIndex] || {{ severity: 'neutral' }};
                    const color = severityColors[atomMeta.severity] || 0x888888;

                    const geometry = new THREE.SphereGeometry(0.25, 24, 24);
                    const material = new THREE.MeshPhongMaterial({{
                        color: color,
                        shininess: 100,
                        emissive: color,
                        emissiveIntensity: 0.2
                    }});
                    const sphere = new THREE.Mesh(geometry, material);
                    sphere.position.set(atom.x, atom.y, atom.z);
                    group.add(sphere);

                    allAtomMeshes.push(sphere);
                    atomToMolecule.push(molIndex);
                }});

                // Create bonds
                mol.bonds.forEach(bond => {{
                    const start = mol.atoms[bond.atom1];
                    const end = mol.atoms[bond.atom2];

                    const startVec = new THREE.Vector3(start.x, start.y, start.z);
                    const endVec = new THREE.Vector3(end.x, end.y, end.z);
                    const direction = new THREE.Vector3().subVectors(endVec, startVec);
                    const length = direction.length();

                    const geometry = new THREE.CylinderGeometry(0.04, 0.04, length, 8);
                    const material = new THREE.MeshPhongMaterial({{
                        color: 0x444444,
                        shininess: 50
                    }});

                    const cylinder = new THREE.Mesh(geometry, material);
                    cylinder.position.copy(startVec).add(direction.multiplyScalar(0.5));
                    cylinder.quaternion.setFromUnitVectors(
                        new THREE.Vector3(0, 1, 0),
                        direction.normalize()
                    );
                    group.add(cylinder);
                    allBondMeshes.push(cylinder);
                }});
            }});
        }}

        // Initial build
        buildMolecules();

        // Add molecule labels (only once)
        molLayouts.forEach((_, molIndex) => {{
            const offset = getMoleculeOffset(molIndex, molLayouts.length);
            addLabel(moleculeNames[molIndex], offset, moleculeColors[molIndex]);
        }});

        // Create inter-file link bonds (thicker, colored) with arrows
        interFileLinks.forEach(link => {{
            const offset1 = getMoleculeOffset(link[0], molLayouts.length);
            const offset2 = getMoleculeOffset(link[1], molLayouts.length);

            const startVec = new THREE.Vector3(offset1.x, offset1.y, offset1.z);
            const endVec = new THREE.Vector3(offset2.x, offset2.y, offset2.z);
            const direction = new THREE.Vector3().subVectors(endVec, startVec);
            const length = direction.length();
            const dirNorm = direction.clone().normalize();

            const arrowLength = 1.4;
            const arrowGap = 2.5; // Distance from molecule center
            const shaftLength = length - arrowLength - arrowGap;

            const linkMaterial = new THREE.MeshPhongMaterial({{
                color: 0xff79c6,
                shininess: 100,
                transparent: true,
                opacity: 0.6
            }});

            // Shaft (cylinder)
            const shaftGeometry = new THREE.CylinderGeometry(0.12, 0.12, shaftLength, 8);
            const shaft = new THREE.Mesh(shaftGeometry, linkMaterial);
            shaft.position.copy(startVec).add(dirNorm.clone().multiplyScalar(shaftLength / 2));
            shaft.quaternion.setFromUnitVectors(new THREE.Vector3(0, 1, 0), dirNorm);
            scene.add(shaft);

            // Arrow head (cone) - positioned with gap from molecule center
            const arrowGeometry = new THREE.ConeGeometry(0.5, arrowLength, 12);
            const arrow = new THREE.Mesh(arrowGeometry, linkMaterial);
            const arrowPos = endVec.clone().sub(dirNorm.clone().multiplyScalar(arrowGap + arrowLength / 2));
            arrow.position.copy(arrowPos);
            arrow.quaternion.setFromUnitVectors(new THREE.Vector3(0, 1, 0), dirNorm);
            scene.add(arrow);
        }});

        // Add text label using sprite
        function addLabel(text, position, color) {{
            const canvas = document.createElement('canvas');
            const ctx = canvas.getContext('2d');
            canvas.width = 256;
            canvas.height = 64;

            ctx.fillStyle = 'rgba(0,0,0,0.7)';
            ctx.fillRect(0, 0, canvas.width, canvas.height);

            ctx.font = 'bold 24px sans-serif';
            ctx.fillStyle = '#' + color.getHexString();
            ctx.textAlign = 'center';
            ctx.textBaseline = 'middle';
            ctx.fillText(text.length > 20 ? text.substring(0, 18) + '...' : text, 128, 32);

            const texture = new THREE.CanvasTexture(canvas);
            const material = new THREE.SpriteMaterial({{ map: texture }});
            const sprite = new THREE.Sprite(material);
            sprite.position.set(position.x, position.y + 5, position.z);
            sprite.scale.set(8, 2, 1);
            scene.add(sprite);
        }}

        // Build molecule list UI
        const listEl = document.getElementById('molecule-list');
        moleculeNames.forEach((name, i) => {{
            const item = document.createElement('div');
            item.className = 'molecule-item';
            const formula = metadataList[i]?.formula || '';
            item.innerHTML = `<span class="molecule-color" style="background: #${{moleculeColors[i].getHexString()}}"></span><div class="molecule-info"><span class="molecule-name">${{name}}</span><span class="molecule-formula">${{formula}}</span></div>`;
            item.onclick = () => focusMolecule(i);
            listEl.appendChild(item);
        }});

        // Build layout switcher UI
        const layoutEl = document.getElementById('layout-switcher');
        layoutEl.innerHTML = '<div class="layout-switcher-title">Atom Layout</div>';
        layoutNames.forEach(name => {{
            const btn = document.createElement('button');
            btn.className = 'layout-btn' + (name === currentLayout ? ' active' : '');
            btn.textContent = name;
            btn.onclick = () => switchLayout(name);
            layoutEl.appendChild(btn);
        }});

        function switchLayout(name) {{
            if (name === currentLayout) return;
            currentLayout = name;

            // Update button states
            document.querySelectorAll('.layout-btn').forEach(btn => {{
                btn.classList.toggle('active', btn.textContent === name);
            }});

            // Rebuild molecules with new layout
            buildMolecules();
        }}

        function focusMolecule(index) {{
            const offset = getMoleculeOffset(index, molLayouts.length);
            const target = new THREE.Vector3(offset.x, offset.y, offset.z);

            // Animate camera to focus on molecule
            const startPos = camera.position.clone();
            const endPos = target.clone().add(new THREE.Vector3(0, 5, 15));

            let progress = 0;
            const animate = () => {{
                progress += 0.05;
                if (progress >= 1) {{
                    camera.position.copy(endPos);
                    controls.target.copy(target);
                    return;
                }}
                camera.position.lerpVectors(startPos, endPos, progress);
                controls.target.lerp(target, progress);
                requestAnimationFrame(animate);
            }};
            animate();

            // Highlight in list
            document.querySelectorAll('.molecule-item').forEach((el, i) => {{
                el.classList.toggle('selected', i === index);
            }});
        }}

        // Raycaster for click detection
        const raycaster = new THREE.Raycaster();
        const mouse = new THREE.Vector2();

        function showTooltip(meshIndex) {{
            const molIndex = atomToMolecule[meshIndex];
            const metadata = metadataList[molIndex];

            // Find atom index within this molecule
            let atomIndex = meshIndex;
            for (let i = 0; i < molIndex; i++) {{
                atomIndex -= metadataList[i].atoms.length;
            }}

            const atomMeta = metadata.atoms[atomIndex];
            if (!atomMeta) return;

            document.getElementById('tooltip-file').textContent = moleculeNames[molIndex];
            document.getElementById('tooltip-category').textContent = atomMeta.category || '';
            document.getElementById('tooltip-trait').textContent = atomMeta.trait_id || atomMeta.symbol;
            document.getElementById('tooltip-severity').textContent = atomMeta.severity;
            document.getElementById('tooltip-severity').className = 'severity ' + atomMeta.severity;

            const descEl = document.getElementById('tooltip-desc');
            if (atomMeta.description) {{
                descEl.textContent = atomMeta.description;
                descEl.style.display = 'block';
            }} else {{
                descEl.style.display = 'none';
            }}

            const evidenceEl = document.getElementById('tooltip-evidence');
            if (atomMeta.evidence && atomMeta.evidence.length > 0) {{
                let html = '<div class="evidence-title">Evidence:</div>';
                atomMeta.evidence.forEach(ev => {{
                    const truncated = ev.length > 100 ? ev.substring(0, 100) + '...' : ev;
                    html += '<div class="evidence-item">' + escapeHtml(truncated) + '</div>';
                }});
                evidenceEl.innerHTML = html;
                evidenceEl.style.display = 'block';
            }} else {{
                evidenceEl.style.display = 'none';
            }}

            document.getElementById('tooltip').classList.add('visible');
        }}

        function hideTooltip() {{
            document.getElementById('tooltip').classList.remove('visible');
        }}

        function escapeHtml(text) {{
            const div = document.createElement('div');
            div.textContent = text;
            return div.innerHTML;
        }}

        // Click handler
        renderer.domElement.addEventListener('click', (event) => {{
            mouse.x = (event.clientX / window.innerWidth) * 2 - 1;
            mouse.y = -(event.clientY / window.innerHeight) * 2 + 1;

            raycaster.setFromCamera(mouse, camera);
            const intersects = raycaster.intersectObjects(allAtomMeshes);

            if (intersects.length > 0) {{
                const clickedMesh = intersects[0].object;
                const atomIndex = allAtomMeshes.indexOf(clickedMesh);
                if (atomIndex >= 0) {{
                    showTooltip(atomIndex);
                }}
            }}
        }});

        // Hover cursor change
        renderer.domElement.addEventListener('mousemove', (event) => {{
            mouse.x = (event.clientX / window.innerWidth) * 2 - 1;
            mouse.y = -(event.clientY / window.innerHeight) * 2 + 1;

            raycaster.setFromCamera(mouse, camera);
            const intersects = raycaster.intersectObjects(allAtomMeshes);

            renderer.domElement.style.cursor = intersects.length > 0 ? 'pointer' : 'default';
        }});

        // Animation loop
        function animate() {{
            requestAnimationFrame(animate);
            controls.update();
            renderer.render(scene, camera);
        }}
        animate();

        // Handle resize
        window.addEventListener('resize', () => {{
            camera.aspect = window.innerWidth / window.innerHeight;
            camera.updateProjectionMatrix();
            renderer.setSize(window.innerWidth, window.innerHeight);
        }});
    </script>
</body>
</html>
"##,
        total_molecules = total_molecules,
        mol_layouts_js = mol_layouts_js,
        metadata_js = metadata_js,
        names_js = names_js,
        file_types_js = file_types_js,
        links_js = links_js
    )
}

/// Generate an HTML file with embedded Three.js viewer for the malecule.
fn generate_html_viewer(
    name: &str,
    mol_contents: &[(String, String)],
    json_content: &str,
) -> String {
    // Build the layouts object for JavaScript
    let layouts_js: String = mol_contents
        .iter()
        .map(|(layout_name, mol)| {
            format!(
                "        \"{}\": `{}`",
                layout_name,
                mol.replace('`', "\\`").replace("${", "\\${")
            )
        })
        .collect::<Vec<_>>()
        .join(",\n");

    format!(
        r##"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Malecule: {name}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: #1a1a2e;
            color: #eee;
            overflow: hidden;
        }}
        #container {{ width: 100vw; height: 100vh; }}
        #info {{
            position: absolute;
            top: 10px;
            left: 10px;
            background: rgba(0,0,0,0.7);
            padding: 15px;
            border-radius: 8px;
            max-width: 300px;
            z-index: 100;
        }}
        #info h1 {{ font-size: 18px; margin-bottom: 8px; }}
        #info p {{ font-size: 12px; margin: 4px 0; opacity: 0.8; }}
        .formula {{ font-family: monospace; font-size: 16px; color: #ff79c6; }}
        .layout-switcher {{ margin-top: 12px; display: flex; gap: 6px; flex-wrap: wrap; }}
        .layout-btn {{
            padding: 4px 10px;
            font-size: 11px;
            background: #333;
            border: 1px solid #555;
            color: #aaa;
            border-radius: 4px;
            cursor: pointer;
            transition: all 0.2s;
        }}
        .layout-btn:hover {{ background: #444; color: #fff; }}
        .layout-btn.active {{ background: #ff79c6; color: #000; border-color: #ff79c6; }}
        .legend {{ margin-top: 10px; }}
        .legend-item {{ display: flex; align-items: center; margin: 4px 0; font-size: 11px; }}
        .legend-color {{ width: 12px; height: 12px; border-radius: 50%; margin-right: 8px; }}
        .hostile {{ background: #ff4444; }}
        .suspicious {{ background: #4488ff; }}
        .notable {{ background: #ffffff; }}
        .neutral {{ background: #888888; }}
        #tooltip {{
            position: absolute;
            bottom: 20px;
            right: 20px;
            background: rgba(0,0,0,0.85);
            padding: 15px;
            border-radius: 8px;
            max-width: 400px;
            z-index: 100;
            display: none;
            border: 1px solid #444;
        }}
        #tooltip.visible {{ display: block; }}
        #tooltip h2 {{ font-size: 14px; margin-bottom: 8px; color: #ff79c6; word-break: break-all; }}
        #tooltip .severity {{ font-size: 11px; padding: 2px 8px; border-radius: 4px; margin-bottom: 8px; display: inline-block; }}
        #tooltip .severity.hostile {{ background: #ff4444; color: #fff; }}
        #tooltip .severity.suspicious {{ background: #4488ff; color: #fff; }}
        #tooltip .severity.notable {{ background: #ffffff; color: #000; }}
        #tooltip .severity.neutral {{ background: #888888; color: #fff; }}
        #tooltip .description {{ font-size: 12px; margin: 8px 0; line-height: 1.4; color: #ccc; }}
        #tooltip .evidence {{ font-size: 11px; margin-top: 10px; }}
        #tooltip .evidence-title {{ color: #888; margin-bottom: 4px; }}
        #tooltip .evidence-item {{ font-family: monospace; font-size: 10px; background: #2a2a3e; padding: 4px 8px; margin: 2px 0; border-radius: 3px; word-break: break-all; }}
        #tooltip .close {{ position: absolute; top: 8px; right: 10px; cursor: pointer; color: #666; font-size: 16px; }}
        #tooltip .close:hover {{ color: #fff; }}
        #tooltip .category {{ font-size: 10px; color: #666; margin-bottom: 4px; }}
    </style>
</head>
<body>
    <div id="info">
        <h1>{name}</h1>
        <p class="formula" id="formula"></p>
        <p id="stats"></p>
        <div class="layout-switcher" id="layout-switcher"></div>
        <div class="legend">
            <div class="legend-item"><span class="legend-color hostile"></span>Hostile</div>
            <div class="legend-item"><span class="legend-color suspicious"></span>Suspicious</div>
            <div class="legend-item"><span class="legend-color notable"></span>Notable</div>
            <div class="legend-item"><span class="legend-color neutral"></span>Neutral</div>
        </div>
    </div>
    <div id="tooltip">
        <span class="close" onclick="hideTooltip()">&times;</span>
        <div class="category" id="tooltip-category"></div>
        <h2 id="tooltip-trait"></h2>
        <span class="severity" id="tooltip-severity"></span>
        <div class="description" id="tooltip-desc"></div>
        <div class="evidence" id="tooltip-evidence"></div>
    </div>
    <div id="container"></div>

    <script src="https://cdnjs.cloudflare.com/ajax/libs/three.js/r128/three.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/three@0.128.0/examples/js/controls/OrbitControls.js"></script>
    <script>
        // All layout data
        const layouts = {{
{layouts_js}
        }};
        const metadata = {json_content};
        let currentLayout = 'Spherical';

        // Display info
        document.getElementById('formula').textContent = metadata.formula;
        document.getElementById('stats').textContent =
            `${{metadata.summary.total_atoms}} atoms, ${{metadata.summary.total_bonds}} bonds`;

        // Three.js setup
        const container = document.getElementById('container');
        const scene = new THREE.Scene();
        scene.background = new THREE.Color(0x1a1a2e);

        const camera = new THREE.PerspectiveCamera(75, window.innerWidth / window.innerHeight, 0.1, 1000);
        camera.position.z = 10;

        const renderer = new THREE.WebGLRenderer({{ antialias: true }});
        renderer.setSize(window.innerWidth, window.innerHeight);
        renderer.setPixelRatio(window.devicePixelRatio);
        container.appendChild(renderer.domElement);

        const controls = new THREE.OrbitControls(camera, renderer.domElement);
        controls.enableDamping = true;
        controls.dampingFactor = 0.05;

        // Lighting
        const ambientLight = new THREE.AmbientLight(0x404040, 0.5);
        scene.add(ambientLight);
        const directionalLight = new THREE.DirectionalLight(0xffffff, 1);
        directionalLight.position.set(5, 5, 5);
        scene.add(directionalLight);

        // Color mapping
        const severityColors = {{
            'hostile': 0xff4444,
            'suspicious': 0x4488ff,
            'notable': 0xffffff,
            'neutral': 0x888888
        }};

        // Parse MOL file
        function parseMol(molString) {{
            const lines = molString.trim().split('\n');
            const atoms = [];
            const bonds = [];

            // Find counts line (line 4, index 3)
            if (lines.length < 5) {{
                console.error('Invalid MOL file: too few lines', lines.length);
                return {{ atoms: [], bonds: [] }};
            }}
            const countsLine = lines[3];
            if (!countsLine || countsLine.length < 6) {{
                console.error('Invalid counts line:', countsLine);
                return {{ atoms: [], bonds: [] }};
            }}
            const numAtoms = parseInt(countsLine.substring(0, 3).trim()) || 0;
            const numBonds = parseInt(countsLine.substring(3, 6).trim()) || 0;

            // Parse atoms (starting at line 5)
            for (let i = 4; i < 4 + numAtoms; i++) {{
                const line = lines[i];
                const x = parseFloat(line.substring(0, 10).trim());
                const y = parseFloat(line.substring(10, 20).trim());
                const z = parseFloat(line.substring(20, 30).trim());
                const symbol = line.substring(31, 34).trim();
                atoms.push({{ x, y, z, symbol }});
            }}

            // Parse bonds
            const bondStart = 4 + numAtoms;
            for (let i = bondStart; i < bondStart + numBonds; i++) {{
                if (i >= lines.length) break;
                const line = lines[i];
                const atom1 = parseInt(line.substring(0, 3).trim()) - 1;
                const atom2 = parseInt(line.substring(3, 6).trim()) - 1;
                const bondType = parseInt(line.substring(6, 9).trim());
                bonds.push({{ atom1, atom2, bondType }});
            }}

            return {{ atoms, bonds }};
        }}

        // Create layout switcher buttons
        const switcherDiv = document.getElementById('layout-switcher');
        Object.keys(layouts).forEach(name => {{
            const btn = document.createElement('button');
            btn.className = 'layout-btn' + (name === currentLayout ? ' active' : '');
            btn.textContent = name;
            btn.onclick = () => switchLayout(name);
            switcherDiv.appendChild(btn);
        }});

        // Molecule meshes storage
        const atomMeshes = [];
        const bondMeshes = [];
        let currentMol = null;

        // Create initial molecule
        function createMolecule() {{
            currentMol = parseMol(layouts[currentLayout]);

            // Create atoms
            currentMol.atoms.forEach((atom, i) => {{
                const atomMeta = metadata.atoms[i] || {{ severity: 'neutral' }};
                const color = severityColors[atomMeta.severity] || 0x888888;

                const geometry = new THREE.SphereGeometry(0.3, 32, 32);
                const material = new THREE.MeshPhongMaterial({{
                    color: color,
                    shininess: 100,
                    emissive: color,
                    emissiveIntensity: 0.2
                }});
                const sphere = new THREE.Mesh(geometry, material);
                sphere.position.set(atom.x, atom.y, atom.z);
                scene.add(sphere);
                atomMeshes.push(sphere);
            }});

            // Create bonds
            createBonds();
        }}

        function createBonds() {{
            currentMol.bonds.forEach(bond => {{
                const start = currentMol.atoms[bond.atom1];
                const end = currentMol.atoms[bond.atom2];

                const startVec = new THREE.Vector3(start.x, start.y, start.z);
                const endVec = new THREE.Vector3(end.x, end.y, end.z);
                const direction = new THREE.Vector3().subVectors(endVec, startVec);
                const length = direction.length();

                const geometry = new THREE.CylinderGeometry(0.05, 0.05, length, 8);
                const material = new THREE.MeshPhongMaterial({{
                    color: 0x666666,
                    shininess: 50
                }});

                const cylinder = new THREE.Mesh(geometry, material);
                cylinder.position.copy(startVec).add(direction.multiplyScalar(0.5));
                cylinder.quaternion.setFromUnitVectors(
                    new THREE.Vector3(0, 1, 0),
                    direction.normalize()
                );
                scene.add(cylinder);
                bondMeshes.push(cylinder);
            }});
        }}

        function switchLayout(name) {{
            if (name === currentLayout) return;
            currentLayout = name;

            // Update button states
            document.querySelectorAll('.layout-btn').forEach(btn => {{
                btn.classList.toggle('active', btn.textContent === name);
            }});

            // Parse new layout
            const newMol = parseMol(layouts[name]);
            currentMol = newMol;

            // Update atom positions
            newMol.atoms.forEach((atom, i) => {{
                if (atomMeshes[i]) {{
                    atomMeshes[i].position.set(atom.x, atom.y, atom.z);
                }}
            }});

            // Remove old bonds and create new ones
            bondMeshes.forEach(mesh => scene.remove(mesh));
            bondMeshes.length = 0;
            createBonds();
        }}

        createMolecule();

        // Animation loop
        function animate() {{
            requestAnimationFrame(animate);
            controls.update();
            renderer.render(scene, camera);
        }}
        animate();

        // Handle resize
        window.addEventListener('resize', () => {{
            camera.aspect = window.innerWidth / window.innerHeight;
            camera.updateProjectionMatrix();
            renderer.setSize(window.innerWidth, window.innerHeight);
        }});

        // Raycasting for click detection
        const raycaster = new THREE.Raycaster();
        const mouse = new THREE.Vector2();

        function showTooltip(atomIndex) {{
            const atomMeta = metadata.atoms[atomIndex];
            if (!atomMeta) return;

            const tooltip = document.getElementById('tooltip');
            const categoryEl = document.getElementById('tooltip-category');
            const traitEl = document.getElementById('tooltip-trait');
            const severityEl = document.getElementById('tooltip-severity');
            const descEl = document.getElementById('tooltip-desc');
            const evidenceEl = document.getElementById('tooltip-evidence');

            // Category path
            categoryEl.textContent = atomMeta.category || '';

            // Trait ID (or element symbol for hub atoms)
            if (atomMeta.trait_id) {{
                traitEl.textContent = atomMeta.trait_id;
            }} else {{
                traitEl.textContent = atomMeta.symbol + ' (' + (atomMeta.category || 'core') + ')';
            }}

            // Severity badge
            severityEl.textContent = atomMeta.severity;
            severityEl.className = 'severity ' + atomMeta.severity;

            // Description
            if (atomMeta.description) {{
                descEl.textContent = atomMeta.description;
                descEl.style.display = 'block';
            }} else {{
                descEl.style.display = 'none';
            }}

            // Evidence
            if (atomMeta.evidence && atomMeta.evidence.length > 0) {{
                let html = '<div class="evidence-title">Evidence:</div>';
                atomMeta.evidence.forEach(ev => {{
                    // Truncate long evidence
                    const truncated = ev.length > 100 ? ev.substring(0, 100) + '...' : ev;
                    html += '<div class="evidence-item">' + escapeHtml(truncated) + '</div>';
                }});
                evidenceEl.innerHTML = html;
                evidenceEl.style.display = 'block';
            }} else {{
                evidenceEl.style.display = 'none';
            }}

            tooltip.classList.add('visible');
        }}

        function hideTooltip() {{
            document.getElementById('tooltip').classList.remove('visible');
        }}

        function escapeHtml(text) {{
            const div = document.createElement('div');
            div.textContent = text;
            return div.innerHTML;
        }}

        // Click handler
        renderer.domElement.addEventListener('click', (event) => {{
            mouse.x = (event.clientX / window.innerWidth) * 2 - 1;
            mouse.y = -(event.clientY / window.innerHeight) * 2 + 1;

            raycaster.setFromCamera(mouse, camera);
            const intersects = raycaster.intersectObjects(atomMeshes);

            if (intersects.length > 0) {{
                const clickedMesh = intersects[0].object;
                const atomIndex = atomMeshes.indexOf(clickedMesh);
                if (atomIndex >= 0) {{
                    showTooltip(atomIndex);
                }}
            }}
        }});

        // Hover cursor change
        renderer.domElement.addEventListener('mousemove', (event) => {{
            mouse.x = (event.clientX / window.innerWidth) * 2 - 1;
            mouse.y = -(event.clientY / window.innerHeight) * 2 + 1;

            raycaster.setFromCamera(mouse, camera);
            const intersects = raycaster.intersectObjects(atomMeshes);

            renderer.domElement.style.cursor = intersects.length > 0 ? 'pointer' : 'default';
        }});
    </script>
</body>
</html>
"##,
        name = name,
        layouts_js = layouts_js,
        json_content = json_content
    )
}
