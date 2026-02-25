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

use crate::analyzers::{
    self, archive::ArchiveAnalyzer, detect_file_type, elf::ElfAnalyzer, macho::MachOAnalyzer,
    pe::PEAnalyzer, Analyzer, FileType,
};
use crate::capabilities::CapabilityMapper;
use crate::cli;
use crate::commands::shared::{check_criticality_error, process_yara_result};
use crate::composite_rules;
use crate::malecule_bridge;
use crate::output;
use crate::types;
use crate::yara_engine::YaraEngine;
use anyhow::{Context, Result};
use malecule::LayoutAlgorithm;
use std::fs;
use std::path::Path;
use std::sync::Arc;

/// Shared analysis context for reusing expensive resources across multiple files.
/// YARA rules take ~27s to compile, so we load once and share via Arc.
struct AnalysisContext {
    yara_engine: Option<Arc<YaraEngine>>,
    capability_mapper: Arc<CapabilityMapper>,
}

/// Load YARA engine and capability mapper once for reuse across multiple files.
fn create_analysis_context(
    enable_third_party: bool,
    yara_disabled: bool,
    platforms: &[composite_rules::Platform],
    min_hostile_precision: f32,
    min_suspicious_precision: f32,
    enable_full_validation: bool,
) -> AnalysisContext {
    // Load capability mapper and YARA rules in parallel
    let yara_handle: Option<std::thread::JoinHandle<(YaraEngine, usize, usize)>> = if yara_disabled
    {
        None
    } else {
        Some(std::thread::spawn(move || {
            let empty_mapper = CapabilityMapper::empty();
            let mut engine = YaraEngine::new_with_mapper(empty_mapper);
            let (builtin, third_party) = engine.load_all_rules(enable_third_party);
            (engine, builtin, third_party)
        }))
    };

    // Allow skipping trait loading for tests that don't need it
    let capability_mapper = if std::env::var("cleave_SKIP_TRAITS").is_ok() {
        tracing::info!("Traits skipped (cleave_SKIP_TRAITS set)");
        Arc::new(CapabilityMapper::empty())
    } else {
        Arc::new(
            CapabilityMapper::new_with_precision_thresholds(
                min_hostile_precision,
                min_suspicious_precision,
                enable_full_validation,
            )
            .with_platforms(platforms.to_vec()),
        )
    };

    let yara_engine = if yara_disabled {
        tracing::info!("YARA scanning disabled");
        None
    } else if let Some(handle) = yara_handle {
        let (engine, builtin_count, third_party_count) = handle
            .join()
            .unwrap_or_else(|e| std::panic::resume_unwind(e));
        tracing::info!(
            "YARA engine loaded with {} rules",
            builtin_count + third_party_count
        );
        if builtin_count + third_party_count > 0 {
            Some(Arc::new(engine))
        } else {
            None
        }
    } else {
        None
    };

    AnalysisContext {
        yara_engine,
        capability_mapper,
    }
}

/// Analyze a single file with comprehensive malware detection.
///
/// This is the main entry point for single-file analysis. It handles:
/// - Directory recursion (delegates to scan_paths)
/// - File type detection
/// - Parallel YARA + capability mapper loading
/// - Format-specific analysis routing
/// - Terminal vs JSONL output formatting
///
/// # Parameters
///
/// - `target`: Path to the file or directory to analyze
/// - `enable_third_party`: Whether to load third-party YARA rules
/// - `format`: Output format (Terminal or JSONL)
/// - `zip_passwords`: List of passwords to try when extracting encrypted archives
/// - `disabled`: Components to disable (e.g., YARA scanning)
/// - `error_if_levels`: Exit with error if findings match these criticality levels
/// - `verbose`: Include detailed analysis data in output
/// - `all_files`: Analyze all files (not just programs) when scanning directories
/// - `sample_extraction`: Configuration for extracting suspicious files from archives
/// - `platforms`: Platform filters for composite rules
/// - `min_hostile_precision`: Minimum precision for hostile composite rules
/// - `min_suspicious_precision`: Minimum precision for suspicious composite rules
/// - `max_memory_file_size`: Maximum file size to load into memory from archives
/// - `enable_full_validation`: Enable comprehensive validation of capability definitions
///
/// # Returns
///
/// Formatted analysis report as a string (JSONL or Terminal format)
///
/// # Errors
///
/// Returns error if:
/// - Path does not exist
/// - File type detection fails
/// - Analysis fails for the detected file type
/// - Criticality check fails (when using --error-if)
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
    let _start = std::time::Instant::now();
    let path = Path::new(target);

    if !path.exists() {
        anyhow::bail!("Path does not exist: {}", target);
    }

    // If target is a directory, process files recursively with shared context
    if path.is_dir() {
        // Load YARA engine and capability mapper ONCE for all files
        let ctx = create_analysis_context(
            enable_third_party,
            disabled.yara,
            platforms,
            min_hostile_precision,
            min_suspicious_precision,
            enable_full_validation,
        );

        // For JSONL mode, stream results immediately for progress tracking
        let streaming = matches!(format, cli::OutputFormat::Jsonl);
        let mut results = Vec::new();

        // Collect all files first when shuffling, otherwise stream directly
        let mut files: Vec<_> = walkdir::WalkDir::new(path)
            .follow_links(false)
            .into_iter()
            .filter_entry(|e| !e.file_name().to_string_lossy().starts_with(".git"))
            .filter_map(std::result::Result::ok)
            .filter(|e| e.file_type().is_file())
            .collect();

        // Shuffle files for random processing order when requested.
        // This prevents predictable iteration patterns and ensures diverse sampling
        // when used with trait-basher for analysis tuning.
        if shuffle {
            use rand::seq::SliceRandom;
            files.shuffle(&mut rand::rng());
        }

        for entry in files {
            let file_path = entry.path().to_string_lossy().to_string();
            // Skip unknown file types unless --all-files is set
            if !all_files {
                let file_type = detect_file_type(entry.path()).unwrap_or(FileType::Unknown);
                if !file_type.is_program() {
                    continue;
                }
            }
            // Use shared context for analysis
            let result = analyze_file_with_context(
                &file_path,
                format,
                zip_passwords,
                error_if_levels,
                verbose,
                sample_extraction,
                max_memory_file_size,
                &ctx,
                mol_path,
                mol_layout,
            )?;
            if streaming {
                // Print immediately for JSONL streaming - enables progress tracking
                // format_jsonl already includes trailing newline
                tracing::info!(
                    path = %file_path,
                    jsonl_bytes = result.len(),
                    "JSONL output"
                );
                print!("{}", result);
                // Flush for piped output (stdout is block-buffered when not a tty)
                use std::io::Write;
                let _ = std::io::stdout().flush();
            } else {
                results.push(result);
            }
        }
        return Ok(results.join(""));
    }

    // Single file: create context and analyze
    let ctx = create_analysis_context(
        enable_third_party,
        disabled.yara,
        platforms,
        min_hostile_precision,
        min_suspicious_precision,
        enable_full_validation,
    );

    analyze_file_with_context(
        target,
        format,
        zip_passwords,
        error_if_levels,
        verbose,
        sample_extraction,
        max_memory_file_size,
        &ctx,
        mol_path,
        mol_layout,
    )
}

/// Analyze a single file using a pre-loaded analysis context.
/// This avoids reloading YARA rules for each file in a directory.
#[allow(clippy::too_many_arguments)]
fn analyze_file_with_context(
    target: &str,
    format: &cli::OutputFormat,
    zip_passwords: &[String],
    error_if_levels: Option<&[types::Criticality]>,
    verbose: bool,
    sample_extraction: Option<&types::SampleExtractionConfig>,
    max_memory_file_size: u64,
    ctx: &AnalysisContext,
    mol_path: Option<&str>,
    mol_layout: cli::MolLayout,
) -> Result<String> {
    let path = Path::new(target);

    // Status messages go to stderr (only in terminal mode)
    if *format == cli::OutputFormat::Terminal {
        eprintln!("Analyzing: {}", target);
    }
    tracing::info!("Starting analysis of {}", target);

    // Detect file type first (fast - just reads magic bytes)
    tracing::debug!("Detecting file type");
    let file_type = detect_file_type(path)?;
    if *format == cli::OutputFormat::Terminal {
        eprintln!("Detected file type: {:?}", file_type);
    }
    tracing::info!("File type: {:?}", file_type);

    // Use pre-loaded YARA engine and capability mapper from context
    let capability_mapper = &ctx.capability_mapper;
    let yara_engine = &ctx.yara_engine;

    // Route to appropriate analyzer.
    // For ELF/MachO/PE: structural analysis and YARA scan run in parallel via rayon::join,
    // followed by a single centralized trait evaluation pass.
    // Archive and source types are handled sequentially (archives manage their own YARA).
    let _t3 = std::time::Instant::now();
    let mut report = match file_type {
        FileType::MachO => {
            let data = fs::read(path).context("Failed to read file")?;
            let analyzer =
                MachOAnalyzer::new().with_capability_mapper((**capability_mapper).clone());
            let range = analyzer.preferred_arch_range(&data);
            let arch_data = &data[range.clone()];
            let is_fat = analyzer.all_arch_ranges(&data).len() > 1;
            let file_types: &[&str] = &["macho", "dylib", "kext"];
            let (struct_result, yara_result) = rayon::join(
                || analyzer.analyze_structural(path, arch_data),
                || {
                    yara_engine
                        .as_ref()
                        .filter(|e| e.is_loaded())
                        .map(|e| e.scan_bytes_with_inline(arch_data, Some(file_types)))
                },
            );
            let mut report = struct_result?;
            analyzer.apply_fat_metadata(&mut report, &data);

            // For FAT binaries, re-extract strings from the full file so offsets are file-relative.
            // This ensures offset_range constraints (like [-2200, -100]) work correctly.
            if is_fat {
                let string_extractor = crate::strings::StringExtractor::default();
                report.strings = string_extractor.extract_smart(&data, None);
                // Update string count metric
                if let Some(ref mut metrics) = report.metrics {
                    if let Some(ref mut binary_metrics) = metrics.binary {
                        binary_metrics.string_count = report.strings.len() as u32;
                    }
                }
            }

            let inline_yara = process_yara_result(&mut report, yara_result, yara_engine.as_deref());
            // For FAT binaries, evaluate against full file since strings have file-relative offsets
            let eval_data = if is_fat { &data[..] } else { arch_data };
            capability_mapper.evaluate_and_merge_findings(
                &mut report,
                eval_data,
                None,
                Some(&inline_yara),
            );
            report
        }
        FileType::Elf => {
            let data = fs::read(path).context("Failed to read file")?;
            let analyzer = ElfAnalyzer::new().with_capability_mapper((**capability_mapper).clone());
            let file_types: &[&str] = &["elf", "so", "ko"];
            let (mut report, yara_result) = rayon::join(
                || analyzer.analyze_structural(path, &data),
                || {
                    yara_engine
                        .as_ref()
                        .filter(|e| e.is_loaded())
                        .map(|e| e.scan_bytes_with_inline(&data, Some(file_types)))
                },
            );
            let inline_yara = process_yara_result(&mut report, yara_result, yara_engine.as_deref());
            capability_mapper.evaluate_and_merge_findings(
                &mut report,
                &data,
                None,
                Some(&inline_yara),
            );
            crate::path_mapper::analyze_and_link_paths(&mut report);
            crate::env_mapper::analyze_and_link_env_vars(&mut report);
            report
        }
        FileType::Pe => {
            let data = fs::read(path).context("Failed to read file")?;
            let mut analyzer =
                PEAnalyzer::new().with_capability_mapper((**capability_mapper).clone());
            if let Some(arc) = yara_engine {
                analyzer = analyzer.with_yara_arc(arc.clone());
            }
            let file_types: &[&str] = &["pe", "exe", "dll", "bat", "ps1"];
            let (struct_result, yara_result) = rayon::join(
                || analyzer.analyze_structural(path, &data),
                || {
                    yara_engine
                        .as_ref()
                        .filter(|e| e.is_loaded())
                        .map(|e| e.scan_bytes_with_inline(&data, Some(file_types)))
                },
            );
            let mut report = struct_result?;
            let inline_yara = process_yara_result(&mut report, yara_result, yara_engine.as_deref());
            capability_mapper.evaluate_and_merge_findings(
                &mut report,
                &data,
                None,
                Some(&inline_yara),
            );
            report
        }
        FileType::JavaClass => {
            let analyzer = analyzers::java_class::JavaClassAnalyzer::new()
                .with_capability_mapper((**capability_mapper).clone());
            analyzer.analyze(path)?
        }
        FileType::Jar => {
            // JAR files are analyzed like archives but with Java-specific handling
            let mut analyzer = ArchiveAnalyzer::new()
                .with_capability_mapper((**capability_mapper).clone())
                .with_zip_passwords(zip_passwords.to_vec())
                .with_max_memory_file_size(max_memory_file_size);
            if let Some(engine) = yara_engine {
                analyzer = analyzer.with_yara_arc(engine.clone());
            }
            if let Some(config) = sample_extraction {
                analyzer = analyzer.with_sample_extraction(config.clone());
            }
            analyzer.analyze(path)?
        }
        FileType::PackageJson => {
            let analyzer = analyzers::package_json::PackageJsonAnalyzer::new()
                .with_capability_mapper((**capability_mapper).clone());
            analyzer.analyze(path)?
        }
        FileType::VsixManifest => {
            let analyzer = analyzers::vsix_manifest::VsixManifestAnalyzer::new()
                .with_capability_mapper((**capability_mapper).clone());
            analyzer.analyze(path)?
        }
        FileType::Archive => {
            let mut analyzer = ArchiveAnalyzer::new()
                .with_capability_mapper((**capability_mapper).clone())
                .with_zip_passwords(zip_passwords.to_vec())
                .with_max_memory_file_size(max_memory_file_size);
            if let Some(engine) = yara_engine {
                analyzer = analyzer.with_yara_arc(engine.clone());
            }
            if let Some(config) = sample_extraction {
                analyzer = analyzer.with_sample_extraction(config.clone());
            }
            // Use streaming for JSONL format to emit files as they're analyzed
            if matches!(format, cli::OutputFormat::Jsonl) {
                analyzer.analyze_streaming(path, |file_analysis| {
                    if let Ok(line) = output::format_jsonl_line(file_analysis) {
                        println!("{}", line);
                    }
                })?
            } else {
                analyzer.analyze(path)?
            }
        }
        // All source code languages use the unified analyzer (or generic fallback)
        _ => {
            if let Some(analyzer) =
                analyzers::analyzer_for_file_type(&file_type, Some((**capability_mapper).clone()))
            {
                analyzer.analyze(path)?
            } else {
                anyhow::bail!("Unsupported file type: {:?}", file_type);
            }
        }
    };

    // Run YARA universally for file types that didn't handle it internally
    // This ensures all program files get scanned with YARA rules
    if let Some(engine) = yara_engine {
        if file_type.is_program() && engine.is_loaded() {
            let file_types = file_type.yara_filetypes();
            let filter = if file_types.is_empty() {
                None
            } else {
                Some(file_types.as_slice())
            };

            match engine.scan_file_to_findings(path, filter) {
                Ok((matches, findings)) => {
                    // Add YARA matches to report
                    report.yara_matches = matches;

                    // Add findings that don't already exist
                    let existing: std::collections::HashSet<String> =
                        report.findings.iter().map(|f| f.id.clone()).collect();
                    for finding in findings {
                        if !existing.contains(finding.id.as_str()) {
                            report.findings.push(finding);
                        }
                    }

                    // Mark that we used YARA
                    if !report.metadata.tools_used.contains(&"yara-x".to_string()) {
                        report.metadata.tools_used.push("yara-x".to_string());
                    }
                }
                Err(e) => {
                    eprintln!("⚠️  YARA scan failed: {}", e);
                }
            }
        }
    }

    // Check if report's criticality matches --error-if criteria
    check_criticality_error(&report, error_if_levels)?;

    // Free excess capacity in all Vec fields to reduce memory footprint
    report.shrink_to_fit();

    // Convert to v2 schema (flat files array) and filter based on verbosity
    report.convert_to_v2(verbose);

    // Filter out low-value composite "any" rules before output
    // These are rules with needs=1 that add no value over the underlying trait
    let removed = report.filter_findings(|f| !capability_mapper.is_low_value_any_rule(&f.id));
    if removed > 0 {
        tracing::debug!(
            "Filtered {} low-value composite 'any' rules from output",
            removed
        );
    }

    // Filter out component-criticality traits that aren't referenced by any composite
    // Component traits are building blocks that should only appear when their composite fires
    // Only filter for terminal output - keep all components in JSON for ML signal
    if *format == cli::OutputFormat::Terminal {
        let removed = report.filter_unmatched_components();
        if removed > 0 {
            tracing::debug!(
                "Filtered {} unmatched component traits from terminal output",
                removed
            );
        }
    }

    // Generate MOL file if requested
    if let Some(base_path) = mol_path {
        write_malecule_files(&report, base_path, mol_layout)?;
    }

    // Format output based on requested format
    let _t4 = std::time::Instant::now();

    match format {
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

/// Write MOL, JSON sidecar, and HTML viewer files for the analysis report.
fn write_malecule_files(
    report: &types::AnalysisReport,
    base_path: &str,
    mol_layout: cli::MolLayout,
) -> Result<()> {
    let layout = mol_layout_to_algorithm(mol_layout);

    // Generate malecule for each file in the report
    for file in &report.files {
        if file.findings.is_empty() {
            continue;
        }

        let malecule = malecule_bridge::malecule_from_file_analysis(file, layout);

        // Skip if no meaningful structure
        if malecule.atoms.len() <= 1 {
            continue;
        }

        // Generate file-specific suffix from file path
        let suffix = file
            .path
            .rsplit('/')
            .next()
            .unwrap_or(&file.path)
            .replace(['.', '/', '\\', ' '], "_");

        let mol_file_path = if report.files.len() == 1 {
            format!("{}.mol", base_path)
        } else {
            format!("{}_{}.mol", base_path, suffix)
        };

        let json_file_path = mol_file_path.replace(".mol", ".json");
        let html_file_path = mol_file_path.replace(".mol", ".html");

        // Write MOL file
        let mol_content = malecule::mol::generate_mol(&malecule);
        fs::write(&mol_file_path, &mol_content).context("Failed to write MOL file")?;

        // Write JSON sidecar
        let json_content =
            malecule::mol::generate_metadata_json(&malecule).context("Failed to generate JSON")?;
        fs::write(&json_file_path, &json_content).context("Failed to write JSON sidecar")?;

        // Write HTML viewer
        let html_content = generate_html_viewer(&malecule.name, &mol_content, &json_content);
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
    }

    Ok(())
}

/// Generate an HTML file with embedded Three.js viewer for the malecule.
fn generate_html_viewer(name: &str, mol_content: &str, json_content: &str) -> String {
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
        .legend {{ margin-top: 10px; }}
        .legend-item {{ display: flex; align-items: center; margin: 4px 0; font-size: 11px; }}
        .legend-color {{ width: 12px; height: 12px; border-radius: 50%; margin-right: 8px; }}
        .hostile {{ background: #ff4444; }}
        .suspicious {{ background: #4488ff; }}
        .notable {{ background: #ffffff; }}
        .neutral {{ background: #888888; }}
    </style>
</head>
<body>
    <div id="info">
        <h1>{name}</h1>
        <p class="formula" id="formula"></p>
        <p id="stats"></p>
        <div class="legend">
            <div class="legend-item"><span class="legend-color hostile"></span>Hostile</div>
            <div class="legend-item"><span class="legend-color suspicious"></span>Suspicious</div>
            <div class="legend-item"><span class="legend-color notable"></span>Notable</div>
            <div class="legend-item"><span class="legend-color neutral"></span>Neutral</div>
        </div>
    </div>
    <div id="container"></div>

    <script src="https://cdnjs.cloudflare.com/ajax/libs/three.js/r128/three.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/three@0.128.0/examples/js/controls/OrbitControls.js"></script>
    <script>
        // Embedded data
        const molData = `{mol_content}`;
        const metadata = {json_content};

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
            const lines = molString.trim().split(/\\r?\\n/);
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

        // Create molecule
        const mol = parseMol(molData);
        const atomMeshes = [];

        // Create atoms
        mol.atoms.forEach((atom, i) => {{
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
        mol.bonds.forEach(bond => {{
            const start = mol.atoms[bond.atom1];
            const end = mol.atoms[bond.atom2];

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
        name = name,
        mol_content = mol_content.replace('`', "\\`").replace("${", "\\${"),
        json_content = json_content
    )
}
