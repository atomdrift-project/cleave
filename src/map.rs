//! Map visualization of trait relationships.
#![allow(clippy::unwrap_used, clippy::expect_used)]
//!
//! Generates DOT (Graphviz) or ASCII format showing directory-level trait dependencies.
//! Two modes:
//! - Definition mode: Shows relationships from trait YAML definitions
//! - Findings mode: Shows relationships from actual JSONL analysis results

use crate::capabilities::validation::collect_trait_refs_from_rule;
use crate::capabilities::CapabilityMapper;
use crate::cli::MapFormat;
use crate::types::Criticality;
use anyhow::Result;
use rustc_hash::FxHashMap;
use std::collections::HashMap;
use std::io::{BufRead, BufReader};

/// Node in the dependency graph (represents a trait directory)
#[derive(Debug)]
struct GraphNode {
    /// Number of traits in this directory
    trait_count: usize,
    /// Highest criticality level found in this directory
    max_criticality: Criticality,
    /// Sum of all criticality values (for computing average)
    criticality_sum: f32,
}

impl GraphNode {
    fn average_criticality(&self) -> f32 {
        if self.trait_count == 0 {
            0.0
        } else {
            self.criticality_sum / self.trait_count as f32
        }
    }
}

/// Node representing a matched trait/composite in findings mode
#[derive(Debug)]
struct FindingNode {
    /// Full trait/composite ID (truncated to depth)
    id: String,
    /// Number of times this was matched
    match_count: usize,
    /// Highest criticality level seen
    max_criticality: Criticality,
    /// Whether this is a composite rule (has trait_refs)
    is_composite: bool,
    /// Whether this is a low-value any rule
    is_low_value: bool,
}

/// Graph built from JSONL findings
struct FindingsGraph {
    nodes: FxHashMap<String, FindingNode>,
    edges: HashMap<(String, String), usize>,
}

/// Generate a DOT map of trait relationships at directory level (definition mode)
pub fn generate_trait_map(
    depth: usize,
    output_path: Option<&str>,
    min_refs: usize,
    namespace_filter: Option<&str>,
) -> Result<String> {
    // Load capability mapper to get all traits
    let mapper = CapabilityMapper::new();

    let mut nodes: FxHashMap<String, GraphNode> = FxHashMap::default();
    let mut edges: HashMap<(String, String), usize> = HashMap::new();

    // Parse namespace filter if provided
    let allowed_namespaces: Option<Vec<String>> =
        namespace_filter.map(|s| s.split(',').map(|ns| ns.trim().to_lowercase()).collect());

    // Process all composite rules to extract relationships
    for composite in mapper.composite_rules() {
        let source_dir = extract_directory(&composite.id, depth);

        // Skip if filtered by namespace
        if let Some(ref allowed) = allowed_namespaces {
            let top_level = source_dir.split('/').next().unwrap_or("");
            if !allowed.contains(&top_level.to_lowercase()) {
                continue;
            }
        }

        // Update source node
        let node = nodes
            .entry(source_dir.clone())
            .or_insert_with(|| GraphNode {
                trait_count: 0,
                max_criticality: Criticality::Filtered,
                criticality_sum: 0.0,
            });
        node.trait_count += 1;
        node.criticality_sum += criticality_to_f32(composite.crit);
        if composite.crit > node.max_criticality {
            node.max_criticality = composite.crit;
        }

        // Extract all trait references (returns Vec<(trait_id, rule_id)>)
        let trait_refs = collect_trait_refs_from_rule(composite);

        for (trait_ref, _rule_id) in trait_refs {
            let target_dir = extract_directory(&trait_ref, depth);

            // Skip self-references
            if target_dir == source_dir {
                continue;
            }

            // Skip if filtered by namespace
            if let Some(ref allowed) = allowed_namespaces {
                let top_level = target_dir.split('/').next().unwrap_or("");
                if !allowed.contains(&top_level.to_lowercase()) {
                    continue;
                }
            }

            // Ensure target node exists
            nodes
                .entry(target_dir.clone())
                .or_insert_with(|| GraphNode {
                    trait_count: 0,
                    max_criticality: Criticality::Filtered,
                    criticality_sum: 0.0,
                });

            // Increment edge weight
            *edges.entry((source_dir.clone(), target_dir)).or_insert(0) += 1;
        }
    }

    // Generate DOT output
    let dot = generate_dot(&nodes, &edges, min_refs);

    // Write to file or stdout
    let message = if let Some(path) = output_path {
        std::fs::write(path, &dot)?;
        format!("Map written to: {}", path)
    } else {
        dot
    };

    Ok(message)
}

/// Generate map from JSONL findings (findings mode)
pub fn generate_findings_map(
    input: &str,
    depth: usize,
    output_path: Option<&str>,
    min_refs: usize,
    namespace_filter: Option<&str>,
    format: MapFormat,
    min_crit: &str,
    show_low_value: bool,
) -> Result<String> {
    // Parse min_crit
    let min_criticality = parse_criticality(min_crit);

    // Read JSONL (file or stdin)
    let reader: Box<dyn BufRead> = if input == "-" {
        Box::new(BufReader::new(std::io::stdin()))
    } else {
        Box::new(BufReader::new(std::fs::File::open(input)?))
    };

    // Build graph from findings
    let graph = build_graph_from_findings(reader, depth, min_criticality, namespace_filter)?;

    // Generate output based on format
    let output = match format {
        MapFormat::Dot => generate_findings_dot(&graph, min_refs, show_low_value),
        MapFormat::Ascii => generate_findings_ascii(&graph, show_low_value),
    };

    // Write to file or return
    if let Some(path) = output_path {
        std::fs::write(path, &output)?;
        Ok(format!("Map written to: {}", path))
    } else {
        Ok(output)
    }
}

/// Parse criticality level from string
fn parse_criticality(s: &str) -> Criticality {
    match s.to_lowercase().as_str() {
        "filtered" => Criticality::Filtered,
        "component" => Criticality::Component,
        "notable" => Criticality::Notable,
        "suspicious" => Criticality::Suspicious,
        "hostile" | "malicious" => Criticality::Hostile,
        _ => Criticality::Baseline, // includes "baseline" and any unknown value
    }
}

/// Build graph from JSONL findings
fn build_graph_from_findings<R: BufRead>(
    reader: R,
    depth: usize,
    min_crit: Criticality,
    namespace_filter: Option<&str>,
) -> Result<FindingsGraph> {
    let allowed_namespaces: Option<Vec<String>> =
        namespace_filter.map(|s| s.split(',').map(|ns| ns.trim().to_lowercase()).collect());

    let mut nodes: FxHashMap<String, FindingNode> = FxHashMap::default();
    let mut edges: HashMap<(String, String), usize> = HashMap::new();

    for line in reader.lines() {
        let line = line?;
        let line = line.trim();
        if line.is_empty() {
            continue;
        }

        // Parse JSON line
        let json: serde_json::Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(_) => continue, // Skip malformed lines
        };

        // Skip summary lines
        if json.get("type").and_then(|v| v.as_str()) == Some("summary") {
            continue;
        }

        // Extract findings array
        let Some(findings) = json.get("findings").and_then(|f| f.as_array()) else {
            continue;
        };

        for finding in findings {
            // Get finding ID
            let Some(id) = finding.get("id").and_then(|v| v.as_str()) else {
                continue;
            };

            // Get criticality
            let crit_str = finding
                .get("crit")
                .and_then(|v| v.as_str())
                .unwrap_or("baseline");
            let crit = parse_criticality(crit_str);

            // Skip if below min criticality
            if crit < min_crit {
                continue;
            }

            let dir = extract_directory(id, depth);

            // Skip if filtered by namespace
            if let Some(ref allowed) = allowed_namespaces {
                let top_level = dir.split('/').next().unwrap_or("");
                if !allowed.contains(&top_level.to_lowercase()) {
                    continue;
                }
            }

            // Get trait_refs for composite rules
            let trait_refs: Vec<&str> = finding
                .get("trait_refs")
                .and_then(|v| v.as_array())
                .map(|arr| arr.iter().filter_map(|v| v.as_str()).collect())
                .unwrap_or_default();

            let is_composite = !trait_refs.is_empty();

            // Update/create node
            let node = nodes.entry(dir.clone()).or_insert_with(|| FindingNode {
                id: dir.clone(),
                match_count: 0,
                max_criticality: Criticality::Filtered,
                is_composite: false,
                is_low_value: false,
            });
            node.match_count += 1;
            if crit > node.max_criticality {
                node.max_criticality = crit;
            }
            if is_composite {
                node.is_composite = true;
            }

            // Add edges from trait_refs
            for trait_ref in trait_refs {
                let target_dir = extract_directory(trait_ref, depth);

                // Skip self-references
                if target_dir == dir {
                    continue;
                }

                // Skip if filtered by namespace
                if let Some(ref allowed) = allowed_namespaces {
                    let top_level = target_dir.split('/').next().unwrap_or("");
                    if !allowed.contains(&top_level.to_lowercase()) {
                        continue;
                    }
                }

                // Ensure target node exists
                nodes
                    .entry(target_dir.clone())
                    .or_insert_with(|| FindingNode {
                        id: target_dir.clone(),
                        match_count: 0,
                        max_criticality: Criticality::Filtered,
                        is_composite: false,
                        is_low_value: false,
                    });

                *edges.entry((dir.clone(), target_dir)).or_insert(0) += 1;
            }
        }
    }

    // Mark low-value rules using CapabilityMapper
    let mapper = CapabilityMapper::new();
    for (id, node) in nodes.iter_mut() {
        // A node is low-value if ALL rules in that directory are low-value
        // For simplicity, we check if any matching rule is low-value
        if mapper.is_low_value_any_rule(id) {
            node.is_low_value = true;
        }
    }

    Ok(FindingsGraph { nodes, edges })
}

/// Generate DOT output from findings graph
fn generate_findings_dot(graph: &FindingsGraph, min_refs: usize, show_low_value: bool) -> String {
    let mut output = String::new();

    // Header
    output.push_str("digraph findings_map {\n");
    output.push_str("  rankdir=LR;\n");
    output.push_str("  node [shape=box, style=\"filled,bold\", penwidth=3, fontname=\"Arial\"];\n");
    output.push_str("  edge [fontname=\"Arial\", fontsize=10];\n");
    output.push('\n');

    // Nodes
    for (path, node) in &graph.nodes {
        if !show_low_value && node.is_low_value {
            continue;
        }

        let fill = criticality_fill_color(node.max_criticality);
        let outline = outline_color(path);
        let label = format!("{} (x{})", shorten_path(path), node.match_count);

        output.push_str(&format!(
            "  \"{}\" [fillcolor=\"{}\", color=\"{}\", label=\"{}\"];\n",
            path, fill, outline, label
        ));
    }

    output.push('\n');

    // Edges (filtered by min_refs)
    let mut edge_list: Vec<(&(String, String), &usize)> = graph.edges.iter().collect();
    edge_list.sort_by(|a, b| b.1.cmp(a.1)); // Sort by weight descending

    for ((from, to), weight) in edge_list {
        if *weight < min_refs {
            continue;
        }

        // Skip edges to/from low-value nodes if not showing them
        if !show_low_value {
            if let Some(from_node) = graph.nodes.get(from) {
                if from_node.is_low_value {
                    continue;
                }
            }
            if let Some(to_node) = graph.nodes.get(to) {
                if to_node.is_low_value {
                    continue;
                }
            }
        }

        // Scale penwidth: 1-3 refs = 1, 4-7 = 2, 8-15 = 4, 16+ = 8
        let penwidth = if *weight >= 16 {
            8
        } else if *weight >= 8 {
            4
        } else if *weight >= 4 {
            2
        } else {
            1
        };

        output.push_str(&format!(
            "  \"{}\" -> \"{}\" [penwidth={}, label=\"{}\"];\n",
            from, to, penwidth, weight
        ));
    }

    output.push_str("}\n");
    output
}

/// Generate ASCII output from findings graph
fn generate_findings_ascii(graph: &FindingsGraph, show_low_value: bool) -> String {
    let mut output = String::new();

    // Group by top-level namespace
    let mut by_namespace: FxHashMap<&str, Vec<&FindingNode>> = FxHashMap::default();
    for node in graph.nodes.values() {
        if !show_low_value && node.is_low_value {
            continue;
        }
        let ns = node.id.split('/').next().unwrap_or(&node.id);
        by_namespace.entry(ns).or_default().push(node);
    }

    // Sort namespaces
    let mut namespaces: Vec<_> = by_namespace.keys().copied().collect();
    namespaces.sort();

    for ns in namespaces {
        if let Some(nodes) = by_namespace.get(ns) {
            let mut nodes = nodes.clone();
            // Sort by criticality descending, then by match_count descending
            nodes.sort_by(|a, b| {
                b.max_criticality
                    .cmp(&a.max_criticality)
                    .then_with(|| b.match_count.cmp(&a.match_count))
            });

            output.push_str(&format!("\n{}\n", ns.to_uppercase()));
            output.push_str(&"-".repeat(50));
            output.push('\n');

            for node in nodes {
                let indicator = match node.max_criticality {
                    Criticality::Hostile => "[!!!]",
                    Criticality::Suspicious => "[!! ]",
                    Criticality::Notable => "[!  ]",
                    _ => "[   ]",
                };

                // Get outgoing edges for this node
                let refs: Vec<_> = graph
                    .edges
                    .iter()
                    .filter(|((from, _), _)| from == &node.id)
                    .map(|((_, to), weight)| format!("{}(x{})", shorten_path(to), weight))
                    .collect();

                if !refs.is_empty() {
                    output.push_str(&format!(
                        "  {} {} (x{}) <- {}\n",
                        indicator,
                        shorten_path(&node.id),
                        node.match_count,
                        refs.join(", ")
                    ));
                } else {
                    output.push_str(&format!(
                        "  {} {} (x{})\n",
                        indicator,
                        shorten_path(&node.id),
                        node.match_count
                    ));
                }
            }
        }
    }

    output
}

/// Extract directory path up to specified depth
/// Example: "micro-behaviors/communications/socket/raw::trait-id" with depth=3 -> "micro-behaviors/communications/socket"
fn extract_directory(trait_id: &str, depth: usize) -> String {
    // Remove trait name after "::" if present
    let path_part = trait_id.split("::").next().unwrap_or(trait_id);

    // Split by '/' and take first N segments
    let segments: Vec<&str> = path_part.split('/').take(depth).collect();
    segments.join("/")
}

/// Convert Criticality to numeric value for averaging
fn criticality_to_f32(crit: Criticality) -> f32 {
    match crit {
        Criticality::Filtered => -1.0,
        Criticality::Component => -0.5,
        Criticality::Baseline => 0.0,
        Criticality::Notable => 1.0,
        Criticality::Suspicious => 2.0,
        Criticality::Hostile => 3.0,
    }
}

/// Get fill color based on average criticality (for definition mode)
fn fill_color(avg_criticality: f32) -> &'static str {
    if avg_criticality < 0.5 {
        "#90EE90" // Light green (baseline)
    } else if avg_criticality < 1.5 {
        "#FFFF99" // Light yellow (notable)
    } else if avg_criticality < 2.5 {
        "#FFA500" // Orange (suspicious)
    } else {
        "#FF6347" // Tomato red (hostile)
    }
}

/// Get fill color based on criticality level (for findings mode)
fn criticality_fill_color(crit: Criticality) -> &'static str {
    match crit {
        Criticality::Filtered | Criticality::Component | Criticality::Baseline => "#90EE90", // Light green
        Criticality::Notable => "#FFFF99",    // Light yellow
        Criticality::Suspicious => "#FFA500", // Orange
        Criticality::Hostile => "#FF6347",    // Tomato red
    }
}

/// Get outline color based on top-level namespace
fn outline_color(path: &str) -> &'static str {
    let top_level = path.split('/').next().unwrap_or("");
    match top_level {
        "micro-behaviors" => "#228B22", // Forest green
        "objectives" => "#DC143C",      // Crimson red
        "well-known" => "#8B008B",      // Dark magenta (purple)
        "metadata" => "#696969",        // Dim gray
        _ => "#000000",                 // Black (fallback)
    }
}

/// Generate DOT format output (for definition mode)
fn generate_dot(
    nodes: &FxHashMap<String, GraphNode>,
    edges: &HashMap<(String, String), usize>,
    min_refs: usize,
) -> String {
    let mut output = String::new();

    // Header
    output.push_str("digraph trait_dependencies {\n");
    output.push_str("  rankdir=LR;\n");
    output.push_str("  node [shape=box, style=\"filled,bold\", penwidth=3, fontname=\"Arial\"];\n");
    output.push_str("  edge [fontname=\"Arial\", fontsize=10];\n");
    output.push('\n');

    // Nodes
    for (path, node) in nodes {
        let avg_crit = node.average_criticality();
        let fill = fill_color(avg_crit);
        let outline = outline_color(path);
        let label = format!("{} ({})", shorten_path(path), node.trait_count);

        output.push_str(&format!(
            "  \"{}\" [fillcolor=\"{}\", color=\"{}\", label=\"{}\"];\n",
            path, fill, outline, label
        ));
    }

    output.push('\n');

    // Edges (filtered by min_refs)
    let mut edge_list: Vec<(&(String, String), &usize)> = edges.iter().collect();
    edge_list.sort_by(|a, b| b.1.cmp(a.1)); // Sort by weight descending

    for ((from, to), weight) in edge_list {
        if *weight >= min_refs {
            // Scale penwidth: 1-3 refs = 1, 4-7 = 2, 8-15 = 4, 16+ = 8
            let penwidth = if *weight >= 16 {
                8
            } else if *weight >= 8 {
                4
            } else if *weight >= 4 {
                2
            } else {
                1
            };

            output.push_str(&format!(
                "  \"{}\" -> \"{}\" [penwidth={}, label=\"{}\"];\n",
                from, to, penwidth, weight
            ));
        }
    }

    output.push_str("}\n");
    output
}

/// Shorten path for display (keep last 2-3 segments)
fn shorten_path(path: &str) -> String {
    let segments: Vec<&str> = path.split('/').collect();
    if segments.len() <= 2 {
        path.to_string()
    } else if let Some(last) = segments.last() {
        // Show first + last segments with ellipsis if too long
        format!("{}/.../{}", segments[0], last)
    } else {
        path.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_directory() {
        assert_eq!(
            extract_directory("micro-behaviors/communications/socket/raw::trait-id", 2),
            "micro-behaviors/communications"
        );
        assert_eq!(
            extract_directory("micro-behaviors/communications/socket/raw::trait-id", 3),
            "micro-behaviors/communications/socket"
        );
        assert_eq!(
            extract_directory("micro-behaviors/communications/socket/raw::trait-id", 4),
            "micro-behaviors/communications/socket/raw"
        );
        assert_eq!(
            extract_directory("micro-behaviors/communications/socket/raw::trait-id", 1),
            "micro-behaviors"
        );

        // Without :: separator
        assert_eq!(
            extract_directory("micro-behaviors/communications/socket", 2),
            "micro-behaviors/communications"
        );
        assert_eq!(extract_directory("micro-behaviors", 2), "micro-behaviors");
    }

    #[test]
    fn test_criticality_to_f32() {
        assert_eq!(criticality_to_f32(Criticality::Filtered), -1.0);
        assert_eq!(criticality_to_f32(Criticality::Baseline), 0.0);
        assert_eq!(criticality_to_f32(Criticality::Notable), 1.0);
        assert_eq!(criticality_to_f32(Criticality::Suspicious), 2.0);
        assert_eq!(criticality_to_f32(Criticality::Hostile), 3.0);
    }

    #[test]
    fn test_fill_color() {
        assert_eq!(fill_color(0.0), "#90EE90"); // baseline
        assert_eq!(fill_color(0.4), "#90EE90"); // baseline
        assert_eq!(fill_color(1.0), "#FFFF99"); // Notable
        assert_eq!(fill_color(1.4), "#FFFF99"); // Notable
        assert_eq!(fill_color(2.0), "#FFA500"); // Suspicious
        assert_eq!(fill_color(2.4), "#FFA500"); // Suspicious
        assert_eq!(fill_color(2.8), "#FF6347"); // Hostile
        assert_eq!(fill_color(3.0), "#FF6347"); // Hostile
    }

    #[test]
    fn test_outline_color() {
        assert_eq!(
            outline_color("micro-behaviors/communications/socket"),
            "#228B22"
        ); // Green
        assert_eq!(
            outline_color("objectives/command-and-control/beacon"),
            "#DC143C"
        ); // Red
        assert_eq!(outline_color("well-known/malware/mirai"), "#8B008B"); // Purple
        assert_eq!(outline_color("metadata/lang"), "#696969"); // Gray
        assert_eq!(outline_color("unknown/namespace"), "#000000"); // Black fallback
    }

    #[test]
    fn test_shorten_path() {
        assert_eq!(shorten_path("micro-behaviors"), "micro-behaviors");
        assert_eq!(
            shorten_path("micro-behaviors/communications"),
            "micro-behaviors/communications"
        );
        assert_eq!(
            shorten_path("micro-behaviors/communications/socket"),
            "micro-behaviors/.../socket"
        );
        assert_eq!(
            shorten_path("micro-behaviors/communications/socket/raw"),
            "micro-behaviors/.../raw"
        );
    }

    #[test]
    fn test_graph_node_average_criticality() {
        let node = GraphNode {
            trait_count: 4,
            max_criticality: Criticality::Suspicious,
            criticality_sum: 6.0, // (0 + 1 + 2 + 3) / 4 = 1.5
        };
        assert_eq!(node.average_criticality(), 1.5);

        // Empty node
        let empty_node = GraphNode {
            trait_count: 0,
            max_criticality: Criticality::Baseline,
            criticality_sum: 0.0,
        };
        assert_eq!(empty_node.average_criticality(), 0.0);
    }

    #[test]
    fn test_parse_criticality() {
        assert_eq!(parse_criticality("hostile"), Criticality::Hostile);
        assert_eq!(parse_criticality("SUSPICIOUS"), Criticality::Suspicious);
        assert_eq!(parse_criticality("Notable"), Criticality::Notable);
        assert_eq!(parse_criticality("baseline"), Criticality::Baseline);
        assert_eq!(parse_criticality("filtered"), Criticality::Filtered);
        assert_eq!(parse_criticality("unknown"), Criticality::Baseline); // Default
    }

    #[test]
    fn test_build_graph_from_findings_empty() {
        let input = "";
        let reader = std::io::BufReader::new(input.as_bytes());
        let graph = build_graph_from_findings(reader, 3, Criticality::Baseline, None).unwrap();
        assert!(graph.nodes.is_empty());
        assert!(graph.edges.is_empty());
    }

    #[test]
    fn test_build_graph_from_findings_basic() {
        let input = r#"{"path":"test.bin","findings":[{"id":"objectives/persistence/bootkit","crit":"hostile","trait_refs":["micro-behaviors/fs/write"]}]}"#;
        let reader = std::io::BufReader::new(input.as_bytes());
        let graph = build_graph_from_findings(reader, 2, Criticality::Baseline, None).unwrap();

        assert!(graph.nodes.contains_key("objectives/persistence"));
        assert!(graph.nodes.contains_key("micro-behaviors/fs"));

        let obj_node = graph.nodes.get("objectives/persistence").unwrap();
        assert_eq!(obj_node.match_count, 1);
        assert_eq!(obj_node.max_criticality, Criticality::Hostile);
        assert!(obj_node.is_composite);
    }
}
