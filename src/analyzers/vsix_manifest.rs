//! VS Code extension manifest analyzer.
//!
//! Analyzes .vsixmanifest files from VS Code extensions for suspicious patterns.

use crate::analyzers::Analyzer;
use crate::capabilities::CapabilityMapper;
use crate::types::*;
use anyhow::{Context, Result};
use std::fs;
use std::path::Path;
use std::sync::Arc;

/// VSCode extension.vsixmanifest analyzer
#[derive(Debug)]
pub(crate) struct VsixManifestAnalyzer {
    capability_mapper: Arc<CapabilityMapper>,
}

impl VsixManifestAnalyzer {
    #[must_use]
    pub(crate) fn new() -> Self {
        Self {
            capability_mapper: Arc::new(CapabilityMapper::empty()),
        }
    }

    /// Create analyzer with pre-existing capability mapper (wraps in Arc)
    #[must_use]
    pub(crate) fn with_capability_mapper(mut self, mapper: CapabilityMapper) -> Self {
        self.capability_mapper = Arc::new(mapper);
        self
    }

    /// Create analyzer with shared capability mapper (avoids cloning)
    #[must_use]
    pub(crate) fn with_capability_mapper_arc(mut self, mapper: Arc<CapabilityMapper>) -> Self {
        self.capability_mapper = mapper;
        self
    }

    fn analyze_manifest(&self, file_path: &Path, content: &str) -> Result<AnalysisReport> {
        let start = std::time::Instant::now();

        let doc =
            roxmltree::Document::parse(content).context("Failed to parse .vsixmanifest XML")?;

        let mut identity = String::new();
        if let Some(node) = doc.descendants().find(|n| n.has_tag_name("Identity")) {
            let id = node.attribute("Id").unwrap_or("unknown");
            let publisher = node.attribute("Publisher").unwrap_or("unknown");
            let version = node.attribute("Version").unwrap_or("unknown");
            identity = format!("{}.{} v{}", publisher, id, version);
        }

        let target = TargetInfo {
            path: file_path.display().to_string(),
            file_type: "vsix_manifest".to_string(),
            size_bytes: content.len() as u64,
            sha256: crate::analyzers::utils::calculate_sha256(content.as_bytes()),
            architectures: None,
        };

        let mut report = AnalysisReport::new(target);

        // Add structural feature
        report.structure.push(StructuralFeature {
            id: "manifest/vscode/vsixmanifest".to_string(),
            desc: format!("VSCode extension manifest: {}", identity),
            evidence: vec![Evidence {
                method: "parser".to_string(),
                source: "roxmltree".to_string(),
                value: identity,
                location: None,
            }],
        });

        // Check for interesting properties
        for property in doc.descendants().filter(|n| n.has_tag_name("Property")) {
            if let (Some(id), Some(value)) = (property.attribute("Id"), property.attribute("Value"))
            {
                if id == "Microsoft.VisualStudio.Code.ExecutesCode" && value == "true" {
                    report.add_finding(
                        Finding::capability(
                            "eco/vscode/manifest/executes-code".to_string(),
                            "Extension explicitly marks that it executes code".to_string(),
                            1.0,
                        )
                        .with_criticality(Criticality::Notable)
                        .with_evidence(vec![Evidence {
                            method: "xml_attr".to_string(),
                            source: "vsixmanifest".to_string(),
                            value: "ExecutesCode=true".to_string(),
                            location: None,
                        }]),
                    );
                }
            }
        }

        // Evaluate all rules (atomic + composite) and merge into report
        self.capability_mapper.evaluate_and_merge_findings(
            &mut report,
            content.as_bytes(),
            None,
            None,
        );

        report.metadata.analysis_duration_ms = start.elapsed().as_millis() as u64;
        report.metadata.tools_used = vec!["roxmltree".to_string()];

        Ok(report)
    }
}

impl Default for VsixManifestAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

impl Analyzer for VsixManifestAnalyzer {
    fn analyze(&self, file_path: &Path) -> Result<AnalysisReport> {
        let bytes = fs::read(file_path).context("Failed to read .vsixmanifest file")?;
        let content = String::from_utf8_lossy(&bytes);
        self.analyze_manifest(file_path, &content)
    }

    fn can_analyze(&self, file_path: &Path) -> bool {
        file_path
            .file_name()
            .map(|n| {
                n.to_string_lossy()
                    .to_lowercase()
                    .ends_with(".vsixmanifest")
            })
            .unwrap_or(false)
    }
}
