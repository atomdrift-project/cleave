//! Configuration for third-party YARA rule criticality levels.
#![allow(clippy::unwrap_used, clippy::expect_used)]
//!
//! Loads criticality mappings from `third_party/config.yaml` to assign
//! appropriate severity levels to third-party YARA detections.

use serde::Deserialize;
use std::collections::HashMap;
use std::sync::OnceLock;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ConfigFile {
    default_crit: String,
    #[serde(default)]
    sources: Vec<SourceConfig>,
    #[serde(default)]
    overrides: Vec<RuleOverride>,
}

#[derive(Debug, Deserialize)]
struct SourceConfig {
    name: String,
    #[serde(default)]
    #[allow(dead_code)]
    url: String,
    crit: String,
}

#[derive(Debug, Deserialize)]
struct RuleOverride {
    id: String,
    #[serde(default)]
    crit: Option<String>,
    #[serde(default)]
    disable: bool,
    #[serde(default)]
    #[allow(dead_code)]
    reason: Option<String>,
}

struct Config {
    default_crit: String,
    source_crit: HashMap<String, String>,
    overrides: HashMap<String, RuleOverride>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            default_crit: "suspicious".to_string(),
            source_crit: HashMap::new(),
            overrides: HashMap::new(),
        }
    }
}

impl Config {
    fn from_yaml(yaml: &str) -> Result<Self, serde_yaml::Error> {
        let file: ConfigFile = serde_yaml::from_str(yaml)?;

        let source_crit = file.sources.into_iter().map(|s| (s.name, s.crit)).collect();

        let overrides = file
            .overrides
            .into_iter()
            .map(|o| (o.id.clone(), o))
            .collect();

        Ok(Self {
            default_crit: file.default_crit,
            source_crit,
            overrides,
        })
    }

    fn load() -> Self {
        let config_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("third_party")
            .join("config.yaml");

        match std::fs::read_to_string(&config_path) {
            Ok(yaml) => match Self::from_yaml(&yaml) {
                Ok(config) => config,
                Err(e) => {
                    tracing::warn!(
                        "Failed to parse third_party/config.yaml: {}, using defaults",
                        e
                    );
                    Self::default()
                }
            },
            Err(e) => {
                tracing::warn!(
                    "Failed to read third_party/config.yaml: {}, using defaults",
                    e
                );
                Self::default()
            }
        }
    }

    fn criticality_for(&self, vendor: &str, trait_id: Option<&str>) -> Option<String> {
        // 1. Check rule override (highest priority)
        if let Some(trait_id) = trait_id {
            if let Some(override_rule) = self.overrides.get(trait_id) {
                if override_rule.disable {
                    return None; // Rule disabled
                }
                if let Some(ref crit) = override_rule.crit {
                    return Some(crit.clone());
                }
            }
        }

        // 2. Check source default
        if let Some(crit) = self.source_crit.get(vendor) {
            return Some(crit.clone());
        }

        // 3. Global default
        Some(self.default_crit.clone())
    }
}

static CONFIG: OnceLock<Config> = OnceLock::new();

fn config() -> &'static Config {
    CONFIG.get_or_init(Config::load)
}

fn extract_vendor(namespace: &str) -> &str {
    namespace
        .strip_prefix("3p.")
        .unwrap_or(namespace)
        .split('.')
        .next()
        .unwrap_or("")
}

/// Get criticality for a third-party YARA match.
///
/// Returns `None` if the rule is disabled via override.
/// Lookup priority: rule override > source default > global default
pub(crate) fn third_party_criticality(namespace: &str, trait_id: Option<&str>) -> Option<String> {
    let vendor = extract_vendor(namespace);
    config().criticality_for(vendor, trait_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_minimal_config() {
        let yaml = r#"
default_crit: "suspicious"
sources: []
"#;
        let config = Config::from_yaml(yaml).unwrap();
        assert_eq!(config.default_crit, "suspicious");
        assert_eq!(config.source_crit.len(), 0);
    }

    #[test]
    fn test_parse_full_config() {
        let yaml = r#"
default_crit: "suspicious"
sources:
  - name: elastic
    url: https://github.com/elastic/protections-artifacts
    crit: "hostile"
  - name: bartblaze
    crit: "suspicious"
overrides:
  - id: third_party/elastic/linux/test
    crit: "notable"
    reason: "High FP rate"
"#;
        let config = Config::from_yaml(yaml).unwrap();
        assert_eq!(
            config.source_crit.get("elastic"),
            Some(&"hostile".to_string())
        );
        assert_eq!(
            config.source_crit.get("bartblaze"),
            Some(&"suspicious".to_string())
        );
        assert_eq!(config.overrides.len(), 1);
    }

    #[test]
    fn test_criticality_priority() {
        let yaml = r#"
default_crit: "notable"
sources:
  - name: elastic
    crit: "suspicious"
overrides:
  - id: third_party/elastic/test
    crit: "hostile"
"#;
        let config = Config::from_yaml(yaml).unwrap();

        // Override wins
        assert_eq!(
            config.criticality_for("elastic", Some("third_party/elastic/test")),
            Some("hostile".to_string())
        );

        // Source default
        assert_eq!(
            config.criticality_for("elastic", Some("third_party/elastic/other")),
            Some("suspicious".to_string())
        );

        // Global default
        assert_eq!(
            config.criticality_for("unknown", None),
            Some("notable".to_string())
        );
    }

    #[test]
    fn test_disabled_rule() {
        let yaml = r#"
default_crit: "suspicious"
overrides:
  - id: third_party/test/disabled
    disable: true
"#;
        let config = Config::from_yaml(yaml).unwrap();
        assert_eq!(
            config.criticality_for("test", Some("third_party/test/disabled")),
            None
        );
    }

    #[test]
    fn test_vendor_extraction() {
        assert_eq!(extract_vendor("3p.elastic"), "elastic");
        assert_eq!(extract_vendor("3p.bartblaze.APT"), "bartblaze");
        assert_eq!(extract_vendor("3p.YARAForge"), "YARAForge");
    }
}
