//! Per-language metric structs (PythonMetrics, JavaScriptMetrics, …) retired.
//!
//! No production code ever emitted them. The trait-engine field-path
//! manifest in `field_paths.rs` previously enumerated them so YAML
//! rule authors could reference language-specific paths; that
//! manifest has been pruned to keep only paths actually emitted by
//! the active producers (expose source extractors).
