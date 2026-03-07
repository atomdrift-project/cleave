//! Lazy-loaded global resources for efficient reuse across analyses.
//!
//! This module provides singleton instances of expensive-to-initialize resources
//! like the YARA engine and CapabilityMapper. These are initialized on first use
//! and shared across all subsequent analyses. The CapabilityMapper supports
//! hot-reloading via `reload_capability_mapper()`.

use crate::capabilities::CapabilityMapper;
use crate::yara_engine::YaraEngine;
use std::sync::{Arc, OnceLock};

/// Global CapabilityMapper behind a RwLock for hot-reload support.
static CAPABILITY_MAPPER: parking_lot::RwLock<Option<Arc<CapabilityMapper>>> =
    parking_lot::RwLock::new(None);

/// Global lazy-loaded YARA engine (with third-party rules enabled)
static YARA_ENGINE_WITH_THIRD_PARTY: OnceLock<Arc<YaraEngine>> = OnceLock::new();

/// Global lazy-loaded YARA engine (without third-party rules)
static YARA_ENGINE_BUILTIN_ONLY: OnceLock<Arc<YaraEngine>> = OnceLock::new();

/// Create a CapabilityMapper configured from analysis options.
///
/// Returns the cached global singleton when options match defaults.
/// Custom options create a new mapper (typically CLI one-shots, not hot paths).
pub(crate) fn capability_mapper_with_options(
    options: &crate::AnalysisOptions,
) -> Arc<CapabilityMapper> {
    let is_default = options.min_hostile_precision
        == CapabilityMapper::DEFAULT_MIN_HOSTILE_PRECISION
        && options.min_suspicious_precision == CapabilityMapper::DEFAULT_MIN_SUSPICIOUS_PRECISION
        && !options.enable_full_validation
        && options.platforms.len() == 1
        && options.platforms[0] == crate::composite_rules::Platform::All;

    if is_default {
        return capability_mapper();
    }

    if std::env::var("CLEAVE_SKIP_TRAITS").is_ok() {
        return Arc::new(CapabilityMapper::empty());
    }

    Arc::new(
        CapabilityMapper::new_with_precision_thresholds(
            options.min_hostile_precision,
            options.min_suspicious_precision,
            options.enable_full_validation,
        )
        .with_platforms(options.platforms.clone()),
    )
}

/// Get or initialize the global CapabilityMapper
pub(crate) fn capability_mapper() -> Arc<CapabilityMapper> {
    // Fast path: read lock
    {
        let guard = CAPABILITY_MAPPER.read();
        if let Some(ref mapper) = *guard {
            return mapper.clone();
        }
    }
    // Slow path: write lock + init
    let mut guard = CAPABILITY_MAPPER.write();
    if let Some(ref mapper) = *guard {
        return mapper.clone();
    }
    tracing::debug!("Initializing global CapabilityMapper");
    let mapper = Arc::new(CapabilityMapper::new());
    *guard = Some(mapper.clone());
    mapper
}

/// Reload the global CapabilityMapper from trait definitions on disk.
///
/// Returns the number of traits + composite rules loaded, or an error message.
pub(crate) fn reload_capability_mapper() -> (usize, usize) {
    tracing::info!("Reloading CapabilityMapper from disk");
    let mapper = CapabilityMapper::new();
    let trait_count = mapper.trait_definitions_count();
    let composite_count = mapper.composite_rules_count();
    let mut guard = CAPABILITY_MAPPER.write();
    *guard = Some(Arc::new(mapper));
    drop(guard);

    // SAFETY: The old CapabilityMapper (and its Rules) may be dropped once all
    // Arc references are released. Thread-local YARA scanner caches hold transmuted
    // 'static references to those Rules. We must flush them on ALL threads before
    // any new analysis uses the new mapper, or scanners will dereference freed memory.
    crate::composite_rules::evaluators::clear_scanner_cache();
    rayon::broadcast(|_| {
        crate::composite_rules::evaluators::clear_scanner_cache();
    });

    tracing::info!(
        traits = trait_count,
        composites = composite_count,
        "CapabilityMapper reloaded (scanner caches flushed)"
    );
    (trait_count, composite_count)
}

/// Get or initialize the global YARA engine
pub(crate) fn yara_engine(enable_third_party: bool) -> Arc<YaraEngine> {
    let lock = if enable_third_party {
        &YARA_ENGINE_WITH_THIRD_PARTY
    } else {
        &YARA_ENGINE_BUILTIN_ONLY
    };

    lock.get_or_init(|| {
        tracing::debug!(
            "Initializing global YARA engine (third_party={})",
            enable_third_party
        );
        let mut engine = YaraEngine::new();
        engine.load_all_rules(enable_third_party);
        Arc::new(engine)
    })
    .clone()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_capability_mapper_singleton() {
        let m1 = capability_mapper();
        let m2 = capability_mapper();
        // Same Arc instance
        assert!(Arc::ptr_eq(&m1, &m2));
    }
}
