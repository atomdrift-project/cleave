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
pub(crate) fn reload_capability_mapper() -> Result<(usize, usize), String> {
    tracing::info!("Reloading CapabilityMapper from disk");
    let mapper = CapabilityMapper::new();
    let trait_count = mapper.trait_definitions_count();
    let composite_count = mapper.composite_rules_count();
    let mut guard = CAPABILITY_MAPPER.write();
    *guard = Some(Arc::new(mapper));
    tracing::info!(
        traits = trait_count,
        composites = composite_count,
        "CapabilityMapper reloaded"
    );
    Ok((trait_count, composite_count))
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
