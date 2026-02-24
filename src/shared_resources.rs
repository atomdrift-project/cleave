//! Lazy-loaded global resources for efficient reuse across analyses.
//!
//! This module provides singleton instances of expensive-to-initialize resources
//! like the YARA engine and CapabilityMapper. These are initialized on first use
//! and shared across all subsequent analyses.

use crate::capabilities::CapabilityMapper;
use crate::yara_engine::YaraEngine;
use std::sync::{Arc, OnceLock};

/// Global lazy-loaded CapabilityMapper
static CAPABILITY_MAPPER: OnceLock<Arc<CapabilityMapper>> = OnceLock::new();

/// Global lazy-loaded YARA engine (with third-party rules enabled)
static YARA_ENGINE_WITH_THIRD_PARTY: OnceLock<Arc<YaraEngine>> = OnceLock::new();

/// Global lazy-loaded YARA engine (without third-party rules)
static YARA_ENGINE_BUILTIN_ONLY: OnceLock<Arc<YaraEngine>> = OnceLock::new();

/// Get or initialize the global CapabilityMapper
pub(crate) fn capability_mapper() -> Arc<CapabilityMapper> {
    CAPABILITY_MAPPER
        .get_or_init(|| {
            tracing::debug!("Initializing global CapabilityMapper");
            Arc::new(CapabilityMapper::new())
        })
        .clone()
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
