//! Lazy-loaded global resources for efficient reuse across analyses.
//!
//! This module provides singleton instances of expensive-to-initialize resources
//! like the YARA engine and CapabilityMapper. These are initialized on first use
//! and shared across all subsequent analyses. The CapabilityMapper supports
//! hot-reloading via `reload_capability_mapper()`.

use crate::capabilities::CapabilityMapper;
use crate::yara_engine::YaraEngine;
use std::sync::{Arc, OnceLock};

fn skip_traits_requested() -> bool {
    std::env::var("CLEAVE_SKIP_TRAITS").is_ok() || std::env::var("cleave_SKIP_TRAITS").is_ok()
}

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
) -> anyhow::Result<Arc<CapabilityMapper>> {
    let is_default = options.min_hostile_precision
        == CapabilityMapper::DEFAULT_MIN_HOSTILE_PRECISION
        && options.min_suspicious_precision == CapabilityMapper::DEFAULT_MIN_SUSPICIOUS_PRECISION
        && !options.enable_precision_scoring
        && !options.enable_full_validation
        && options.platforms.len() == 1
        && options.platforms[0] == crate::composite_rules::Platform::All
        && options.slow_rule_ms == CapabilityMapper::DEFAULT_SLOW_RULE_MS;

    if is_default {
        return capability_mapper();
    }

    if skip_traits_requested() {
        return Ok(Arc::new(CapabilityMapper::empty()));
    }

    Ok(Arc::new(
        CapabilityMapper::try_new_with_load_options(
            options.min_hostile_precision,
            options.min_suspicious_precision,
            options.enable_full_validation,
            options.enable_precision_scoring,
        )
        .map_err(|e| anyhow::anyhow!("failed to initialize capability mapper: {e:#}"))?
        .with_platforms(options.platforms.clone())
        .with_slow_rule_ms(options.slow_rule_ms),
    ))
}

/// Return (trait_count, composite_count) if the global CapabilityMapper is already loaded.
/// Returns `None` if the mapper has not been initialized yet (avoids triggering init).
pub(crate) fn capability_mapper_stats() -> Option<(usize, usize)> {
    let guard = CAPABILITY_MAPPER.read();
    guard
        .as_ref()
        .map(|m| (m.trait_definitions_count(), m.composite_rules_count()))
}

/// Get or initialize the global CapabilityMapper
pub(crate) fn capability_mapper() -> anyhow::Result<Arc<CapabilityMapper>> {
    // Fast path: already initialized.
    {
        let guard = CAPABILITY_MAPPER.read();
        if let Some(ref mapper) = *guard {
            return Ok(mapper.clone());
        }
    }

    // Slow path: build the mapper with NO locks held.
    //
    // CapabilityMapper::try_new() uses rayon parallel iteration internally. Rayon
    // work-steals freely across the thread pool, so a rayon worker executing our
    // parallel YAML load may also steal an unrelated analysis task that calls
    // capability_mapper() — re-entering this function on the same thread. Any lock
    // held across try_new() would therefore deadlock against itself.
    //
    // The solution: build with no locks at all. Multiple threads may build concurrently
    // on first startup (wasteful but correct). The write lock is held only for the
    // brief check-and-swap; the first writer wins and all others discard their copy.
    tracing::debug!(
        on_rayon_thread = rayon::current_thread_index().is_some(),
        "CapabilityMapper not yet initialized; building (no lock held)"
    );
    let mapper = Arc::new(CapabilityMapper::try_new()?);

    let mut guard = CAPABILITY_MAPPER.write();
    if let Some(ref existing) = *guard {
        // Another thread finished first; use their mapper.
        return Ok(existing.clone());
    }
    *guard = Some(mapper.clone());
    Ok(mapper)
}

/// Reload the global CapabilityMapper from trait definitions on disk.
///
/// Loads new traits into a temporary mapper first. Only if loading succeeds
/// does it swap the new mapper into the global slot. On failure the previous
/// mapper remains active and an error is returned.
pub fn reload_capability_mapper() -> Result<(usize, usize), String> {
    tracing::info!("Reloading CapabilityMapper from disk");

    if skip_traits_requested() {
        let mapper = CapabilityMapper::empty();
        let mut guard = CAPABILITY_MAPPER.write();
        *guard = Some(Arc::new(mapper));
        return Ok((0, 0));
    }

    let resolved = cleave::traits_repo::try_resolve()?;
    let path = resolved.as_path();

    let mapper = if path.is_dir() {
        CapabilityMapper::from_directory_with_options(
            path,
            CapabilityMapper::DEFAULT_MIN_HOSTILE_PRECISION,
            CapabilityMapper::DEFAULT_MIN_SUSPICIOUS_PRECISION,
            false,
            false,
        )
        .map_err(|e| format!("Failed to load traits from {}: {e:#}", resolved.display()))?
    } else if path.is_file() {
        CapabilityMapper::from_yaml_with_options(
            path,
            CapabilityMapper::DEFAULT_MIN_HOSTILE_PRECISION,
            CapabilityMapper::DEFAULT_MIN_SUSPICIOUS_PRECISION,
            false,
            false,
        )
        .map_err(|e| format!("Failed to load traits from {}: {e:#}", resolved.display()))?
    } else {
        return Err(format!(
            "Traits path does not exist: {}",
            resolved.display()
        ));
    };

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
    Ok((trait_count, composite_count))
}

/// Get or initialize the global YARA engine
pub(crate) fn yara_engine(enable_third_party: bool) -> Arc<YaraEngine> {
    let lock = if enable_third_party {
        &YARA_ENGINE_WITH_THIRD_PARTY
    } else {
        &YARA_ENGINE_BUILTIN_ONLY
    };

    // OnceLock::get_or_init blocks all concurrent callers on a single internal Mutex until
    // the first initializer completes. When multiple rayon threads reach analyze_bytes for the
    // first time simultaneously, they all converge here. The winner compiles YARA rules (30-60s
    // on first run without cache); every other thread is parked inside the stdlib OnceLock.
    // This is *not* a deadlock — rayon's work-stealing still services other tasks — but all
    // analysis threads are stalled until compilation finishes.
    if lock.get().is_none() {
        tracing::debug!(
            enable_third_party,
            on_rayon_thread = rayon::current_thread_index().is_some(),
            "YARA engine not yet initialized; this thread will block until compilation completes \
             (30-60s on first run without cache). Other threads contending on OnceLock are parked."
        );
    }

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
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use std::sync::{Mutex, OnceLock};

    fn test_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    #[test]
    fn test_capability_mapper_singleton() {
        let _guard = test_lock()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let _skip_guard = EnvVarGuard::set("CLEAVE_SKIP_TRAITS", "1");
        let _skip_guard_lower = EnvVarGuard::unset("cleave_SKIP_TRAITS");
        reload_capability_mapper().expect("reload empty mapper");
        let m1 = capability_mapper().expect("mapper should load");
        let m2 = capability_mapper().expect("mapper should load");
        // Same Arc instance
        assert!(Arc::ptr_eq(&m1, &m2));
    }

    /// RAII guard to restore an env var on drop (including panics).
    struct EnvVarGuard {
        key: &'static str,
        original: Option<String>,
    }

    impl EnvVarGuard {
        fn set(key: &'static str, value: impl AsRef<std::ffi::OsStr>) -> Self {
            let original = std::env::var(key).ok();
            std::env::set_var(key, value);
            Self { key, original }
        }

        fn unset(key: &'static str) -> Self {
            let original = std::env::var(key).ok();
            std::env::remove_var(key);
            Self { key, original }
        }
    }

    impl Drop for EnvVarGuard {
        fn drop(&mut self) {
            match &self.original {
                Some(v) => std::env::set_var(self.key, v),
                None => std::env::remove_var(self.key),
            }
        }
    }

    /// Verify that a failed reload preserves the previous mapper.
    ///
    /// Uses CLEAVE_TRAITS_DIR pointed at a temp directory containing invalid YAML.
    /// The reload should return Err and leave the previous global mapper intact.
    #[test]
    fn test_reload_rollback_on_bad_traits() {
        let _guard = test_lock()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let _skip_guard = EnvVarGuard::unset("CLEAVE_SKIP_TRAITS");
        let _skip_guard_lower = EnvVarGuard::unset("cleave_SKIP_TRAITS");

        let good = tempfile::tempdir().expect("create tempdir");
        std::fs::write(
            good.path().join("good.yaml"),
            r#"
defaults:
  for: [all]

traits:
  - id: "test/simple::basic"
    desc: "Basic test trait"
    crit: baseline
    if:
      type: string_value
      substr: "test_pattern"
"#,
        )
        .expect("write good yaml");

        // Seed the global mapper from a known-good temp traits dir so this test
        // does not depend on any developer-local traits checkout.
        let good_guard = EnvVarGuard::set("CLEAVE_TRAITS_DIR", good.path());
        reload_capability_mapper().expect("load good traits");

        let before = capability_mapper().expect("mapper before bad reload");
        let before_traits = before.trait_definitions_count();

        // Point CLEAVE_TRAITS_DIR at a nonexistent directory and attempt reload.
        // EnvVarGuard restores the original value on drop (including panics).
        let bad_path = good.path().join("missing-traits-dir");
        let _guard = EnvVarGuard::set("CLEAVE_TRAITS_DIR", &bad_path);

        let result = reload_capability_mapper();

        // Reload should have failed
        assert!(result.is_err(), "Expected reload to fail with bad YAML");

        // The global mapper should still be the same instance with the same trait count
        let after = capability_mapper().expect("mapper after bad reload");
        assert_eq!(
            after.trait_definitions_count(),
            before_traits,
            "Trait count should be unchanged after failed reload"
        );
        assert!(
            Arc::ptr_eq(&before, &after),
            "Global mapper should be the same Arc after failed reload"
        );

        drop(good_guard);
    }
}
