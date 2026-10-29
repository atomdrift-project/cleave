//! The `CLEAVE_*` environment variables, read one way.
//!
//! Every boolean variable is read through [`flag`] or [`bool_var`] and every
//! numeric one through [`parse`], so `CLEAVE_X=0` means off everywhere and a
//! value that does not parse is logged instead of silently ignored.
//!
//! The variables fall into three groups:
//!
//! - **Configuration**: `CLEAVE_TRAITS_DIR`, `CLEAVE_CACHE_DIR`,
//!   `CLEAVE_LOG_LEVEL`, `CLEAVE_FORMAT`, `CLEAVE_NO_UPDATE_CHECK`,
//!   `CLEAVE_RAYON_THREADS`, `CLEAVE_SKIP_CACHE`, `CLEAVE_SKIP_MAPPER_CACHE`,
//!   `CLEAVE_SKIP_YARA_CACHE`, `CLEAVE_VALIDATE`, `CLEAVE_VALIDATE_SOFT`.
//! - **Diagnostics**: `CLEAVE_DEBUG_BACKTRACE`, `CLEAVE_TRAIT_TIMING`,
//!   `CLEAVE_TRAIT_TIMING_TOP`, `CLEAVE_PHASE_STATS`, `CLEAVE_PROFILE`,
//!   `CLEAVE_WARN_DEAD_ANY`, `CLEAVE_VALIDATE_FACTS`, `CLEAVE_SKIP_CLEAN_MARK`.
//! - **Tuning** (scheduling and memory knobs for large deployments and
//!   benchmarks; unstable, and may change or disappear in any release): the
//!   remaining `CLEAVE_*` variables read in this crate.
//!
//! Tests use `CLEAVE_SKIP_TRAITS`, `CLEAVE_SKIP_YARA`, `CLEAVE_BUILTIN_YARA_ONLY`
//! and `CLEAVE_UPDATE_URL` to run without the full rule set or network.

/// The boolean value of `name`: `None` when unset, otherwise
/// [`truthy`] of its value.
pub(crate) fn bool_var(name: &str) -> Option<bool> {
    let value = std::env::var(name).ok()?;
    let on = truthy(&value);
    if on.is_none() {
        tracing::warn!(
            variable = name,
            value,
            "unrecognized boolean; treating as false"
        );
    }
    Some(on.unwrap_or(false))
}

/// `1`/`true`/`yes`/`on` (any case) are true; `0`/`false`/`no`/`off` and
/// empty are false; anything else is `None`.
fn truthy(value: &str) -> Option<bool> {
    let value = value.trim();
    let is = |words: &[&str]| words.iter().any(|w| value.eq_ignore_ascii_case(w));
    if is(&["1", "true", "yes", "on"]) {
        Some(true)
    } else if value.is_empty() || is(&["0", "false", "no", "off"]) {
        Some(false)
    } else {
        None
    }
}

/// Whether `name` is set to a true value (see [`bool_var`]).
pub(crate) fn flag(name: &str) -> bool {
    bool_var(name).unwrap_or(false)
}

/// `name` parsed as `T`, or `None` when it is unset or does not parse (the
/// latter is logged).
pub(crate) fn parse<T: std::str::FromStr>(name: &str) -> Option<T> {
    let value = std::env::var(name).ok()?;
    let parsed = value.trim().parse().ok();
    if parsed.is_none() {
        tracing::warn!(
            variable = name,
            value,
            "unparsable value; using the default"
        );
    }
    parsed
}

#[cfg(test)]
mod tests {
    use super::truthy;

    #[test]
    fn zero_and_false_mean_off() {
        for (value, expected) in [
            ("1", Some(true)),
            ("TRUE", Some(true)),
            ("yes", Some(true)),
            ("0", Some(false)),
            ("false", Some(false)),
            ("", Some(false)),
            ("off", Some(false)),
            ("maybe", None),
        ] {
            assert_eq!(truthy(value), expected, "{value:?}");
        }
    }
}
