//! YAML deserialization, configured once.
//!
//! Only `true` and `false` are booleans. YAML 1.1 also reads `yes`, `no`,
//! `on`, `off`, `y` and `n` as booleans, but rule files use those words as
//! text (`exact: n`) and sample files must not change meaning with them.

/// Deserialize `input` as YAML.
pub(crate) fn from_str<'de, T: serde::Deserialize<'de>>(
    input: &'de str,
) -> Result<T, serde_saphyr::Error> {
    serde_saphyr::from_str_with_options(input, options())
}

/// Deserialize `input` as YAML.
pub(crate) fn from_slice<'de, T: serde::Deserialize<'de>>(
    input: &'de [u8],
) -> Result<T, serde_saphyr::Error> {
    serde_saphyr::from_slice_with_options(input, options())
}

fn options() -> serde_saphyr::Options {
    serde_saphyr::options! { strict_booleans: true }
}

#[cfg(test)]
mod tests {
    #[test]
    fn only_true_and_false_are_booleans() {
        let value: serde_json::Value = super::from_str("a: n\nb: off\nc: true").unwrap_or_default();
        assert_eq!(value["a"], "n");
        assert_eq!(value["b"], "off");
        assert_eq!(value["c"], true);
    }
}
