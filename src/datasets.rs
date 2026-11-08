//! Named datasets: reviewed lists of strings that validators compare against.
//!
//! A trait names a dataset rather than restating its contents:
//! `is: {typo_of: top-npm-packages}`. Each dataset is a YAML file in
//! `src/datasets/`, embedded at compile time, with `entries` and, where a
//! check needs them, `lookalikes` -- established names close to an entry
//! that are not impostors. Keeping the lists here, as data, means one review
//! covers every trait that uses them and no trait repeats an exception.
//!
//! Adding a dataset is a new file plus one line in [`SOURCES`].

use std::collections::HashSet;
use std::fmt;
use std::sync::OnceLock;

/// Every dataset, by name, sorted by name.
const SOURCES: &[(&str, &str)] = &[
    ("abused-tlds", include_str!("datasets/abused-tlds.yaml")),
    (
        "top-npm-packages",
        include_str!("datasets/top-npm-packages.yaml"),
    ),
    (
        "top-pypi-packages",
        include_str!("datasets/top-pypi-packages.yaml"),
    ),
    (
        "trusted-fetch-hosts",
        include_str!("datasets/trusted-fetch-hosts.yaml"),
    ),
];

/// One dataset's contents.
#[derive(Debug, Default, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Contents {
    pub(crate) entries: HashSet<String>,
    #[serde(default)]
    pub(crate) lookalikes: HashSet<String>,
}

fn loaded() -> &'static [Contents] {
    static LOADED: OnceLock<Vec<Contents>> = OnceLock::new();
    LOADED.get_or_init(|| {
        SOURCES
            .iter()
            .map(|(name, text)| {
                crate::yaml::from_str(text).unwrap_or_else(|error| {
                    tracing::warn!(dataset = name, %error, "dataset unreadable; treating as empty");
                    Contents::default()
                })
            })
            .collect()
    })
}

/// A dataset, by its position in [`SOURCES`]. Resolved from its name when a
/// trait loads, so evaluation never looks a name up.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Dataset(u8);

impl Dataset {
    /// The dataset called `name`, if there is one.
    #[must_use]
    pub(crate) fn named(name: &str) -> Option<Self> {
        let index = SOURCES.binary_search_by_key(&name, |(n, _)| n).ok()?;
        u8::try_from(index).ok().map(Self)
    }

    /// The dataset's name.
    #[must_use]
    pub(crate) fn name(self) -> &'static str {
        SOURCES
            .get(usize::from(self.0))
            .map_or("", |(name, _)| name)
    }

    /// The dataset's contents.
    #[must_use]
    pub(crate) fn contents(self) -> &'static Contents {
        static EMPTY: OnceLock<Contents> = OnceLock::new();
        loaded()
            .get(usize::from(self.0))
            .unwrap_or_else(|| EMPTY.get_or_init(Contents::default))
    }

    fn known_names() -> String {
        SOURCES
            .iter()
            .map(|(name, _)| *name)
            .collect::<Vec<_>>()
            .join(", ")
    }
}

impl fmt::Display for Dataset {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

impl std::str::FromStr for Dataset {
    type Err = String;

    fn from_str(name: &str) -> Result<Self, Self::Err> {
        Self::named(name)
            .ok_or_else(|| format!("unknown dataset `{name}`; known: {}", Self::known_names()))
    }
}

impl serde::Serialize for Dataset {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.name())
    }
}

impl<'de> serde::Deserialize<'de> for Dataset {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let name = String::deserialize(deserializer)?;
        name.parse().map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn every_dataset_parses_and_is_sorted() {
        assert!(SOURCES.windows(2).all(|w| w[0].0 < w[1].0));
        for (name, text) in SOURCES {
            let contents: Contents =
                crate::yaml::from_str(text).unwrap_or_else(|e| panic!("{name}: {e}"));
            assert!(!contents.entries.is_empty(), "{name}");
            let dataset = Dataset::named(name).expect("named");
            assert_eq!(dataset.name(), *name);
            assert_eq!(dataset.contents().entries.len(), contents.entries.len());
        }
    }

    #[test]
    fn unknown_names_list_the_known_ones() {
        let err = "top-crates".parse::<Dataset>().unwrap_err();
        assert!(err.contains("top-npm-packages"), "{err}");
    }
}
