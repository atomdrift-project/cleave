//! Shannon entropy for detecting obfuscation.
//!
//! High entropy sections often indicate encryption, compression, or packing.
//! filefacts computes whole-file and per-section entropy (`file.entropy` and
//! the section metrics); [`shannon`] covers cleave-produced bytes such as
//! archive members and decoded strings, and [`EntropyLevel`] classifies a
//! value into coarse bands.

/// Shannon entropy of `data` in bits per byte (0.0 for empty input).
pub(crate) fn shannon(data: &[u8]) -> f64 {
    let mut counts = [0usize; 256];
    for &byte in data {
        counts[usize::from(byte)] += 1;
    }
    let len = data.len() as f64;
    counts
        .iter()
        .filter(|&&count| count != 0)
        .map(|&count| {
            let p = count as f64 / len;
            -p * p.log2()
        })
        .sum()
}

/// Classify entropy level
#[derive(Debug, PartialEq)]
pub(crate) enum EntropyLevel {
    VeryLow,  // < 4.0
    Normal,   // 4.0-6.0
    Elevated, // 6.0-7.2
    High,     // > 7.2
}

impl EntropyLevel {
    pub(crate) fn from_value(entropy: f64) -> Self {
        if entropy < 4.0 {
            EntropyLevel::VeryLow
        } else if entropy < 6.0 {
            EntropyLevel::Normal
        } else if entropy < 7.2 {
            EntropyLevel::Elevated
        } else {
            EntropyLevel::High
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_entropy_classification() {
        assert_eq!(EntropyLevel::from_value(2.5), EntropyLevel::VeryLow);
        assert_eq!(EntropyLevel::from_value(5.0), EntropyLevel::Normal);
        assert_eq!(EntropyLevel::from_value(6.5), EntropyLevel::Elevated);
        assert_eq!(EntropyLevel::from_value(7.5), EntropyLevel::High);
    }

    #[test]
    fn test_entropy_boundary_conditions() {
        assert_eq!(EntropyLevel::from_value(3.99), EntropyLevel::VeryLow);
        assert_eq!(EntropyLevel::from_value(4.0), EntropyLevel::Normal);
        assert_eq!(EntropyLevel::from_value(5.99), EntropyLevel::Normal);
        assert_eq!(EntropyLevel::from_value(6.0), EntropyLevel::Elevated);
        assert_eq!(EntropyLevel::from_value(7.19), EntropyLevel::Elevated);
        assert_eq!(EntropyLevel::from_value(7.2), EntropyLevel::High);
    }
}
