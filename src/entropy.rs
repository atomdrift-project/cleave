//! Entropy calculation for detecting obfuscation.
//!
//! High entropy sections often indicate encryption, compression, or packing.

/// Calculate Shannon entropy of a byte slice
///
/// Returns value between 0.0 (no entropy) and 8.0 (maximum entropy)
/// Typical values:
/// - < 4.0: Very low (sparse data, English text)
/// - 4.0-6.0: Normal (typical code/data)
/// - 6.0-7.2: Elevated (compressed or obfuscated)
/// - > 7.2: High (encrypted or packed)
pub(crate) fn calculate_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }

    let mut freq = [0usize; 256];
    for &byte in data {
        freq[byte as usize] += 1;
    }

    let len = data.len() as f64;
    freq.iter()
        .filter(|&&c| c > 0)
        .fold(0.0, |entropy, &count| {
            let p = count as f64 / len;
            entropy - p * p.log2()
        })
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
    fn test_zero_entropy() {
        let data = vec![0u8; 100];
        let entropy = calculate_entropy(&data);
        assert_eq!(entropy, 0.0);
    }

    #[test]
    fn test_max_entropy() {
        // Uniform distribution should have high entropy
        let data: Vec<u8> = (0..=255).collect();
        let entropy = calculate_entropy(&data);
        assert!(entropy > 7.5); // Close to theoretical max of 8.0
    }

    #[test]
    fn test_text_entropy() {
        let data = b"Hello, World! This is a test string with some text.";
        let entropy = calculate_entropy(data);
        assert!(entropy > 3.0 && entropy < 6.0); // English text typically 4-5 bits
    }

    #[test]
    fn test_entropy_classification() {
        assert_eq!(EntropyLevel::from_value(2.5), EntropyLevel::VeryLow);
        assert_eq!(EntropyLevel::from_value(5.0), EntropyLevel::Normal);
        assert_eq!(EntropyLevel::from_value(6.5), EntropyLevel::Elevated);
        assert_eq!(EntropyLevel::from_value(7.5), EntropyLevel::High);
    }

    #[test]
    fn test_empty_data() {
        let data = vec![];
        let entropy = calculate_entropy(&data);
        assert_eq!(entropy, 0.0);
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

    #[test]
    fn test_entropy_with_repeating_pattern() {
        let data = vec![0xAA, 0xBB, 0xAA, 0xBB, 0xAA, 0xBB]; // Alternating pattern
        let entropy = calculate_entropy(&data);
        assert!(entropy > 0.9 && entropy < 1.1); // Should be close to 1.0 (2 equally likely values)
    }
}
