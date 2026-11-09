//! Shannon entropy for detecting obfuscation.
//!
//! filefacts computes whole-file and per-section entropy (`file.entropy` and
//! the section metrics); [`shannon`] covers cleave-produced bytes such as
//! archive members and decoded strings. Whether a value is high is for traits.

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shannon_is_bits_per_byte() {
        assert_eq!(shannon(b""), 0.0);
        assert_eq!(shannon(&[7u8; 64]), 0.0);
        let every_byte: Vec<u8> = (0..=255).collect();
        assert!((shannon(&every_byte) - 8.0).abs() < 1e-9);
        assert!((shannon(b"abab") - 1.0).abs() < 1e-9);
    }
}
