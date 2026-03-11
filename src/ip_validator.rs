//! IP address validation for detecting external IPs.
//!
//! Provides validation to filter out IPs that are not useful for malware detection:
//! - Private ranges (10.x, 172.16-31.x, 192.168.x)
//! - Loopback (127.x)
//! - Link-local (169.254.x)
//! - Multicast and reserved ranges
//! - Version-like patterns (1.2.3.4)
//! - Invalid string formats (leading zeros like 010.001.001.001)

use std::net::Ipv4Addr;
use std::sync::OnceLock;

/// Regex pattern to find IP-like strings in text.
/// Matches any sequence of digits separated by dots (will be validated later).
#[allow(clippy::unwrap_used)] // Static regex pattern is hardcoded and valid
fn ip_pattern() -> &'static regex::Regex {
    static PATTERN: OnceLock<regex::Regex> = OnceLock::new();
    PATTERN.get_or_init(|| {
        regex::Regex::new(r"\b([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\b").unwrap()
    })
}

/// Check if a parsed IPv4 address is external (external, routable, potentially C2).
///
/// Returns false for:
/// - Private ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
/// - Loopback (127.0.0.0/8)
/// - Link-local (169.254.0.0/16)
/// - Multicast (224.0.0.0/4)
/// - Reserved (240.0.0.0/4)
/// - Documentation ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24)
/// - Version-like (first octet 0-3)
/// - IPs with 2+ zero octets
#[must_use]
pub(crate) fn is_external_ip(ip: &Ipv4Addr) -> bool {
    let octets = ip.octets();

    // Reject if two or more octets are zero (likely garbage data)
    let zero_count = octets.iter().filter(|&&x| x == 0).count();
    if zero_count >= 2 {
        return false;
    }

    // Reject all 0xFF (255.255.255.255)
    if octets.iter().all(|&x| x == 0xFF) {
        return false;
    }

    // Reject loopback (127.0.0.0/8)
    if octets[0] == 127 {
        return false;
    }

    // Reject private ranges - these are not external C2 indicators
    // 10.0.0.0/8
    if octets[0] == 10 {
        return false;
    }
    // 172.16.0.0/12
    if octets[0] == 172 && (16..=31).contains(&octets[1]) {
        return false;
    }
    // 192.168.0.0/16
    if octets[0] == 192 && octets[1] == 168 {
        return false;
    }

    // Reject link-local (169.254.0.0/16)
    if octets[0] == 169 && octets[1] == 254 {
        return false;
    }

    // Reject multicast (224.0.0.0/4)
    if octets[0] >= 224 && octets[0] <= 239 {
        return false;
    }

    // Reject reserved (240.0.0.0/4 and above, except broadcast)
    if octets[0] >= 240 {
        return false;
    }

    // Reject common test/documentation ranges
    // 192.0.2.0/24 (TEST-NET-1), 198.51.100.0/24 (TEST-NET-2), 203.0.113.0/24 (TEST-NET-3)
    if (octets[0] == 192 && octets[1] == 0 && octets[2] == 2)
        || (octets[0] == 198 && octets[1] == 51 && octets[2] == 100)
        || (octets[0] == 203 && octets[1] == 0 && octets[2] == 113)
    {
        return false;
    }

    // Reject IPs that look like version strings (low first octet often indicates
    // misinterpreted data, e.g., 1.2.3.4 could be version "1.2.3.4")
    if octets[0] <= 3 {
        return false;
    }

    // Reject IPs ending in .1.1 - these are almost always version numbers
    // (e.g., "7.18.1.1" looks like version 7.18.1.1, not a real C2 server)
    if octets[2] == 1 && octets[3] == 1 {
        return false;
    }

    // Reject IPs ending in .0.0 - often padding/garbage
    if octets[2] == 0 && octets[3] == 0 {
        return false;
    }

    // Reject IPs ending in .0.1 - often version strings or test data
    if octets[2] == 0 && octets[3] == 1 {
        return false;
    }

    true
}


/// Parse a single decimal octet without going through `str::parse`.
/// Returns `None` for empty strings, leading zeros, or values > 255.
fn parse_octet_fast(s: &str) -> Option<u8> {
    let b = s.as_bytes();
    match b.len() {
        0 => None,
        1 => {
            let d = b[0].wrapping_sub(b'0');
            if d <= 9 { Some(d) } else { None }
        }
        2 => {
            // Leading zero check
            if b[0] == b'0' {
                return None;
            }
            let d0 = b[0].wrapping_sub(b'0');
            let d1 = b[1].wrapping_sub(b'0');
            if d0 <= 9 && d1 <= 9 {
                Some(d0 * 10 + d1)
            } else {
                None
            }
        }
        3 => {
            // Leading zero check
            if b[0] == b'0' {
                return None;
            }
            let d0 = b[0].wrapping_sub(b'0');
            let d1 = b[1].wrapping_sub(b'0');
            let d2 = b[2].wrapping_sub(b'0');
            if d0 <= 9 && d1 <= 9 && d2 <= 9 {
                let v = d0 as u16 * 100 + d1 as u16 * 10 + d2 as u16;
                if v <= 255 { Some(v as u8) } else { None }
            } else {
                None
            }
        }
        _ => None,
    }
}

/// Validate an IP address string and check if it's an external IP.
///
/// This combines format validation (no leading zeros) with semantic validation
/// (not private/loopback/reserved).
///
/// Returns Some(Ipv4Addr) if the IP is valid and external, None otherwise.
#[must_use]
pub(crate) fn validate_external_ip_string(ip_str: &str) -> Option<Ipv4Addr> {
    // Parse all four octets inline using split('.') without collecting to Vec
    let mut octets = [0u8; 4];
    let mut parts = ip_str.split('.');
    for octet in &mut octets {
        *octet = parse_octet_fast(parts.next()?)?;
    }
    // Reject if there are extra parts
    if parts.next().is_some() {
        return None;
    }

    let ip = Ipv4Addr::new(octets[0], octets[1], octets[2], octets[3]);

    if is_external_ip(&ip) {
        Some(ip)
    } else {
        None
    }
}

/// Check if a text string contains at least one external IP address.
///
/// This is the main entry point for the `external_ip: true` condition modifier.
/// It finds all IP-like patterns in the text and returns true if any of them
/// are valid external IPs.
#[must_use]
pub(crate) fn contains_external_ip(text: &str) -> bool {
    // Fast reject: no dots means no IPs possible
    if memchr::memchr(b'.', text.as_bytes()).is_none() {
        return false;
    }
    // Use find_iter instead of captures_iter — we only need the full match
    for m in ip_pattern().find_iter(text) {
        if validate_external_ip_string(m.as_str()).is_some() {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_external_ip_public() {
        // Public IPs should be external
        assert!(is_external_ip(&Ipv4Addr::new(8, 8, 8, 8)));
        assert!(is_external_ip(&Ipv4Addr::new(45, 33, 32, 156)));
        assert!(is_external_ip(&Ipv4Addr::new(104, 16, 132, 229)));
    }

    #[test]
    fn test_external_ip_common_dns_servers() {
        // Common public DNS servers should be detected as external
        // Google DNS - most commonly seen in malware C2
        assert!(is_external_ip(&Ipv4Addr::new(8, 8, 8, 8)));
        assert!(is_external_ip(&Ipv4Addr::new(8, 8, 4, 4)));
        // Quad9 DNS
        assert!(is_external_ip(&Ipv4Addr::new(9, 9, 9, 9)));
        // OpenDNS
        assert!(is_external_ip(&Ipv4Addr::new(208, 67, 222, 222)));
        assert!(is_external_ip(&Ipv4Addr::new(208, 67, 220, 220)));

        // Note: Cloudflare DNS (1.1.1.1, 1.0.0.1) is rejected because first octet <= 3
        // filters version-like strings. This is an acceptable trade-off since:
        // 1. Version strings like "1.2.3.4" are very common false positives
        // 2. Google DNS (8.8.8.8) is far more commonly seen in malware
        assert!(!is_external_ip(&Ipv4Addr::new(1, 1, 1, 1)));
        assert!(!is_external_ip(&Ipv4Addr::new(1, 0, 0, 1)));
    }

    #[test]
    fn test_external_ip_private_rejected() {
        // Private ranges should be rejected
        assert!(!is_external_ip(&Ipv4Addr::new(192, 168, 1, 1)));
        assert!(!is_external_ip(&Ipv4Addr::new(192, 168, 0, 1)));
        assert!(!is_external_ip(&Ipv4Addr::new(10, 0, 0, 1)));
        assert!(!is_external_ip(&Ipv4Addr::new(10, 255, 255, 255)));
        assert!(!is_external_ip(&Ipv4Addr::new(172, 16, 0, 1)));
        assert!(!is_external_ip(&Ipv4Addr::new(172, 31, 255, 255)));
    }

    #[test]
    fn test_external_ip_loopback_rejected() {
        assert!(!is_external_ip(&Ipv4Addr::new(127, 0, 0, 1)));
        assert!(!is_external_ip(&Ipv4Addr::new(127, 255, 255, 255)));
    }

    #[test]
    fn test_external_ip_link_local_rejected() {
        assert!(!is_external_ip(&Ipv4Addr::new(169, 254, 0, 1)));
        assert!(!is_external_ip(&Ipv4Addr::new(169, 254, 255, 255)));
    }

    #[test]
    fn test_external_ip_multicast_rejected() {
        assert!(!is_external_ip(&Ipv4Addr::new(224, 0, 0, 1)));
        assert!(!is_external_ip(&Ipv4Addr::new(239, 255, 255, 255)));
    }

    #[test]
    fn test_external_ip_reserved_rejected() {
        assert!(!is_external_ip(&Ipv4Addr::new(240, 0, 0, 1)));
        assert!(!is_external_ip(&Ipv4Addr::new(255, 255, 255, 255)));
    }

    #[test]
    fn test_external_ip_two_zero_octets_rejected() {
        // Two zero octets should be rejected (likely garbage)
        assert!(!is_external_ip(&Ipv4Addr::new(8, 8, 0, 0)));
        assert!(!is_external_ip(&Ipv4Addr::new(192, 0, 0, 1)));
        assert!(!is_external_ip(&Ipv4Addr::new(0, 0, 8, 8)));
    }

    #[test]
    fn test_external_ip_version_like_rejected() {
        // Low first octet (version-like) should be rejected
        assert!(!is_external_ip(&Ipv4Addr::new(1, 2, 3, 4)));
        assert!(!is_external_ip(&Ipv4Addr::new(2, 0, 0, 1)));
        assert!(!is_external_ip(&Ipv4Addr::new(3, 14, 159, 26)));
    }

    #[test]
    fn test_external_ip_documentation_rejected() {
        // TEST-NET ranges should be rejected
        assert!(!is_external_ip(&Ipv4Addr::new(192, 0, 2, 1)));
        assert!(!is_external_ip(&Ipv4Addr::new(198, 51, 100, 1)));
        assert!(!is_external_ip(&Ipv4Addr::new(203, 0, 113, 1)));
    }

    #[test]
    fn test_parse_octet_fast() {
        assert_eq!(parse_octet_fast("0"), Some(0));
        assert_eq!(parse_octet_fast("1"), Some(1));
        assert_eq!(parse_octet_fast("10"), Some(10));
        assert_eq!(parse_octet_fast("100"), Some(100));
        assert_eq!(parse_octet_fast("255"), Some(255));
        assert_eq!(parse_octet_fast("256"), None);

        // Leading zeros should be rejected
        assert_eq!(parse_octet_fast("00"), None);
        assert_eq!(parse_octet_fast("01"), None);
        assert_eq!(parse_octet_fast("010"), None);
        assert_eq!(parse_octet_fast("001"), None);
    }

    #[test]
    fn test_validate_external_ip_string() {
        // Valid external IP
        assert!(validate_external_ip_string("8.8.8.8").is_some());
        assert!(validate_external_ip_string("45.33.32.156").is_some());

        // Private IPs - valid format but not external
        assert!(validate_external_ip_string("192.168.1.1").is_none());
        assert!(validate_external_ip_string("10.0.0.1").is_none());

        // Leading zeros - invalid format
        assert!(validate_external_ip_string("010.001.001.001").is_none());
        assert!(validate_external_ip_string("8.08.8.8").is_none());
        assert!(validate_external_ip_string("192.168.01.1").is_none());

        // Invalid octets (> 255)
        assert!(validate_external_ip_string("256.1.1.1").is_none());
        assert!(validate_external_ip_string("8.8.8.999").is_none());

        // Not an IP
        assert!(validate_external_ip_string("not.an.ip.address").is_none());
        assert!(validate_external_ip_string("1.2.3").is_none());
        assert!(validate_external_ip_string("1.2.3.4.5").is_none());
    }

    #[test]
    fn test_contains_external_ip() {
        // URLs with external IPs
        assert!(contains_external_ip("http://45.33.32.156/malware"));
        assert!(contains_external_ip("ftp://8.8.8.8:21/file"));
        assert!(contains_external_ip("target=104.16.132.229"));

        // URLs with private IPs - should not match
        assert!(!contains_external_ip("http://192.168.1.1/admin"));
        assert!(!contains_external_ip("http://10.0.0.1/internal"));
        assert!(!contains_external_ip("http://127.0.0.1/localhost"));

        // Leading zeros - should not match
        assert!(!contains_external_ip("http://010.001.001.001/"));

        // No IP at all
        assert!(!contains_external_ip("http://example.com/path"));
        assert!(!contains_external_ip("just some text"));

        // Mixed content - should find the external IP
        assert!(contains_external_ip(
            "Server at 192.168.1.1, forwarding to 45.33.32.156"
        ));
    }

    #[test]
    fn test_leading_zeros_rejected() {
        // IP-like strings with leading zeros in octets should be rejected
        // These often appear when binary data is misinterpreted as ASCII
        assert!(!contains_external_ip("010.011.012.012"));
        assert!(!contains_external_ip("25.01.31.01"));
        assert!(!contains_external_ip("http://010.020.030.040/"));

        // Valid IPs (no leading zeros) should be accepted
        assert!(contains_external_ip("70.11.49.4")); // Valid external IP
        assert!(contains_external_ip("25.1.31.1")); // Valid external IP
    }
}
