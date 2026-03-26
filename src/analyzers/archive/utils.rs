//! Utility functions for archive analysis.

use std::fs::File;
use std::io::{BufRead, BufReader, Read};
use std::path::Path;

/// Calculate SHA256 hash of data
pub(crate) fn calculate_sha256(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

/// Calculate SHA256 hash of a file
#[allow(dead_code)] // Used by binary target
pub(crate) fn calculate_file_sha256(path: &Path) -> std::io::Result<String> {
    use sha2::{Digest, Sha256};
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    std::io::copy(&mut file, &mut hasher)?;
    Ok(hex::encode(hasher.finalize()))
}

/// Extract main class from META-INF/MANIFEST.MF
pub(crate) fn find_main_class(temp_dir: &Path) -> Option<String> {
    let manifest_path = temp_dir.join("META-INF/MANIFEST.MF");
    if !manifest_path.exists() {
        return None;
    }

    let file = File::open(&manifest_path).ok()?;
    let reader = BufReader::new(file);

    for line in reader.lines().map_while(Result::ok) {
        if line.starts_with("Main-Class:") {
            return Some(line.trim_start_matches("Main-Class:").trim().to_string());
        }
    }
    None
}

/// Check if a path is from a known benign Java package (common libraries)
pub(crate) fn is_benign_java_path(path: &Path) -> bool {
    let path_str = path.to_string_lossy();
    // Skip common library packages
    path_str.contains("/com/google/")
        || path_str.contains("/org/apache/")
        || path_str.contains("/org/slf4j/")
        || path_str.contains("/org/json/")
        || path_str.contains("/org/xml/")
        || path_str.contains("/javax/")
        || path_str.contains("/org/w3c/")
        || path_str.contains("/org/bouncycastle/")
        || path_str.contains("/org/junit/")
        || path_str.contains("/org/mockito/")
        || path_str.contains("/com/fasterxml/")
        || path_str.contains("/org/gradle/")
        || path_str.contains("/org/jetbrains/")
        || path_str.contains("/kotlin/")
        || path_str.contains("/scala/")
        || path_str.contains("/io/netty/")
        || path_str.contains("/okhttp3/")
        || path_str.contains("/okio/")
        || path_str.contains("/com/squareup/")
        || path_str.contains("/org/springframework/")
        || path_str.contains("/ch/qos/")
        || path_str.contains("/org/hibernate/")
        || path_str.contains("/com/sun/")
        || path_str.contains("/sun/")
        || path_str.contains("/jdk/")
        || path_str.contains("/java/")
        || path_str.contains("/com/oracle/")
        || path_str.contains("/io/grpc/")
        || path_str.contains("/com/amazonaws/")
        || path_str.contains("/software/amazon/")
        || path_str.contains("/org/eclipse/")
        || path_str.contains("/groovy/")
        || path_str.contains("/org/codehaus/")
        || path_str.contains("/io/micrometer/")
        || path_str.contains("/org/reactivestreams/")
        || path_str.contains("/reactor/")
        || path_str.contains("/org/yaml/")
        || path_str.contains("/org/hamcrest/")
        || path_str.contains("/org/assertj/")
        || path_str.contains("/org/objectweb/")
        || path_str.contains("/net/bytebuddy/")
        || path_str.contains("/org/objenesis/")
        || path_str.contains("/antlr/")
        || path_str.contains("/org/antlr/")
        || path_str.contains("/org/checkerframework/")
        || path_str.contains("/META-INF/")
        || path_str.contains("/joptsimple/")
        || path_str.contains("/oshi/")
        || path_str.contains("/com/typesafe/")
        || path_str.contains("/io/prometheus/")
        || path_str.contains("/javassist/")
        || path_str.contains("/net/java/")
        || path_str.contains("/ibm/icu/")
        || path_str.contains("/com/ibm/")
}

fn ends_with_ci(path_bytes: &[u8], ext: &[u8]) -> bool {
    if path_bytes.len() < ext.len() {
        return false;
    }
    let suffix = &path_bytes[path_bytes.len() - ext.len()..];
    suffix.eq_ignore_ascii_case(ext)
}

/// Detect TAR compression type from file extension.
/// Returns Some("gzip"), Some("bzip2"), Some("xz"), Some("zstd"), or None for plain tar.
#[allow(dead_code)] // Used by binary target
pub(crate) fn detect_tar_compression(path: &Path) -> Option<String> {
    let path_str = path.to_string_lossy();
    let path_bytes = path_str.as_bytes();

    if ends_with_ci(path_bytes, b".tar.gz")
        || ends_with_ci(path_bytes, b".tgz")
        || ends_with_ci(path_bytes, b".crate")
        || ends_with_ci(path_bytes, b".apk")
    // Alpine APK (gzipped tar)
    {
        Some("gzip".to_string())
    } else if ends_with_ci(path_bytes, b".tar.bz2")
        || ends_with_ci(path_bytes, b".tbz2")
        || ends_with_ci(path_bytes, b".tbz")
    {
        Some("bzip2".to_string())
    } else if ends_with_ci(path_bytes, b".tar.xz") || ends_with_ci(path_bytes, b".txz") {
        Some("xz".to_string())
    } else if ends_with_ci(path_bytes, b".tar.zst")
        || ends_with_ci(path_bytes, b".tzst")
        || ends_with_ci(path_bytes, b".xbps")
    {
        Some("zstd".to_string())
    } else {
        None
    }
}

/// Detect archive type from file extension
pub(crate) fn detect_archive_type(path: &Path) -> &'static str {
    let path_str = path.to_string_lossy();
    let path_bytes = path_str.as_bytes();

    // Arch Linux packages (must check before generic .tar.* patterns)
    if ends_with_ci(path_bytes, b".pkg.tar.zst") {
        return "tar.zst";
    } else if ends_with_ci(path_bytes, b".pkg.tar.xz") {
        return "tar.xz";
    } else if ends_with_ci(path_bytes, b".pkg.tar.gz") {
        return "tar.gz";
    }

    if ends_with_ci(path_bytes, b".tar.gz") {
        "tar.gz"
    } else if ends_with_ci(path_bytes, b".tgz") {
        "tgz"
    } else if ends_with_ci(path_bytes, b".tar.bz2") {
        "tar.bz2"
    } else if ends_with_ci(path_bytes, b".tbz2") || ends_with_ci(path_bytes, b".tbz") {
        "tbz"
    } else if ends_with_ci(path_bytes, b".tar.xz") {
        "tar.xz"
    } else if ends_with_ci(path_bytes, b".txz") {
        "txz"
    } else if ends_with_ci(path_bytes, b".tar.zst") || ends_with_ci(path_bytes, b".tzst") {
        "tar.zst"
    } else if ends_with_ci(path_bytes, b".xbps") {
        // Void Linux packages - zstd-compressed tar
        "tar.zst"
    } else if ends_with_ci(path_bytes, b".tar") {
        "tar"
    } else if ends_with_ci(path_bytes, b".zip")
        || ends_with_ci(path_bytes, b".jar")
        || ends_with_ci(path_bytes, b".war")
        || ends_with_ci(path_bytes, b".ear")
        || ends_with_ci(path_bytes, b".aar")
        || ends_with_ci(path_bytes, b".egg")
        || ends_with_ci(path_bytes, b".whl")
        || ends_with_ci(path_bytes, b".phar")
        || ends_with_ci(path_bytes, b".nupkg")
        || ends_with_ci(path_bytes, b".vsix")
        || ends_with_ci(path_bytes, b".xpi")
        || ends_with_ci(path_bytes, b".ipa")
        || ends_with_ci(path_bytes, b".epub")
    {
        "zip"
    } else if ends_with_ci(path_bytes, b".apk") {
        // Could be Android APK (zip) or Alpine APK (tar.gz)
        // Default to "apk", use detect_archive_type_with_magic to resolve
        "apk"
    } else if ends_with_ci(path_bytes, b".crx") {
        "crx"
    } else if ends_with_ci(path_bytes, b".7z") {
        "7z"
    } else if ends_with_ci(path_bytes, b".gem") {
        "tar"
    } else if ends_with_ci(path_bytes, b".crate") {
        "tar.gz"
    } else if ends_with_ci(path_bytes, b".xz") {
        "xz"
    } else if ends_with_ci(path_bytes, b".gz") {
        "gz"
    } else if ends_with_ci(path_bytes, b".zst") {
        "zst"
    } else if ends_with_ci(path_bytes, b".bz2") {
        "bz2"
    } else if ends_with_ci(path_bytes, b".deb") {
        "deb"
    } else if ends_with_ci(path_bytes, b".rpm") {
        "rpm"
    } else if ends_with_ci(path_bytes, b".pkg") {
        // Could be macOS PKG (xar) or FreeBSD pkg (tar.xz)
        // Default to "pkg", use detect_archive_type_with_magic to resolve
        "pkg"
    } else if ends_with_ci(path_bytes, b".rar") {
        "rar"
    } else if ends_with_ci(path_bytes, b".cab") {
        "cab"
    } else {
        "unknown"
    }
}

/// Detect archive type using magic bytes for ambiguous extensions.
/// Call this when extension-based detection returns "apk" or "pkg".
pub(crate) fn detect_archive_type_with_magic(path: &Path) -> std::io::Result<&'static str> {
    let extension_type = detect_archive_type(path);

    // Only check magic for ambiguous types
    match extension_type {
        "apk" => {
            // Alpine APK: gzip (0x1f 0x8b) - tar.gz
            // Android APK: ZIP (PK\x03\x04)
            let mut file = File::open(path)?;
            let mut magic = [0u8; 4];
            file.read_exact(&mut magic)?;

            if magic[0..2] == [0x1f, 0x8b] {
                Ok("tar.gz") // Alpine APK
            } else {
                Ok("zip") // Android APK (default)
            }
        }
        "pkg" => {
            // macOS PKG: XAR ("xar!" at offset 0)
            // FreeBSD pkg: usually starts with xz or zstd magic
            let mut file = File::open(path)?;
            let mut magic = [0u8; 6];
            file.read_exact(&mut magic)?;

            if &magic[0..4] == b"xar!" {
                Ok("pkg") // macOS XAR package
            } else if magic[0..2] == [0xfd, 0x37] {
                // XZ magic - FreeBSD pkg (tar.xz)
                Ok("tar.xz")
            } else if magic[0..4] == [0x28, 0xb5, 0x2f, 0xfd] {
                // Zstd magic - FreeBSD pkg (tar.zst)
                Ok("tar.zst")
            } else {
                Ok("pkg") // Default to macOS
            }
        }
        other => Ok(other),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn test_detect_tar_compression_gem() {
        // Ruby .gem files are plain TAR (not gzipped)
        assert_eq!(detect_tar_compression(Path::new("rails.gem")), None);
        assert_eq!(detect_tar_compression(Path::new("RAILS.GEM")), None);
    }

    #[test]
    fn test_detect_tar_compression_crate() {
        // Rust .crate files are gzipped TAR
        assert_eq!(
            detect_tar_compression(Path::new("serde.crate")),
            Some("gzip".to_string())
        );
        assert_eq!(
            detect_tar_compression(Path::new("SERDE.CRATE")),
            Some("gzip".to_string())
        );
    }

    #[test]
    fn test_detect_tar_compression_variants() {
        // Plain TAR
        assert_eq!(detect_tar_compression(Path::new("archive.tar")), None);

        // Gzipped TAR
        assert_eq!(
            detect_tar_compression(Path::new("archive.tar.gz")),
            Some("gzip".to_string())
        );
        assert_eq!(
            detect_tar_compression(Path::new("archive.tgz")),
            Some("gzip".to_string())
        );

        // Bzip2 TAR
        assert_eq!(
            detect_tar_compression(Path::new("archive.tar.bz2")),
            Some("bzip2".to_string())
        );
        assert_eq!(
            detect_tar_compression(Path::new("archive.tbz2")),
            Some("bzip2".to_string())
        );

        // XZ TAR
        assert_eq!(
            detect_tar_compression(Path::new("archive.tar.xz")),
            Some("xz".to_string())
        );
        assert_eq!(
            detect_tar_compression(Path::new("archive.txz")),
            Some("xz".to_string())
        );

        // Zstd TAR
        assert_eq!(
            detect_tar_compression(Path::new("archive.tar.zst")),
            Some("zstd".to_string())
        );
        assert_eq!(
            detect_tar_compression(Path::new("archive.tzst")),
            Some("zstd".to_string())
        );
    }
}
