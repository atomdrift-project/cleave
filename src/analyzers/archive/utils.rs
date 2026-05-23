//! Utility functions for archive analysis.

use std::fs::File;
use std::io::{BufRead, BufReader};
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
    let raw = path.to_string_lossy().replace('\\', "/");
    let path_str = format!("/{}/", raw.trim_matches('/'));
    // Skip common library packages. The leading/trailing slashes make this
    // work for both extracted absolute paths and in-memory archive-relative
    // paths such as `com/google/Foo.class`.
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
        || path_str.contains("/meta-inf/")
        || path_str.contains("/joptsimple/")
        || path_str.contains("/oshi/")
        || path_str.contains("/com/typesafe/")
        || path_str.contains("/io/prometheus/")
        || path_str.contains("/javassist/")
        || path_str.contains("/net/java/")
        || path_str.contains("/ibm/icu/")
        || path_str.contains("/com/ibm/")
}
