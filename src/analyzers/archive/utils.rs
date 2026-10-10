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

/// Package prefixes of common Java libraries, relative to a class root.
const BENIGN_JAVA_PREFIXES: &[&str] = &[
    "com/google/",
    "org/apache/",
    "org/slf4j/",
    "org/json/",
    "org/xml/",
    "javax/",
    "org/w3c/",
    "org/bouncycastle/",
    "org/junit/",
    "org/mockito/",
    "com/fasterxml/",
    "org/gradle/",
    "org/jetbrains/",
    "kotlin/",
    "scala/",
    "io/netty/",
    "okhttp3/",
    "okio/",
    "com/squareup/",
    "org/springframework/",
    "ch/qos/",
    "org/hibernate/",
    "com/sun/",
    "sun/",
    "jdk/",
    "java/",
    "com/oracle/",
    "io/grpc/",
    "com/amazonaws/",
    "software/amazon/",
    "org/eclipse/",
    "groovy/",
    "org/codehaus/",
    "io/micrometer/",
    "org/reactivestreams/",
    "reactor/",
    "org/yaml/",
    "org/hamcrest/",
    "org/assertj/",
    "org/objectweb/",
    "net/bytebuddy/",
    "org/objenesis/",
    "antlr/",
    "org/antlr/",
    "org/checkerframework/",
    "META-INF/",
    "meta-inf/",
    "joptsimple/",
    "oshi/",
    "com/typesafe/",
    "io/prometheus/",
    "javassist/",
    "net/java/",
    "ibm/icu/",
    "com/ibm/",
];

/// Check if a jar member is in a known benign Java package (common libraries).
///
/// `path` is relative to the jar root, and the package must begin the class
/// path: `x/java/Loader.class` is not `java/...`, so a payload cannot hide
/// from analysis by nesting itself under a library-looking directory.
pub(crate) fn is_benign_java_path(path: &Path) -> bool {
    let raw = path.to_string_lossy().replace('\\', "/");
    let raw = raw.trim_start_matches('/');
    // Spring Boot and WAR archives keep their own classes one level down.
    let class_path = ["BOOT-INF/classes/", "WEB-INF/classes/"]
        .iter()
        .find_map(|root| raw.strip_prefix(root))
        .unwrap_or(raw);
    BENIGN_JAVA_PREFIXES
        .iter()
        .any(|prefix| class_path.starts_with(prefix))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn benign_java_package_must_begin_the_class_path() {
        for benign in [
            "com/google/common/Foo.class",
            "java/lang/Bar.class",
            "META-INF/MANIFEST.MF",
            "BOOT-INF/classes/org/springframework/App.class",
            "WEB-INF/classes/org/apache/Servlet.class",
        ] {
            assert!(is_benign_java_path(Path::new(benign)), "{benign}");
        }
        for payload in [
            "x/java/Loader.class",
            "evil/com/google/Stage2.class",
            "a/b/META-INF/payload.bin",
            "Loader.class",
        ] {
            assert!(!is_benign_java_path(Path::new(payload)), "{payload}");
        }
    }
}
