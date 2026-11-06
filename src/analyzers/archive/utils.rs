//! Utility functions for archive analysis.

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

    main_class_from_manifest(&std::fs::read(&manifest_path).ok()?)
}

/// The `Main-Class:` of a JAR manifest. The manifest comes from the archive,
/// so a line that is not UTF-8 must not hide the lines after it.
pub(crate) fn main_class_from_manifest(manifest: &[u8]) -> Option<String> {
    manifest.split(|&b| b == b'\n').find_map(|line| {
        let line = String::from_utf8_lossy(line);
        line.strip_prefix("Main-Class:")
            .map(|class| class.trim().to_string())
    })
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
    fn main_class_survives_a_non_utf8_manifest_line() {
        let manifest =
            b"Manifest-Version: 1.0\r\nCreated-By: \xff\xfe\r\nMain-Class: evil.Loader\r\n";
        assert_eq!(
            main_class_from_manifest(manifest).as_deref(),
            Some("evil.Loader")
        );
    }

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
