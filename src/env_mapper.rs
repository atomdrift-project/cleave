//! Environment variable access tracking.
//!
//! Identifies environment variable access and categorizes by sensitivity.

use crate::types::*;

/// Extract environment variable access from strings and categorize them
#[must_use]
pub(crate) fn extract_envvars_from_strings(strings: &[StringInfo]) -> Vec<EnvVarInfo> {
    let mut env_vars = Vec::new();

    for string_info in strings {
        // Look for common environment variable names in strings
        if is_env_var_name(&string_info.value) {
            let env_var_info =
                analyze_env_var(&string_info.value, "strings", EnvVarAccessType::Unknown);
            env_vars.push(env_var_info);
        }
    }

    env_vars
}

/// Check if string looks like an environment variable name
fn is_env_var_name(s: &str) -> bool {
    // Must be uppercase letters, numbers, and underscores
    if s.is_empty() || s.len() > 100 {
        return false;
    }

    // Must be all uppercase with underscores or numbers
    let valid_chars = s
        .chars()
        .all(|c| c.is_ascii_uppercase() || c == '_' || c.is_ascii_digit());
    if !valid_chars {
        return false;
    }

    // Must not start with a digit
    if let Some(first) = s.chars().next() {
        if first.is_ascii_digit() {
            return false;
        }
    }

    // Check against known environment variables
    is_known_env_var(s)
}

/// Check if this is a known environment variable name
fn is_known_env_var(name: &str) -> bool {
    matches!(
        name,
        // Common system vars
        "PATH" | "HOME" | "USER" | "USERNAME" | "SHELL" | "TERM" | "HOSTNAME" |
        "PWD" | "OLDPWD" | "LOGNAME" | "DISPLAY" | "LANG" |

        // Temporary directories
        "TEMP" | "TMP" | "TMPDIR" | "TEMPDIR" |

        // Windows-specific
        "USERPROFILE" | "APPDATA" | "LOCALAPPDATA" | "PROGRAMFILES" |
        "SYSTEMROOT" | "WINDIR" | "COMSPEC" | "HOMEDRIVE" | "HOMEPATH" |

        // Runtime paths
        "LD_LIBRARY_PATH" | "LD_PRELOAD" | "DYLD_LIBRARY_PATH" |
        "DYLD_INSERT_LIBRARIES" | "DYLD_FORCE_FLAT_NAMESPACE" |
        "PYTHONPATH" | "PYTHONHOME" | "NODE_PATH" | "RUBYLIB" | "GOPATH" | "CLASSPATH" |

        // Platform-specific
        "ANDROID_ROOT" | "ANDROID_DATA" | "ANDROID_STORAGE" |

        // Network/proxy
        "http_proxy" | "https_proxy" | "HTTP_PROXY" | "HTTPS_PROXY" | "no_proxy" | "NO_PROXY" |
        "FTP_PROXY" | "ftp_proxy" | "ALL_PROXY" | "all_proxy" |

        // Editor/pager
        "EDITOR" | "VISUAL" | "PAGER" |

        // SSH
        "SSH_AUTH_SOCK" | "SSH_AGENT_PID" | "SSH_CONNECTION" | "SSH_CLIENT" | "SSH_TTY" |

        // Locale
        "LC_ALL" | "LC_CTYPE" | "LC_COLLATE" | "LC_TIME" | "LC_NUMERIC" |
        "LC_MONETARY" | "LC_MESSAGES" | "LANGUAGE"
    ) || name.starts_with("LC_") ||  // Locale variables
        // NOTE: Removed generic _TOKEN, _KEY, _SECRET, _PASSWORD suffixes.
        // These are too broad and match legitimate software constants like
        // INPUT_KEY, MODIFIER_KEY, ENCRYPTION_KEY (non-credential), etc.
        // Credential detection is now handled by is_credential_env_var() which
        // requires both a known provider prefix AND a sensitive suffix.
        name.starts_with("AWS_") ||   // AWS credentials
        name.starts_with("GITHUB_") || // GitHub tokens
        name.starts_with("DOCKER_") || // Docker config
        name.starts_with("KUBERNETES_") || // K8s config
        name.starts_with("CI_") ||    // CI/CD variables
        name.starts_with("JENKINS_") || // Jenkins
        name.starts_with("TRAVIS_") || // Travis CI
        name.starts_with("GITLAB_") || // GitLab CI
        name.starts_with("ANDROID_") // Android platform
}

/// Check if this looks like a credential environment variable
/// Be specific to avoid false positives on legitimate software
fn is_credential_env_var(name: &str) -> bool {
    // Known credential prefixes - high confidence
    let known_credential_prefixes = [
        "AWS_",
        "GITHUB_",
        "GH_",
        "GITLAB_",
        "AZURE_",
        "GOOGLE_",
        "DOCKER_",
        "NPM_",
        "PYPI_",
        "NUGET_",
        "ARTIFACTORY_",
        "SLACK_",
        "DISCORD_",
        "OPENAI_",
        "ANTHROPIC_",
        "STRIPE_",
        "TWILIO_",
        "SENDGRID_",
        "DATABASE_",
        "DB_",
        "REDIS_",
        "MONGO_",
        "POSTGRES_",
        "MYSQL_",
        "SONAR_",
        "SNYK_",
        "VAULT_",
        "HASHICORP_",
    ];

    // Check for known credential prefixes with sensitive suffixes
    for prefix in known_credential_prefixes {
        if name.starts_with(prefix) {
            // Any token/key/secret/password from known providers is a credential
            if name.ends_with("_TOKEN")
                || name.ends_with("_KEY")
                || name.ends_with("_SECRET")
                || name.ends_with("_PASSWORD")
                || name.ends_with("_CREDENTIALS")
                || name.ends_with("_AUTH")
                || name.contains("ACCESS_KEY")
                || name.contains("SECRET_KEY")
                || name.contains("API_KEY")
            {
                return true;
            }
        }
    }

    // Known specific credential variables
    // NOTE: Generic names like API_KEY, SECRET_KEY, etc. can appear in
    // legitimate binaries as protocol constants, debug strings, or config
    // parsing code. We only flag very specific service credentials.
    matches!(
        name,
        "SSH_PRIVATE_KEY"
            | "JWT_SECRET"
            | "SESSION_SECRET"
            | "COOKIE_SECRET"
            | "ROOT_PASSWORD"
            | "ADMIN_PASSWORD"
            | "SERVICE_ACCOUNT_KEY"
    )
}

/// Analyze a single environment variable and categorize it
fn analyze_env_var(name: &str, source: &str, access_type: EnvVarAccessType) -> EnvVarInfo {
    let category = classify_env_var_category(name);

    EnvVarInfo {
        name: name.to_string(),
        access_type,
        source: source.to_string(),
        category,
        evidence: vec![Evidence {
            method: "string_pattern".to_string(),
            source: source.to_string(),
            value: name.to_string(),
            location: None,
        }],
        referenced_by_traits: Vec::new(),
    }
}

/// Classify environment variable by semantic category
fn classify_env_var_category(name: &str) -> EnvVarCategory {
    // Credential/secret detection (highest priority)
    // Be specific to avoid false positives on graphics libs (DEPTH_TOKEN, SHADER_KEY, etc.)
    if is_credential_env_var(name) {
        return EnvVarCategory::Credential;
    }

    // Injection/evasion
    if name == "LD_PRELOAD"
        || name == "DYLD_INSERT_LIBRARIES"
        || name == "DYLD_FORCE_FLAT_NAMESPACE"
    {
        return EnvVarCategory::Injection;
    }

    // Path-related
    if name == "PATH"
        || name == "LD_LIBRARY_PATH"
        || name == "DYLD_LIBRARY_PATH"
        || name == "PYTHONPATH"
        || name == "NODE_PATH"
        || name == "RUBYLIB"
        || name == "GOPATH"
        || name == "CLASSPATH"
    {
        return EnvVarCategory::Path;
    }

    // User information
    if name == "USER"
        || name == "USERNAME"
        || name == "LOGNAME"
        || name == "HOME"
        || name == "USERPROFILE"
        || name == "HOMEDRIVE"
        || name == "HOMEPATH"
    {
        return EnvVarCategory::User;
    }

    // System information
    if name == "HOSTNAME"
        || name == "SHELL"
        || name == "TERM"
        || name == "PWD"
        || name == "OLDPWD"
        || name == "SYSTEMROOT"
        || name == "WINDIR"
    {
        return EnvVarCategory::System;
    }

    // Temporary directories
    if name == "TEMP" || name == "TMP" || name == "TMPDIR" || name == "TEMPDIR" {
        return EnvVarCategory::Temp;
    }

    // Display/UI
    if name == "DISPLAY" || name.starts_with("WAYLAND_") {
        return EnvVarCategory::Display;
    }

    // Runtime paths
    if name == "PYTHONHOME"
        || name.starts_with("PYTHON")
        || name.starts_with("NODE_")
        || name.starts_with("RUBY")
        || name.starts_with("GO")
        || name == "JAVA_HOME"
    {
        return EnvVarCategory::Runtime;
    }

    // Platform-specific
    if name.starts_with("ANDROID_") || name.starts_with("IOS_") {
        return EnvVarCategory::Platform;
    }

    // Locale
    if name == "LANG" || name == "LANGUAGE" || name.starts_with("LC_") {
        return EnvVarCategory::Locale;
    }

    // Network/proxy
    if name.contains("proxy") || name.contains("PROXY") {
        return EnvVarCategory::Network;
    }

    EnvVarCategory::Other
}

/// NOTE: All detections moved to YAML with composite rules + count_min:
/// - Credential harvesting: traits/objectives/credential-access/env/harvesting.yaml
/// - LD_PRELOAD/DYLD_INSERT_LIBRARIES: traits/objectives/evasion/library-injection/env/preload.yaml
/// - User discovery (>= 2 user vars): traits/objectives/discovery/env/user-discovery.yaml
/// - System discovery (>= 2 system vars): traits/objectives/discovery/env/system-discovery.yaml
/// - PATH manipulation: traits/objectives/persistence/env/path-manipulation.yaml
/// - Android platform: traits/objectives/discovery/platform/android-env.yaml
/// - Display check: traits/objectives/discovery/env/display-check.yaml
/// - SSH check: traits/objectives/anti-analysis/env/ssh-detection.yaml
#[must_use]
pub(crate) fn generate_traits_from_env_vars(_env_vars: &[EnvVarInfo]) -> Vec<Finding> {
    Vec::new()
}

/// Main entry point: analyze environment variables and link to traits
pub(crate) fn analyze_and_link_env_vars(report: &mut AnalysisReport) {
    // Step 1: Start with existing env_vars (from script analyzers like Python)
    // then add env vars extracted from strings
    let mut env_vars = report.env_vars.clone();
    env_vars.extend(extract_envvars_from_strings(&report.strings));

    // Step 2: Generate behavioral traits from patterns
    // NOTE: Basic env API detection (getenv, setenv, etc.) is now handled by YAML traits
    // in traits/micro-behaviors/os/env/vars/traits.yaml via symbol matching
    let new_traits = generate_traits_from_env_vars(&env_vars);

    // Step 3: Add back-references
    for trait_obj in &new_traits {
        // Mark env vars that contributed to this trait
        for env_var in &mut env_vars {
            if trait_obj.evidence.iter().any(|e| e.value == env_var.name) {
                env_var.referenced_by_traits.push(trait_obj.id.clone());
            }
        }
    }

    // Store results
    report.env_vars = env_vars;
    report.findings.extend(new_traits);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_env_var_name() {
        assert!(is_env_var_name("PATH"));
        assert!(is_env_var_name("HOME"));

        assert!(!is_env_var_name(""));
        assert!(!is_env_var_name("a")); // Too short
        assert!(!is_env_var_name("path")); // All lowercase
    }

    #[test]
    fn test_is_known_env_var() {
        // System paths
        assert!(is_known_env_var("PATH"));
        assert!(is_known_env_var("HOME"));
        assert!(is_known_env_var("TEMP"));

        // User info
        assert!(is_known_env_var("USER"));
        assert!(is_known_env_var("USERNAME"));

        // Shell vars
        assert!(is_known_env_var("SHELL"));
        assert!(is_known_env_var("TERM"));

        // Unknown
        assert!(!is_known_env_var("MY_CUSTOM_VAR"));
    }

    #[test]
    fn test_classify_env_var_category_path() {
        assert_eq!(classify_env_var_category("PATH"), EnvVarCategory::Path);
        assert_eq!(
            classify_env_var_category("LD_LIBRARY_PATH"),
            EnvVarCategory::Path
        );
    }

    #[test]
    fn test_classify_env_var_category_user() {
        assert_eq!(classify_env_var_category("HOME"), EnvVarCategory::User);
        assert_eq!(classify_env_var_category("USER"), EnvVarCategory::User);
        assert_eq!(classify_env_var_category("USERNAME"), EnvVarCategory::User);
    }

    #[test]
    fn test_classify_env_var_category_system() {
        assert_eq!(classify_env_var_category("SHELL"), EnvVarCategory::System);
        assert_eq!(classify_env_var_category("TERM"), EnvVarCategory::System);
        assert_eq!(classify_env_var_category("PWD"), EnvVarCategory::System);
    }

    #[test]
    fn test_classify_env_var_category_temp() {
        assert_eq!(classify_env_var_category("TEMP"), EnvVarCategory::Temp);
        assert_eq!(classify_env_var_category("TMP"), EnvVarCategory::Temp);
        assert_eq!(classify_env_var_category("TMPDIR"), EnvVarCategory::Temp);
    }

    #[test]
    fn test_classify_env_var_category_locale() {
        assert_eq!(classify_env_var_category("LANG"), EnvVarCategory::Locale);
        assert_eq!(classify_env_var_category("LC_ALL"), EnvVarCategory::Locale);
        assert_eq!(
            classify_env_var_category("LANGUAGE"),
            EnvVarCategory::Locale
        );
    }

    #[test]
    fn test_classify_env_var_category_network() {
        assert_eq!(
            classify_env_var_category("HTTP_PROXY"),
            EnvVarCategory::Network
        );
        assert_eq!(
            classify_env_var_category("HTTPS_PROXY"),
            EnvVarCategory::Network
        );
        assert_eq!(
            classify_env_var_category("NO_PROXY"),
            EnvVarCategory::Network
        );
    }

    #[test]
    fn test_classify_env_var_category_other() {
        assert_eq!(
            classify_env_var_category("MY_CUSTOM_VAR"),
            EnvVarCategory::Other
        );
        assert_eq!(
            classify_env_var_category("UNKNOWN_VAR"),
            EnvVarCategory::Other
        );
    }
}
