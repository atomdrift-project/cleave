//! Helper functions for Java class analysis.

impl super::JavaClassAnalyzer {
    pub(super) fn is_interesting_string(&self, s: &str) -> bool {
        // Filter out very short strings and common Java internal strings
        if s.len() < 4 {
            return false;
        }

        // Skip common Java internal strings
        if s.starts_with("()") || s.starts_with("(L") || s.starts_with("[L") {
            return false;
        }

        // Include URLs, paths, commands, etc.
        if s.contains("http://")
            || s.contains("https://")
            || s.contains('/')
            || s.contains('\\')
            || s.contains(".exe")
            || s.contains(".dll")
            || s.contains(".jar")
            || s.contains("cmd")
            || s.contains("powershell")
            || s.contains("bash")
            || s.contains("password")
            || s.contains("secret")
            || s.contains("key")
            || s.contains("token")
            || s.contains("admin")
            || s.contains("root")
        {
            return true;
        }

        // Include strings that look like they contain meaningful text
        s.chars().filter(|c| c.is_alphabetic()).count() > 3
    }
}
