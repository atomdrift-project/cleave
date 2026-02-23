//! Helper functions for Java class analysis.

#[allow(dead_code)] // Used by tests
impl super::JavaClassAnalyzer {
    pub(super) fn major_to_java_version(major: u16) -> String {
        match major {
            45 => "1.1".to_string(),
            46 => "1.2".to_string(),
            47 => "1.3".to_string(),
            48 => "1.4".to_string(),
            49 => "5".to_string(),
            50 => "6".to_string(),
            51 => "7".to_string(),
            52 => "8".to_string(),
            53 => "9".to_string(),
            54 => "10".to_string(),
            55 => "11".to_string(),
            56 => "12".to_string(),
            57 => "13".to_string(),
            58 => "14".to_string(),
            59 => "15".to_string(),
            60 => "16".to_string(),
            61 => "17".to_string(),
            62 => "18".to_string(),
            63 => "19".to_string(),
            64 => "20".to_string(),
            65 => "21".to_string(),
            _ => format!("{}", major - 44),
        }
    }

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

    /// Format a Java type descriptor into human-readable form
    fn format_type_descriptor(&self, desc: &str) -> String {
        let mut chars = desc.chars().peekable();
        self.parse_type_descriptor(&mut chars)
    }

    fn parse_type_descriptor<'a>(
        &self,
        chars: &mut std::iter::Peekable<std::str::Chars<'a>>,
    ) -> String {
        match chars.next() {
            Some('B') => "byte".to_string(),
            Some('C') => "char".to_string(),
            Some('D') => "double".to_string(),
            Some('F') => "float".to_string(),
            Some('I') => "int".to_string(),
            Some('J') => "long".to_string(),
            Some('S') => "short".to_string(),
            Some('Z') => "boolean".to_string(),
            Some('V') => "void".to_string(),
            Some('[') => format!("{}[]", self.parse_type_descriptor(chars)),
            Some('L') => {
                let mut class_name = String::new();
                while let Some(&c) = chars.peek() {
                    if c == ';' {
                        chars.next();
                        break;
                    }
                    if let Some(ch) = chars.next() {
                        class_name.push(ch);
                    }
                }
                class_name.replace('/', ".")
            }
            _ => "unknown".to_string(),
        }
    }

    /// Format a method signature into human-readable form
    fn format_method_signature(&self, name: &str, desc: &str) -> String {
        let mut chars = desc.chars().peekable();

        // Skip opening paren
        if chars.next() != Some('(') {
            return format!("{}()", name);
        }

        let mut params = Vec::new();
        while chars.peek() != Some(&')') && chars.peek().is_some() {
            params.push(self.parse_type_descriptor(&mut chars));
        }
        chars.next(); // Skip ')'

        let return_type = self.parse_type_descriptor(&mut chars);
        format!("{} {}({})", return_type, name, params.join(", "))
    }

    /// Count parameters from method descriptor
    fn count_parameters(&self, desc: &str) -> u32 {
        let mut chars = desc.chars().peekable();
        if chars.next() != Some('(') {
            return 0;
        }

        let mut count = 0;
        while chars.peek() != Some(&')') && chars.peek().is_some() {
            // Skip array dimensions
            while chars.peek() == Some(&'[') {
                chars.next();
            }
            match chars.peek() {
                Some('L') => {
                    // Object type - skip until ';'
                    while chars.next() != Some(';') {}
                    count += 1;
                }
                Some('B' | 'C' | 'D' | 'F' | 'I' | 'J' | 'S' | 'Z') => {
                    chars.next();
                    count += 1;
                }
                _ => break,
            }
        }
        count
    }
}
