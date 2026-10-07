//! Bounded constant reconstruction for PowerShell character-table obfuscation.
//! Only literal arithmetic and explicit character joins are interpreted. No
//! PowerShell runtime, sample functions, or external resources are invoked.

use std::collections::HashMap;

use crate::{analyzers::FileType, types::ExtractedPayload};
use regex::Regex;

#[derive(Clone, Copy)]
struct Rational(i128, i128);

impl Rational {
    fn new(mut n: i128, mut d: i128) -> Option<Self> {
        if d == 0 {
            return None;
        }
        if d < 0 {
            n = n.checked_neg()?;
            d = d.checked_neg()?;
        }
        let (mut a, mut b) = (n.checked_abs()?, d);
        while b != 0 {
            (a, b) = (b, a % b);
        }
        Some(Self(n / a, d / a))
    }

    fn combine(self, rhs: Self, op: u8) -> Option<Self> {
        let Self(a, b) = self;
        let Self(c, d) = rhs;
        match op {
            b'+' => Self::new(
                a.checked_mul(d)?.checked_add(c.checked_mul(b)?)?,
                b.checked_mul(d)?,
            ),
            b'-' => Self::new(
                a.checked_mul(d)?.checked_sub(c.checked_mul(b)?)?,
                b.checked_mul(d)?,
            ),
            b'*' => Self::new(a.checked_mul(c)?, b.checked_mul(d)?),
            b'/' => Self::new(a.checked_mul(d)?, b.checked_mul(c)?),
            _ => None,
        }
    }
}

struct Arithmetic<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl Arithmetic<'_> {
    fn whitespace(&mut self) {
        while self
            .bytes
            .get(self.pos)
            .is_some_and(u8::is_ascii_whitespace)
        {
            self.pos += 1;
        }
    }

    fn expression(&mut self, depth: usize) -> Option<Rational> {
        let mut left = self.product(depth)?;
        loop {
            self.whitespace();
            let Some(&op @ (b'+' | b'-')) = self.bytes.get(self.pos) else {
                break;
            };
            self.pos += 1;
            left = left.combine(self.product(depth)?, op)?;
        }
        Some(left)
    }

    fn product(&mut self, depth: usize) -> Option<Rational> {
        let mut left = self.value(depth)?;
        loop {
            self.whitespace();
            let Some(&op @ (b'*' | b'/')) = self.bytes.get(self.pos) else {
                break;
            };
            self.pos += 1;
            left = left.combine(self.value(depth)?, op)?;
        }
        Some(left)
    }

    fn value(&mut self, depth: usize) -> Option<Rational> {
        if depth > 32 {
            return None;
        }
        self.whitespace();
        match *self.bytes.get(self.pos)? {
            b'+' | b'-' => {
                let negative = self.bytes[self.pos] == b'-';
                self.pos += 1;
                let Rational(n, d) = self.value(depth + 1)?;
                Some(Rational(if negative { n.checked_neg()? } else { n }, d))
            }
            b'(' => {
                self.pos += 1;
                let result = self.expression(depth + 1)?;
                self.whitespace();
                if self.bytes.get(self.pos) != Some(&b')') {
                    return None;
                }
                self.pos += 1;
                Some(result)
            }
            _ => {
                let mut n = 0i128;
                let mut d = 1i128;
                let mut decimal = false;
                let mut digits = 0;
                while let Some(&b) = self.bytes.get(self.pos) {
                    if b == b'.' && !decimal {
                        decimal = true;
                    } else if b.is_ascii_digit() {
                        n = n.checked_mul(10)?.checked_add(i128::from(b - b'0'))?;
                        if decimal {
                            d = d.checked_mul(10)?;
                        }
                        digits += 1;
                    } else {
                        break;
                    }
                    self.pos += 1;
                }
                if digits == 0 {
                    return None;
                }
                Rational::new(n, d)
            }
        }
    }
}

fn integer_literal(expression: &str) -> Option<i128> {
    let mut parser = Arithmetic {
        bytes: expression.as_bytes(),
        pos: 0,
    };
    let Rational(n, d) = parser.expression(0)?;
    parser.whitespace();
    (parser.pos == parser.bytes.len() && d == 1).then_some(n)
}

fn character_string(numbers: &str) -> Option<String> {
    if numbers.len() > 262_144 {
        return None;
    }
    let units = numbers
        .split(',')
        .map(|part| integer_literal(part).and_then(|n| u16::try_from(n).ok()))
        .collect::<Option<Vec<_>>>()?;
    if units.len() > 65_536 {
        return None;
    }
    String::from_utf16(&units).ok()
}

fn quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

pub(crate) fn extract_powershell_literal_payload(data: &[u8]) -> Option<ExtractedPayload> {
    if data.len() > 2 * 1024 * 1024 {
        return None;
    }
    let source = std::str::from_utf8(data).ok()?;
    let lower = source.to_ascii_lowercase();
    if !lower.contains("[char]") && !lower.contains("[char[]]") {
        return None;
    }
    let arithmetic = Regex::new(r"\(([0-9\s+*/.\-]{1,8192})\)").ok()?;
    let joined = Regex::new(r#"(?i)\[char\[\]\]\s*@\(([0-9,\s-]+)\)\s*-join\s*(?:''|"")"#).ok()?;
    let pipeline = Regex::new(
        r"(?i)-join\s*\(@\(([0-9,\s-]+)\)\s*\|\s*([\w-]+)\s*\{\s*\[char\]\s*\$_\s*\}\s*\)",
    )
    .ok()?;
    let alias = Regex::new(r"(?i)&\s*\(*'set-alias'\)*\s+(\w+)\s+\(*'([^']+)'\)*").ok()?;
    let type_alias = Regex::new(r"(?i)::Add\(\(*'([^']+)'\)*,\s*\[type\]\(*'([^']+)'\)*\)").ok()?;
    let mut aliases = HashMap::<String, String>::new();
    let mut types = HashMap::<String, String>::new();
    let mut rendered = source.to_string();
    let mut count = 0;
    for _ in 0..64 {
        let previous = rendered.clone();
        rendered = arithmetic
            .replace_all(&rendered, |c: &regex::Captures<'_>| {
                if c.get(0)
                    .and_then(|m| m.start().checked_sub(1))
                    .is_some_and(|i| rendered.as_bytes()[i] == b'@')
                {
                    return c[0].to_string();
                }
                integer_literal(&c[1]).map_or_else(|| c[0].to_string(), |n| n.to_string())
            })
            .into_owned();
        rendered = joined
            .replace_all(&rendered, |c: &regex::Captures<'_>| {
                character_string(&c[1]).map_or_else(
                    || c[0].to_string(),
                    |s| {
                        count += 1;
                        quote(&s)
                    },
                )
            })
            .into_owned();
        rendered = pipeline
            .replace_all(&rendered, |c: &regex::Captures<'_>| {
                let command = c[2].to_ascii_lowercase();
                if aliases
                    .get(&command)
                    .map_or(command.as_str(), String::as_str)
                    != "foreach-object"
                {
                    return c[0].to_string();
                }
                character_string(&c[1]).map_or_else(
                    || c[0].to_string(),
                    |s| {
                        count += 1;
                        quote(&s)
                    },
                )
            })
            .into_owned();
        for c in alias.captures_iter(&rendered) {
            aliases.insert(c[1].to_ascii_lowercase(), c[2].to_ascii_lowercase());
        }
        for c in type_alias.captures_iter(&rendered) {
            types.insert(c[1].to_ascii_lowercase(), c[2].to_string());
        }
        let string_types = std::iter::once("string")
            .chain(std::iter::once("system.string"))
            .chain(types.iter().filter_map(|(k, v)| {
                matches!(v.to_ascii_lowercase().as_str(), "string" | "system.string")
                    .then_some(k.as_str())
            }))
            .map(regex::escape)
            .collect::<Vec<_>>()
            .join("|");
        let constructor = Regex::new(&format!(
            r"(?i)\[(?:{string_types})\]::(?:new|\(*'new'\)*)\(@\(([0-9,\s-]+)\)\)"
        ))
        .ok()?;
        rendered = constructor
            .replace_all(&rendered, |c: &regex::Captures<'_>| {
                character_string(&c[1]).map_or_else(
                    || c[0].to_string(),
                    |s| {
                        count += 1;
                        quote(&s)
                    },
                )
            })
            .into_owned();
        if rendered == previous {
            break;
        }
    }
    if count < 3 {
        return None;
    }
    // Resolve literal type registrations; alias bindings remain in the output
    // as corroboration. This is an analysis rendering, never executed.
    let type_reference = Regex::new(r"\[([A-Za-z][A-Za-z0-9_]*)\]").ok()?;
    rendered = type_reference
        .replace_all(&rendered, |c: &regex::Captures<'_>| {
            types
                .get(&c[1].to_ascii_lowercase())
                .map_or_else(|| c[0].to_string(), |t| format!("[{t}]"))
        })
        .into_owned();
    let command_reference = Regex::new(r"(^|[^A-Za-z0-9_$])([A-Za-z][A-Za-z0-9_]*)\b").ok()?;
    rendered = command_reference
        .replace_all(&rendered, |c: &regex::Captures<'_>| {
            aliases
                .get(&c[2].to_ascii_lowercase())
                .map_or_else(|| c[0].to_string(), |command| format!("{}{command}", &c[1]))
        })
        .into_owned();
    let literal_wrapper = Regex::new(r"\(('(?:[^']|'')*')\)").ok()?;
    for _ in 0..8 {
        let normalized = literal_wrapper
            .replace_all(&rendered, |c: &regex::Captures<'_>| {
                let preceding = c
                    .get(0)
                    .and_then(|m| m.start().checked_sub(1))
                    .map(|i| rendered.as_bytes()[i]);
                if preceding.is_some_and(|b| b.is_ascii_alphanumeric() || b"_'\"]):".contains(&b)) {
                    c[0].to_string()
                } else {
                    c[1].to_string()
                }
            })
            .into_owned();
        if normalized == rendered {
            break;
        }
        rendered = normalized;
    }
    let member = Regex::new(r"(::|\.)\('([A-Za-z][A-Za-z0-9_]*)'\)").ok()?;
    rendered = member.replace_all(&rendered, "$1$2").into_owned();
    Some(ExtractedPayload {
        preview: rendered.chars().take(200).collect(),
        data: rendered.into_bytes(),
        encoding_chain: vec![
            "powershell-literal-arithmetic".into(),
            "character-table".into(),
        ],
        detected_type: FileType::PowerShell,
        original_offset: 0,
    })
}
