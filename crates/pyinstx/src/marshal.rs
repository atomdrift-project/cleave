//! Minimal CPython `marshal` reader — just enough to decode a PYZ TOC.
//!
//! A PYZ TOC is a `list[tuple[str, tuple[int, int, int]]]` (or a dict in older
//! pyinstaller releases). Decoding requires only a handful of marshal type
//! codes; the rest are left unimplemented intentionally.

use thiserror::Error;

#[derive(Debug, Error)]
pub(crate) enum MarshalError {
    #[error("short read")]
    ShortRead,
    #[error("unsupported marshal type: {0:#x}")]
    UnsupportedType(u8),
    #[error("unexpected shape")]
    UnexpectedShape,
}

#[derive(Debug)]
pub(crate) struct PyzEntry {
    pub key: String,
    pub is_pkg: bool,
    pub pos: usize,
    pub length: usize,
}

#[derive(Debug, Clone)]
enum Value {
    None,
    Bool(bool),
    Int(i64),
    Str(String),
    Bytes(Vec<u8>),
    Tuple(Vec<Value>),
    List(Vec<Value>),
    Dict(Vec<(Value, Value)>),
}

const FLAG_REF: u8 = 0x80;

struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
    refs: Vec<Value>,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self {
            buf,
            pos: 0,
            refs: Vec::new(),
        }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], MarshalError> {
        let end = self.pos.checked_add(n).ok_or(MarshalError::ShortRead)?;
        let slice = self.buf.get(self.pos..end).ok_or(MarshalError::ShortRead)?;
        self.pos = end;
        Ok(slice)
    }

    fn u8(&mut self) -> Result<u8, MarshalError> {
        Ok(self.take(1)?[0])
    }

    fn u32_le(&mut self) -> Result<u32, MarshalError> {
        let s = self.take(4)?;
        Ok(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
    }

    fn read_value(&mut self) -> Result<Value, MarshalError> {
        let code = self.u8()?;
        let has_ref = (code & FLAG_REF) != 0;
        let kind = code & !FLAG_REF;
        // Reserve a ref slot before recursing so cycles resolve in order.
        let slot = if has_ref {
            let idx = self.refs.len();
            self.refs.push(Value::None);
            Some(idx)
        } else {
            None
        };

        let value = match kind {
            b'0' | b'N' => Value::None,
            b'T' => Value::Bool(true),
            b'F' => Value::Bool(false),
            b'i' => {
                let value = self.u32_le()? as i32;
                Value::Int(i64::from(value))
            }
            b'I' => {
                let s = self.take(8)?;
                let mut arr = [0u8; 8];
                arr.copy_from_slice(s);
                Value::Int(i64::from_le_bytes(arr))
            }
            // Byte strings.
            b's' | b't' => {
                let len = self.u32_le()? as usize;
                let bytes = self.take(len)?.to_vec();
                Value::Bytes(bytes)
            }
            // Unicode / ASCII strings (4-byte length).
            b'u' | b'a' | b'A' => {
                let len = self.u32_le()? as usize;
                let bytes = self.take(len)?;
                Value::Str(String::from_utf8_lossy(bytes).into_owned())
            }
            // Short ASCII (1-byte length).
            b'z' | b'Z' => {
                let len = self.u8()? as usize;
                let bytes = self.take(len)?;
                Value::Str(String::from_utf8_lossy(bytes).into_owned())
            }
            // Tuples.
            b'(' => {
                let n = self.u32_le()? as usize;
                let mut items = Vec::with_capacity(n.min(1024));
                for _ in 0..n {
                    items.push(self.read_value()?);
                }
                Value::Tuple(items)
            }
            b')' => {
                let n = self.u8()? as usize;
                let mut items = Vec::with_capacity(n);
                for _ in 0..n {
                    items.push(self.read_value()?);
                }
                Value::Tuple(items)
            }
            b'[' => {
                let n = self.u32_le()? as usize;
                let mut items = Vec::with_capacity(n.min(1024));
                for _ in 0..n {
                    items.push(self.read_value()?);
                }
                Value::List(items)
            }
            b'{' => {
                // Dict: key/value pairs terminated by TYPE_NULL ('0').
                let mut items = Vec::new();
                loop {
                    // Peek for terminator.
                    if self.buf.get(self.pos).copied() == Some(b'0') {
                        self.pos += 1;
                        break;
                    }
                    let k = self.read_value()?;
                    let v = self.read_value()?;
                    items.push((k, v));
                }
                Value::Dict(items)
            }
            b'r' => {
                let idx = self.u32_le()? as usize;
                self.refs.get(idx).cloned().unwrap_or(Value::None)
            }
            other => return Err(MarshalError::UnsupportedType(other)),
        };

        if let Some(idx) = slot {
            if let Some(slot) = self.refs.get_mut(idx) {
                *slot = value.clone();
            }
        }
        Ok(value)
    }
}

/// Parse a PYZ TOC blob and return the list of inner entries.
pub(crate) fn parse_pyz_toc(data: &[u8]) -> Result<Vec<PyzEntry>, MarshalError> {
    let mut reader = Reader::new(data);
    let root = reader.read_value()?;
    let items: Vec<(Value, Value)> = match root {
        // pyinstaller 3.1+ — list of (key, value) tuples.
        Value::List(list) => list
            .into_iter()
            .filter_map(|v| match v {
                Value::Tuple(t) if t.len() == 2 => {
                    let mut iter = t.into_iter();
                    Some((iter.next()?, iter.next()?))
                }
                _ => None,
            })
            .collect(),
        // pyinstaller <3.1 — dict.
        Value::Dict(d) => d,
        _ => return Err(MarshalError::UnexpectedShape),
    };

    let mut out = Vec::with_capacity(items.len());
    for (key, value) in items {
        let key_str = match key {
            Value::Str(s) => s,
            Value::Bytes(b) => String::from_utf8_lossy(&b).into_owned(),
            _ => continue,
        };
        let inner = match value {
            Value::Tuple(t) if t.len() == 3 => t,
            _ => continue,
        };
        let is_pkg = matches!(inner.first(), Some(Value::Int(n)) if *n != 0)
            || matches!(inner.first(), Some(Value::Bool(true)));
        let pos = match inner.get(1) {
            Some(Value::Int(n)) if *n >= 0 => *n as usize,
            _ => continue,
        };
        let length = match inner.get(2) {
            Some(Value::Int(n)) if *n >= 0 => *n as usize,
            _ => continue,
        };
        out.push(PyzEntry {
            key: key_str,
            is_pkg,
            pos,
            length,
        });
    }
    Ok(out)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn parses_short_ascii() {
        // [( 'foo', (0, 100, 200) )]
        // List: '['  count=1  Tuple:'('  count=2  Str:'z' len=3 'foo'
        //   inner Tuple:'(' count=3  Int:'i' 0  Int:'i' 100  Int:'i' 200
        let mut buf = vec![];
        buf.push(b'[');
        buf.extend_from_slice(&1u32.to_le_bytes());
        buf.push(b'(');
        buf.extend_from_slice(&2u32.to_le_bytes());
        buf.push(b'z');
        buf.push(3);
        buf.extend_from_slice(b"foo");
        buf.push(b'(');
        buf.extend_from_slice(&3u32.to_le_bytes());
        buf.push(b'i');
        buf.extend_from_slice(&0i32.to_le_bytes());
        buf.push(b'i');
        buf.extend_from_slice(&100i32.to_le_bytes());
        buf.push(b'i');
        buf.extend_from_slice(&200i32.to_le_bytes());
        let toc = parse_pyz_toc(&buf).unwrap();
        assert_eq!(toc.len(), 1);
        assert_eq!(toc[0].key, "foo");
        assert!(!toc[0].is_pkg);
        assert_eq!(toc[0].pos, 100);
        assert_eq!(toc[0].length, 200);
    }
}
