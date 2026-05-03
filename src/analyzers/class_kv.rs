//! Java `.class` structural extraction — surfaces raw class-file
//! metadata as a `class.*` kv subtree.
//!
//! Distinct from `analyzers::java_class`'s capability/string analysis:
//! this module reads the structural header (constant pool + access
//! flags + class hierarchy + class-level attributes) without walking
//! method bytecode. Cheap; mirrors the way `binary_kv` complements the
//! existing PE/ELF/Mach-O analyzers.
//!
//! # Why these fields
//!
//! The `SourceFile` attribute carries the original `.java` filename
//! from the build host — supply-chain attackers recompiling a JAR
//! routinely leak a different name (e.g. `Foo.java` →
//! `Foo_patched.java` or a directory rename). Combined with the major
//! version (JDK target), it pins down which compiler ran where.
//! `this_class` / `super_class` / `interfaces` lock the type
//! hierarchy so swapped implementations are detectable even when the
//! classname is preserved.
//!
//! # Schema
//!
//! ```text
//! class:
//!   major_version       u16  (e.g. 65 = Java 21, 52 = Java 8)
//!   minor_version       u16
//!   access_flags        u16  (raw — public/final/abstract/interface)
//!   this_class          str  fully-qualified name (`com/foo/Bar`)
//!   super_class         str  fully-qualified name
//!   interfaces[]        str  fully-qualified names
//!   constant_pool_size  u16
//!   source_file         str  SourceFile attribute (build-host leak)
//!   signature           str  Signature attribute (generic types)
//!   inner_classes[]     str  InnerClasses attribute names
//! ```

use serde_json::{json, Map, Value};

const CP_UTF8: u8 = 1;
const CP_INTEGER: u8 = 3;
const CP_FLOAT: u8 = 4;
const CP_LONG: u8 = 5;
const CP_DOUBLE: u8 = 6;
const CP_CLASS: u8 = 7;
const CP_STRING: u8 = 8;
const CP_FIELDREF: u8 = 9;
const CP_METHODREF: u8 = 10;
const CP_INTERFACE_METHODREF: u8 = 11;
const CP_NAME_AND_TYPE: u8 = 12;
const CP_METHOD_HANDLE: u8 = 15;
const CP_METHOD_TYPE: u8 = 16;
const CP_DYNAMIC: u8 = 17;
const CP_INVOKE_DYNAMIC: u8 = 18;
const CP_MODULE: u8 = 19;
const CP_PACKAGE: u8 = 20;

#[derive(Debug, Clone)]
enum CpEntry {
    Empty,
    Utf8(String),
    Class(u16),
    Other,
}

/// Extract the `class.*` kv subtree from raw `.class` bytes. Returns
/// `None` for non-class inputs or truncated headers.
#[must_use]
pub(crate) fn extract(data: &[u8]) -> Option<Value> {
    if data.len() < 10 || u32::from_be_bytes([data[0], data[1], data[2], data[3]]) != 0xCAFEBABE {
        return None;
    }
    let minor_version = u16::from_be_bytes([data[4], data[5]]);
    let major_version = u16::from_be_bytes([data[6], data[7]]);
    let cp_count = u16::from_be_bytes([data[8], data[9]]) as usize;

    let mut pos = 10usize;
    let cp = parse_constant_pool(data, &mut pos, cp_count)?;

    // access_flags + this_class + super_class
    let access_flags = read_u16(data, &mut pos)?;
    let this_idx = read_u16(data, &mut pos)?;
    let super_idx = read_u16(data, &mut pos)?;

    let interfaces_count = read_u16(data, &mut pos)? as usize;
    let mut interfaces: Vec<u16> = Vec::with_capacity(interfaces_count);
    for _ in 0..interfaces_count {
        interfaces.push(read_u16(data, &mut pos)?);
    }

    // Skip fields and methods so we can reach class-level attributes,
    // where SourceFile / Signature / InnerClasses live.
    skip_member_table(data, &mut pos)?; // fields
    skip_member_table(data, &mut pos)?; // methods

    let attrs = parse_attributes(data, &mut pos, &cp);

    let mut out = Map::new();
    out.insert("major_version".into(), json!(major_version));
    out.insert("minor_version".into(), json!(minor_version));
    out.insert("access_flags".into(), json!(access_flags));
    out.insert("constant_pool_size".into(), json!(cp_count as u32));
    if let Some(name) = class_name(&cp, this_idx) {
        out.insert("this_class".into(), json!(name));
    }
    if let Some(name) = class_name(&cp, super_idx) {
        out.insert("super_class".into(), json!(name));
    }
    if !interfaces.is_empty() {
        let names: Vec<String> = interfaces
            .iter()
            .filter_map(|i| class_name(&cp, *i))
            .collect();
        if !names.is_empty() {
            out.insert("interfaces".into(), json!(names));
        }
    }
    if let Some(s) = attrs.source_file {
        out.insert("source_file".into(), json!(s));
    }
    if let Some(s) = attrs.signature {
        out.insert("signature".into(), json!(s));
    }
    if !attrs.inner_classes.is_empty() {
        out.insert("inner_classes".into(), json!(attrs.inner_classes));
    }

    Some(Value::Object(out))
}

/// Resolve a constant-pool index → fully-qualified class name string.
fn class_name(cp: &[CpEntry], idx: u16) -> Option<String> {
    let entry = cp.get(idx as usize)?;
    let CpEntry::Class(name_idx) = entry else { return None };
    if let Some(CpEntry::Utf8(s)) = cp.get(*name_idx as usize) {
        Some(s.clone())
    } else {
        None
    }
}

#[derive(Default)]
struct ClassAttributes {
    source_file: Option<String>,
    signature: Option<String>,
    inner_classes: Vec<String>,
}

fn parse_attributes(data: &[u8], pos: &mut usize, cp: &[CpEntry]) -> ClassAttributes {
    let mut out = ClassAttributes::default();
    let Some(count) = read_u16(data, pos) else { return out };
    for _ in 0..count {
        let Some(name_idx) = read_u16(data, pos) else { return out };
        let Some(length) = read_u32(data, pos).map(|v| v as usize) else { return out };
        let body_start = *pos;
        let body_end = match body_start.checked_add(length) {
            Some(e) if e <= data.len() => e,
            _ => return out,
        };
        let body = &data[body_start..body_end];
        let attr_name = match cp.get(name_idx as usize) {
            Some(CpEntry::Utf8(s)) => s.as_str(),
            _ => "",
        };
        match attr_name {
            "SourceFile" if body.len() >= 2 => {
                let idx = u16::from_be_bytes([body[0], body[1]]);
                if let Some(CpEntry::Utf8(s)) = cp.get(idx as usize) {
                    out.source_file = Some(s.clone());
                }
            }
            "Signature" if body.len() >= 2 => {
                let idx = u16::from_be_bytes([body[0], body[1]]);
                if let Some(CpEntry::Utf8(s)) = cp.get(idx as usize) {
                    out.signature = Some(s.clone());
                }
            }
            "InnerClasses" if body.len() >= 2 => {
                let n = u16::from_be_bytes([body[0], body[1]]) as usize;
                let mut p = 2;
                for _ in 0..n {
                    if p + 8 > body.len() {
                        break;
                    }
                    let inner_class_info_idx =
                        u16::from_be_bytes([body[p], body[p + 1]]);
                    if let Some(name) = class_name(cp, inner_class_info_idx) {
                        if !out.inner_classes.iter().any(|x| x == &name) {
                            out.inner_classes.push(name);
                        }
                    }
                    p += 8; // inner_class_info + outer_class_info + inner_name + flags
                }
            }
            _ => {}
        }
        *pos = body_end;
    }
    out
}

/// Skip a fields[] or methods[] table; we don't need their contents
/// for kv but we do need to advance past them to reach class-level
/// attributes. Each entry: u2 access + u2 name + u2 desc + attributes.
fn skip_member_table(data: &[u8], pos: &mut usize) -> Option<()> {
    let count = read_u16(data, pos)?;
    for _ in 0..count {
        // access_flags(2) + name_index(2) + descriptor_index(2)
        *pos = pos.checked_add(6)?;
        if *pos > data.len() {
            return None;
        }
        let attrs = read_u16(data, pos)?;
        for _ in 0..attrs {
            // attribute_name_index(2) + attribute_length(4)
            *pos = pos.checked_add(2)?;
            let len = read_u32(data, pos)? as usize;
            *pos = pos.checked_add(len)?;
            if *pos > data.len() {
                return None;
            }
        }
    }
    Some(())
}

fn parse_constant_pool(data: &[u8], pos: &mut usize, count: usize) -> Option<Vec<CpEntry>> {
    let mut cp = vec![CpEntry::Empty; count];
    let mut i = 1usize;
    while i < count {
        let tag = *data.get(*pos)?;
        *pos += 1;
        match tag {
            CP_UTF8 => {
                let len = read_u16(data, pos)? as usize;
                let end = pos.checked_add(len)?;
                if end > data.len() {
                    return None;
                }
                let s = String::from_utf8_lossy(&data[*pos..end]).into_owned();
                cp[i] = CpEntry::Utf8(s);
                *pos = end;
            }
            CP_CLASS => {
                let idx = read_u16(data, pos)?;
                cp[i] = CpEntry::Class(idx);
            }
            CP_STRING | CP_METHOD_TYPE | CP_MODULE | CP_PACKAGE => {
                *pos = pos.checked_add(2)?;
                cp[i] = CpEntry::Other;
            }
            CP_INTEGER | CP_FLOAT => {
                *pos = pos.checked_add(4)?;
                cp[i] = CpEntry::Other;
            }
            CP_LONG | CP_DOUBLE => {
                *pos = pos.checked_add(8)?;
                cp[i] = CpEntry::Other;
                i += 1; // longs/doubles take two CP slots
            }
            CP_FIELDREF | CP_METHODREF | CP_INTERFACE_METHODREF | CP_NAME_AND_TYPE
            | CP_DYNAMIC | CP_INVOKE_DYNAMIC => {
                *pos = pos.checked_add(4)?;
                cp[i] = CpEntry::Other;
            }
            CP_METHOD_HANDLE => {
                *pos = pos.checked_add(3)?;
                cp[i] = CpEntry::Other;
            }
            _ => return None,
        }
        i += 1;
    }
    Some(cp)
}

fn read_u16(data: &[u8], pos: &mut usize) -> Option<u16> {
    let bytes = data.get(*pos..*pos + 2)?.try_into().ok()?;
    *pos += 2;
    Some(u16::from_be_bytes(bytes))
}

fn read_u32(data: &[u8], pos: &mut usize) -> Option<u32> {
    let bytes = data.get(*pos..*pos + 4)?.try_into().ok()?;
    *pos += 4;
    Some(u32::from_be_bytes(bytes))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    /// Build a minimal class file with given strings in the constant
    /// pool, then assemble the rest of the structural fields.
    /// Constant pool layout (1-indexed):
    ///   1 = Utf8("MyClass")
    ///   2 = Utf8("java/lang/Object")
    ///   3 = Utf8("SourceFile")
    ///   4 = Utf8("MyClass.java")
    ///   5 = Class(1)
    ///   6 = Class(2)
    fn build_class(major: u16, with_source: bool) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&0xCAFEBABE_u32.to_be_bytes());
        out.extend_from_slice(&0u16.to_be_bytes()); // minor
        out.extend_from_slice(&major.to_be_bytes()); // major
        // CP count = 7 (entries 1..6 used)
        out.extend_from_slice(&7u16.to_be_bytes());
        // 1 Utf8 "MyClass"
        out.push(CP_UTF8);
        out.extend_from_slice(&7u16.to_be_bytes());
        out.extend_from_slice(b"MyClass");
        // 2 Utf8 "java/lang/Object"
        out.push(CP_UTF8);
        out.extend_from_slice(&16u16.to_be_bytes());
        out.extend_from_slice(b"java/lang/Object");
        // 3 Utf8 "SourceFile"
        out.push(CP_UTF8);
        out.extend_from_slice(&10u16.to_be_bytes());
        out.extend_from_slice(b"SourceFile");
        // 4 Utf8 "MyClass.java"
        out.push(CP_UTF8);
        out.extend_from_slice(&12u16.to_be_bytes());
        out.extend_from_slice(b"MyClass.java");
        // 5 Class -> 1
        out.push(CP_CLASS);
        out.extend_from_slice(&1u16.to_be_bytes());
        // 6 Class -> 2
        out.push(CP_CLASS);
        out.extend_from_slice(&2u16.to_be_bytes());

        // access_flags (PUBLIC=0x0001 | SUPER=0x0020)
        out.extend_from_slice(&0x0021u16.to_be_bytes());
        // this_class -> CP[5]
        out.extend_from_slice(&5u16.to_be_bytes());
        // super_class -> CP[6]
        out.extend_from_slice(&6u16.to_be_bytes());
        // interfaces_count = 0
        out.extend_from_slice(&0u16.to_be_bytes());
        // fields_count = 0
        out.extend_from_slice(&0u16.to_be_bytes());
        // methods_count = 0
        out.extend_from_slice(&0u16.to_be_bytes());

        // attributes
        if with_source {
            out.extend_from_slice(&1u16.to_be_bytes()); // attributes_count = 1
            // SourceFile attribute: name_index=3, length=2, sourcefile_index=4
            out.extend_from_slice(&3u16.to_be_bytes());
            out.extend_from_slice(&2u32.to_be_bytes());
            out.extend_from_slice(&4u16.to_be_bytes());
        } else {
            out.extend_from_slice(&0u16.to_be_bytes());
        }
        out
    }

    #[test]
    fn rejects_non_class() {
        assert!(extract(b"not a class").is_none());
    }

    #[test]
    fn surfaces_version_and_hierarchy() {
        let bytes = build_class(65, true); // Java 21
        let kv = extract(&bytes).unwrap();
        assert_eq!(kv["major_version"], 65);
        assert_eq!(kv["minor_version"], 0);
        assert_eq!(kv["access_flags"], 0x0021);
        assert_eq!(kv["this_class"], "MyClass");
        assert_eq!(kv["super_class"], "java/lang/Object");
        assert_eq!(kv["source_file"], "MyClass.java");
    }

    #[test]
    fn omits_source_file_when_attribute_absent() {
        let bytes = build_class(52, false); // Java 8 stripped
        let kv = extract(&bytes).unwrap();
        assert_eq!(kv["major_version"], 52);
        assert!(kv.get("source_file").is_none());
    }
}
