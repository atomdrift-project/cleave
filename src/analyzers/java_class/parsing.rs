//! Java class file parsing.

use anyhow::{bail, Result};
use std::collections::HashSet;

#[derive(Debug)]
pub(crate) struct ClassInfo {
    pub strings: HashSet<String>,
    pub class_refs: HashSet<String>,
    pub methods: Vec<MethodInfo>,
}

#[derive(Debug)]
pub(crate) struct MethodInfo {
    pub name: String,
}

#[derive(Debug, Clone)]
pub(crate) enum ConstantPoolEntry {
    Empty,
    Utf8(String),
    Class(u16),
    MethodRef((), ()),
    NameAndType((), ()),
    Integer(()),
    Float(()),
    Long(()),
    Double(()),
    String(()),
}

impl super::JavaClassAnalyzer {
    pub(super) fn parse_class_file(&self, data: &[u8]) -> Result<ClassInfo> {
        if data.len() < 10 {
            bail!("File too small to be a valid class file");
        }

        // Check magic number (0xCAFEBABE)
        let magic = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
        if magic != 0xCAFEBABE {
            bail!("Invalid class file magic number");
        }

        let mut pos = 8; // Skip magic and version

        // Parse constant pool
        if pos + 2 > data.len() {
            bail!("Truncated class file");
        }
        let constant_pool_count = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
        pos += 2;

        let mut constant_pool = vec![ConstantPoolEntry::Empty; constant_pool_count];
        let mut i = 1;
        while i < constant_pool_count {
            if pos >= data.len() {
                bail!("Truncated constant pool");
            }
            let tag = data[pos];
            pos += 1;

            match tag {
                1 => {
                    // UTF8
                    if pos + 2 > data.len() {
                        bail!("Truncated UTF8 entry");
                    }
                    let length = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
                    pos += 2;
                    if pos + length > data.len() {
                        bail!("Truncated UTF8 string");
                    }
                    let s = String::from_utf8_lossy(&data[pos..pos + length]).to_string();
                    constant_pool[i] = ConstantPoolEntry::Utf8(s);
                    pos += length;
                }
                7 => {
                    // Class
                    if pos + 2 > data.len() {
                        bail!("Truncated class entry");
                    }
                    let name_index = u16::from_be_bytes([data[pos], data[pos + 1]]);
                    constant_pool[i] = ConstantPoolEntry::Class(name_index);
                    pos += 2;
                }
                8 => {
                    // String
                    if pos + 2 > data.len() {
                        bail!("Truncated string entry");
                    }
                    constant_pool[i] = ConstantPoolEntry::String(());
                    pos += 2;
                }
                10 => {
                    // Methodref
                    if pos + 4 > data.len() {
                        bail!("Truncated methodref entry");
                    }
                    constant_pool[i] = ConstantPoolEntry::MethodRef((), ());
                    pos += 4;
                }
                12 => {
                    // NameAndType
                    if pos + 4 > data.len() {
                        bail!("Truncated name and type entry");
                    }
                    constant_pool[i] = ConstantPoolEntry::NameAndType((), ());
                    pos += 4;
                }
                3 => {
                    // Integer
                    if pos + 4 > data.len() {
                        bail!("Truncated integer entry");
                    }
                    constant_pool[i] = ConstantPoolEntry::Integer(());
                    pos += 4;
                }
                4 => {
                    // Float
                    if pos + 4 > data.len() {
                        bail!("Truncated float entry");
                    }
                    constant_pool[i] = ConstantPoolEntry::Float(());
                    pos += 4;
                }
                5 => {
                    // Long (takes 2 slots)
                    if pos + 8 > data.len() {
                        bail!("Truncated long entry");
                    }
                    constant_pool[i] = ConstantPoolEntry::Long(());
                    pos += 8;
                    i += 1; // Long takes 2 slots
                    if i < constant_pool_count {
                        constant_pool[i] = ConstantPoolEntry::Empty;
                    }
                }
                6 => {
                    // Double (takes 2 slots)
                    if pos + 8 > data.len() {
                        bail!("Truncated double entry");
                    }
                    constant_pool[i] = ConstantPoolEntry::Double(());
                    pos += 8;
                    i += 1; // Double takes 2 slots
                    if i < constant_pool_count {
                        constant_pool[i] = ConstantPoolEntry::Empty;
                    }
                }
                _ => {
                    // Skip unknown types
                    pos += match tag {
                        9 | 11 | 18 => 4, // Fieldref, InterfaceMethodref, InvokeDynamic
                        15 => 3,          // MethodHandle
                        16 => 2,          // MethodType
                        _ => 0,
                    };
                }
            }
            i += 1;
        }

        // Extract strings and class references
        let mut strings = HashSet::new();
        let mut class_refs = HashSet::new();

        for entry in &constant_pool {
            match entry {
                ConstantPoolEntry::Utf8(s) => {
                    if self.is_interesting_string(s) {
                        strings.insert(s.clone());
                    }
                }
                ConstantPoolEntry::Class(idx) => {
                    if let Some(ConstantPoolEntry::Utf8(name)) = constant_pool.get(*idx as usize) {
                        class_refs.insert(name.clone());
                    }
                }
                _ => {}
            }
        }

        Ok(ClassInfo {
            strings,
            class_refs,
            methods: Vec::new(),
        })
    }
}
