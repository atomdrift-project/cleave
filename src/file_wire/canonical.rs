//! Stable serialization for the only flexible JSON subtrees in a file record.
//! Typed struct fields and BTreeMaps already have deterministic order. Sort
//! dynamic maps by key without constructing a report DOM or cloning values.
use crate::types::CompactFacts;
use serde::{
    Serialize, Serializer,
    ser::{SerializeMap, SerializeSeq},
};
use serde_json::Value;
use std::collections::BTreeMap;

struct Sorted<'a>(&'a Value);

impl Serialize for Sorted<'_> {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        match self.0 {
            Value::Object(map) => {
                let mut out = s.serialize_map(Some(map.len()))?;
                if map.keys().is_sorted() {
                    for (k, v) in map {
                        out.serialize_entry(k, &Sorted(v))?;
                    }
                } else {
                    let mut fields: Vec<_> = map.iter().collect();
                    fields.sort_unstable_by(|a, b| a.0.cmp(b.0));
                    for (k, v) in fields {
                        out.serialize_entry(k, &Sorted(v))?;
                    }
                }
                out.end()
            }
            Value::Array(values) => {
                let mut out = s.serialize_seq(Some(values.len()))?;
                for v in values {
                    out.serialize_element(&Sorted(v))?;
                }
                out.end()
            }
            value => value.serialize(s),
        }
    }
}

pub(super) fn facts<S: Serializer>(facts: &CompactFacts, s: S) -> Result<S::Ok, S::Error> {
    let metrics = facts.metrics.as_ref().map(|m| Sorted(&m.0));
    facts.serialize_with_metrics(s, metrics.as_ref())
}

pub(super) fn registry<S: Serializer>(
    values: &BTreeMap<String, Value>,
    s: S,
) -> Result<S::Ok, S::Error> {
    let mut out = s.serialize_map(Some(values.len()))?;
    for (k, v) in values {
        out.serialize_entry(k, &Sorted(v))?;
    }
    out.end()
}
