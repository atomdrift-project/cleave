//! Interned immutable strings for high-duplication identifier fields.
//!
//! A scan of a member-heavy archive holds the same few thousand distinct
//! trait ids and descriptions in hundreds of thousands of `Finding`s, the
//! `Note`s that re-own them per context line, and the `CompactTrait`s the
//! output carries — each copy a separate small heap allocation. Measured on
//! the gauntlet peak, that duplication is the core of jemalloc's small-class
//! fragmentation (1.75 GB active−allocated, concentrated in the ≤4 KB bins).
//!
//! [`Istr`] is an `Arc<str>` behind a newtype whose ergonomics match
//! `String` closely enough that field conversions rarely touch call sites:
//! it derefs to `str`, compares against `str`/`&str`/`String`, displays,
//! orders, hashes by content, and serializes as a plain string — the wire
//! format is unchanged. Construction goes through a process-wide dedup pool,
//! so equal strings share one allocation; deserialization interns too, which
//! makes analysis-cache hits dedupe as well.
//!
//! The pool holds strong references and sweeps entries whose only owner is
//! the pool itself once growth crosses a threshold — dynamic descriptions
//! (per-package names and the like) are reclaimed after their reports drop,
//! so a long-running worker does not accumulate every string it ever saw.

use std::fmt;
use std::sync::Arc;

use rustc_hash::FxHashSet;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Sweep the pool when it exceeds this many entries; entries only the pool
/// still holds (`strong_count == 1`) are dropped. Distinct trait ids and
/// static descriptions number in the low tens of thousands, so a healthy
/// steady state sits far below this.
const SWEEP_THRESHOLD: usize = 262_144;

fn pool() -> &'static parking_lot::Mutex<FxHashSet<Arc<str>>> {
    static POOL: std::sync::OnceLock<parking_lot::Mutex<FxHashSet<Arc<str>>>> =
        std::sync::OnceLock::new();
    POOL.get_or_init(|| parking_lot::Mutex::new(FxHashSet::default()))
}

fn intern(s: &str) -> Arc<str> {
    let mut pool = pool().lock();
    if let Some(existing) = pool.get(s) {
        return Arc::clone(existing);
    }
    if pool.len() >= SWEEP_THRESHOLD {
        pool.retain(|e| Arc::strong_count(e) > 1);
    }
    let arc: Arc<str> = Arc::from(s);
    pool.insert(Arc::clone(&arc));
    arc
}

/// An interned immutable string. See the module docs.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Istr(Arc<str>);

impl Istr {
    /// The string slice. Also available through `Deref`.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Whether the string is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl Default for Istr {
    fn default() -> Self {
        static EMPTY: std::sync::OnceLock<Arc<str>> = std::sync::OnceLock::new();
        Self(Arc::clone(EMPTY.get_or_init(|| Arc::from(""))))
    }
}

impl std::ops::Deref for Istr {
    type Target = str;
    fn deref(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for Istr {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl std::borrow::Borrow<str> for Istr {
    fn borrow(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Istr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&*self.0, f)
    }
}

impl fmt::Debug for Istr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&*self.0, f)
    }
}

impl From<&str> for Istr {
    fn from(s: &str) -> Self {
        Self(intern(s))
    }
}

impl From<String> for Istr {
    fn from(s: String) -> Self {
        Self(intern(&s))
    }
}

impl From<&String> for Istr {
    fn from(s: &String) -> Self {
        Self(intern(s))
    }
}

impl From<&Istr> for Istr {
    fn from(s: &Istr) -> Self {
        s.clone()
    }
}

impl PartialEq<str> for Istr {
    fn eq(&self, other: &str) -> bool {
        &*self.0 == other
    }
}

impl PartialEq<&str> for Istr {
    fn eq(&self, other: &&str) -> bool {
        &*self.0 == *other
    }
}

impl PartialEq<String> for Istr {
    fn eq(&self, other: &String) -> bool {
        &*self.0 == other.as_str()
    }
}

impl PartialEq<Istr> for str {
    fn eq(&self, other: &Istr) -> bool {
        self == &*other.0
    }
}

impl PartialEq<Istr> for &str {
    fn eq(&self, other: &Istr) -> bool {
        *self == &*other.0
    }
}

impl PartialEq<Istr> for String {
    fn eq(&self, other: &Istr) -> bool {
        self.as_str() == &*other.0
    }
}

impl Serialize for Istr {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for Istr {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct V;
        impl serde::de::Visitor<'_> for V {
            type Value = Istr;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a string")
            }
            fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Istr, E> {
                Ok(Istr::from(v))
            }
            fn visit_string<E: serde::de::Error>(self, v: String) -> Result<Istr, E> {
                Ok(Istr::from(v.as_str()))
            }
        }
        deserializer.deserialize_str(V)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    /// Equal strings share one allocation; distinct strings do not.
    #[test]
    fn interning_shares_backing_storage() {
        let a = Istr::from("objectives/execution/shell::bash");
        let b = Istr::from("objectives/execution/shell::bash");
        let c = Istr::from("something/else");
        assert!(Arc::ptr_eq(&a.0, &b.0));
        assert!(!Arc::ptr_eq(&a.0, &c.0));
        assert_eq!(a, b);
        assert_eq!(a, "objectives/execution/shell::bash");
        assert_eq!("objectives/execution/shell::bash", a);
    }

    /// The wire format is a plain string, both directions, and
    /// deserialization interns.
    #[test]
    fn serde_round_trips_as_plain_string() {
        let a = Istr::from("net/socket");
        let json = serde_json::to_string(&a).unwrap();
        assert_eq!(json, "\"net/socket\"");
        let back: Istr = serde_json::from_str(&json).unwrap();
        assert!(Arc::ptr_eq(&a.0, &back.0), "deserialize must intern");
    }

    /// The sweep drops pool-only entries and keeps live ones.
    #[test]
    fn sweep_reclaims_dead_entries() {
        let live = Istr::from("istr-test-live");
        {
            let _dead = Istr::from("istr-test-dead");
        }
        let mut pool = pool().lock();
        pool.retain(|e| Arc::strong_count(e) > 1);
        assert!(pool.get("istr-test-live").is_some());
        assert!(pool.get("istr-test-dead").is_none());
        drop(pool);
        drop(live);
    }
}
