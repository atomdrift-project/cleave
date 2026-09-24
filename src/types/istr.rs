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
//! the pool itself once it has doubled since the last sweep — dynamic
//! descriptions (per-package names and the like) are reclaimed after their
//! reports drop, so a long-running worker does not accumulate every string
//! it ever saw.

use std::fmt;
use std::sync::Arc;

use rustc_hash::FxHashSet;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// The pool never sweeps below this many entries. Distinct trait ids and
/// static descriptions number in the low tens of thousands, so a healthy
/// steady state never sweeps at all.
const SWEEP_THRESHOLD: usize = 262_144;

/// The dedup pool, and the size at which it next sweeps.
///
/// A sweep walks every entry under the process-wide lock, so it must stay
/// rare however many strings remain live. `sweep_at` doubles from what the
/// last sweep kept, which bounds sweeping to amortized O(1) per intern. A
/// fixed threshold did not: once more strings than that stayed live, every
/// miss swept the whole pool. Measured 2026-09-24 on a 128-thread worker
/// holding 601k live import ids: a 10 ms sweep per miss, the lock held 99.9%
/// of the time, and a 3 KB archive member taking 48 s.
struct Pool {
    set: FxHashSet<Arc<str>>,
    sweep_at: usize,
}

impl Pool {
    fn new() -> Self {
        Self {
            set: FxHashSet::default(),
            sweep_at: SWEEP_THRESHOLD,
        }
    }

    fn intern(&mut self, s: &str) -> Arc<str> {
        if let Some(existing) = self.set.get(s) {
            return Arc::clone(existing);
        }
        if self.set.len() >= self.sweep_at {
            self.sweep();
        }
        let arc: Arc<str> = Arc::from(s);
        self.set.insert(Arc::clone(&arc));
        arc
    }

    /// Drop the entries only the pool still holds (`strong_count == 1`).
    fn sweep(&mut self) {
        self.set.retain(|e| Arc::strong_count(e) > 1);
        let live = self.set.len();
        self.sweep_at = live.saturating_mul(2).max(SWEEP_THRESHOLD);
        // Staying large after a sweep means a high-cardinality field is being
        // interned, so the pool pins strings that would otherwise be freed —
        // `Finding::source_file` did this (one member path per member) and cost
        // ~0.3-1.2 GB. Warn once.
        if live >= SWEEP_THRESHOLD / 2 {
            static WARNED: std::sync::Once = std::sync::Once::new();
            WARNED.call_once(|| {
                tracing::warn!(
                    live,
                    next_sweep_at = self.sweep_at,
                    "istr: intern pool stayed large after sweep — a high-cardinality \
                     field is likely being interned; Istr is for low-cardinality \
                     identifiers only"
                );
            });
        }
    }
}

fn intern(s: &str) -> Arc<str> {
    static POOL: std::sync::OnceLock<parking_lot::Mutex<Pool>> = std::sync::OnceLock::new();
    POOL.get_or_init(|| parking_lot::Mutex::new(Pool::new()))
        .lock()
        .intern(s)
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

    /// A sweep drops pool-only entries, keeps live ones, and re-arms at the
    /// floor once the pool is small again.
    #[test]
    fn sweep_reclaims_dead_entries() {
        let mut pool = Pool::new();
        let live = pool.intern("live");
        for i in 0..SWEEP_THRESHOLD {
            pool.intern(&i.to_string());
        }
        // The last intern found the pool at the threshold and swept first.
        assert_eq!(pool.set.len(), 2, "only `live` and the newest survive");
        assert!(pool.set.contains("live"));
        assert_eq!(pool.sweep_at, SWEEP_THRESHOLD);
        drop(live);
    }

    /// With more strings live than the threshold, the next sweep is always
    /// ahead of the pool, so a miss does not sweep again — the sweep point
    /// doubles instead: once at the threshold, once at twice it.
    #[test]
    fn sweeps_stay_rare_when_most_strings_stay_live() {
        let mut pool = Pool::new();
        let mut held = Vec::with_capacity(2 * SWEEP_THRESHOLD + 1);
        for i in 0..=2 * SWEEP_THRESHOLD {
            held.push(pool.intern(&i.to_string()));
            assert!(
                pool.set.len() <= pool.sweep_at,
                "pool of {} live strings would sweep again at {}",
                pool.set.len(),
                pool.sweep_at
            );
        }
        assert_eq!(pool.sweep_at, 4 * SWEEP_THRESHOLD);
        assert_eq!(pool.set.len(), held.len());
    }
}
