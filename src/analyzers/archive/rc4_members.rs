//! Pair opaque APK assets with referenced DEX literals without retaining an APK.
//! Decoding and full container validation live in filefacts; this collector owns
//! bounded cross-member context, provenance, cancellation and archive limits.
use super::{FileType, MemoryArchiveMember, calculate_sha256};
use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, Ordering};

const MAX_DEX_BYTES: usize = 32 * 1024 * 1024;
const MAX_ASSET_BYTES: usize = 32 * 1024 * 1024;
const MAX_OUTPUT: usize = 16 * 1024 * 1024;
const MAX_KEYS: usize = 8192;
const MAX_ATTEMPTS: usize = 32768;

#[derive(Default)]
pub(super) struct Collector {
    keys: Vec<Vec<u8>>,
    seen_keys: HashSet<Vec<u8>>,
    sources: Vec<String>,
    assets: Vec<(String, Vec<u8>)>,
    dex_bytes: usize,
    asset_bytes: usize,
    limited: bool,
}

fn opaque_asset(path: &str, data: &[u8]) -> bool {
    if !path.starts_with("assets/")
        || !(128..=filefacts::recover::rc4::MAX_INPUT).contains(&data.len())
        || std::str::from_utf8(data).is_ok()
    {
        return false;
    }
    // Select by bytes rather than the attacker-controlled filename/extension.
    // Recognized resources remain on their ordinary analyzers.
    let known: &[&[u8]] = &[
        b"\x89PNG",
        b"\xff\xd8\xff",
        b"GIF8",
        b"RIFF",
        b"ID3",
        b"OggS",
        b"fLaC",
        b"OTTO",
        b"ttcf",
        b"wOFF",
        b"wOF2",
        b"\0\x01\0\0",
        b"PK\x03\x04",
        b"dex\n",
        b"\x7fELF",
    ];
    if known.iter().any(|prefix| data.starts_with(prefix)) {
        return false;
    }
    crate::entropy::shannon(&data[..data.len().min(4096)]) >= 6.5
}

impl Collector {
    pub(super) fn observe(&mut self, member: &MemoryArchiveMember, cancelled: &impl Fn() -> bool) {
        if cancelled() || member.relative_path.len() > 4096 {
            return;
        }
        let data: &[u8] = &member.data;
        if member.file_type == FileType::Dex {
            if self.sources.len() >= 16 || self.dex_bytes.saturating_add(data.len()) > MAX_DEX_BYTES
            {
                self.limited = true;
                return;
            }
            self.dex_bytes += data.len();
            self.sources.push(member.relative_path.clone());
            let parsed = filefacts::OpenOptions::new()
                .cache(false)
                .file_type(filefacts::FileType::Dex)
                .open(data);
            for literal in parsed.literals() {
                if cancelled() {
                    return;
                }
                let key = literal.value.as_bytes();
                if !(1..=64).contains(&key.len()) || self.seen_keys.contains(key) {
                    continue;
                }
                if self.keys.len() >= MAX_KEYS {
                    self.limited = true;
                    break;
                }
                self.seen_keys.insert(key.to_vec());
                self.keys.push(key.to_vec());
            }
        } else if opaque_asset(&member.relative_path, data) {
            if self.assets.len() >= 32
                || self.asset_bytes.saturating_add(data.len()) > MAX_ASSET_BYTES
            {
                self.limited = true;
                return;
            }
            self.asset_bytes += data.len();
            self.assets
                .push((member.relative_path.clone(), data.to_vec()));
        }
    }

    pub(super) fn recover(
        self,
        mut diagnostic: impl FnMut(String),
        cancellation: Option<&AtomicBool>,
    ) -> Vec<MemoryArchiveMember> {
        let cancelled = || cancellation.is_some_and(|flag| flag.load(Ordering::Acquire));
        let mut out = Vec::new();
        if self.assets.is_empty() || self.keys.is_empty() {
            return out;
        }
        if self.limited {
            diagnostic(
                "APK RC4 candidate search reached a DEX, key or asset retention budget".into(),
            );
        }
        let mut attempts = 0;
        let mut output = 0usize;
        for (path, data) in self.assets {
            for key in &self.keys {
                if cancelled() {
                    return out;
                }
                attempts += 1;
                if attempts > MAX_ATTEMPTS {
                    diagnostic("APK RC4 candidate search reached its 32768-probe budget".into());
                    return out;
                }
                let Some(decoded) = filefacts::recover::rc4::recover(&data, key, cancellation)
                else {
                    continue;
                };
                if output.saturating_add(decoded.data.len()) > MAX_OUTPUT {
                    diagnostic("APK RC4 recovery reached its 16 MiB output budget".into());
                    return out;
                }
                output += decoded.data.len();
                let (file_type, suffix) = match decoded.kind {
                    filefacts::recover::rc4::Kind::Dex => (FileType::Dex, "dex"),
                    filefacts::recover::rc4::Kind::Zip => (FileType::Zip, "zip"),
                };
                out.push(MemoryArchiveMember {
                    relative_path: format!("{path}.rc4-decoded.{suffix}"),
                    sha256: calculate_sha256(&decoded.data),
                    data: decoded.data.into(),
                    file_type,
                    container_kind: Some("rc4-decoded-asset".into()),
                });
                break;
            }
        }
        out
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    fn member(path: &str, bytes: &[u8], file_type: FileType) -> MemoryArchiveMember {
        MemoryArchiveMember {
            relative_path: path.into(),
            data: bytes.to_vec().into(),
            file_type,
            sha256: calculate_sha256(bytes),
            container_kind: None,
        }
    }

    #[test]
    fn pairs_referenced_dex_keys_with_assets_in_either_order() {
        for reverse in [false, true] {
            let dex = member(
                "classes.dex",
                include_bytes!("testdata/rc4-key.dex"),
                FileType::Dex,
            );
            let asset = member(
                "assets/renamed.jpg",
                include_bytes!("testdata/rc4-asset.bin"),
                FileType::Unknown,
            );
            let mut collector = Collector::default();
            let mut members = vec![dex, asset];
            if reverse {
                members.reverse();
            }
            for member in &members {
                collector.observe(member, &|| false);
            }
            let recovered = collector.recover(|_| {}, None);
            assert_eq!(recovered.len(), 1);
            assert_eq!(&*recovered[0].data, include_bytes!("testdata/rc4-key.dex"));
            assert_eq!(
                recovered[0].container_kind.as_deref(),
                Some("rc4-decoded-asset")
            );
        }
    }

    #[test]
    fn bounds_total_key_asset_probes() {
        let mut collector = Collector::default();
        collector.sources.push("classes.dex".into());
        collector.keys = (0..MAX_KEYS)
            .map(|i| (i as u64).to_le_bytes().to_vec())
            .collect();
        for i in 0..5 {
            collector.assets.push((
                format!("assets/{i}"),
                include_bytes!("testdata/rc4-asset.bin").to_vec(),
            ));
        }
        let mut notes = Vec::new();
        assert!(
            collector
                .recover(|message| notes.push(message), None)
                .is_empty()
        );
        assert!(
            notes
                .iter()
                .any(|message| message.contains("32768-probe budget"))
        );
    }

    #[test]
    fn requires_dex_context_and_honors_cancellation_and_retention() {
        let asset = member(
            "assets/blob",
            include_bytes!("testdata/rc4-asset.bin"),
            FileType::Unknown,
        );
        let mut collector = Collector::default();
        collector.observe(&asset, &|| false);
        assert!(collector.recover(|_| {}, None).is_empty());
        let mut collector = Collector::default();
        let dex = member(
            "classes.dex",
            include_bytes!("testdata/rc4-key.dex"),
            FileType::Dex,
        );
        collector.observe(&dex, &|| false);
        collector.observe(&asset, &|| false);
        assert!(
            collector
                .recover(|_| {}, Some(&AtomicBool::new(true)))
                .is_empty()
        );
        let mut collector = Collector::default();
        for _ in 0..17 {
            collector.observe(&dex, &|| false);
        }
        assert!(collector.limited);
        assert_eq!(collector.sources.len(), 16);
        assert_eq!(collector.keys.len(), 1);
        assert!(!opaque_asset("outside/blob", &asset.data));
        assert!(!opaque_asset(
            "assets/plain.txt",
            b"not an encrypted code container"
        ));
    }
}
