//! Contiguous archive bytes without committing RAM for large zero-filled members.

use std::ops::Deref;

const MAPPED_MEMBER_THRESHOLD: usize = 128 * 1024 * 1024;
const COPY_CHUNK: usize = 65536;
static ZERO_CHUNK: [u8; COPY_CHUNK] = [0; COPY_CHUNK];

pub(super) enum MemberData {
    Owned(Vec<u8>),
    Mapped {
        mapping: memmap2::MmapMut,
        len: usize,
    },
}

impl MemberData {
    pub(super) fn for_tar(size: u64) -> Self {
        if let Ok(size) = usize::try_from(size)
            && size >= MAPPED_MEMBER_THRESHOLD
        {
            // Anonymous mappings start zero-filled. Leave zero chunks untouched:
            // readers still see every byte, backed by the OS shared zero page.
            // No scratch file or tmpfs allocation is involved.
            match memmap2::MmapMut::map_anon(size) {
                Ok(mapping) => return Self::Mapped { mapping, len: 0 },
                Err(error) => tracing::debug!(size, %error, "Anonymous member mapping unavailable"),
            }
        }
        Self::Owned(Vec::with_capacity(size.min(16 * 1024 * 1024) as usize))
    }

    pub(super) fn append(&mut self, bytes: &[u8]) -> std::io::Result<()> {
        match self {
            Self::Owned(data) => data.extend_from_slice(bytes),
            Self::Mapped { mapping, len } => {
                let end = len
                    .checked_add(bytes.len())
                    .filter(|end| *end <= mapping.len())
                    .ok_or_else(|| {
                        std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "TAR member exceeded its declared logical size",
                        )
                    })?;
                for (source, target) in bytes
                    .chunks(COPY_CHUNK)
                    .zip(mapping[*len..end].chunks_mut(COPY_CHUNK))
                {
                    if source != &ZERO_CHUNK[..source.len()] {
                        target.copy_from_slice(source);
                    }
                }
                *len = end;
            }
        }
        Ok(())
    }
}

impl From<Vec<u8>> for MemberData {
    fn from(data: Vec<u8>) -> Self {
        Self::Owned(data)
    }
}

impl Deref for MemberData {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        match self {
            Self::Owned(data) => data,
            Self::Mapped { mapping, len } => &mapping[..*len],
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn mapped_member_preserves_zero_runs_and_unaligned_payloads() {
        let mut data = MemberData::Mapped {
            mapping: memmap2::MmapMut::map_anon(8 * COPY_CHUNK).unwrap(),
            len: 0,
        };
        let chunks = [
            vec![0; 37],
            vec![1; 79],
            vec![0; 2 * COPY_CHUNK + 11],
            (0..COPY_CHUNK + 3).map(|i| (i % 251) as u8).collect(),
            vec![0; COPY_CHUNK],
        ];
        let mut expected = Vec::new();
        for chunk in chunks {
            data.append(&chunk).unwrap();
            expected.extend(chunk);
            assert_eq!(&*data, expected.as_slice());
        }
        assert_eq!(
            crate::analyzers::archive::utils::calculate_sha256(&data),
            crate::analyzers::archive::utils::calculate_sha256(&expected)
        );
    }

    #[test]
    fn mapped_member_keeps_only_readable_prefix_on_overflow() {
        let mut data = MemberData::Mapped {
            mapping: memmap2::MmapMut::map_anon(10).unwrap(),
            len: 0,
        };
        data.append(b"payload").unwrap();
        assert!(data.append(b"too long").is_err());
        assert_eq!(&*data, b"payload");
    }
}
