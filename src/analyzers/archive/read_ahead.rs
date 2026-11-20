//! Decode a slow stream ahead of the thread that reads it.

use std::io::{self, Read};
use std::sync::mpsc::{Receiver, sync_channel};
use std::thread::Scope;

/// Bytes decoded per hand-off to the reader.
const CHUNK: usize = 1 << 20;

/// A reader fed by a helper thread that decodes `source` up to `ahead` bytes
/// in front of it.
///
/// An archive's members are analyzed a window at a time, and the thread that
/// fills a window is the one that then waits for its analysis. An xz or bzip2
/// stream decodes at about 130 MB/s on that one thread, so the pool idled
/// while each window filled and the decoder idled while it was analyzed.
/// Decoded ahead, the next window is already in memory when the last one is
/// done.
///
/// The helper needs nothing but `source`: it never asks the rayon pool for
/// anything, so a pool worker may wait on it. Handing the *analysis* to a
/// helper instead, as this once did, has the worker wait on a thread that
/// waits for a worker; with one such archive per worker, all of them waited.
pub(super) struct ReadAhead {
    chunks: Receiver<io::Result<Vec<u8>>>,
    chunk: Vec<u8>,
    read: usize,
}

impl ReadAhead {
    /// Decode `source` on a thread of `scope`, at most `ahead` bytes in front
    /// of the returned reader. Dropping the reader stops the thread.
    ///
    /// # Errors
    /// When the thread cannot be started.
    pub(super) fn spawn<'scope, R: Read + Send + 'scope>(
        scope: &'scope Scope<'scope, '_>,
        mut source: R,
        ahead: usize,
    ) -> io::Result<Self> {
        let (tx, chunks) = sync_channel((ahead / CHUNK).max(1));
        std::thread::Builder::new()
            .name("archive-read-ahead".into())
            .spawn_scoped(scope, move || {
                loop {
                    let mut chunk = Vec::with_capacity(CHUNK);
                    let read = source.by_ref().take(CHUNK as u64).read_to_end(&mut chunk);
                    // What was decoded before an error is still the stream's:
                    // the reader gets those bytes, then the error.
                    let last = read.is_err() || chunk.len() < CHUNK;
                    if !chunk.is_empty() && tx.send(Ok(chunk)).is_err() {
                        return;
                    }
                    if let Err(error) = read {
                        let _ = tx.send(Err(error));
                    }
                    if last {
                        return;
                    }
                }
            })?;
        Ok(Self {
            chunks,
            chunk: Vec::new(),
            read: 0,
        })
    }
}

impl Read for ReadAhead {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.read == self.chunk.len() {
            match self.chunks.recv() {
                Ok(Ok(chunk)) => {
                    self.chunk = chunk;
                    self.read = 0;
                }
                Ok(Err(error)) => return Err(error),
                // The helper is done: the stream has ended.
                Err(_) => return Ok(0),
            }
        }
        let n = buf.len().min(self.chunk.len() - self.read);
        buf[..n].copy_from_slice(&self.chunk[self.read..self.read + n]);
        self.read += n;
        Ok(n)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    /// A reader that yields `good` bytes in small reads, then fails.
    struct Failing {
        good: usize,
    }

    impl Read for Failing {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if self.good == 0 {
                return Err(io::Error::other("stream cut"));
            }
            let n = buf.len().min(self.good).min(4096);
            buf[..n].fill(7);
            self.good -= n;
            Ok(n)
        }
    }

    #[test]
    fn the_reader_sees_the_bytes_of_the_source_in_order() {
        // Sizes on both sides of a chunk boundary, and a small look-ahead so
        // the helper has to wait for the reader.
        for len in [0, 1, CHUNK - 1, CHUNK, CHUNK + 1, 3 * CHUNK + 17] {
            let data: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
            let mut out = Vec::new();
            std::thread::scope(|scope| {
                let mut reader = ReadAhead::spawn(scope, data.as_slice(), CHUNK).unwrap();
                reader.read_to_end(&mut out).unwrap();
            });
            assert!(out == data, "{len} bytes arrive as they were");
        }
    }

    #[test]
    fn bytes_decoded_before_an_error_arrive_before_it() {
        let good = CHUNK + 4096;
        std::thread::scope(|scope| {
            let mut reader = ReadAhead::spawn(scope, Failing { good }, CHUNK).unwrap();
            let mut out = Vec::new();
            let error = reader.read_to_end(&mut out).unwrap_err();
            assert_eq!(error.to_string(), "stream cut");
            assert_eq!(out.len(), good, "the prefix is delivered whole");
        });
    }

    #[test]
    fn dropping_the_reader_stops_the_helper() {
        // The scope ends only when the helper does: a helper still blocked on
        // a full queue after its reader was dropped would hang here.
        let data = vec![1u8; 8 * CHUNK];
        std::thread::scope(|scope| {
            let mut reader = ReadAhead::spawn(scope, data.as_slice(), CHUNK).unwrap();
            let mut first = [0u8; 16];
            reader.read_exact(&mut first).unwrap();
        });
    }
}
