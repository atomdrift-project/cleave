# lzx

LZX decompression for the CAB, CHM and XNB containers, and the LZX DELTA format described in
[MS-PATCH][1]. Decompression only. Malformed input yields an error rather than a panic.

This crate is a fork of [lzxd][2] 0.2.6 by Lonami Exo, maintained as part of cleave.

```rust
use lzx::{Lzxd, WindowSize};

let mut decoder = Lzxd::new(WindowSize::KB64);

// Each chunk is one compressed frame, with the container's chunk-size prefix already
// stripped, and decodes to `lzx::MAX_CHUNK_SIZE` (32 KB) except possibly the last.
while let Some((chunk, output_len)) = next_chunk() {
    let decompressed = decoder.decompress_next(&chunk, output_len)?;
    write_data(decompressed);
}
```

- `Lzxd::new` reads the E8-translation header that begins CAB, CHM, XNB and LZX DELTA
  streams.
- `decompress_next(chunk, output_len)` returns a slice of exactly `output_len` bytes that
  borrows the decoder until the next call, or a `DecompressError`.
- `reset()` returns the decoder to its initial state, as CHM requires at every reset
  interval.
- The window size is not stored in the bitstream; take it from the container (for example
  the CHM `LZXC` control data).

Match lengths beyond 257 (the LZX DELTA Extra Length field) are not decoded.

## Credits

lzxd was written by Lonami Exo. Its author thanks [LeonBlade's xnbcli][3], which helped debug
the implementation, and [dorkbox's CabParser][4], which helped validate it against real-world
data.

## License

Licensed under either of

* Apache License, Version 2.0 ([LICENSE-APACHE] or
  http://www.apache.org/licenses/LICENSE-2.0)

* MIT license ([LICENSE-MIT] or http://opensource.org/licenses/MIT)

at your option, as is the original lzxd.

[1]: https://docs.microsoft.com/en-us/openspecs/exchange_server_protocols/ms-patch/cc78752a-b4af-4eee-88cb-01f4d8a4c2bf
[2]: https://github.com/Lonami/lzxd
[3]: https://github.com/LeonBlade/xnbcli
[4]: https://github.com/dorkbox/CabParser/
[LICENSE-APACHE]: LICENSE-APACHE
[LICENSE-MIT]: LICENSE-MIT
