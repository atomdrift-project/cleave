# XOR-obfuscated source fixtures

Positive fixtures for XOR detection in source. Each pairs a single-byte XOR
payload (the encoded IOC `https://evil.example.com/stage2/payload.exe`, key
`0x58`) with a genuine `^`-based decoder. stng's XOR scanners are built for
binaries and run only on binary input, so these are detected by source-shaped
signals.

| file | language | proves |
|------|----------|--------|
| `xor_loader.js` | JavaScript | AST XOR traits (`xor-operator`, `js-xor-decoder-ast`) |
| `xor_base64_stealer.py` | Python | XOR-then-base64 stealer pattern |

The IOC is fictional; these are benign test inputs, not live malware.

Regenerate by XORing the IOC with `0x58` and embedding the (printable,
embed-safe) result verbatim. Guarded by `tests/it/xor_source_detection_test.rs`.
