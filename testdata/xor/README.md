# XOR-obfuscated source fixtures

Positive fixtures for the source/script XOR-scan gate (filefacts
`formats::mod` → `common::has_xor_intent`). Each pairs a **real** single-byte
XOR payload (the encoded IOC `https://evil.example.com/stage2/payload.exe`,
key `0x58`) with a genuine `^`-based decoder, so the bytes show XOR intent and
the gate runs stng's XOR scan.

| file | language | proves |
|------|----------|--------|
| `xor_dropper.c` | C | scan-based `metadata/encoded-payload/xor` |
| `xor_loader.js` | JavaScript | AST XOR traits (`xor-operator`, `js-xor-decoder-ast`) |
| `xor_raw_beacon.py` | Python | raw-XOR payload → `encoded-payload/xor` |
| `xor_base64_stealer.py` | Python | XOR-then-base64 stealer pattern |
| `xor_drop.sh` | bash | scan-based `metadata/encoded-payload/xor` |

The IOC is fictional; these are benign test inputs, not live malware.

Regenerate with `tests/../` helper or by XORing the IOC with `0x58` and embedding
the (printable, embed-safe) result verbatim. Guarded by
`tests/xor_source_detection_test.rs`. The companion negative case — benign
source with no `^`/`xor` must NOT produce a speculative XOR finding — is covered
by the realworld benchmark corpus and the filefacts `has_xor_intent` unit tests.
