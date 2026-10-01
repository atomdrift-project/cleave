# XOR-embedded universal Mach-O dropper

Wrapper SHA-256: `30c99015f9c432604d8a8206ce8dcb4fba7866b062e5bd1a8f0adb88fba8807c`.
Untrusted malware fixture; static extraction only. Size: 227,184 bytes.

The reviewed `xeryna` function copies 153,824 bytes from file offset 0x6210,
XORs every byte with the global key 0x9c, writes `/var/tmp/exe`, makes it
executable, invokes it, and removes it. The recovered image is a universal
Mach-O with x86_64 and ARM64 slices. SHA-256:
`5f522222dd8c3237058f7b7b00e717d1365f14aea6f45e41c9f982dd866cb8c0`.

The existing string pass recovers an XorKey observation at offset 0x6210 and
raw strings from this image. `decode_xor_fat_macho` now exposes the same validated
binary recovery to consumers. It takes an already located candidate and key,
uses the FAT architecture table for the exact extent, caps output at 32 MiB,
and requires every slice to parse as Mach-O. Zero keys are rejected.

Cleave uses these located key observations for recursive binary analysis, exposing
socket imports, directory iteration, popen, and the embedded executable's own
metadata. It considers at most eight candidates and retains at most 32 MiB per
file. It performs no second section scan or key search. Both standalone and
archive-member analysis paths use this recovery.

Independent manual XOR and the native API produce identical bytes; the audit,
all three decompilations, and function coverage are preserved in
`/var/tmp/triage40/review/macho-30c990/`. Regression coverage now includes original specimen/output hashes, public key
provenance, malformed tables/slices, truncation, arbitrary keys and size limits
in stng; Cleave additionally tests candidate/output budgets, deduplication,
conservative nesting and standalone/archive recursive analysis.
See `tests/test_xor_fat_macho.rs` in stng and
`src/extractors/encoded_payload_xor_test.rs`, `tests/xor_macho_payload.rs` in Cleave.
