# XOR-decoded identifier mistaken for nested Base64

SHA-256: `d29ae5317de4d11481e1fde1961dd85b56c364cb8467f9771ec97bfdb792e486`.
118,304-byte universal Mach-O. Untrusted malware fixture; static analysis only.

Both slices implement a detached remote AppleScript loader and ZIP uploader.
All application functions were reviewed in Ghidra and Rizin. The 17 initialized
constants were reconstructed from operands and file bytes independently of stng;
stng recovers all 14 that meet its default minimum length. The 64-character
hexadecimal build ID is passed unchanged into `txd` / `buildtxd` query arguments.
There is no Base64 or hex decoding stage in the native code after XOR.

Before the repair, `decompress_and_nest` accepted any Base64-compatible alphabet,
so it decoded the build ID into opaque bytes and emitted
`metadata/encoded-payload/xor-base64`. Nested candidates now require readable
text, a recognized file header, or successful decompression. Rejected candidates
retain the already decoded value and its existing encoding chain.

Expected scan: XOR finding present; XOR → Base64 finding absent; remote loader
and chunk-upload findings retained. Evidence and complete decompilations:
`/var/tmp/triage40/review/macho-gapi-update/`.
No unit tests added or run.
