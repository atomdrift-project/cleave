# Test samples

Some tests need real malicious files. They are stored XOR-encoded with the key
`0x42` and named with a `_xor_0x42_encoded` suffix, so the repository never
holds a live sample that endpoint protection would quarantine or that someone
could run by accident. Tests decode them in memory
(`crate::test_samples::read` in unit tests, `support::sample` and
`support::sample_file` in `tests/it`).

To encode or decode a file by hand (XOR is its own inverse):

```sh
python3 -c 'import sys; d=open(sys.argv[1],"rb").read(); open(sys.argv[2],"wb").write(bytes(b^0x42 for b in d))' IN OUT
```

The directories that hold untrusted samples are listed in
`tests/it/sample_encoding_test.rs`, which fails if a raw file appears there.
Synthetic fixtures written for a test (no live payload) are exempt and listed in
that test by name.
