# Office corpus

Ground-truth corpus for cleave's office-document accuracy regression
test (`tests/office_corpus_test.rs`).

## Layout

```
tests/testdata/office/
├── malicious/             malware samples (xor-encoded if from public sources)
├── benign-with-macros/    legitimate documents that use VBA
├── benign-no-macros/      legitimate documents without macros
├── snapshots/             insta snapshots (one per sample)
└── manifest.yaml          per-sample expected behavior
```

## Encoding

Per-project policy (and following maldoca's convention), known-malicious
samples are stored XOR-encoded with key `0x42` and named with the
`_xor_0x42_encoded` suffix. The harness decodes them on the fly into a
temp file before running the analyzer. **Never** commit a raw malicious
sample.

To encode/decode a sample manually:

```sh
# Encode (or decode — XOR is its own inverse with the same key)
python3 -c "
import sys
data = open(sys.argv[1], 'rb').read()
sys.stdout.buffer.write(bytes(b ^ 0x42 for b in data))
" sample.docm > sample.docm_xor_0x42_encoded
```

## Manifest format

`manifest.yaml` lists each sample with its expected criticality bucket
and the trait IDs we expect to fire. The harness asserts:

1. The sample analyzes without panic.
2. The maximum criticality across findings is at least the manifest's
   `min_max_crit` (so adding a new trait that *raises* coverage doesn't
   regress).
3. Every trait ID in `must_fire` appears in the findings list.
4. No trait ID in `must_not_fire` appears.
5. `office.*` metrics roundtrip through serde without producing extra
   keys for fields the manifest declares as `expected_zero`.

Snapshots (via `insta`) capture the *full* finding list per sample so
behavior diffs surface in PRs. To accept a snapshot change after an
intentional rule update:

```sh
cargo insta review --workspace-root .
```

## Adding a sample

1. Drop the file in the right bucket (encode if malicious).
2. Add an entry to `manifest.yaml` with `path`, `min_max_crit`, and any
   `must_fire`/`must_not_fire` trait IDs that anchor the expected
   detection.
3. Run `cargo test --test office_corpus_test`. On first run, accept the
   generated snapshot with `cargo insta accept`.

## Initial state

This corpus starts empty. The harness skips with a clear message when
no samples are present, so the test passes on a fresh checkout. As
samples are added, the harness automatically gates them.
