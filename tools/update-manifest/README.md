# update-manifest

Builds a signed trait-update manifest for R2 distribution. Implements the v1
(current-engine) slice of `docs/UPDATE_DISTRIBUTION.md`.

## What it does

For a trait commit, in order:

1. **Resolve** the commit → `key` (short sha), `date`, filename `<date>-<key>.tar.xz`.
2. **Archive** the committed tree via `git archive` — deterministic bytes,
   committed content only (no untracked files).
3. **Validate** that exact tree against the engine you pass (`cleave validate`);
   a non-zero exit aborts and does **not** advance the pointer.
4. **Build** the reproducible artifact (`xz -T1`; single-thread = deterministic).
5. **Update** the source-of-truth TSVs in `--out`:
   - `artifacts.tsv` — immutable, append-only catalog (one row per commit).
   - `pointers.tsv` — `(release, channel) → key`, replaced in place.
6. **Render** `versions.toml` (via `render-manifest.awk`, deterministic).
7. **Sign** `versions.toml` with cosign keyless (only with `--sign`).

The artifact validated in step 3 and shipped in step 4 are the same bytes, both
derived from the commit.

## Scope (v1)

Validates against **one** engine — the `--engine` binary. The cross-version
"last 5 releases" matrix in the design doc needs prior engine binaries archived
to R2 first; until then, run this per release line with that line's engine.

## Usage

```sh
tools/update-manifest/build-manifest.sh \
  --traits ../traits-dev --commit HEAD \
  --release 2.0.0 --channel beta \
  --engine ./target/debug/cleave --out ./dist
```

Add `--sign --identity releaser@<project>.iam.gserviceaccount.com` to sign.
`--no-validate` skips the gate (use only for pointer-only edits / testing).

Or via make:

```sh
make update-manifest TRAITS=../traits-dev COMMIT=HEAD RELEASE=2.0.0 CHANNEL=beta
```

## Signing note

`--sign` runs `cosign sign-blob --new-bundle-format`, which records the signer's
identity in **public, permanent** transparency logs (Fulcio CT + Rekor). Use the
dedicated `releaser@` service account, not a personal identity. Verification was
proven against `sigstore-rs` v0.14 — see the spike referenced in the design doc.

## Files

- `build-manifest.sh` — orchestrator.
- `render-manifest.awk` — pure TSV → `versions.toml` renderer (inputs must be
  pre-sorted; the script does this). Distinguishes its two inputs by argument
  order, not filename.

## Not yet wired

- R2 upload (tarball first, then `versions.toml`, then the `.sigstore.json`).
- The cross-version matrix + archived engine binaries.
- The `valid_until` window is fixed at 7 days; revisit when poll cadence is set.
