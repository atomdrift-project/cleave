# manifest-gen

Generates the trait-update `versions.toml` from the last few cleave engine
release tags and the last few `cleave-traits` commits, gating each pointer on
`cleave validate`. Go reimplementation of the automated path; see
`docs/UPDATE_DISTRIBUTION.md` for the design.

## What it does

1. Reads the last `--releases` engine release tags from `--repo` (this repo) →
   the manifest's `[<version>]` keys.
2. Walks the last `--commits` traits commits (newest first) and runs
   `cleave validate` (the `--engine` binary) against each committed tree.
   Results are memoized in `<out>/.validate-cache.tsv` on `(engineVer, commit)`.
3. **beta** = newest commit that passes. **stable** = newest passing commit at
   least `--soak-days` old (time-based soak; falls back to beta if none).
4. Builds reproducible artifacts (`git archive` → `xz -T1`, committed tree only)
   and computes sha256 in-process.
5. Renders `versions.toml`; with `--sign`, cosign-signs it.

The tree validated in step 2 and shipped in step 4 are the same bytes.

## Scope (v1)

Validation runs against the **single** `--engine` binary, so every enumerated
release key gets the same selected commits (logged). The cross-version matrix
needs archived prior engine binaries — see the design doc.

## Build & run

A parent `go.work` (sibling projects) doesn't list this module, so build with
the workspace disabled:

```sh
cd tools/manifest-gen && GOWORK=off go build -o manifest-gen .
```

```sh
tools/manifest-gen/manifest-gen \
  --traits ../cleave-traits --repo . \
  --engine ./target/release/cleave --out ./dist \
  --releases 2 --commits 10 --soak-days 7
```

Or: `make gen-manifest` (builds the release engine + the tool, then runs it).

Add `--sign --identity releaser@<project>.iam.gserviceaccount.com` to sign.
Use a **release** engine binary — the debug build validates an order of
magnitude slower.

## Flags

| Flag | Default | Meaning |
|------|---------|---------|
| `--traits` | `../cleave-traits` | traits git repo |
| `--repo` | `.` | engine repo (for release tags) |
| `--engine` | `./target/release/cleave` | validation oracle |
| `--out` | `dist` | artifacts + manifest output |
| `--releases` | `2` | recent release tags to key the manifest |
| `--commits` | `10` | recent traits commits to consider |
| `--soak-days` | `7` | stable lags beta by ≥ this many days |
| `--valid-days` | `7` | `valid_until` = now + this |
| `--channels` | `stable,beta` | channels to populate, in order |
| `--no-validate` | off | skip the gate (structure only; unsafe) |
| `--sign` / `--identity` | off | cosign-sign the manifest |

## Relationship to `../update-manifest`

`update-manifest` (shell) advances **one** explicit `(release, channel, commit)`.
`manifest-gen` (this) is the **automated** path: it discovers releases/commits
and runs the selection + soak logic itself. They emit the identical schema and
produce byte-identical artifacts for the same commit. Pick one to keep
long-term; both exist now so the shell version stays as a minimal reference.
