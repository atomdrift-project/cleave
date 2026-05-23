# Wolfi packaging for cleave

This directory builds [Wolfi](https://wolfi.dev) apks for `cleave` and a
`cleave-traits` data subpackage, then assembles them into a minimal OCI
image. The `melange.yaml` is shaped to be drop-in copyable into
[wolfi-dev/os](https://github.com/wolfi-dev/os) for upstream submission;
the local Makefile targets exist so contributors can iterate on the
package definition without a Wolfi-dev clone.

## Layout

```
packaging/wolfi/
  melange.yaml              # cleave + cleave-traits subpackages (UPSTREAMABLE)
  apko.yaml                 # local OCI app image (NOT upstreamed)
  lima.yaml                 # Ubuntu 26.04 LTS sandbox for macOS builds
  scripts/
    bootstrap-lima.sh       # idempotent VM + runtime setup
    build.sh                # melange build → apko build, with stamp-skip
    smoke-test.sh           # asserts the image runs and uses bundled traits
```

## Local build (macOS or Linux)

```sh
make wolfi          # bootstrap + build + smoke-test (~10 min cold, ~0s warm)
make wolfi-build    # just (re)build the image
make wolfi-test     # just run smoke tests against an existing image
make wolfi-shell    # interactive shell in the built image
make wolfi-clean    # remove out/wolfi/ (keeps the Lima VM)
make wolfi-nuke     # also deletes the Lima VM (slow to recreate)
```

The Makefile target is idempotent: re-running `make wolfi` after a
successful build is a no-op unless `melange.yaml`, `apko.yaml`, or the
cleave source tree has changed (hash compared against
`out/wolfi/.build.stamp`).

Per-arch build:

```sh
WOLFI_ARCH=aarch64 make wolfi-build      # default is the host arch
WOLFI_ARCH=x86_64  make wolfi-build      # cross via QEMU; significantly slower
```

### macOS specifics

On macOS the build runs inside a dedicated Lima VM named `cleave-wolfi`
(Ubuntu 26.04 LTS, 4 CPU / 6GB RAM, see `lima.yaml`). The bootstrap
script creates and starts the VM idempotently; `make wolfi-nuke` removes
it. Inside the VM, [nerdctl](https://github.com/containerd/nerdctl) runs
Chainguard's official `melange` and `apko` images.

### Linux specifics

The bootstrap probes `nerdctl`, `docker`, then `podman` and uses the
first available runtime. Volumes are mounted directly from the host —
no VM in between.

## How local dev differs from upstream Wolfi

`melange.yaml` declares a `git-checkout` step that pulls the cleave
source from codeberg at a pinned commit. That's what upstream Wolfi CI
runs. Locally, `build.sh` passes `--source-dir` to melange, which
replaces the checkout with a bind-mount of the working tree. This lets
you iterate on the package definition without pushing to codeberg, and
keeps the upstream pipeline reproducible.

The `cleave-traits` subpackage still fetches from codeberg via
`git-checkout` (~1MB; melange caches it under `~/.cache/cleave-wolfi`).

## Upstream blocker: filefacts path dep

Before this can land in [wolfi-dev/os](https://github.com/wolfi-dev/os),
cleave's `Cargo.toml` reference to `filefacts = { path = "../filefacts" }`
must go. Pick one:

- **Move filefacts into cleave's workspace** — simplest if filefacts has
  no other consumers.
- **Publish filefacts to crates.io**, then switch to `filefacts = "0.1"`.
- **Switch to a git dep**: `filefacts = { git =
  "https://codeberg.org/atomdrift/filefacts", tag = "v0.1.0" }`.

The local build works around this by rsyncing both repos into a staging
dir, so you can iterate on the package definition today and unblock the
upstream PR once the dep shape is fixed.

## Submitting upstream

1. Resolve the filefacts dep above.
2. Tag a cleave release (`vX.Y.Z` on codeberg).
2. Update `melange.yaml`:
   - `package.version` → new version (drop the `v` prefix).
   - `expected-commit` in the first `git-checkout` → the tag's commit SHA.
   - `expected-commit` in the `cleave-traits` subpackage → the
     cleave-traits commit you want shipped with this release.
3. Validate locally: `make wolfi` should pass.
4. In a [wolfi-dev/os](https://github.com/wolfi-dev/os) clone:

   ```sh
   cp .../cleave/packaging/wolfi/melange.yaml packages/cleave.yaml
   make package/cleave
   ```

   This runs the same pipeline that Wolfi's CI uses. If it builds clean
   and `test:` passes, open a PR.

Wolfi's [update bot](https://github.com/wolfi-dev/wolfictl) reads the
`update:` block at the bottom of `melange.yaml` and will open PRs for
new cleave releases automatically once the package is in upstream.

## Troubleshooting

- **`limactl: VM already running with stale config`** — `make wolfi-nuke`
  then `make wolfi`.
- **First build is very slow (15+ min)** — expected; cargo downloads
  ~500 crates and compiles them inside the sandbox. The stamp file
  short-circuits subsequent runs.
- **`smoke FAILED` on test 4** — the bogus-traits negative check. If
  cleave's behavior changes such that it tolerates a missing
  `CLEAVE_TRAITS_DIR`, update `smoke-test.sh` to look for the new
  symptom rather than weakening the assertion.
