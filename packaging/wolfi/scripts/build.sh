#!/bin/sh
# Build cleave + cleave-traits apks via melange, then assemble an OCI
# image via apko. Idempotent: skips work when source + yaml hashes match
# the on-disk stamp.

set -eu

HERE=$(cd "$(dirname "$0")" && pwd)
PKG_DIR=$(cd "$HERE/.." && pwd)
REPO_ROOT=$(cd "$PKG_DIR/../.." && pwd)
SIBLING_DIR=$(cd "$REPO_ROOT/.." && pwd)
OUT_DIR="$REPO_ROOT/out/wolfi"
STAGE_DIR="$OUT_DIR/source"
STAMP="$OUT_DIR/.build.stamp"
VM_NAME="cleave-wolfi"
APKO_IMAGE="${APKO_IMAGE:-cgr.dev/chainguard/apko:latest}"
MELANGE_IMAGE="${MELANGE_IMAGE:-cgr.dev/chainguard/melange:latest}"

# Default arch is the host arch; override with WOLFI_ARCH=x86_64,aarch64.
host_arch=$(uname -m)
case "$host_arch" in
  arm64|aarch64) default_arch=aarch64 ;;
  x86_64|amd64)  default_arch=x86_64 ;;
  *) echo "error: unsupported host arch '$host_arch'" >&2; exit 1 ;;
esac
WOLFI_ARCH="${WOLFI_ARCH:-$default_arch}"

mkdir -p "$OUT_DIR/packages" "$STAGE_DIR"

# Generate a local-build variant of melange.yaml with the upstream
# `git-checkout` step removed. melange's --source-dir pre-populates the
# workspace, but the subsequent git-checkout would overwrite it with the
# tagged upstream tree — causing a mismatch with the working copy. The
# stripped step is bracketed by LOCAL_BUILD_STRIP_{BEGIN,END} markers.
LOCAL_YAML="$OUT_DIR/melange.local.yaml"
# Also drop `--locked` from cargo invocations: rewriting Cargo.toml to
# vendor filefacts forces cargo to refresh the lock, which --locked
# forbids. Upstream keeps --locked.
awk '
  /# LOCAL_BUILD_STRIP_BEGIN/ { skip = 1; next }
  /# LOCAL_BUILD_STRIP_END/   { skip = 0; next }
  !skip
' "$PKG_DIR/melange.yaml" \
  | sed 's/ --locked//g' \
  > "$LOCAL_YAML.new" && mv -f "$LOCAL_YAML.new" "$LOCAL_YAML"

# Compute a stable hash of inputs that should trigger a rebuild.
compute_hash() {
  {
    (cd "$REPO_ROOT" && find src crates cleave-macros Cargo.toml Cargo.lock \
        -type f \
        -not -path '*/target/*' \
        -not -name '*.swp' \
        -print0 2>/dev/null \
      | sort -z \
      | xargs -0 shasum -a 256 2>/dev/null)
    (cd "$SIBLING_DIR/filefacts" && find . \
        -type f \
        -not -path '*/target/*' \
        -not -path '*/.git/*' \
        -not -name '*.swp' \
        -print0 2>/dev/null \
      | sort -z \
      | xargs -0 shasum -a 256 2>/dev/null)
    shasum -a 256 "$PKG_DIR/melange.yaml" "$PKG_DIR/apko.yaml" 2>/dev/null
    echo "arch=$WOLFI_ARCH"
  } | shasum -a 256 | awk '{print $1}'
}

want_hash=$(compute_hash)
if [ -f "$STAMP" ] && [ "$(cat "$STAMP")" = "$want_hash" ] && [ -f "$OUT_DIR/cleave.tar" ]; then
  echo "==> up to date (hash $want_hash); skipping build"
  echo "    force rebuild: rm $STAMP"
  exit 0
fi

# Stage a clean copy of cleave with filefacts vendored as a subdirectory.
# Strips target/ (~23GB), .git/, our own out/ to keep melange's workspace
# copy fast. Cleave depends on `../filefacts` via a path dep that won't
# resolve inside melange's chroot, so we copy filefacts into the cleave
# stage at _filefacts/ and rewrite Cargo.toml to point there + exclude
# it from the workspace. The unmodified upstream layout is unaffected;
# this rewriting is local-build-only.
echo "==> staging source into $STAGE_DIR"
command -v rsync >/dev/null 2>&1 || { echo "error: rsync required" >&2; exit 1; }
EXCLUDES="--exclude=target/ --exclude=.git/ --exclude=out/ --exclude=node_modules/ --exclude=.DS_Store"
# shellcheck disable=SC2086  # word-splitting EXCLUDES is intentional
rsync -a --delete $EXCLUDES "$REPO_ROOT/" "$STAGE_DIR/cleave/"
# shellcheck disable=SC2086
rsync -a --delete $EXCLUDES "$SIBLING_DIR/filefacts/" "$STAGE_DIR/cleave/_filefacts/"

# Rewrite cleave's Cargo.toml in the stage to point filefacts at the
# vendored copy and exclude it from the cleave workspace.
awk '
  /^members = \[/ && !ws_excluded {
    print
    print "exclude = [\"_filefacts\"]"
    ws_excluded = 1
    next
  }
  /^filefacts = \{ path = "\.\.\/filefacts" \}/ {
    print "filefacts = { path = \"_filefacts\" }"
    next
  }
  { print }
' "$STAGE_DIR/cleave/Cargo.toml" > "$STAGE_DIR/cleave/Cargo.toml.new"
mv -f "$STAGE_DIR/cleave/Cargo.toml.new" "$STAGE_DIR/cleave/Cargo.toml"

# Sanity-check the rewrite landed.
grep -q '^filefacts = { path = "_filefacts" }$' "$STAGE_DIR/cleave/Cargo.toml" \
  || { echo "error: Cargo.toml rewrite for filefacts failed" >&2; exit 1; }
grep -q '^exclude = \["_filefacts"\]$' "$STAGE_DIR/cleave/Cargo.toml" \
  || { echo "error: Cargo.toml workspace.exclude injection failed" >&2; exit 1; }

# Pick the container runtime. Inside the container:
#   /src     staged source (cleave/ + filefacts/), read-only
#   /out     build output (apks, OCI tarball, signing key)
#   /cache   persistent melange + apko cache
os=$(uname -s)
case "$os" in
  Darwin)
    # --workdir / avoids the harmless but noisy "cd: ... No such file"
    # warning when limactl shell tries to mirror the macOS CWD.
    NERDCTL="limactl shell --workdir / $VM_NAME nerdctl"
    # /work/out is the lima mount; staging is a subdir of it.
    SRC_IN_RT="/work/out/source"
    OUT_IN_RT="/work/out"
    CACHE_IN_RT="/work/cache"
    ;;
  Linux)
    if command -v nerdctl >/dev/null 2>&1; then NERDCTL="nerdctl";
    elif command -v docker >/dev/null 2>&1; then NERDCTL="docker";
    elif command -v podman >/dev/null 2>&1; then NERDCTL="podman";
    else echo "error: no container runtime" >&2; exit 1; fi
    SRC_IN_RT="$STAGE_DIR"
    OUT_IN_RT="$OUT_DIR"
    CACHE_IN_RT="${XDG_CACHE_HOME:-$HOME/.cache}/cleave-wolfi"
    mkdir -p "$CACHE_IN_RT"
    ;;
  *) echo "error: unsupported OS '$os'" >&2; exit 1 ;;
esac

# Generate a one-shot melange signing key if missing. Not trusted by
# anyone; apko requires a key when consuming a local melange-built repo.
if [ ! -f "$OUT_DIR/melange.rsa" ]; then
  echo "==> generating local melange signing key"
  $NERDCTL run --rm \
    -v "$OUT_IN_RT:/out" \
    -w /out \
    "$MELANGE_IMAGE" keygen melange.rsa
fi

echo "==> building cleave + cleave-traits ($WOLFI_ARCH)"
# --source-dir overrides the upstream git-checkout step in melange.yaml
# with the local staging tree. The upstream fetch is preserved so the
# same file works unchanged in wolfi-dev/os CI.
$NERDCTL run --rm \
  -v "$SRC_IN_RT:/src:ro" \
  -v "$OUT_IN_RT:/out" \
  -v "$CACHE_IN_RT:/cache" \
  -w /out \
  --privileged \
  "$MELANGE_IMAGE" build \
    /out/melange.local.yaml \
    --arch "$WOLFI_ARCH" \
    --source-dir /src/cleave \
    --cache-dir /cache/melange \
    --signing-key /out/melange.rsa \
    --out-dir /out/packages

# apko needs the pub key adjacent to the @local repo for verification.
cp -f "$OUT_DIR/melange.rsa.pub" "$OUT_DIR/packages/melange.rsa.pub"

echo "==> assembling OCI image with apko"
TAR_TMP="$OUT_DIR/cleave.tar.new"
rm -f "$TAR_TMP"
$NERDCTL run --rm \
  -v "$SRC_IN_RT:/src:ro" \
  -v "$OUT_IN_RT:/out" \
  -v "$CACHE_IN_RT:/cache" \
  -w /out \
  "$APKO_IMAGE" build \
    /src/cleave/packaging/wolfi/apko.yaml \
    cleave:latest \
    /out/cleave.tar.new \
    --arch "$WOLFI_ARCH" \
    --keyring-append /out/melange.rsa.pub \
    --cache-dir /cache/apko

mv -f "$TAR_TMP" "$OUT_DIR/cleave.tar"
echo "$want_hash" > "$STAMP.new" && mv -f "$STAMP.new" "$STAMP"

echo "==> done: $OUT_DIR/cleave.tar"
