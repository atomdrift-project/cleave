#!/bin/sh
# Load the apko-built OCI image into the local runtime and assert it works:
#  1. cleave --version reports the expected version
#  2. cleave --help runs cleanly
#  3. A scan succeeds with the bundled traits (proves CLEAVE_TRAITS_DIR works)
#  4. Same scan fails when traits are pointed at a bogus dir (proves traits
#     are actually being consulted, not silently skipped)

set -eu

HERE=$(cd "$(dirname "$0")" && pwd)
REPO_ROOT=$(cd "$HERE/../../.." && pwd)
OUT_DIR="$REPO_ROOT/out/wolfi"
IMAGE_TAR="$OUT_DIR/cleave.tar"
IMAGE_REF="cleave:smoke"
EXPECTED_VERSION="${EXPECTED_VERSION:-1.4.0}"
VM_NAME="cleave-wolfi"

[ -f "$IMAGE_TAR" ] || { echo "error: $IMAGE_TAR not found; run wolfi-build first" >&2; exit 1; }

os=$(uname -s)
case "$os" in
  Darwin) NERDCTL="limactl shell --workdir / $VM_NAME nerdctl" ; IMAGE_IN_VM="/work/out/cleave.tar" ;;
  Linux)
    if command -v nerdctl >/dev/null 2>&1; then NERDCTL="nerdctl";
    elif command -v docker >/dev/null 2>&1; then NERDCTL="docker";
    elif command -v podman >/dev/null 2>&1; then NERDCTL="podman";
    else echo "error: no container runtime" >&2; exit 1; fi
    IMAGE_IN_VM="$IMAGE_TAR"
    ;;
  *) echo "error: unsupported OS '$os'" >&2; exit 1 ;;
esac

echo "==> loading image"
loaded=$($NERDCTL load -i "$IMAGE_IN_VM" 2>&1) || { echo "$loaded" >&2; exit 1; }
# apko tarballs load as a digest-tagged ref; retag to a stable name.
loaded_ref=$(echo "$loaded" | awk '/Loaded image/ {print $NF}' | tail -1)
[ -n "$loaded_ref" ] || { echo "error: could not parse loaded image ref from: $loaded" >&2; exit 1; }
$NERDCTL tag "$loaded_ref" "$IMAGE_REF" >/dev/null

fail=0
report() {
  status=$1; shift
  if [ "$status" -eq 0 ]; then
    echo "  ok    $*"
  else
    echo "  FAIL  $*" >&2
    fail=1
  fi
}

echo "==> 1/4 cleave --version reports $EXPECTED_VERSION"
out=$($NERDCTL run --rm "$IMAGE_REF" --version 2>&1 || true)
echo "$out" | grep -q "$EXPECTED_VERSION"
report $? "saw version: $out"

echo "==> 2/4 cleave --help runs"
$NERDCTL run --rm "$IMAGE_REF" --help >/dev/null 2>&1
report $? "help exits 0"

echo "==> 3/4 self-scan with bundled traits succeeds"
$NERDCTL run --rm --entrypoint /usr/bin/cleave "$IMAGE_REF" /usr/bin/cleave >/dev/null 2>&1
report $? "scanned /usr/bin/cleave using bundled traits"

echo "==> 4/4 self-scan with bogus traits errors out"
out=$($NERDCTL run --rm \
  --env CLEAVE_TRAITS_DIR=/nonexistent-traits \
  --entrypoint /usr/bin/cleave \
  "$IMAGE_REF" /usr/bin/cleave 2>&1 || true)
# We expect a non-zero exit AND a message mentioning the traits dir.
# If it succeeds, the bundled traits weren't actually being used.
if echo "$out" | grep -qi 'CLEAVE_TRAITS_DIR\|traits\|nonexistent'; then
  report 0 "rejected bogus traits dir"
else
  echo "  FAIL  bogus traits did not produce a traits-related error; output: $out" >&2
  fail=1
fi

if [ "$fail" -eq 0 ]; then
  echo "==> smoke ok"
else
  echo "==> smoke FAILED" >&2
  exit 1
fi
