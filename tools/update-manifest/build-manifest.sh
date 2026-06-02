#!/usr/bin/env bash
#
# build-manifest.sh — validate a trait commit against the current engine, build
# a reproducible artifact, advance the channel pointer, render + (optionally)
# sign versions.toml.
#
# Scope (v1): validates against ONE engine (the cleave binary you pass). The
# cross-version "last 5 releases" matrix arrives once prior engine binaries are
# archived — see docs/UPDATE_DISTRIBUTION.md.
#
# The artifact is `git archive` of the commit: deterministic bytes, committed
# tree only (no untracked files), provably the same tree that was validated.
#
# Usage:
#   build-manifest.sh --traits DIR --commit REF --release VER --channel CH \
#                     --engine PATH --out DIR [--sign --identity EMAIL --issuer URI] \
#                     [--no-validate]
#
# Example:
#   build-manifest.sh --traits ../cleave-traits --commit HEAD \
#       --release 2.0.0 --channel beta \
#       --engine ./target/debug/cleave --out ./dist
#
set -euo pipefail

die() { echo "error: $*" >&2; exit 1; }

TRAITS="" COMMIT="" RELEASE="" CHANNEL="" ENGINE="" OUT=""
SIGN=0 IDENTITY="" ISSUER="https://accounts.google.com" VALIDATE=1
while [ $# -gt 0 ]; do
  case "$1" in
    --traits)     TRAITS=$2; shift 2;;
    --commit)     COMMIT=$2; shift 2;;
    --release)    RELEASE=$2; shift 2;;
    --channel)    CHANNEL=$2; shift 2;;
    --engine)     ENGINE=$2; shift 2;;
    --out)        OUT=$2; shift 2;;
    --sign)       SIGN=1; shift;;
    --identity)   IDENTITY=$2; shift 2;;
    --issuer)     ISSUER=$2; shift 2;;
    --no-validate) VALIDATE=0; shift;;
    *) die "unknown arg: $1";;
  esac
done

[ -n "$TRAITS" ]  || die "--traits required"
[ -n "$COMMIT" ]  || die "--commit required"
[ -n "$RELEASE" ] || die "--release required"
[ -n "$CHANNEL" ] || die "--channel required"
[ -n "$OUT" ]     || die "--out required"
[ -d "$TRAITS/.git" ] || git -C "$TRAITS" rev-parse --git-dir >/dev/null 2>&1 || die "--traits is not a git repo: $TRAITS"
[ "$SIGN" -eq 1 ] && [ -z "$IDENTITY" ] && die "--sign requires --identity"

HERE=$(cd "$(dirname "$0")" && pwd)
mkdir -p "$OUT"

# --- resolve the commit to immutable identity + naming ---------------------
FULL_COMMIT=$(git -C "$TRAITS" rev-parse "$COMMIT")          || die "bad commit: $COMMIT"
KEY=$(git -C "$TRAITS" rev-parse --short=9 "$COMMIT")
DATE=$(git -C "$TRAITS" show -s --format=%cd --date=format:%Y-%m-%d "$FULL_COMMIT")
FILE="${DATE}-${KEY}.tar.xz"
echo "commit $FULL_COMMIT  key=$KEY  date=$DATE  file=$FILE"

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

# --- materialize the committed tree (canonical bytes for this commit) ------
git -C "$TRAITS" archive --format=tar "$FULL_COMMIT" > "$WORK/tree.tar"

# --- validate gate: same tree we will ship ---------------------------------
if [ "$VALIDATE" -eq 1 ]; then
  [ -n "$ENGINE" ] || die "--engine required unless --no-validate"
  mkdir -p "$WORK/checkout"
  tar -xf "$WORK/tree.tar" -C "$WORK/checkout"
  echo "validating $KEY against $($ENGINE --version 2>/dev/null | head -1 || echo "$ENGINE") ..."
  if ! CLEAVE_TRAITS_DIR="$WORK/checkout" "$ENGINE" validate; then
    die "validation FAILED for commit $KEY — pointer NOT advanced"
  fi
  echo "✓ validation passed"
else
  echo "skipping validation (--no-validate)"
fi

# --- reproducible artifact: xz -T1 (single-thread = deterministic) ---------
xz -9 -T1 -c < "$WORK/tree.tar" > "$OUT/$FILE"
SHA=$(shasum -a 256 "$OUT/$FILE" | cut -d' ' -f1)
echo "✓ built $OUT/$FILE  sha256=$SHA"

# --- update source-of-truth TSVs (catalog + pointers) ----------------------
ARTIFACTS="$OUT/artifacts.tsv"
POINTERS="$OUT/pointers.tsv"
touch "$ARTIFACTS" "$POINTERS"

# catalog: add this artifact if absent (immutable, append-only, keyed by KEY)
if ! cut -f1 "$ARTIFACTS" | grep -qx "$KEY"; then
  printf '%s\t%s\t%s\t%s\t%s\n' "$KEY" "$FILE" "$SHA" "$FULL_COMMIT" "$DATE" >> "$ARTIFACTS"
fi

# pointer: set (release, channel) -> KEY, replacing any prior row for that pair
TMP_PTR=$(mktemp)
awk -F'\t' -v r="$RELEASE" -v c="$CHANNEL" '!($1==r && $2==c)' "$POINTERS" > "$TMP_PTR" || true
printf '%s\t%s\t%s\n' "$RELEASE" "$CHANNEL" "$KEY" >> "$TMP_PTR"
mv "$TMP_PTR" "$POINTERS"

# --- render versions.toml (deterministic: sort before awk) -----------------
VALID_UNTIL=$(date -u -v+7d '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null \
           || date -u -d '+7 days' '+%Y-%m-%dT%H:%M:%SZ')
SA=$(mktemp); SP=$(mktemp)
sort -t'	' -k1,1 "$ARTIFACTS" > "$SA"
# deterministic order: channel alphabetical, then release descending (newest
# first). Order is semantically irrelevant in TOML; this just keeps diffs stable.
sort -t'	' -k2,2 -k1,1r "$POINTERS" > "$SP"
mv "$SA" "$OUT/.artifacts.sorted"; mv "$SP" "$OUT/.pointers.sorted"
awk -v vu="$VALID_UNTIL" -f "$HERE/render-manifest.awk" \
    "$OUT/.artifacts.sorted" "$OUT/.pointers.sorted" > "$OUT/versions.toml"
rm -f "$OUT/.artifacts.sorted" "$OUT/.pointers.sorted"
echo "✓ rendered $OUT/versions.toml"

# --- optional: sign the manifest (sigstore keyless) ------------------------
# Verified path (see ../../docs/UPDATE_DISTRIBUTION.md and ../sigstore-spike):
# sign ONLY the manifest; per-artifact sha256 chains trust to the bytes.
if [ "$SIGN" -eq 1 ]; then
  echo "signing versions.toml as $IDENTITY (publishes identity to public logs) ..."
  cosign sign-blob --new-bundle-format --yes \
    --bundle "$OUT/versions.toml.sigstore.json" \
    "$OUT/versions.toml"
  echo "✓ signed → $OUT/versions.toml.sigstore.json (pin: $IDENTITY $ISSUER)"
fi

echo "done. release=$RELEASE channel=$CHANNEL → $KEY"
