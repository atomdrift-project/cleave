#!/usr/bin/env python3
"""Pre-publish reliability gate for a generated trait manifest.

Verifies, against the dist directory, that the manifest is internally consistent
and safe to upload:

  - versions.toml parses as TOML
  - a `latest` pointer exists
  - every artifact referenced by `latest` and by [stable] is in the catalog,
    its bundle file is present on disk, and its sha256 matches the bytes
  - the signature bundle exists

Exits non-zero (with a clear message) on the first problem, so `make
publish-traits` aborts before touching R2.

Usage: check-manifest.py <dist-dir>
"""
import hashlib
import os
import sys
import tomllib


def fail(msg: str) -> None:
    print(f"✗ manifest check failed: {msg}", file=sys.stderr)
    sys.exit(1)


def main() -> None:
    if len(sys.argv) != 2:
        fail("usage: check-manifest.py <dist-dir>")
    dist = sys.argv[1]
    manifest = os.path.join(dist, "versions.toml")

    try:
        with open(manifest, "rb") as f:
            m = tomllib.load(f)
    except FileNotFoundError:
        fail(f"no manifest at {manifest} (run 'make gen-manifest' first)")
    except tomllib.TOMLDecodeError as e:
        fail(f"{manifest} is not valid TOML: {e}")

    latest = m.get("latest")
    if not latest:
        fail("no `latest` pointer in manifest")

    stable = m.get("stable", {})
    if not stable:
        fail(
            "[stable] has no pointers — no released engine produced a model "
            "(per-release build or validation failed upstream); refusing to publish"
        )

    artifacts = m.get("artifacts", {})
    referenced = {latest} | set(stable.values())

    for key in sorted(referenced):
        if key not in artifacts:
            fail(f"pointer {key!r} has no [artifacts.{key}] entry")
        a = artifacts[key]
        bundle = os.path.join(dist, os.path.basename(a["file"]))
        if not os.path.exists(bundle):
            fail(f"bundle for {key!r} missing on disk: {bundle}")
        digest = hashlib.sha256(open(bundle, "rb").read()).hexdigest()
        if digest != a["sha256"]:
            fail(f"sha256 mismatch for {key!r}: file {digest} != manifest {a['sha256']}")

    sig = os.path.join(dist, "versions.toml.sigstore.json")
    if not os.path.exists(sig) or os.path.getsize(sig) == 0:
        fail(f"signature bundle missing or empty: {sig} (sign before publishing)")

    upgrade = m.get("upgrade", {})
    print(
        f"✓ manifest OK: latest={latest}, "
        f"{len(referenced)} referenced artifact(s) verified (sha256 + present), "
        f"signature present, {len(upgrade)} release(s) flagged for upgrade"
    )


if __name__ == "__main__":
    main()
