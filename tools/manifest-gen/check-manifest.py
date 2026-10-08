#!/usr/bin/env python3
"""Pre-publish reliability gate for a generated trait manifest.

Verifies, against the dist directory, that the manifest is internally consistent
and safe to upload:

  - versions.toml parses as TOML
  - a `latest` pointer exists
  - every artifact referenced by `latest` and by [stable] is in the catalog,
    and either its bundle is on disk with a matching sha256, or it is reused
    unchanged (same file, same sha256) from the published manifest
  - the signature bundle exists

With --presence-only it instead checks just that every referenced bundle is
named in a listing of the bucket -- the gate between uploading bundles and
uploading the manifest that points at them.

Exits non-zero (with a clear message) on the first problem, so `make
publish-traits` aborts before touching R2.

Usage: check-manifest.py <dist-dir> [--published <versions.toml>]
       check-manifest.py <dist-dir> --presence-only <bucket-listing>
"""
import argparse
import hashlib
import os
import sys
import tomllib


def fail(msg: str) -> None:
    print(f"✗ manifest check failed: {msg}", file=sys.stderr)
    sys.exit(1)


def load_toml(path: str) -> dict:
    with open(path, "rb") as f:
        return tomllib.load(f)


def main() -> None:
    ap = argparse.ArgumentParser(description="pre-publish trait manifest gate")
    ap.add_argument("dist")
    ap.add_argument("--published", help="the manifest currently live in the bucket")
    ap.add_argument("--presence-only", metavar="LISTING",
                    help="only check referenced bundles are named in this bucket listing")
    args = ap.parse_args()
    dist = args.dist
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

    if args.presence_only:
        # The manifest must never go up pointing at a bundle the bucket lacks.
        with open(args.presence_only) as f:
            present = {line.strip() for line in f if line.strip()}
        for key in sorted(referenced):
            name = os.path.basename(artifacts[key]["file"])
            if name not in present:
                fail(f"bundle for {key!r} is not in the bucket: {name}")
        print(f"✓ all {len(referenced)} referenced bundle(s) present in the bucket")
        return

    published = {}
    if args.published and os.path.exists(args.published):
        try:
            published = load_toml(args.published).get("artifacts", {})
        except tomllib.TOMLDecodeError as e:
            fail(f"published manifest {args.published} is not valid TOML: {e}")

    reused = 0
    for key in sorted(referenced):
        a = artifacts[key]
        bundle = os.path.join(dist, os.path.basename(a["file"]))
        if not os.path.exists(bundle):
            # Reused from the live manifest: manifest-gen only does that for a
            # content-addressed bundle, whose bytes were verified when it was
            # first published. Anything else missing locally is an error.
            p = published.get(key)
            if p and p.get("file") == a["file"] and p.get("sha256") == a["sha256"]:
                reused += 1
                continue
            fail(f"bundle for {key!r} missing on disk and not reused from the published manifest: {bundle}")
        digest = hashlib.sha256(open(bundle, "rb").read()).hexdigest()
        if digest != a["sha256"]:
            fail(f"sha256 mismatch for {key!r}: file {digest} != manifest {a['sha256']}")

    # The signature is required by default (a signed release must not ship without
    # it). CLEAVE_ALLOW_UNSIGNED=1 downgrades this to a warning for the deliberately
    # unsigned publish path (make publish-traits-cron) — every other check above
    # still gates the upload.
    sig = os.path.join(dist, "versions.toml.sigstore.json")
    signed = os.path.exists(sig) and os.path.getsize(sig) > 0
    if not signed:
        msg = f"signature bundle missing or empty: {sig} (sign before publishing)"
        if os.environ.get("CLEAVE_ALLOW_UNSIGNED") == "1":
            print(f"⚠ {msg} — proceeding UNSIGNED (CLEAVE_ALLOW_UNSIGNED=1)", file=sys.stderr)
        else:
            fail(msg)

    upgrade = m.get("upgrade", {})
    print(
        f"✓ manifest OK: latest={latest}, "
        f"{len(referenced)} referenced artifact(s) verified "
        f"({len(referenced) - reused} by sha256 on disk, {reused} reused as published), "
        f"signature {'present' if signed else 'ABSENT (unsigned)'}, "
        f"{len(upgrade)} release(s) flagged for upgrade"
    )


if __name__ == "__main__":
    main()
