# Maintainer targets: build, sign and publish trait-update bundles.
#
# Included by the Makefile. Nothing here is needed to build, test or use cleave;
# these targets need rclone, cosign, Go, and write access to the update bucket.
# See tools/manifest-gen/README.md.

.PHONY: gen-manifest publish-cleave release-cleave check-manifest publish-traits publish-traits-cron

# Path to the traits git checkout the bundles are built from.
TRAITS ?= ../traits-dev
DIST ?= dist
# VERSIONS = total versions to compat-test, INCLUDING HEAD (validated for `latest`).
# 3 = HEAD + the last 2 release tags. RELEASES (tag count) is derived as VERSIONS-1.
VERSIONS ?= 3
RELEASES ?= $(shell expr $(VERSIONS) - 1)
# How far back to walk traits commits for OLD release tags (per-version compat).
# HEAD/`latest` ignores this entirely — it only ever uses the single newest commit
# and fails the whole publish if that commit doesn't validate.
COMMITS ?= 8
# No soak for now (stable = newest compatible commit). A soak window would starve
# a release whose only compatible traits are recent (e.g. rc.4 → a 1-day-old commit).
SOAK_DAYS ?= 0
CHANNELS ?= stable
ARTIFACT_PREFIX ?= traits/
# ENGINE set  → validate every release key with this ONE binary (single-engine mode).
# ENGINE empty → build each release tag's own engine and validate per-version (the
#                true cross-version matrix; only works for post-decoupling tags).
ENGINE ?= ./$(CARGO_TARGET)/release/$(BINARY)
# HEAD_ENGINE validates the `latest` pointer (newest bundle that works for the
# current build); it's the working-tree binary, so always the local release build.
HEAD_ENGINE ?= ./$(CARGO_TARGET)/release/$(BINARY)
# The manifest is built on the one that is LIVE, fetched from the R2 origin (not
# the CDN, which can lag): its floors, and its content-addressed bundles, which
# are reused instead of rebuilt, so two publishers never produce different bytes
# under one immutable name. Unreachable is not fatal: names carry their content
# hash, so a rebuild is correct, only slower.
gen-manifest: release ## Auto-generate versions.toml ([RELEASES=5] [COMMITS=8] [SOAK_DAYS=7] [ENGINE=path|empty] [SIGN=1 IDENTITY=...])
	cd tools/manifest-gen && GOWORK=off go build -o manifest-gen .
	@mkdir -p "$(DIST)"
	@if command -v rclone >/dev/null && rclone copyto "$(R2_REMOTE)/$(R2_CLEAVE)/versions.toml" "$(DIST)/versions.published.toml" 2>/dev/null; then \
	  echo "→ building on the published manifest ($(R2_REMOTE)/$(R2_CLEAVE)/versions.toml, R2 origin)"; \
	else rm -f "$(DIST)/versions.published.toml"; \
	  echo "⚠ published manifest unavailable; building on $(DIST)/versions.toml (bundles may be rebuilt)"; fi
	tools/manifest-gen/manifest-gen \
	  --traits "$(TRAITS)" --repo . --out "$(DIST)" --published "$(DIST)/versions.published.toml" \
	  $(if $(ENGINE),--engine "$(ENGINE)",) \
	  --head-engine "$(HEAD_ENGINE)" \
	  --releases $(RELEASES) --commits $(COMMITS) --soak-days $(SOAK_DAYS) \
	  --channels "$(CHANNELS)" --artifact-prefix "$(ARTIFACT_PREFIX)" \
	  $(if $(SIGN),--sign --identity "$(IDENTITY)",)

# Public R2 bucket layout: <remote>/<R2_CLEAVE>/versions.toml + <R2_CLEAVE>/traits/<bundles>
R2_REMOTE ?= atomdrift-updates:atomdrift-updates
R2_CLEAVE ?= cleave
publish-cleave: ## Upload dist/ bundles + versions.toml to R2 (artifacts FIRST, then manifest; unsigned publish removes any orphaned R2 signature)
	@command -v rclone >/dev/null || { echo "rclone not found"; exit 1; }
	@[ -f "$(DIST)/versions.toml" ] || { echo "no $(DIST)/versions.toml — run 'make gen-manifest' first"; exit 1; }
	@echo "→ bundles (immutable, cache forever; never overwritten)"
	# --ignore-existing: a bundle name carries its content hash, so an existing
	# name already holds these bytes -- and overwriting one is exactly what an
	# `immutable` edge cache cannot follow.
	rclone copy "$(DIST)" "$(R2_REMOTE)/$(R2_CLEAVE)/traits/" --include "*.tar.zst" --ignore-existing \
	  --header-upload "Cache-Control: public, max-age=31536000, immutable" --progress
	@echo "→ checking every referenced bundle is in the bucket before the manifest points at it"
	rclone lsf "$(R2_REMOTE)/$(R2_CLEAVE)/traits/" --files-only --include "*.tar.zst" > "$(DIST)/.bucket-bundles"
	python3 tools/manifest-gen/check-manifest.py "$(DIST)" --presence-only "$(DIST)/.bucket-bundles"
	@echo "→ manifest (short cache so polls see updates)"
	rclone copyto "$(DIST)/versions.toml" "$(R2_REMOTE)/$(R2_CLEAVE)/versions.toml" \
	  --header-upload "Cache-Control: public, max-age=60"
	@if [ -f "$(DIST)/versions.toml.sigstore.json" ]; then \
	  echo "→ signature"; \
	  rclone copyto "$(DIST)/versions.toml.sigstore.json" "$(R2_REMOTE)/$(R2_CLEAVE)/versions.toml.sigstore.json" \
	    --header-upload "Cache-Control: public, max-age=60"; \
	elif [ -n "$$(rclone lsf "$(R2_REMOTE)/$(R2_CLEAVE)/" --files-only --include 'versions.toml.sigstore.json' 2>/dev/null)" ]; then \
	  echo "→ unsigned publish: deleting orphaned signature in R2 (channel was signed) so clients see no signature, not a stale one"; \
	  rclone deletefile "$(R2_REMOTE)/$(R2_CLEAVE)/versions.toml.sigstore.json"; \
	else echo "(unsigned; no signature in $(DIST) and none in R2)"; fi
	@echo "✓ published to $(R2_REMOTE)/$(R2_CLEAVE)/"

release-cleave: gen-manifest publish-cleave ## Generate the manifest and publish it to R2 in one step

ISSUER ?= https://accounts.google.com
check-manifest: ## Pre-publish gate: manifest parses, artifacts present + sha match, signature verifies
	python3 tools/manifest-gen/check-manifest.py "$(DIST)" --published "$(DIST)/versions.published.toml"
	@if [ -n "$(IDENTITY)" ]; then \
	  echo "→ verifying signature with cosign ($(IDENTITY))"; \
	  cosign verify-blob --new-bundle-format \
	    --bundle "$(DIST)/versions.toml.sigstore.json" \
	    --certificate-identity "$(IDENTITY)" \
	    --certificate-oidc-issuer "$(ISSUER)" \
	    "$(DIST)/versions.toml" && echo "✓ signature verifies for $(IDENTITY)"; \
	else echo "⚠ IDENTITY unset — skipping cosign signature verification"; fi

# Soft validation for the release gate: a trait bundle is rejected only for
# flaws that break loading or lose detections (unparseable YAML, uncompilable
# regex, invalid/unknown file types, duplicate ids) plus fixture regressions —
# never for authoring hygiene (taxonomy, size, dedup, style, precision). Passed
# as an env toggle, not a `--soft` flag, so older per-release engines in the
# cross-version matrix silently ignore it instead of failing on an unknown flag.
# Exported so it propagates through the `gen-manifest` sub-make into manifest-gen
# and on into every engine subprocess it spawns.
publish-traits: export CLEAVE_VALIDATE_SOFT := 1
publish-traits: ## FULL RELEASE: compat-test HEAD + last (VERSIONS-1) releases → sign → verify → upload to R2 ([VERSIONS=3] IDENTITY=<signer>)
	@[ -n "$(IDENTITY)" ] || { echo "publish-traits: IDENTITY=<signer> required (e.g. releaser@<project>.iam.gserviceaccount.com)"; exit 1; }
	@command -v rclone >/dev/null || { echo "publish-traits: rclone not found"; exit 1; }
	@command -v cosign >/dev/null || { echo "publish-traits: cosign not found"; exit 1; }
	# manifest-gen reads the traits repo's LOCAL git log (no fetch), so the newest
	# cleave-traits commit must already be checked out. Fast-forward to the remote
	# tip and abort if it can't (diverged/dirty/offline) — never publish stale.
	git -C "$(TRAITS)" pull --ff-only
	$(MAKE) gen-manifest ENGINE= VERSIONS=$(VERSIONS) CHANNELS=stable SIGN=1 IDENTITY="$(IDENTITY)"
	$(MAKE) check-manifest IDENTITY="$(IDENTITY)"
	$(MAKE) publish-cleave
	@echo "✓ publish-traits complete: compat-tested HEAD + last $(shell expr $(VERSIONS) - 1) release(s), signed, verified, uploaded"

# --- Unattended trait publishing (periodic timer) ----------------------------
# The timer that drives this target is provisioned alongside the traits repo;
# it runs `make publish-traits-cron` with this checkout as its working directory.
# Change-gated wrapper around the publish flow for the timer. It rebuilds+publishes
# ONLY when one of the three inputs manifest-gen actually keys off has moved since
# the last successful publish (fingerprinted in TRAITS_STAMP):
#   1. cleave-traits tip   — new trait commits beyond what the manifest points at
#                            (in mirror mode: the embargo cutoff, not the tip)
#   2. cleave source HEAD  — the HEAD engine that validates the `latest` pointer
#   3. stable release tags — the top-N `v<n>` tags the manifest is keyed by, i.e.
#                            "new cleave versions" (a plain `main` HEAD stamp would
#                            miss a tag pushed onto an existing commit)
# The whole gate is LOCAL and read-only: one lightweight `git fetch` of the small
# traits repo (cleave source + tags are refreshed by the unit's ExecStartPre), then
# rev-parse/for-each-ref + a compare — no working-tree mutation, no `release` build,
# no manifest render on an idle tick. Only a real change fast-forwards and runs the
# multi-minute compat-test matrix. So an idle 30-min tick costs ~one small fetch.
#
# UNSIGNED: it runs gen-manifest WITHOUT SIGN=1, so no cosign/IDENTITY is needed and
# nothing is written to the public Rekor transparency log. versions.toml ships with
# no signature bundle, so clients that require a signature will NOT apply the update
# — i.e. auto-update is effectively disabled until signing is wired up. To turn
# signing on later, sign in an automated fashion and swap the gen-manifest line below for
# `SIGN=1 IDENTITY=$(IDENTITY)`
# plus a `check-manifest IDENTITY=$(IDENTITY)` gate. The R2 upload is idempotent
# (published bundles are reused, never rebuilt or overwritten), so a redundant publish is cheap.
# Safe to run by hand.
#
# PUBLIC MIRROR (opt-in): setting TRAITS_PUBLIC_REMOTE to a git remote name on
# $(TRAITS) turns the cycle into an embargoed public-first publisher:
#   * only commits at least TRAITS_EMBARGO old are eligible (rev-list --before
#     on origin/main), so the private repo keeps a quarantine window in which a
#     bad commit can be fixed before anything about it becomes public;
#   * the eligible cutoff is pushed to TRAITS_PUBLIC_REMOTE BEFORE the R2 upload
#     and the manifest is rendered from THAT commit, so R2 never ships a bundle
#     whose source commit is not already public — bundle filenames and the
#     versions.toml `commit` keys stay auditable against the mirror by SHA.
# The mirror push is fast-forward-only and a failure aborts the cycle before R2:
# never rewrite private history older than TRAITS_EMBARGO, or every cycle fails
# until the mirror is reconciled by hand.
TRAITS_STAMP ?= $(DIST)/.publish-traits.stamp
TRAITS_PUBLIC_REMOTE ?=
TRAITS_EMBARGO ?= 72 hours
publish-traits-cron: ## 30-min timer cycle: skip fast unless traits/source/release-tags moved, else [mirror+]gen+check+publish UNSIGNED
	@command -v rclone >/dev/null || { echo "publish-traits-cron: rclone not found"; exit 1; }
	@git -C "$(TRAITS)" rev-parse --is-inside-work-tree >/dev/null 2>&1 \
	  || { echo "publish-traits-cron: TRAITS=$(TRAITS) is not a git checkout — clone the traits repo there first"; exit 1; }
	@set -e; \
	git -C "$(TRAITS)" fetch -q origin 2>/dev/null || echo "publish-traits-cron: WARN fetch $(TRAITS) failed; using cached refs"; \
	traits_tip=$$(git -C "$(TRAITS)" rev-parse origin/main 2>/dev/null || git -C "$(TRAITS)" rev-parse HEAD); \
	if [ -n "$(TRAITS_PUBLIC_REMOTE)" ]; then \
	  traits_tip=$$(git -C "$(TRAITS)" rev-list -1 --before="$(TRAITS_EMBARGO) ago" "$$traits_tip"); \
	  [ -n "$$traits_tip" ] || { echo "publish-traits-cron: no trait commit older than $(TRAITS_EMBARGO) yet; skipping"; exit 0; }; \
	fi; \
	traits_short=$$(git -C "$(TRAITS)" rev-parse --short "$$traits_tip"); \
	src_head=$$(git -C . rev-parse HEAD 2>/dev/null || echo nogit); \
	tagsig=$$(git -C . for-each-ref --format='%(objectname) %(refname:short)' 'refs/tags/v*' 2>/dev/null | awk '$$2 ~ /^v[0-9]/ && $$2 !~ /-/' | sort || true); \
	stamp=$$(printf 'traits %s\nsrc %s\ntags\n%s\n' "$$traits_tip" "$$src_head" "$$tagsig" | git hash-object --stdin); \
	if [ -f "$(TRAITS_STAMP)" ] && [ "$$(cat "$(TRAITS_STAMP)" 2>/dev/null)" = "$$stamp" ]; then \
	  echo "→ no new trait commits or cleave versions since last publish (cleave-traits $$traits_short); skipping"; \
	  exit 0; \
	fi; \
	if [ -n "$(TRAITS_PUBLIC_REMOTE)" ]; then \
	  echo "→ change detected (cleave-traits $$traits_short); mirroring to $(TRAITS_PUBLIC_REMOTE), then publishing UNSIGNED"; \
	  git -C "$(TRAITS)" push -q "$(TRAITS_PUBLIC_REMOTE)" "$$traits_tip:refs/heads/main"; \
	  git -C "$(TRAITS)" reset --hard -q "$$traits_tip"; \
	else \
	  echo "→ change detected (cleave-traits $$traits_short); fast-forwarding + publishing UNSIGNED"; \
	  git -C "$(TRAITS)" merge -q --ff-only "$$traits_tip"; \
	fi; \
	$(MAKE) gen-manifest ENGINE= VERSIONS=$(VERSIONS) CHANNELS=stable; \
	CLEAVE_ALLOW_UNSIGNED=1 $(MAKE) check-manifest; \
	$(MAKE) publish-cleave; \
	mkdir -p "$$(dirname "$(TRAITS_STAMP)")"; \
	printf '%s\n' "$$stamp" > "$(TRAITS_STAMP)"; \
	echo "✓ publish-traits-cron complete (unsigned) at $$traits_short"

