# cleave Makefile
# Build and test commands for deep static analysis tool
# Compatible with both GNU make and BSD make

BINARY = cleave
OUT_DIR = out

# Honor CARGO_TARGET_DIR if set (cleave-tuna sets it to share the cargo cache
# across worktrees). Falls back to the cargo default `target` otherwise.
CARGO_TARGET ?= $(if $(CARGO_TARGET_DIR),$(CARGO_TARGET_DIR),target)

# For sccache, set RUSTC_WRAPPER=sccache in your environment

.PHONY: all build debug release release-lto check-cargo install tarball rollout-bastille test test-fast test-unit lint fix fmt clean coverage ci install-hooks help regenerate-testdata loadtest bench-build benchmark sampled-benchmark validate tuna tuna-once wolfi wolfi-bootstrap wolfi-build wolfi-test wolfi-shell wolfi-clean wolfi-nuke

# Default target
all: build

help: ## Show this help
	@echo "cleave Makefile"
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@echo "  build                 - Build in debug mode (default)"
	@echo "  debug                 - Build in debug mode"
	@echo "  release               - Build in release mode"
	@echo "  install               - Build release and install to PATH"
	@echo "  tarball               - Build release tarball (binary + traits)"
	@echo "  rollout-bastille      - Deploy to Bastille jails (BUILD=jail RUN=jail)"
	@echo "  test                  - Run all tests (unit + integration)"
	@echo "  test-fast             - Run tests quickly (skip YARA, lib tests only)"
	@echo "  test-unit             - Run only unit tests (skip integration tests)"
	@echo "  fmt                   - Format all code with rustfmt"
	@echo "  fix                   - Auto-fix clippy lints, then format with rustfmt"
	@echo "  lint                  - Run code formatting and linting checks"
	@echo "  coverage              - Generate code coverage report"
	@echo "  ci                    - Run all CI checks (test + lint)"
	@echo "  regenerate-testdata   - Regenerate integration test snapshots from ~/data/cleave"
	@echo "  loadtest              - Run load test against cleave server"
	@echo "  validate              - Validate trait definitions (for: restrictions, taxonomy, etc.)"
	@echo "  benchmark             - Benchmark release build against ~/data/benchmark/ (DATASET=200MB)"
	@echo "  sampled-benchmark     - Benchmark with samply CPU profiling (DATASET=200MB)"
	@echo "  tuna                  - LLM autoresearch loop, alternating memory/cpu; cherry-picks wins (Ctrl-C to stop)"
	@echo "  tuna-once             - Run one tuna cycle then cherry-pick accepted experiments"
	@echo "  wolfi                 - Bootstrap + build + smoke-test the Wolfi OCI image (WOLFI_ARCH=)"
	@echo "  wolfi-bootstrap       - Ensure Lima VM (macOS) or container runtime (Linux) is ready"
	@echo "  wolfi-build           - Build cleave + cleave-traits apks and assemble OCI image (idempotent)"
	@echo "  wolfi-test            - Run smoke tests against the built image"
	@echo "  wolfi-shell           - Open an interactive shell in the built image (debugging)"
	@echo "  wolfi-clean           - Remove Wolfi build output (keeps the Lima VM)"
	@echo "  wolfi-nuke            - wolfi-clean + delete the Lima VM (destructive opt-in)"
	@echo "  clean                 - Clean all build artifacts"

build: debug ## Build in debug mode (default)

debug: ## Build in debug mode
	@echo "Building $(BINARY) (debug mode, treating warnings as errors)..."
	cargo build
	@echo "✓ Debug build successful"

check-cargo: ## Verify cargo is installed
	@command -v cargo >/dev/null 2>&1 || { \
		echo "Error: cargo not found. Install Rust via:"; \
		case "$$(uname -s)" in \
			Darwin)  echo "  brew install rust   # or: curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh" ;; \
			FreeBSD) echo "  pkg install rust" ;; \
			OpenBSD) echo "  pkg_add rust" ;; \
			NetBSD)  echo "  pkgin install rust   # or: pkg_add rust" ;; \
			SunOS)   echo "  pkgin install rust" ;; \
			Linux) \
				if command -v apt-get >/dev/null 2>&1; then \
					echo "  apt-get install cargo   # or: curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh"; \
				elif command -v dnf >/dev/null 2>&1; then \
					echo "  dnf install cargo   # or: curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh"; \
				elif command -v pacman >/dev/null 2>&1; then \
					echo "  pacman -S rust   # or: curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh"; \
				elif command -v apk >/dev/null 2>&1; then \
					echo "  apk add cargo   # or: curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh"; \
				else \
					echo "  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh"; \
				fi ;; \
			*) echo "  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh" ;; \
		esac; \
		exit 1; \
	}

release: check-cargo $(OUT_DIR) ## Build in release mode (thin LTO)
	@echo "Building $(BINARY) (release mode, treating warnings as errors)..."
	cargo build --release --features jemalloc
	cp $(CARGO_TARGET)/release/$(BINARY) $(OUT_DIR)/$(BINARY).new && mv -f $(OUT_DIR)/$(BINARY).new $(OUT_DIR)/$(BINARY)
	@if [ "$$(uname)" = "Darwin" ]; then codesign -s - -f $(OUT_DIR)/$(BINARY); fi
	@echo "✓ Release binary: $(OUT_DIR)/$(BINARY)"

# Fat LTO + single codegen unit. Multi-minute link, marginal runtime win
# over the default release profile. Use for container/tarball builds.
release-lto: check-cargo $(OUT_DIR) ## Build in distribution mode (fat LTO; multi-minute link)
	@echo "Building $(BINARY) (release-lto: fat LTO, single codegen unit)..."
	cargo build --profile release-lto --features jemalloc
	cp $(CARGO_TARGET)/release-lto/$(BINARY) $(OUT_DIR)/$(BINARY).new && mv -f $(OUT_DIR)/$(BINARY).new $(OUT_DIR)/$(BINARY)
	@if [ "$$(uname)" = "Darwin" ]; then codesign -s - -f $(OUT_DIR)/$(BINARY); fi
	@echo "✓ Release-LTO binary: $(OUT_DIR)/$(BINARY)"

install: release ## Install binary to first writeable location
	@set -e; \
	if echo "$$PATH" | tr ':' '\n' | grep -qx "$$HOME/.cargo/bin" && [ -d "$$HOME/.cargo/bin" ]; then \
		dest="$$HOME/.cargo/bin/$(BINARY)"; \
	elif [ -d "$$HOME/bin" ] && [ -w "$$HOME/bin" ]; then \
		dest="$$HOME/bin/$(BINARY)"; \
	elif [ -d "$$HOME/.local/bin" ] && [ -w "$$HOME/.local/bin" ]; then \
		dest="$$HOME/.local/bin/$(BINARY)"; \
	elif [ -w /usr/local/bin ]; then \
		dest="/usr/local/bin/$(BINARY)"; \
	else \
		mkdir -p "$$HOME/.cargo/bin"; \
		dest="$$HOME/.cargo/bin/$(BINARY)"; \
	fi; \
	install -m 755 $(OUT_DIR)/$(BINARY) "$$dest.new" && mv -f "$$dest.new" "$$dest"; \
	echo "✓ Installed to $$dest"

tarball: release ## Build release tarball with binary and traits
	@echo "Creating tarball..."
	tar -czf $(OUT_DIR)/cleave.tgz -C $(OUT_DIR) cleave -C "$$PWD" traits
	@echo "✓ Tarball: $(OUT_DIR)/cleave.tgz"

rollout-bastille: ## Deploy to Bastille jails (BUILD=jail RUN=jail)
	@[ -n "$(BUILD)" ] && [ -n "$(RUN)" ] || { echo "Usage: make rollout-bastille BUILD=<build-jail> RUN=<run-jail>"; exit 1; }
	./hacks/rollout-bastille.sh "$(BUILD)" "$(RUN)"

# Keep filefacts' on-by-default extraction cache out of the test runs so they
# stay hermetic (no reads/writes to the shared user cache dir).
test test-fast test-unit: export FILEFACTS_CACHE := 0

test: ## Run all tests (unit + integration)
	@echo "Running all tests (hybrid: nextest + cargo test for state-sharing tests)..."
	@echo ""
	@cargo build --quiet
	@# Run state-sharing tests with cargo test (Lazy sharing saves ~100s)
	@echo "Phase 1: Running state-sharing tests with cargo test..."
	@cargo test --test utf16_support_test --test embedded_code_detection_test -- --test-threads=1
	@echo ""
	@# Run remaining tests with nextest for parallelism
	@echo "Phase 2: Running parallel tests with nextest..."
	@if command -v cargo-nextest >/dev/null 2>&1; then \
		cargo nextest run --workspace -E 'not (binary(utf16_support_test) | binary(embedded_code_detection_test))'; \
	else \
		cargo test --workspace; \
	fi
	@echo ""
	@echo "✓ All tests passed"

test-fast: ## Run tests quickly (skip YARA in spawned processes, uses nextest)
	@echo "Running fast tests (YARA skipped in integration tests)..."
	@echo ""
	@cargo build --quiet
	@if command -v cargo-nextest >/dev/null 2>&1; then \
		CLEAVE_SKIP_YARA=1 cargo nextest run --workspace --lib; \
	else \
		CLEAVE_SKIP_YARA=1 cargo test --workspace --lib; \
	fi
	@echo ""
	@echo "✓ Fast tests passed"

test-unit: ## Run only unit tests (skip integration tests, fastest)
	@echo "Running unit tests only..."
	@echo ""
	@if command -v cargo-nextest >/dev/null 2>&1; then \
		cargo nextest run --lib; \
	else \
		cargo test --lib; \
	fi
	@echo ""
	@echo "✓ Unit tests passed"

fmt: ## Format all code with rustfmt
	@echo "Formatting code..."
	@cargo fmt --all
	@echo "✓ Code formatted"

fix: ## Auto-fix clippy lints, then format with rustfmt
	@echo "Applying clippy fixes..."
	@cargo clippy --fix --workspace --all-targets --all-features --allow-dirty --allow-staged
	@cargo fmt --all
	@echo "✓ Fixes applied"

lint: ## Run code formatting and linting checks
	@echo "Checking formatting..."
	@cargo fmt --all --check
	@echo "✓ Formatting passed"
	@echo ""
	@echo "Running clippy with workspace lints..."
	@cargo clippy --workspace --all-targets --all-features
	@echo "✓ Clippy passed"
	@echo ""
	@echo "Checking for unused dependencies..."
	@cargo machete --with-metadata || echo "Note: cargo-machete not installed, skipping dependency check"
	@echo ""
	@echo "✓ All lints passed"

coverage: ## Generate code coverage report
	@echo "Generating code coverage report..."
	@command -v cargo-llvm-cov >/dev/null 2>&1 || { echo "Error: cargo-llvm-cov not installed. Run: cargo install cargo-llvm-cov"; exit 1; }
	cargo llvm-cov --workspace --ignore-filename-regex '(tests|main\.rs)' --html
	@echo "✓ Coverage report generated at: $(CARGO_TARGET)/llvm-cov/html/index.html"

ci: test lint ## Run all CI checks (test + lint)
	@echo "✓ All CI checks passed"

install-hooks: ## Install the git pre-commit hook (lint + test + no local Cargo overrides)
	cp scripts/pre-commit .git/hooks/pre-commit
	chmod +x .git/hooks/pre-commit
	@echo "✓ Pre-commit hook installed."

validate: ## Validate trait definitions (for: restrictions, taxonomy, precision, etc.)
	@echo "Validating trait definitions..."
	cargo build --quiet
	CLEAVE_TRAITS_DIR=$(TRAITS) ./$(CARGO_TARGET)/debug/$(BINARY) validate
	@echo "✓ Validation passed"

TRAITS ?= ../cleave-traits
COMMIT ?= HEAD
CHANNEL ?= beta
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
gen-manifest: release ## Auto-generate versions.toml ([RELEASES=5] [COMMITS=8] [SOAK_DAYS=7] [ENGINE=path|empty] [SIGN=1 IDENTITY=...])
	cd tools/manifest-gen && GOWORK=off go build -o manifest-gen .
	tools/manifest-gen/manifest-gen \
	  --traits "$(TRAITS)" --repo . --out "$(DIST)" \
	  $(if $(ENGINE),--engine "$(ENGINE)",) \
	  --head-engine "$(HEAD_ENGINE)" \
	  --releases $(RELEASES) --commits $(COMMITS) --soak-days $(SOAK_DAYS) \
	  --channels "$(CHANNELS)" --artifact-prefix "$(ARTIFACT_PREFIX)" \
	  $(if $(SIGN),--sign --identity "$(IDENTITY)",)

# Public R2 bucket layout: <remote>/<R2_CLEAVE>/versions.toml + <R2_CLEAVE>/traits/<bundles>
R2_REMOTE ?= atomdrift-updates:atomdrift-updates
R2_CLEAVE ?= cleave
publish-cleave: ## Upload dist/ bundles + versions.toml to R2 (artifacts FIRST, then manifest, then signature)
	@command -v rclone >/dev/null || { echo "rclone not found"; exit 1; }
	@[ -f "$(DIST)/versions.toml" ] || { echo "no $(DIST)/versions.toml — run 'make gen-manifest' first"; exit 1; }
	@echo "→ bundles (immutable, cache forever)"
	rclone copy "$(DIST)" "$(R2_REMOTE)/$(R2_CLEAVE)/traits/" --include "*.tar.zst" \
	  --header-upload "Cache-Control: public, max-age=31536000, immutable" --progress
	@echo "→ manifest (short cache so polls see updates)"
	rclone copyto "$(DIST)/versions.toml" "$(R2_REMOTE)/$(R2_CLEAVE)/versions.toml" \
	  --header-upload "Cache-Control: public, max-age=60"
	@if [ -f "$(DIST)/versions.toml.sigstore.json" ]; then \
	  echo "→ signature"; \
	  rclone copyto "$(DIST)/versions.toml.sigstore.json" "$(R2_REMOTE)/$(R2_CLEAVE)/versions.toml.sigstore.json" \
	    --header-upload "Cache-Control: public, max-age=60"; \
	else echo "(no signature bundle in $(DIST); skipping — sign before a real release)"; fi
	@echo "✓ published to $(R2_REMOTE)/$(R2_CLEAVE)/"

release-cleave: gen-manifest publish-cleave ## Generate the manifest and publish it to R2 in one step

ISSUER ?= https://accounts.google.com
check-manifest: ## Pre-publish gate: manifest parses, artifacts present + sha match, signature verifies
	python3 tools/manifest-gen/check-manifest.py "$(DIST)"
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

# --- Unattended trait publishing (30-min systemd timer via hacks/traiter-linux.sh) --
# Change-gated wrapper around the publish flow for the timer. It rebuilds+publishes
# ONLY when one of the three inputs manifest-gen actually keys off has moved since
# the last successful publish (fingerprinted in TRAITS_STAMP):
#   1. cleave-traits tip   — new trait commits beyond what the manifest points at
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
# signing on later, sign in an automated fashion (see the hacks/traiter-linux.sh
# header) and swap the gen-manifest line below for `SIGN=1 IDENTITY=$(IDENTITY)`
# plus a `check-manifest IDENTITY=$(IDENTITY)` gate. The R2 upload is idempotent
# (rclone skips unchanged bundles), so a redundant publish is cheap.
# Safe to run by hand.
TRAITS_STAMP ?= $(DIST)/.publish-traits.stamp
.PHONY: publish-traits-cron deploy-traiter
publish-traits-cron: ## 30-min timer cycle: skip fast unless traits/source/release-tags moved, else gen+check+publish UNSIGNED
	@command -v rclone >/dev/null || { echo "publish-traits-cron: rclone not found"; exit 1; }
	@git -C "$(TRAITS)" rev-parse --is-inside-work-tree >/dev/null 2>&1 \
	  || { echo "publish-traits-cron: TRAITS=$(TRAITS) is not a git checkout — clone cleave-traits there first"; exit 1; }
	@set -e; \
	git -C "$(TRAITS)" fetch -q origin 2>/dev/null || echo "publish-traits-cron: WARN fetch $(TRAITS) failed; using cached refs"; \
	traits_tip=$$(git -C "$(TRAITS)" rev-parse origin/main 2>/dev/null || git -C "$(TRAITS)" rev-parse HEAD); \
	traits_short=$$(git -C "$(TRAITS)" rev-parse --short "$$traits_tip"); \
	src_head=$$(git -C . rev-parse HEAD 2>/dev/null || echo nogit); \
	tagsig=$$(git -C . for-each-ref --format='%(objectname) %(refname:short)' 'refs/tags/v*' 2>/dev/null | awk '$$2 ~ /^v[0-9]/ && $$2 !~ /-/' | sort || true); \
	stamp=$$(printf 'traits %s\nsrc %s\ntags\n%s\n' "$$traits_tip" "$$src_head" "$$tagsig" | git hash-object --stdin); \
	if [ -f "$(TRAITS_STAMP)" ] && [ "$$(cat "$(TRAITS_STAMP)" 2>/dev/null)" = "$$stamp" ]; then \
	  echo "→ no new trait commits or cleave versions since last publish (cleave-traits $$traits_short); skipping"; \
	  exit 0; \
	fi; \
	echo "→ change detected (cleave-traits $$traits_short); fast-forwarding + publishing UNSIGNED"; \
	git -C "$(TRAITS)" merge -q --ff-only "$$traits_tip"; \
	$(MAKE) gen-manifest ENGINE= VERSIONS=$(VERSIONS) CHANNELS=stable; \
	$(MAKE) check-manifest; \
	$(MAKE) publish-cleave; \
	mkdir -p "$$(dirname "$(TRAITS_STAMP)")"; \
	printf '%s\n' "$$stamp" > "$(TRAITS_STAMP)"; \
	echo "✓ publish-traits-cron complete (unsigned) at $$traits_short"

deploy-traiter: ## Install the unattended 30-min trait-publish systemd timer on THIS host (see hacks/traiter-linux.sh)
	./hacks/traiter-linux.sh

update-manifest: release ## Build + validate + render a trait-update manifest (RELEASE=x.y.z [CHANNEL=beta] [COMMIT=ref] [SIGN=1 IDENTITY=...])
	@[ -n "$(RELEASE)" ] || { echo "RELEASE=x.y.z required"; exit 1; }
	tools/update-manifest/build-manifest.sh \
	  --traits "$(TRAITS)" --commit "$(COMMIT)" \
	  --release "$(RELEASE)" --channel "$(CHANNEL)" \
	  --engine ./$(CARGO_TARGET)/release/$(BINARY) --out "$(DIST)" \
	  $(if $(SIGN),--sign --identity "$(IDENTITY)",)

clean: ## Clean all build artifacts
	@echo "Cleaning build artifacts..."
	cargo clean
	rm -rf $(OUT_DIR)
	@echo "✓ Clean complete"

regenerate-testdata: release ## Regenerate integration test snapshots
	@echo "Regenerating test data from ~/data/cleave..."
	cargo build --release --quiet --bin regenerate_testdata
	./$(CARGO_TARGET)/release/regenerate_testdata

bench-build: $(OUT_DIR) ## Build benchmark binary (release + debug symbols for profiling)
	@echo "Building $(BINARY) (profiling: release + debug symbols)..."
	cargo build --profile profiling --features jemalloc
	cp $(CARGO_TARGET)/profiling/$(BINARY) $(OUT_DIR)/$(BINARY).bench
	@if [ "$$(uname)" = "Darwin" ]; then codesign -s - -f $(OUT_DIR)/$(BINARY).bench; fi
	@echo "✓ Benchmark binary: $(OUT_DIR)/$(BINARY).bench"

DATASET ?= 200MB
BENCH_DIR = ~/data/benchmark/$(DATASET)

benchmark: bench-build ## Benchmark against ~/data/benchmark/$(DATASET)
	@echo "Benchmarking $(OUT_DIR)/$(BINARY).bench on $(BENCH_DIR)..."
	CLEAVE_SKIP_CACHE=1 time $(OUT_DIR)/$(BINARY).bench --verbose --format=jsonl $(BENCH_DIR) 2>$(OUT_DIR)/bench.err >$(OUT_DIR)/bench.out
	tail -n 20 $(OUT_DIR)/bench.err
	@echo "✓ Output: $(OUT_DIR)/bench.out  Logs: $(OUT_DIR)/bench.err"

sampled-benchmark: bench-build ## Benchmark with samply CPU profiling
	@command -v samply >/dev/null 2>&1 || { echo "Error: samply not installed. Run: cargo install samply"; exit 1; }
	@echo "Profiling $(OUT_DIR)/$(BINARY).bench on $(BENCH_DIR) with samply..."
	CLEAVE_SKIP_CACHE=1 time samply record --save-only -o $(OUT_DIR)/bench.profile.json.gz $(OUT_DIR)/$(BINARY).bench --verbose --format=jsonl $(BENCH_DIR) 2>$(OUT_DIR)/bench.err >$(OUT_DIR)/bench.out
	@echo "✓ Output: $(OUT_DIR)/bench.out  Logs: $(OUT_DIR)/bench.err  Profile: $(OUT_DIR)/bench.profile.json.gz"

heap-build: $(OUT_DIR) ## Build with jemalloc heap profiling support
	@echo "Building $(BINARY) (heap profiling: release + debug + jemalloc-prof)..."
	cargo build --profile profiling --features jemalloc-prof
	cp $(CARGO_TARGET)/profiling/$(BINARY) $(OUT_DIR)/$(BINARY).heap
	@if [ "$$(uname)" = "Darwin" ]; then codesign -s - -f $(OUT_DIR)/$(BINARY).heap; fi
	@echo "✓ Heap-profiling binary: $(OUT_DIR)/$(BINARY).heap"

heap-benchmark: heap-build ## Benchmark with jemalloc heap profiling
	@echo "Heap-profiling $(OUT_DIR)/$(BINARY).heap on $(BENCH_DIR)..."
	@rm -rf $(OUT_DIR)/heap && mkdir -p $(OUT_DIR)/heap
	CLEAVE_SKIP_CACHE=1 _RJEM_MALLOC_CONF="prof:true,prof_active:true,prof_final:true,lg_prof_interval:28,prof_prefix:$(OUT_DIR)/heap/jeprof" \
		time $(OUT_DIR)/$(BINARY).heap --verbose --format=jsonl $(BENCH_DIR) 2>$(OUT_DIR)/bench.err >$(OUT_DIR)/bench.out
	@echo "✓ Output: $(OUT_DIR)/bench.out  Logs: $(OUT_DIR)/bench.err"
	@echo "✓ Heap profiles: $(OUT_DIR)/heap/jeprof.*.heap"
	@echo "  Analyze with: jeprof --text $(OUT_DIR)/$(BINARY).heap $(OUT_DIR)/heap/jeprof.*.heap"
	@echo "  Note: tikv-jemalloc uses _RJEM_MALLOC_CONF (not MALLOC_CONF)"

loadtest: ## Run load test against cleave server
	@echo "Building loadtest tool..."
	@cd tools/loadtest && go build -o loadtest .
	@echo "✓ Running load test..."
	@tools/loadtest/loadtest $(LOADTEST_ARGS)

# cleave-tuna: LLM-driven CPU+memory autoresearch loop.
# See ../cleave-tuna/README.md.
TUNA_REPO        ?= ../cleave-tuna
TUNA_BIN         ?= $(TUNA_REPO)/out/cleave-tuna
TUNA_DATASET     ?= archive
TUNA_EXPERIMENTS ?= 6
TUNA_SCREEN_SAMPLES  ?= 1
TUNA_CONFIRM_SAMPLES ?= 3
TUNA_PROVIDER    ?= gemini,codex,claude
TUNA_MODE        ?=
TUNA_INTERVAL    ?= 30

tuna: ## Run cleave-tuna in a loop, alternating memory/cpu; cherry-pick accepted experiments
	@test -x $(TUNA_BIN) || { echo "build cleave-tuna first: (cd $(TUNA_REPO) && make build)"; exit 1; }
	@test -z "$$(git status --porcelain)" || { echo "working tree must be clean before starting tuna"; exit 1; }
	@echo "tuna: looping forever, alternating memory/cpu (Ctrl-C to stop). settings: dataset=$(TUNA_DATASET) experiments=$(TUNA_EXPERIMENTS) screen-samples=$(TUNA_SCREEN_SAMPLES) confirm-samples=$(TUNA_CONFIRM_SAMPLES) provider=$(TUNA_PROVIDER)"
	@mode=memory; \
	while true; do \
		echo "tuna: starting cycle in $$mode mode"; \
		$(MAKE) tuna-once TUNA_MODE=$$mode || exit $$?; \
		if [ "$$mode" = "memory" ]; then mode=cpu; else mode=memory; fi; \
		echo "tuna: sleeping $(TUNA_INTERVAL)s before next cycle ($$mode) — Ctrl-C to stop"; \
		sleep $(TUNA_INTERVAL); \
	done

tuna-once: ## One cleave-tuna cycle, then cherry-pick accepted experiments
	@test -x $(TUNA_BIN) || { echo "build cleave-tuna first: (cd $(TUNA_REPO) && make build)"; exit 1; }
	@test -z "$$(git status --porcelain)" || { echo "working tree must be clean before tuna-once"; exit 1; }
	@before=$$(git rev-parse HEAD); \
	$(TUNA_BIN) --source $(CURDIR) --root $(TUNA_REPO) --dataset $(TUNA_DATASET) \
		--name cleave \
		--bench-arg --format=jsonl \
		--bench-env CLEAVE_SKIP_CACHE=1 \
		--deny traits/ \
		--experiments $(TUNA_EXPERIMENTS) \
		--screen-samples $(TUNA_SCREEN_SAMPLES) --confirm-samples $(TUNA_CONFIRM_SAMPLES) \
		--provider $(TUNA_PROVIDER) $(if $(TUNA_MODE),--$(TUNA_MODE),) \
		|| { echo "tuna: cleave-tuna exited non-zero; not cherry-picking"; exit 1; }; \
	branch=$$(git for-each-ref --sort=-committerdate --format='%(refname:short)' 'refs/heads/tuna/*' | head -1); \
	if [ -z "$$branch" ]; then echo "tuna: no tuna/* branch found"; exit 0; fi; \
	ahead=$$(git rev-list --count $$before..$$branch); \
	if [ "$$ahead" = "0" ]; then \
		echo "tuna: no accepted experiments on $$branch — nothing to cherry-pick"; \
		exit 0; \
	fi; \
	echo "tuna: cherry-picking $$ahead commit(s) from $$branch"; \
	git cherry-pick $$branch~$$ahead..$$branch

$(OUT_DIR):
	mkdir -p $(OUT_DIR)

# ----- Wolfi packaging ----------------------------------------------------
# Build a Wolfi-based OCI image for cleave via melange + apko. On macOS the
# build runs inside a dedicated Lima VM (`cleave-wolfi`); on Linux it uses
# nerdctl/docker/podman directly. See packaging/wolfi/README.md.
WOLFI_DIR = packaging/wolfi
WOLFI_OUT = $(OUT_DIR)/wolfi
WOLFI_ARCH ?=

wolfi: wolfi-bootstrap wolfi-build wolfi-test ## Bootstrap + build + smoke-test the Wolfi OCI image

wolfi-bootstrap: ## Ensure Lima VM (macOS) or container runtime (Linux) is ready
	@$(WOLFI_DIR)/scripts/bootstrap-lima.sh

wolfi-build: ## Build cleave + cleave-traits apks and assemble OCI image (idempotent)
	@WOLFI_ARCH="$(WOLFI_ARCH)" $(WOLFI_DIR)/scripts/build.sh
	@echo "✓ Wolfi image: $(WOLFI_OUT)/cleave.tar"

wolfi-test: ## Run smoke tests against the built image
	@$(WOLFI_DIR)/scripts/smoke-test.sh

wolfi-shell: ## Open an interactive shell in the built image (debugging)
	@[ -f $(WOLFI_OUT)/cleave.tar ] || { echo "error: run 'make wolfi-build' first"; exit 1; }
	@case "$$(uname -s)" in \
		Darwin) limactl shell --workdir / cleave-wolfi nerdctl run --rm -it --entrypoint /bin/sh cleave:smoke ;; \
		Linux)  for r in nerdctl docker podman; do command -v $$r >/dev/null 2>&1 && { exec $$r run --rm -it --entrypoint /bin/sh cleave:smoke; }; done; echo "no container runtime"; exit 1 ;; \
	esac

wolfi-clean: ## Remove Wolfi build output (keeps the Lima VM)
	rm -rf $(WOLFI_OUT)
	@echo "✓ Wolfi output cleaned"

wolfi-nuke: wolfi-clean ## wolfi-clean + delete the Lima VM (destructive opt-in)
	@case "$$(uname -s)" in \
		Darwin) limactl delete --force cleave-wolfi 2>/dev/null || true ;; \
	esac
	rm -rf $$HOME/.cache/cleave-wolfi
	@echo "✓ Wolfi VM and cache removed"
