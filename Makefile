# cleave Makefile. Requires GNU make.

BINARY = cleave
# Cargo package name, read from Cargo.toml so `cut-release` passes the right `-p`.
PACKAGE := $(shell awk -F'"' '/^name = /{print $$2; exit}' Cargo.toml)
OUT_DIR = out

# Honor CARGO_TARGET_DIR if set; fall back to cargo's default `target`.
CARGO_TARGET ?= $(if $(CARGO_TARGET_DIR),$(CARGO_TARGET_DIR),target)

# For sccache, set RUSTC_WRAPPER=sccache in your environment

.PHONY: all build debug release release-lto check-cargo install test test-fast test-unit lint fix fmt clean coverage ci install-hooks help validate bench-build benchmark sampled-benchmark heap-build heap-benchmark check-bench-dir cut-release

# Default target
all: build

help: ## Show this help
	@echo "Usage: make [target]"
	@echo ""
	@awk -F':.*## ' '/^[a-zA-Z0-9_-]+:.*## / {printf "  %-22s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

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


# Keep the extraction/analysis caches out of the test runs so they stay hermetic
# (no reads/writes to the shared user cache dir — a stale entry there could
# otherwise mask or fabricate a finding across runs).
test test-fast test-unit: export FILEFACTS_CACHE := 0
test test-fast test-unit: export CLEAVE_SKIP_CACHE := 1
# The rule caches (mapper, traits index, compiled YARA) are pure functions of
# the traits tree and the build, so tests share them -- but in a directory of
# their own, never the user's: `cargo clean` drops it, and nothing a test run
# leaves behind can reach a production `cleave`.
test test-fast test-unit: export CLEAVE_CACHE_DIR := $(CURDIR)/target/test-cache
# CLEAVE_SKIP_CACHE alone would also skip the compiled-YARA cache, recompiling
# every bucket a test touches in every process that touches it.
test test-fast test-unit: export CLEAVE_SKIP_YARA_CACHE := 0

# Integration-test modules that mutate process-global state (traits override dir,
# analysis skip-overrides, env vars) and MUST run isolated under nextest — never
# in the shared `cargo test --workspace --test it` process, where their leaked state corrupts
# sibling tests. Kept in sync with `support::ISOLATED_MODULES`; the
# `shared_bucket_has_no_global_state_mutation` guard test fails if they drift.
IT_ISOLATED := archive_determinism_test archive_partial_taxonomy archive_tmp_regression binary_traits_test \
	cache_path_context cpio_members cpio_rpm declared_sources \
	decoded_evidence_provenance directory_selector_threshold embedded_code_detection_test explicit_scan_order \
	facts_cli_json follow_outcomes follow_outcomes_batch nuitka_macho \
	packed_rules_cli rpm_scriptlets security_hold_outcomes shell_ast_predicates \
	source_compound_flow subfile_pipeline_test symbol_extraction_test taxonomy_catalog_budgets \
	tiny_manifest_value_traits_test trait_migration_regression_test traits_override_isolation_test utf16_text_normalization_test \
	validation_performance validation_severity xor_macho_payload yara_init_no_deadlock
empty :=
space := $(empty) $(empty)
IT_SKIP := $(foreach m,$(IT_ISOLATED),--skip $(m)::)
IT_ISOLATED_RE := $(subst $(space),::|,$(IT_ISOLATED))::

# Every test command selects --workspace. Cargo unifies features over the
# selected packages, so `cargo test --test it` and `nextest --workspace` built
# two variants of the crate: two compiles after every edit, and two build
# identities, each with its own cold mapper cache.
#
# Unit tests share one process per crate: a process loads the 100k-trait
# mapper once instead of once per test (~5s for ~4000 tests vs ~100s under
# nextest). They mutate no process-global state; the integration crate's
# isolated modules below are the ones that do.
test: ## Run all tests (unit + integration)
	@echo "Phase 1: unit tests, one shared process per crate (cargo test)..."
	@cargo test --workspace --lib --bins --quiet
	@echo ""
	@# --test-threads=48: many of these tests wait on spawned cleave subprocesses,
	@# so threads > cores overlaps that waiting instead of idling test slots.
	@echo "Phase 2: shared-process integration tests (cargo test)..."
	@cargo test --workspace --test it -- $(IT_SKIP) --test-threads=48
	@echo ""
	@# Without nextest, one `cargo test` puts every isolated module in ONE
	@# process — exactly what IT_ISOLATED forbids: whichever module loads traits
	@# first wins the process-global mapper, so the others evaluate against the
	@# wrong rules. The fallback spawns one process per isolated module itself.
	@echo "Phase 3: process-isolated tests (nextest)..."
	@if command -v cargo-nextest >/dev/null 2>&1; then \
		cargo nextest run --workspace -E 'kind(test) & (not binary(it) | test(/$(IT_ISOLATED_RE)/))'; \
	else \
		echo "  cargo-nextest not found; running one process per isolated module..."; \
		cargo test --workspace --tests --exclude cleave -- --test-threads=1 || exit 1; \
		for m in $(IT_ISOLATED); do \
			echo "  --- $$m"; \
			cargo test --workspace --quiet --test it -- "$$m::" || exit 1; \
		done; \
	fi
	@echo ""
	@echo "✓ All tests passed"

test-fast: ## Run unit tests with YARA skipped
	@CLEAVE_SKIP_YARA=1 cargo test --workspace --lib --bins --quiet
	@echo "✓ Fast tests passed"

test-unit: ## Run only unit tests (skip integration tests, fastest)
	@cargo test --workspace --lib --bins --quiet
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
	@./scripts/check-hygiene.sh
	@echo "✓ Hygiene passed (file length, internal names, validator rule IDs)"
	@echo ""
	@echo "Running clippy with workspace lints..."
	@cargo clippy --workspace --all-targets --all-features -- -D warnings
	@echo "Running clippy without the rule linter (library-only build)..."
	@cargo clippy --lib --bins --no-default-features -- -D warnings
	@echo "Checking rustdoc links..."
	@RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --lib --quiet
	@echo "✓ Clippy passed"
	@echo ""
	@echo "Checking for unused dependencies..."
	@if command -v cargo-machete >/dev/null 2>&1; then \
		cargo machete --with-metadata; \
	else \
		echo "Note: cargo-machete not installed, skipping dependency check"; \
	fi
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

validate: ## Validate trait definitions ([TRAITS=path]; default: the installed traits)
	@echo "Validating trait definitions..."
	cargo build --quiet
	$(if $(TRAITS),CLEAVE_TRAITS_DIR=$(TRAITS) ,)./$(CARGO_TARGET)/debug/$(BINARY) validate
	@echo "✓ Validation passed"

# Cut a release: set the version everywhere it is recorded, prove the result
# builds the way CI will, and commit + tag it as one unit.
#
#     make cut-release VERSION=1.2.3
#
# The version lives in three places that must agree — Cargo.toml, Cargo.lock,
# and the tag — and release.yml rejects the build when any pair disagrees, so
# check that here in seconds rather than an hour into the release matrix.
#
# Pushing stays manual on purpose. That is the step that spends an hour of CI
# and publishes artifacts people download, so it gets a human; everything this
# target does is local and revertible with `git reset --hard HEAD~1` plus
# `git tag -d`.
cut-release: ## Bump version + lockfile, verify, commit and tag (VERSION=x.y.z)
	@test -n "$(VERSION)" || { echo "usage: make cut-release VERSION=x.y.z" >&2; exit 1; }
	@printf '%s\n' "$(VERSION)" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+([-+][0-9A-Za-z.-]+)?$$' \
		|| { echo "VERSION must look like 1.2.3 (got '$(VERSION)')" >&2; exit 1; }
	@test -z "$$(git status --porcelain)" \
		|| { echo "working tree is dirty — the tag must capture exactly what was tested:" >&2; \
		     git status --short >&2; exit 1; }
	@if git rev-parse -q --verify "refs/tags/v$(VERSION)" >/dev/null; then \
		echo "tag v$(VERSION) already exists" >&2; exit 1; fi
	@# Rewrite only the first `version =`, which is the one in [package].
	@awk -v v="$(VERSION)" 'BEGIN{d=0} /^version = "/ && !d {print "version = \"" v "\""; d=1; next} {print}' \
		Cargo.toml > Cargo.toml.tmp && mv Cargo.toml.tmp Cargo.toml
	cargo update -p $(PACKAGE) --offline
	@# The exact gate release.yml applies, minus the hour of linking.
	cargo check --locked --all-targets
	git add Cargo.toml Cargo.lock
	git commit -m "v$(VERSION)"
	git tag -a "v$(VERSION)" -m "$(BINARY) $(VERSION)"
	@echo
	@echo "tagged v$(VERSION). to release:"
	@echo "    git push origin $$(git rev-parse --abbrev-ref HEAD) && git push origin v$(VERSION)"

clean: ## Clean all build artifacts
	@echo "Cleaning build artifacts..."
	cargo clean
	rm -rf $(OUT_DIR)
	@echo "✓ Clean complete"

bench-build: $(OUT_DIR) ## Build benchmark binary (release + debug symbols for profiling)
	@echo "Building $(BINARY) (profiling: release + debug symbols)..."
	cargo build --profile profiling --features jemalloc
	cp $(CARGO_TARGET)/profiling/$(BINARY) $(OUT_DIR)/$(BINARY).bench
	@if [ "$$(uname)" = "Darwin" ]; then codesign -s - -f $(OUT_DIR)/$(BINARY).bench; fi
	@echo "✓ Benchmark binary: $(OUT_DIR)/$(BINARY).bench"

# Directory of samples to benchmark against: make benchmark BENCH_DIR=/path
BENCH_DIR ?=
check-bench-dir:
	@test -n "$(BENCH_DIR)" -a -d "$(BENCH_DIR)" || { echo "usage: make $(MAKECMDGOALS) BENCH_DIR=/path/to/samples" >&2; exit 1; }

benchmark: bench-build check-bench-dir ## Benchmark the release build (BENCH_DIR=path)
	@echo "Benchmarking $(OUT_DIR)/$(BINARY).bench on $(BENCH_DIR)..."
	CLEAVE_SKIP_CACHE=1 time $(OUT_DIR)/$(BINARY).bench --verbose --format=json $(BENCH_DIR) 2>$(OUT_DIR)/bench.err >$(OUT_DIR)/bench.out
	tail -n 20 $(OUT_DIR)/bench.err
	@echo "✓ Output: $(OUT_DIR)/bench.out  Logs: $(OUT_DIR)/bench.err"

sampled-benchmark: bench-build check-bench-dir ## Benchmark with samply CPU profiling (BENCH_DIR=path)
	@command -v samply >/dev/null 2>&1 || { echo "Error: samply not installed. Run: cargo install samply"; exit 1; }
	@echo "Profiling $(OUT_DIR)/$(BINARY).bench on $(BENCH_DIR) with samply..."
	CLEAVE_SKIP_CACHE=1 time samply record --save-only -o $(OUT_DIR)/bench.profile.json.gz $(OUT_DIR)/$(BINARY).bench --verbose --format=json $(BENCH_DIR) 2>$(OUT_DIR)/bench.err >$(OUT_DIR)/bench.out
	@echo "✓ Output: $(OUT_DIR)/bench.out  Logs: $(OUT_DIR)/bench.err  Profile: $(OUT_DIR)/bench.profile.json.gz"

heap-build: $(OUT_DIR) ## Build with jemalloc heap profiling support
	@echo "Building $(BINARY) (heap profiling: release + debug + jemalloc-prof)..."
	cargo build --profile profiling --features jemalloc-prof
	cp $(CARGO_TARGET)/profiling/$(BINARY) $(OUT_DIR)/$(BINARY).heap
	@if [ "$$(uname)" = "Darwin" ]; then codesign -s - -f $(OUT_DIR)/$(BINARY).heap; fi
	@echo "✓ Heap-profiling binary: $(OUT_DIR)/$(BINARY).heap"

heap-benchmark: heap-build check-bench-dir ## Benchmark with jemalloc heap profiling (BENCH_DIR=path)
	@echo "Heap-profiling $(OUT_DIR)/$(BINARY).heap on $(BENCH_DIR)..."
	@rm -rf $(OUT_DIR)/heap && mkdir -p $(OUT_DIR)/heap
	CLEAVE_SKIP_CACHE=1 _RJEM_MALLOC_CONF="prof:true,prof_active:true,prof_final:true,lg_prof_interval:28,prof_prefix:$(OUT_DIR)/heap/jeprof" \
		time $(OUT_DIR)/$(BINARY).heap --verbose --format=json $(BENCH_DIR) 2>$(OUT_DIR)/bench.err >$(OUT_DIR)/bench.out
	@echo "✓ Output: $(OUT_DIR)/bench.out  Logs: $(OUT_DIR)/bench.err"
	@echo "✓ Heap profiles: $(OUT_DIR)/heap/jeprof.*.heap"
	@echo "  Analyze with: jeprof --text $(OUT_DIR)/$(BINARY).heap $(OUT_DIR)/heap/jeprof.*.heap"
	@echo "  Note: tikv-jemalloc uses _RJEM_MALLOC_CONF (not MALLOC_CONF)"

$(OUT_DIR):
	mkdir -p $(OUT_DIR)

# Maintainer targets for publishing trait-update bundles.
include release.mk

# Optional per-developer targets (gitignored).
-include local.mk
