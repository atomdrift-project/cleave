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
# CLEAVE_SKIP_CACHE also disables the compiled-YARA (.yrc) cache. Leave it off:
# with ~150 concurrent cleave processes, deserializing and rewriting every bucket
# costs more than lazily compiling the one bucket a fixture needs.

# Integration-test modules that mutate process-global state (traits override dir,
# analysis skip-overrides, env vars) and MUST run isolated under nextest — never
# in the shared `cargo test --test it` process, where their leaked state corrupts
# sibling tests. Kept in sync with `support::ISOLATED_MODULES`; the
# `shared_bucket_has_no_global_state_mutation` guard test fails if they drift.
IT_ISOLATED := archive_determinism_test archive_tmp_regression binary_traits_test \
	embedded_code_detection_test subfile_pipeline_test symbol_extraction_test \
	tiny_manifest_value_traits_test trait_migration_regression_test \
	traits_override_isolation_test \
	utf16_text_normalization_test yara_init_no_deadlock
empty :=
space := $(empty) $(empty)
IT_SKIP := $(foreach m,$(IT_ISOLATED),--skip $(m)::)
IT_ISOLATED_RE := $(subst $(space),::|,$(IT_ISOLATED))::

test: ## Run all tests (unit + integration)
	@echo "Running all tests (consolidated integration crate: shared libtest + isolated nextest)..."
	@echo ""
	@cargo build --quiet
	@# Phase 1: the ~200 pure integration tests share ONE libtest process (one
	@# capability-mapper build instead of one-per-test), ~20s vs ~10min.
	@echo "Phase 1: shared-process integration tests (cargo test)..."
	@# --test-threads=48: many of these tests wait on spawned cleave subprocesses,
	@# so threads > cores overlaps that waiting instead of idling test slots.
	@cargo test --test it -- $(IT_SKIP) --test-threads=48
	@echo ""
	@# Phase 2: lib + workspace tests AND the global-state integration modules,
	@# each isolated in its own process by nextest. The filter runs everything
	@# outside the `it` binary plus only the isolated `it` modules (the shared
	@# ones already ran in Phase 1).
	@echo "Phase 2: isolated integration + lib/workspace tests (nextest)..."
	@# Without nextest, `cargo test --workspace` puts every `it` test in ONE
	@# process — exactly what IT_ISOLATED forbids, and it fails: whichever module
	@# loads traits first wins the process-global mapper, so the others evaluate
	@# against the wrong rules and the failing set shifts with thread scheduling.
	@# The fallback therefore spawns one process per isolated module itself.
	@if command -v cargo-nextest >/dev/null 2>&1; then \
		cargo nextest run --workspace -E 'not binary(it) | test(/$(IT_ISOLATED_RE)/)'; \
	else \
		echo "  cargo-nextest not found; running lib/workspace tests, then one process per isolated module..."; \
		: "--test-threads=1: a few lib tests (e.g. test_reload_rollback_on_bad_traits)"; \
		: "point CLEAVE_TRAITS_DIR at a temp dir, which nextest isolates per process"; \
		: "but a shared process leaks into any test analyzing concurrently."; \
		cargo test --workspace --lib --bins -- --test-threads=1 || exit 1; \
		cargo test -p scpt --tests -- --test-threads=1 || exit 1; \
		for m in $(IT_ISOLATED); do \
			echo "  --- $$m"; \
			cargo test --quiet --test it -- "$$m::" || exit 1; \
		done; \
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
	@cargo clippy --workspace --all-targets --all-features -- -D warnings
	@echo "Running clippy without the rule linter (library-only build)..."
	@cargo clippy --lib --bins --no-default-features -- -D warnings
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
	CLEAVE_SKIP_CACHE=1 time $(OUT_DIR)/$(BINARY).bench --verbose --format=jsonl $(BENCH_DIR) 2>$(OUT_DIR)/bench.err >$(OUT_DIR)/bench.out
	tail -n 20 $(OUT_DIR)/bench.err
	@echo "✓ Output: $(OUT_DIR)/bench.out  Logs: $(OUT_DIR)/bench.err"

sampled-benchmark: bench-build check-bench-dir ## Benchmark with samply CPU profiling (BENCH_DIR=path)
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

heap-benchmark: heap-build check-bench-dir ## Benchmark with jemalloc heap profiling (BENCH_DIR=path)
	@echo "Heap-profiling $(OUT_DIR)/$(BINARY).heap on $(BENCH_DIR)..."
	@rm -rf $(OUT_DIR)/heap && mkdir -p $(OUT_DIR)/heap
	CLEAVE_SKIP_CACHE=1 _RJEM_MALLOC_CONF="prof:true,prof_active:true,prof_final:true,lg_prof_interval:28,prof_prefix:$(OUT_DIR)/heap/jeprof" \
		time $(OUT_DIR)/$(BINARY).heap --verbose --format=jsonl $(BENCH_DIR) 2>$(OUT_DIR)/bench.err >$(OUT_DIR)/bench.out
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
