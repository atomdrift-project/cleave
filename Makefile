# flayer Makefile
# Build and test commands for deep static analysis tool

BINARY = flayer
OUT_DIR = out

# Use sccache for faster compilation if available
SCCACHE := $(shell command -v sccache 2>/dev/null)
ifdef SCCACHE
export RUSTC_WRAPPER := $(SCCACHE)
endif

.PHONY: all build debug release test test-fast test-unit lint fmt clean coverage ci help regenerate-testdata

# Default target
all: build

help: ## Show this help
	@echo "flayer Makefile"
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@echo "  build                 - Build in debug mode (default)"
	@echo "  debug                 - Build in debug mode"
	@echo "  release               - Build in release mode"
	@echo "  test                  - Run all tests (unit + integration)"
	@echo "  test-fast             - Run tests quickly (skip YARA, lib tests only)"
	@echo "  test-unit             - Run only unit tests (skip integration tests)"
	@echo "  fmt                   - Format all code with rustfmt"
	@echo "  lint                  - Run code formatting and linting checks"
	@echo "  coverage              - Generate code coverage report"
	@echo "  ci                    - Run all CI checks (test + lint)"
	@echo "  regenerate-testdata   - Regenerate integration test snapshots from ~/data/flayer"
	@echo "  clean                 - Clean all build artifacts"

build: debug ## Build in debug mode (default)

debug: ## Build in debug mode
	@echo "Building $(BINARY) (debug mode, treating warnings as errors)..."
	cargo build
	@echo "✓ Debug build successful"

release: $(OUT_DIR) ## Build in release mode
	@echo "Building $(BINARY) (release mode, treating warnings as errors)..."
	cargo build --release
	cp target/release/$(BINARY) $(OUT_DIR)/
	@echo "✓ Release binary: $(OUT_DIR)/$(BINARY)"

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
		FLAYER_SKIP_YARA=1 cargo nextest run --workspace --lib; \
	else \
		FLAYER_SKIP_YARA=1 cargo test --workspace --lib; \
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
	@echo "✓ Coverage report generated at: target/llvm-cov/html/index.html"

ci: test lint ## Run all CI checks (test + lint)
	@echo "✓ All CI checks passed"

clean: ## Clean all build artifacts
	@echo "Cleaning build artifacts..."
	cargo clean
	rm -rf $(OUT_DIR)
	@echo "✓ Clean complete"

regenerate-testdata: release ## Regenerate integration test snapshots
	@echo "Regenerating test data from ~/data/flayer..."
	cargo build --release --quiet --bin regenerate_testdata
	./target/release/regenerate_testdata

$(OUT_DIR):
	mkdir -p $(OUT_DIR)
