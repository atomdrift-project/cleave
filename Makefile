# flayer Makefile
# Build and test commands for deep static analysis tool

BINARY = flayer
OUT_DIR = out

# Use sccache for faster compilation if available
SCCACHE := $(shell command -v sccache 2>/dev/null)
ifdef SCCACHE
export RUSTC_WRAPPER := $(SCCACHE)
endif

.PHONY: all build debug release test lint fmt clean coverage ci help regenerate-testdata

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
	@echo "Running all tests (unit + integration)..."
	@echo ""
	@cargo build --quiet
	@if command -v cargo-nextest >/dev/null 2>&1; then \
		cargo nextest run --workspace; \
	else \
		cargo test --workspace; \
	fi
	@echo ""
	@echo "✓ All tests passed"

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
