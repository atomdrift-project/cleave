# cleave Makefile
# Build and test commands for deep static analysis tool
# Compatible with both GNU make and BSD make

BINARY = cleave
OUT_DIR = out

# Honor CARGO_TARGET_DIR if set (cleave-tuna sets it to share the cargo cache
# across worktrees). Falls back to the cargo default `target` otherwise.
CARGO_TARGET ?= $(if $(CARGO_TARGET_DIR),$(CARGO_TARGET_DIR),target)

# For sccache, set RUSTC_WRAPPER=sccache in your environment

.PHONY: all build debug release check-cargo install tarball rollout-bastille test test-fast test-unit lint fmt clean coverage ci help regenerate-testdata loadtest bench-build benchmark sampled-benchmark validate tuna tuna-once wolfi wolfi-bootstrap wolfi-build wolfi-test wolfi-shell wolfi-clean wolfi-nuke

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

release: check-cargo $(OUT_DIR) ## Build in release mode
	@echo "Building $(BINARY) (release mode, treating warnings as errors)..."
	cargo build --release --features jemalloc
	cp $(CARGO_TARGET)/release/$(BINARY) $(OUT_DIR)/$(BINARY).new && mv -f $(OUT_DIR)/$(BINARY).new $(OUT_DIR)/$(BINARY)
	@if [ "$$(uname)" = "Darwin" ]; then codesign -s - -f $(OUT_DIR)/$(BINARY); fi
	@echo "✓ Release binary: $(OUT_DIR)/$(BINARY)"

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

validate: ## Validate trait definitions (for: restrictions, taxonomy, precision, etc.)
	@echo "Validating trait definitions..."
	cargo build --quiet
	./$(CARGO_TARGET)/debug/$(BINARY) validate
	@echo "✓ Validation passed"

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
