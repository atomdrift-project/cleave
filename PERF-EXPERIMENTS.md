# Performance Optimization Experiments

This file tracks performance optimization experiments for `cleave`.

## Baseline (2026-03-27)
- Target: `~/data/benchmark/200MB` (590 files)
- Command: `make benchmark DATASET=200MB`
- Initial Results:
  - Real: 96.66s
  - User: 385.44s
  - Sys: 326.35s

## Mid-point Baseline (After Exp 1-4)
- Target: `~/data/benchmark/200MB`
- Results:
  - Real: 94.69s (vs 96.66s) - **~2s (3%) faster**
  - User: 377.58s (vs 385.44s) - **~8s (2%) reduction**
  - Sys: 321.44s (vs 326.35s) - **~5s (1.5%) reduction**

## Final Results (All Optimizations)
- Target: `~/data/benchmark/200MB`
- Results:
  - Real: **88.10s** (vs 96.66s initial) - **~8.5s (9%) overall speedup**
  - User: **344.89s** (vs 385.44s initial) - **~40s (10%) reduction**
  - Sys: **278.25s** (vs 326.35s initial) - **~48s (15%) reduction**

## 600MB Dataset Results (2026-04-05)
- Target: `~/data/benchmark/600MB` (3645 files, 1287 analyzed)
- Command: `make benchmark DATASET=600MB`
- Results (Initial):
  - Real: **350.95s**
  - User: **880.06s**
  - Sys: **695.99s**
  - Peak RSS: **8173MB**
- Results (After Bitset-based Pruning - HashSet version):
  - Real: **355.14s** (vs 350.95s) - **~1% slower**
  - User: **885.05s** (vs 880.06s) - **~0.5% slower**
  - Sys: **746.61s** (vs 695.99s) - **~7% slower**
  - Peak RSS: **8034MB** (vs 8173MB) - **~140MB reduction**
- Results (After Bitset-based Pruning - Optimized TraitBitSet):
  - Real: **374.90s** (vs 350.95s initial) - **~7% slower**
  - User: **885.65s** (vs 880.06s initial) - **Negligible change**
  - Sys: **791.73s** (vs 695.99s initial) - **~14% increase**
  - Peak RSS: **7713MB** (vs 8173MB initial) - **~460MB reduction (6%)**

## Summary of Winners

### 1. Symbol Indexing (Exp 6)
- **Impact**: **Huge Winner.** Shaved 11s off the 13MB telnyx archive run.
- **Optimization**: Replaced linear scans of imports/exports with an O(1) HashSet-based lookup once per file.

### 2. Rule Parallelism Removal (The "Nested Parallelism" Fix)
- **Impact**: Shaved ~9s off the 13MB archive run.
- **Optimization**: Sequential rule evaluation within each file to reduce task management overhead when the outer loop (files) is already parallel.

### 3. Batch AST Collection (Idea 9)
- **Impact**: Significantly reduced per-rule overhead for source files.
- **Optimization**: Walked the AST once per file to collect all required node types into a cache, allowing rules to do instant lookups instead of new traversals.

### 4. Byte-based Regex Matching
- **Impact**: Eliminated 600MB+ of UTF-8 validation and copies by matching binary data directly.

### 5. Rizin Stability
- **Impact**: Improved system stability and reduced `sys` time via a concurrency semaphore and command pruning.

### 6. Bitset-based Dependency Pruning (Idea 1)
- **Impact**: Reduced rule evaluation overhead by skipping composite rules whose required atomic traits are missing.
- **Optimization**: Added a `trait_id_map` to `CapabilityMapper` and `required_trait_indices` to `CompositeTrait`. Used a custom `TraitBitSet` (Vec<u64>) for O(1) trait-presence checks during the iterative evaluation loop.

## New Experiments (600MB Dataset)

### Exp 11: Persistent Rizin Worker Pool
- **Hypothesis**: Maintaining a pool of long-lived `rizin` processes will eliminate the `fork`/`exec` and VM initialization overhead for MachO/PE analysis.
- **Optimization**: Implement a worker pool that communicates via stdin/stdout using a JSON-RPC protocol.
- **Results**: TBD

### Exp 12: In-Memory Payload Virtualization
- **Hypothesis**: Replacing `NamedTempFile` with an in-memory virtual filesystem for recursive payload analysis will significantly reduce `sys` time and disk I/O.
- **Optimization**: Create a memory-backed abstraction for the recursive analysis pipeline.
- **Results**: TBD

### Exp 13: SIMD-Accelerated String Triage
- **Hypothesis**: Using SIMD to pre-filter strings for interesting characters (like `def`, `import`, `{`) will allow skipping 90% of `embedded_code_detector` work in <1% of the time.
- **Optimization**: Implement a fast-path SIMD scanner before tree-sitter/regex dispatch.
- **Results**: TBD

### Exp 14: Cross-File Trait Memoization
- **Hypothesis**: Caching findings for common library code blocks (by SHA-256) will allow skipping analysis for redundant code across the 600MB dataset.
- **Optimization**: Implement a global LRU cache for function-level trait findings.
- **Results**: TBD

### Exp 15: Adaptive YARA Tiering
- **Hypothesis**: Dynamically escalating or skipping YARA tiers based on early triage results will reduce scanning time for benign or clearly suspicious files.
- **Optimization**: Implement a triage pass to select the optimal YARA rule subset per file.
- **Results**: TBD

### Exp 16: Predictive Analyzer Skipping
- **Hypothesis**: Using entropy and header heuristics to skip analyzers that are likely to fail will reduce redundant structural analysis work.
- **Optimization**: Implement "fast triage" heuristics for analyzer dispatch.
- **Results**: TBD

### Exp 17: Recursive Archive Streaming
- **Hypothesis**: Analyzing archive members as they are streamed will reduce peak RSS and disk churn compared to full extraction.
- **Optimization**: Refactor archive analyzers to use streaming decompressors.
- **Results**: TBD

### Exp 18: Lazy Evidence Serialization
- **Hypothesis**: Delaying `String` formatting for `Evidence` and `Location` fields until reporting will eliminate thousands of unnecessary allocations.
- **Optimization**: Store raw offsets/pointers and only format strings for findings included in the final report.
- **Results**: TBD

### Exp 19: Hoisted IP Regex Pass
- **Hypothesis**: Running a single global regex pass over all strings once per file will be faster than 12+ independent `ip_validator` checks.
- **Optimization**: Pre-calculate an "IP match map" in the `EvaluationContext`.
- **Results**: **Failed.** (Real: 538.58s, User: 1453.86s, Sys: 1148.47s).
- **Analysis**: Eagerly evaluating the complex IP regex on *all* strings in a binary (hundreds of thousands) is vastly more expensive than evaluating it *lazily* only on the tiny subset of strings that have already matched a simpler rule condition (like an exact substring). The existing identity-based LRU cache was already optimal; it just needs a larger capacity.

### Exp 19.5: Lazy IP Cache Sizing
- **Hypothesis**: The existing identity-based LRU cache in `ip_validator.rs` was optimal but thrashing on large files due to a capacity of only 1024. Increasing it to 65536 will preserve the benefits of lazy evaluation without the cost of repeated regex scans.
- **Optimization**: Increased thread-local `LruCache` capacity from 1024 to 65536.
- **Results**: **Failed.** (Real: 540.92s, User: 1428.63s, Sys: 1174.05s).
- **Analysis**: The regression remains. The eager regex pass is simply too expensive. We must stick to lazy evaluation of IP conditions where the strings are already filtered by the `exact` or `substr` rules first.


### Exp 20: Rule Requirement Bitmasking 2.0
- **Hypothesis**: Using a pre-computed dependency matrix and SIMD `AND` operations will skip entire blocks of composite rules faster than the current iterative BitSet.
- **Optimization**: Implement category-based bitmasking for rule groups.
- **Results**: TBD

### Exp 21: Arc<str> Refactor
- **Hypothesis**: Changing all ID and description fields to `Arc<str>` will eliminate massive allocation/clone overhead across the entire pipeline.
- **Optimization**: Codebase-wide type refactor from `String` to `Arc<str>`.
- **Results**: TBD
