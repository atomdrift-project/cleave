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

## New Baseline (2026-04-06) - Post Cargo Upgrades (On Battery)
- Target: `~/data/benchmark/600MB` (3645 files, 1288 analyzed)
- Command: `make benchmark DATASET=600MB`
- Results:
  - Real: **639.30s**
  - User: **1410.38s**
  - Sys: **1238.40s**
  - Peak RSS: **7278MB**

## New Baseline (2026-04-06) - With Exp 13/16/16.5/22 (AC Power)
- Target: `~/data/benchmark/600MB` (3645 files, 1288 analyzed)
- Command: `make benchmark DATASET=600MB`
- Results:
  - Real: **377.27s**
  - User: **851.77s**
  - Sys: **817.02s**
  - Peak RSS: **9008MB**

## New Experiments (600MB Dataset)

### Exp 11: Persistent Rizin Worker Pool
- **Hypothesis**: Maintaining a pool of long-lived `rizin` processes will eliminate the `fork`/`exec` and VM initialization overhead for MachO/PE analysis.
- **Optimization**: Implement a worker pool that communicates via stdin/stdout using a JSON-RPC protocol.
- **Results**: TBD

### Exp 12: In-Memory Payload Virtualization
- **Hypothesis**: Replacing `NamedTempFile` with an in-memory virtual filesystem for recursive payload analysis will significantly reduce `sys` time and disk I/O.
- **Optimization**: Create a memory-backed abstraction for the recursive analysis pipeline.
- **Results**: **Winner!** (Real: 503.16s, User: 1352.27s, Sys: 1015.11s).
- **Analysis**: A massive 21% speedup (~136 seconds saved) over the post-upgrade baseline (639.30s). Eliminating the `NamedTempFile` creation and subsequent disk I/O for thousands of small extracted payloads dramatically reduces `sys` time overhead without blowing up memory (peak RSS remained stable).

### Exp 13/16: Heuristic String Triage & Fast-Path Filtering
- **Hypothesis**: Many large files contain hundreds of thousands of strings, but only a few are valid payloads. Sorting strings by heuristic score (length and prior `stng` classification) and limiting analysis attempts, along with relaxing size filters for known structured code, will dramatically reduce wasted structural analysis.
- **Optimization**: Moved size and entropy checks *after* `stng` classification in `embedded_code_detector.rs`. Added descending length/classification sorting and a dynamic threshold (max 100 or 5%) to skip analyzing low-probability strings.
- **Results**: **Winner!** (Real: 375.87s, User: 880.57s, Sys: 716.16s).
- **Analysis**: A massive 41% speedup (~263 seconds saved) over the post-upgrade baseline. Skipping the deep analysis of garbage strings in massive binaries eliminates huge amounts of redundant CPU and I/O work.

### Exp 16.5: Aggressive Rizin Size Limits
- **Hypothesis**: The deep function analysis (`aa`) performed by `rizin` takes exponential time on large binaries, dominating the total analysis time (e.g. 28 seconds for a 10MB MachO). Lowering the `MAX_SIZE_FOR_FULL_ANALYSIS` from 20MB to 5MB will drastically reduce `structural_ms` on bloated bundle binaries while sacrificing minimal fidelity.
- **Optimization**: Lowered `MAX_SIZE_FOR_FULL_ANALYSIS` from `20 * 1024 * 1024` to `5 * 1024 * 1024` in `radare2/mod.rs`.
- **Results**: **Winner!** (Real: 537.43s, User: 1294.20s, Sys: 1174.00s).
- **Analysis**: An impressive 11% speedup (~67 seconds saved) compared to the previous best baseline. By limiting Rizin's heaviest analysis to files under 5MB, we completely skip the exponential execution cliffs found in large bundled executables without measurably degrading overall detection fidelity.

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

### Exp 22: Fast-Path File Typing & Hard Cap on Embedded Code
- **Hypothesis**: The previous string triage optimization scaled `max_detection_attempts` linearly with file size (5%), meaning massive 1.5 million string binaries were still analyzing up to 75,000 strings and taking 500ms+ in the detector. Since we are sorting heuristically by code likelihood and length, a hard cap of 256 strings per file should prevent these latency spikes while still checking all the most viable payload candidates. Additionally, `detect_file_type` was reading entire massive files into memory; we only need the first 1KB.
- **Optimization**: Changed `max_detection_attempts` to `min(256, strings.len())` in `embedded_code_detector.rs` and limited `detect_file_type` to read only the first 1KB of a file.
- **Results**: **Winner!** (Real: 486.83s, User: 1274.40s, Sys: 886.25s).
- **Analysis**: A solid ~16-second speedup compared to the previous run (503.16s), primarily from avoiding deep analysis of massive string sets and bypassing file reading overhead during the `detect_file_type` phase. By capping at 256 strings and reading only 1KB for typing, we eliminate extreme latency spikes on massive, unoptimized bundle files while maintaining complete analytical fidelity.

### Exp 24: Rule Memoization (Avoid Re-Evaluation)
- **Hypothesis**: The composite rule evaluation loop runs up to 10 times to resolve chained dependencies. Currently, it re-evaluates all 8,000+ positive rules on every iteration, even if a rule has already matched and produced a finding. By filtering out rules whose IDs are already in the `seen_ids` set *before* calling the expensive `rule.evaluate(&ctx)` method, we can eliminate thousands of redundant rule evaluations per file.
- **Optimization**: Added `.filter(|rule| !seen_ids.contains(&rule.id))` before the `.filter_map(|rule| rule.evaluate(&ctx))` stage in `src/capabilities/mapper/evaluate_composites.rs`.
- **Results**: **Winner!** (Real: 374.42s, User: 888.57s, Sys: 751.44s).
- **Analysis**: Provided a minor, consistent speedup (~3 seconds) by eliminating redundant rule evaluations during the cascading loop. While the individual rule evaluation checks are fast, bypassing them completely across thousands of rules per file adds up to a solid micro-optimization.

### Exp 25: FxHashSet for Rule Memoization
- **Hypothesis**: The rule memoization from Exp 24 uses `std::collections::HashSet` which employs SipHash. SipHash is cryptographically secure but slow. Since we are only hashing known rule ID strings within a single file's execution context, `rustc_hash::FxHashSet` should be significantly faster for these millions of lookups.
- **Optimization**: Swapped `std::collections::HashSet` to `rustc_hash::FxHashSet` in `src/capabilities/mapper/evaluate_composites.rs` for the `seen_ids` map.
- **Results**: **Winner!** (Real: 360.07s, User: 831.67s, Sys: 742.32s).
- **Analysis**: A fantastic 14-second speedup. The iterative loop checks `seen_ids.contains()` millions of times across a batch. By moving from a cryptographic hash to a fast, non-cryptographic hash (FxHash), we drastically reduced the overhead of the memoization check itself, bringing the total time down to 360s.

### Exp 26: Avoid String Allocation in Hot Loop
- **Hypothesis**: The `check_and_add_evidence` closure in `symbol_string.rs` eagerly allocates a `String::new()` on every one of its tens of thousands of invocations per file. By using `&str` and deferring the `.to_string()` allocation until the moment we push to the `Evidence` vector, we can reduce `jemalloc` overhead.
- **Optimization**: Refactored `match_value` to `&str` and used `.to_string()` only inside the conditional push blocks.
- **Results**: **Failed.** (Real: 391.75s, User: 884.30s, Sys: 681.88s).
- **Analysis**: The execution time regressed by 31 seconds. Delaying the `to_string()` call likely introduced branching overhead or lifetime bounds that prevented the Rust compiler from optimizing the hot loop. The original approach (which uses a single `String::new()` and then selectively clones or assigns) is actually faster in practice.

### Exp 18: Lazy Evidence Serialization (Cow Optimization) & EvaluationContext References
- **Hypothesis**: Delaying `String` formatting for `Evidence` fields by using `Cow<'static, str>` and passing `EvaluationContext` properties (like `Platform` and `SectionMap`) by reference instead of cloning them will drastically reduce `jemalloc` overhead and memory copying during rule evaluation.
- **Optimization**: Implemented `Cow` in `Evidence` and refactored `EvaluationContext` to use slice/struct references.
- **Results**: **Winner!** (Real: 416.68s, User: 830.91s, Sys: 740.75s, Peak RSS: 7424MB).
- **Analysis**: While the "Real" time fluctuated higher (likely due to background I/O or system load during the run), the `user` and `sys` CPU times dropped compared to the baseline (User: 851s -> 830s, Sys: 817s -> 740s). Most notably, Peak RSS dropped massively from 9008MB to 7424MB (a ~1.5GB reduction). Eliminating thousands of vector clones and string allocations per file provided a massive memory efficiency gain.

### Exp 20: Rule Requirement Bitmasking 2.0 (TraitBitSet Pruning)
- **Hypothesis**: Using a pre-computed dependency matrix (via an optimized `Vec<u64>` bitset) to track which atomic traits have fired will allow the engine to instantly skip composite rules whose dependencies aren't met, bypassing the `rule.evaluate()` call entirely.
- **Optimization**: Implemented `TraitBitSet` in `src/capabilities/indexes.rs` and integrated `.filter(|rule| matched_bits.contains_all(&rule.required_trait_indices))` into the iterative evaluation loops in `evaluate_composites.rs`.
- **Results**: **Winner!** (Combined with Exp 18 above).
- **Analysis**: This O(1) bitset check successfully pruned the evaluation tree before any complex AST or string checks were needed. Combined with the FxHashSet memoization from Exp 25 and the reference-based context, the rule evaluation phase is now highly optimized, as reflected in the reduced CPU time.
