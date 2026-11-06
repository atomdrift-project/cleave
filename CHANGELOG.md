# Changelog

All notable changes to cleave. Versions follow [semantic versioning](https://semver.org/spec/v2.0.0.html).

## 3.0.0-beta.3 (unreleased)

### Security

- Never install compiled YARA rules from rule bundles; they are native code, so cleave compiles them locally.

### Features

- Recover PyArmor-protected Python and PS2EXE-wrapped PowerShell statically, without running either runtime.
- Recognize Nuitka-compiled binaries and their bundled payloads.
- Recover PE payloads hidden in RC4 table envelopes, metamorphic RC4 grafts and batch certutil hex blobs.
- Analyze Ren'Py RPA archives, rpyc scripts and JPHP bytecode.
- Deobfuscate JavaScript permutations, decimal-packed strings and string tables, including inline scripts in HTML.
- Analyze source package archives as archives, so member rules apply to them.
- Treat a dependency held by its registry for security reasons as hostile on its own.
- Add an experimental render command that redisplays a saved report without rescanning.
- Add an index output format, one row per finding, selected with `--index`.
- Breaking: replace rizin and radare2 with in-process binform analysis; the radare2 component is gone.
- Breaking: bump the JSON schema to 9, and emit `--format json` as one object per line.
- Breaking: retire the tiny output format; terminal and jsonl remain as aliases.
- Breaking: remove `--platforms`, the maximum-criticality filters, and the file size and memory limits.
- Breaking: remove the log-file, update-check, enable-all and full-facts flags, and update's check and pin options.

### Fixes

- Restore YARA bindings on cached rules, so inline traits and YARA composite legs keep matching after warm-up.
- Drop the fully compiled DFA, which made regex-automata miss byte-mode matches in text and raw rules.
- Keep every member of an explicit union alive in `any` composites instead of dropping alternatives.

### Optimizations

- Recompile only YARA rule sets whose sources changed, instead of starting cold after every update.
- Gate symbol and path regexes behind literal atoms, and batch text candidates and AST queries.
- Run rooted tree-sitter queries per root node on deep trees, and skip comments when rules ignore them.
- Write the analysis cache from its own thread, keeping SQLite waits off scanner workers.
- Size work by macOS super cores, and count ZFS ARC as reclaimable memory.

## 3.0.0-beta.1 (2026-10-13)

### Security Notice

- Removed vulnerable & obsolete `--extract-dir` flag to close a path traversal flaw: [GHSA-rjq9-6g6p-98qr](https://github.com/atomdrift-project/cleave/security/advisories/GHSA-rjq9-6g6p-98qr). Kudos to @ajayk for discovery!

### Features

- Expanded capability validation to cover taxonomy, scope, patterns, and oversized rules.
- Added AST timing diagnostics for validation.
- Removed obsolete server mode as part of the 3.0 beta CLI-only transition.
- Updated RAR extraction to maintained unrar-ng.

### Fixes

- Standardized YARA evaluation across analyzers, archives, and unpacked UPX files so findings and inline traits propagate consistently.
- Hardened archive, LZX, and PyInstaller parsing against malformed or oversized untrusted inputs.
- Sanitized terminal output to escape control sequences and Unicode directionality controls.

### Optimizations

- Accelerated rule validation with caching, AST reuse, parallel checks, regex batching, and metadata caching.

## 2.12.1 (2026-10-10)

### Fixes

- Replace UnRAR `extract_to` with in-memory or private-dir extraction, blocking hostile hardlinks.
- Count decoded RAR bytes against the extraction budget, not header-declared sizes.
- Reject `..` and absolute member names during sample extraction.
- Run extractors with an allowlisted environment, so API tokens never reach them.
- Invoke 7z, nm, lldb and gdb by absolute path, with `--` before file arguments.
- Create UPX temp copies owner-only, without inheriting setuid or world-writable bits.
- Return 403 for missing paths in `/analyze-path`, closing a file-existence probe.
- Fail truncated uploads, and honor the configured 250 MB limit instead of axum's 2 MB.
- Rate-limit IPv6 clients per /64 to stop address-rotation bypass.
- Require HTTPS for rule-bundle downloads, and suppress update URLs containing control characters.
- Treat Java library packages as benign only at the class-path root.
- Override the type of `.env`, `.PKGINFO` and `*.rsc` files to Text only when content isn't binary.
- Pin the Electron fixture exemption to its exact SHA-256.
- Truncate regex literal prefixes at whole UTF-8 characters, fixing missed matches.
- Evaluate metrics-based traits in the follow phase for files without source bytes.

### Features

- Add `module_level` and `receiver.from` to `kind: call` symbol conditions.
- Add comments, flow, identity and archive-members views to `cleave facts`/`inspect`.
- Add `graft_located_reference_outcome_traits` to re-check composites using fetch-edge spans.

### Optimizations

- Skip tree-sitter queries whose required literals are absent from the file.
- Cut the AST query CPU budget from 30s to 5s, 3–4× faster on large extensions.

## 2.12.0 (2026-10-09)

### Upgrade Notes

- `for: archive` is retired; target `zip`, `tar`, `rar`, `7z` or `cpio` explicitly.
- Alpine `.apk` files now match `alpine_apk`, not `apk`.
- `cleave validate` rejects filename-based convictions and about 93 retired IDs.

### Features

- New formats: RAR, 7z, cpio, Snap/SquashFS, PHAR, NIB/XIB and AppleScript, plus improved XAR.
- New file types: YARA, JSP, ASP, CFML, TeX, PostScript, DOS COM, mIRC/ircII and raw shellcode.
- New decoders: repeating-key XOR in PE files, Mach-O ChaCha payloads, PowerShell literals and obfuscated Lua.
- Scripts embedded in GitHub Actions workflows are analyzed as code.
- Chrome extension manifests report declared permissions and host access.
- Reports name compression and encoding layers, and flag analysis gaps such as incomplete disassembly.
- `tiny` and `interpret` output show the evidence behind each composite verdict.
- Rules gain YARA-style hex syntax, `not:` and `is:` conditions, and new composite scopes.

### Fixes

- Composites without `scope:` no longer combine evidence across archive members, ending false hostile verdicts.
- Fewer false positives: tar `./` entries are no longer flagged as zip-slip, YARA rule files and signature catalogs no longer match their own rules, and chart-linked OOXML workbooks are no longer flagged as template injection. VBA presence is now notable, not suspicious.
- Archive nesting depth rose from 10 to 32.
- Fixed UTF-16 decoding, including text without a BOM.
- Results from incomplete analyses are no longer cached.

### Optimizations

- Scanning and `cleave validate` are faster, and the work spent on pathological payloads is capped.

## 2.11.0 (2026-09-14)

### Features

- Font analyzer (sfnt/WOFF/WOFF2/EOT) and media analyzer (WAV, AIFF, MP3, MP4, ICO, GIF, BMP, WebP).
- SVG is its own rule type.
- `is: base64` string validator.
- Symbol conditions gained argument positions (`index:`) and value provenance (`from:` with transfer models).
- `downgrade:` gained `scope:` (defaults to file) so one archive member can't silence a rule in another.
- New `analysis_gaps` field reports incomplete analysis in text and JSON, independently of findings.
- `cleave validate` fixtures assert required/forbidden trait hierarchies and required analysis gaps.
- Nine new validators, and hostile composites now need two notable+ legs instead of one.
- Unparseable trait files warn on every run, not just the run that rebuilt the cache.
- PE version-info extraction now enumerates the StringTable structurally, surfacing custom vendor keys like `CompiledScript`.
- PE FileDescription projects to identity title when filefacts supplies none.

### Fixes

- Cache stores key on the traits revision the analysis ran under.
- Archive/decoded roots are never rebuilt from the leaf cache, which dropped children.
- Findings demoted by their own `downgrade:` are kept instead of stripped away entirely.
- Call symbols come from filefacts, giving chained calls one matchable spelling (`open.read`).
- C functions are named by identifier, not by their whole signature.
- Proximity evidence keeps per-offset locations and the winning window's real matched text.
- MSI/OLE/OOXML and Java class reports populate strings, so `type: text` rules work.
- `section: any` is honored by the matcher and spans all mapped sections.
- JAR class triage ranks classes by constant-pool salience rather than attacker-controlled archive order.
- Embedded-binary scanning dedupes by content and samples across the file.
- Mach-O ad-hoc signing no longer double-reports.
- Hex patterns under the concrete-byte floor warn instead of silently never matching.
- Decoded-layer folding rewrites parent IDs, `src`, and composite source edges instead of orphaning them.
- Source string retention is bounded in aggregate.
- `cleave test-rules` evaluates string conditions with their full parameter set.

### Optimizations

- Match locations are collected only for traits that can reach a proximity constraint.
- JAR salience scoring shares the YARA triage read rather than adding a second archive walk.
- Embedded-binary header checks are bucketed per file region (8,192 checks / 1,024 candidates per scan).
- Java class and other analyzers reuse the caller's filefacts parse instead of reopening it.
- wasmtime/cranelift at `opt-level = 2` and `test = false` on helper bins cut cold-build time.

## 2.10.0 (2026-09-10)

### Features

- Trait rules can match nested encoding chains (`base64+base64`).
- New build file-type group; pbxproj and CMake file types usable in rules.
- New filetypes recognized: YAML, PGP, SquashFS, Snap, Flatpak.

### Fixes

- The rich terminal view trims extraneous context.

## 2.9.0 (2026-09-08)

### Features

- JSON reports now include `supp[]`, the traits that matched but were suppressed or demoted by an `unless:`/`downgrade:` leg.
- Composites now carry `uses[]`, the indices of the components they fired on.
- `conf` is always emitted, no longer omitted at 0.5.
- New `cleave regex-cost` subcommand checks patterns for lazy-DFA explosion.
- New regex-explosion validator rejects rules that blow up on bundle-shaped text.
- Decodes Unicode variation-selector steganography.
- Detects PyPI typosquats at edit distance 1 from high-value package names.
- Flags generator-produced identifiers such as DGA labels, maldoc authors, and bundle IDs.
- Reports how much of a VS Code extension pack the publisher actually owns.
- New `references.security_hold_count` counts dependencies pulled for security holds.

### Fixes

- JAR analysis no longer truncates at 100 non-class members.
- A single huge JAR no longer monopolizes the thread pool.
- Container-scope import checks no longer see zero imports under compact retention.
- UPX timeouts and missing binaries are no longer reported as hostile findings.
- Fixed `traits_version` attribution, Java predicates, directory refs, and the Windows memory guard.

### Optimizations

- Regex pre-warming at startup drops a small Python wheel from ~640 ms to ~100 ms.
- Symbol matching uses cleave's thread-local regex scratch instead of the crate's shared pool.
- Duplicate archive members are analyzed once rather than per occurrence.
- Eager full-DFA construction is off by default, saving ~95 MiB on a 44k-pattern set.
- Archive fan-out backs off under host memory pressure.
- cgroup accounting no longer counts page cache as used, which had reported 15.6 GiB free where 55 GiB was.
- The LLM render draws one window per finding, cutting 11% of repeated evidence.

## 2.8.0 (2026-08-25)

### Features

- Expanded embedded-script analysis, including layered deobfuscation and encoded PowerShell detection.
- Added broader archive, SFX, symbol, AES-payload, and format analysis.
- Expanded capability/composite-rule semantics and validation.

### Bugfixes

- Corrected composite applicability, all conditions, offset attribution, and duplicate string handling.
- Improved YARA/source invalidation and rule-loading correctness.
- Fixed several memory, subprocess, and platform edge cases.

### Optimizations

- Added parallel archive analysis and bounded member rebuilding.
- Added regex windowing, cached searchers, indexed capability evaluation, and memory compaction.
- Added heap profiling and Rayon nesting controls.

## 2.7.2 (2026-08-14)

### Fixes

- Windows binaries are back. An `unused_imports = "deny"` failure on a Unix-only `anyhow::Context` import broke the Windows build.
- YARA rule fingerprint now hashes file contents, not just path + length.
- Trait YAML without an inline `type: yara` rule no longer invalidates compiled YARA.
- Fingerprint combination is order-independent without the collision risk of the old `wrapping_add` sum.

### Performance

- The new content hash is memoized on disk against the existing stat-only traits walk.

### Release engineering

- Release matrix split into fast (native, Windows, cross — ~30 min) and slow (emulated/VM platforms — up to 75 min) waves.
- Publish logic extracted into a reusable publish-assets composite action, shared by both waves.
- Windows ARM64 dropped from the default matrix.
- 32-bit ARM musl targets now link `-lgcc` for the jemalloc intrinsics (`__ffsdi2`, byte-width CAS) that musl and compiler_builtins don't provide.

### Dependencies

- Updated filefacts, stng 1.8.0 → 1.9.0, libredox 0.1.19 → 0.1.20.

## 2.7.1 (2026-08-14)

### Faster

- Pre-compiled YARA rules ship with the binary — no rule compilation on first scan.
- Big-buffer literal scanning is chunked and parallelized; ASCII patterns skip Unicode compilation.
- Composite rule lookups indexed instead of rebuilt three times per call.

### Detects more

- Win32 EXE, Win64 DLL, Mach-O, ELF executable now map to real file types. Those upstream rules never ran before.
- Fixed a panic on multibyte characters in YARA rule comments.

### Better diffs

- Truncation is severity-ordered: a hostile finding in a late file can no longer be crowded out by baseline noise.
- Version-stamped archive roots are paired, so a version bump shows real per-file changes instead of total churn.
- Diff JSON gains `conf` and `file_type`.

### Correctness

- Caches are keyed by detected file type, and cached results no longer come back missing symbols.
- jemalloc build fix for NetBSD, illumos, and Solaris — this was blocking the release.

### Supply-chain integrity

- Compiled rules carry a fingerprint; a mismatch against source is rejected, not silently scanned with.
- Rule updates de-duplicate case-variant files, so a checkout is identical on every filesystem.
- Full CI/release pipeline landed: 20+ platforms, signed and notarized macOS, SHA-pinned actions.

## 2.7.0 (2026-08-14)

### Faster scanning

- Text traits with alternations or case-insensitive literals now go through the Aho-Corasick prefilter instead of running their regex against every file — the prefilter extracts a mandatory literal set from each pattern, and traits matching inside decoded layers (base64, xor) are still fed candidates from those layers so nothing is gated out.
- Identical bytes are analyzed once: concurrent requests for the same SHA256 (both sides of a diff, duplicate archive members) share a single in-flight analysis, with care taken so Rayon workers never block on it.
- Diffs skip members whose SHA is identical on both sides entirely.
- jemalloc keeps freed pages around for 10 minutes instead of returning them immediately, bounding kernel VMA count without growing RSS.

### Better archive analysis

- Nested member paths keep full provenance (`bundle.zip!!setup.exe!!payload.dll`), and child executables inherit the enclosing archive's config — limits, YARA, extraction settings — instead of standalone defaults.
- SFX/self-extracting installers found inside archives are materialized to temp files so external extractors (7z, innoextract) can open them.
- LZMA-alone (`.lzma`) archives are supported, including base64-embedded blobs.
- With `--all-files`, unrecognized members now get the full pipeline (strings, filefacts, capability evaluation) instead of a bare path entry.
- File-count guard raised from 100k to 350k members (Kibana 9.4 ships ~137k).

### Fewer false positives, fewer misses

- npm download-and-execute detection now only fires on install/publish lifecycle scripts — fixes a Kibana FP from a codegen script.
- Unchanged files that are hostile on both sides of a diff stay visible in the output instead of being filtered as "no change".
- New incompatible-regex validator: trait patterns using lookaround or backreferences — which the linear-time engine silently can't compile — are now a hard validation error instead of dead rules.

### New surface

- Repeatable `--zip-password` flag for encrypted archives (appended to the built-in password list).
- Library API `cleave::extract_member()` returns one member's raw bytes (64 MiB cap).
- New PE layout metrics: header size/ratio, directory-vs-section mismatches, and prose-looking section counts.

## 2.6.0 (2026-08-10)

### Detection

- `type: syscall` traits match for the first time — nothing ever populated the syscall list, so every such rule was dead.
- Syscall conditions take an `args:` predicate, so a rule can pin `PROT_EXEC` on `mprotect`.
- OCI/Docker images, Void `.xbps`, and Gentoo `.gpkg.tar` extract and recurse.
- 20 file types stopped routing to unknown — lockfiles, `.SRCINFO`, OpenDocument, bare gz/bz2/xz, `.dmg`, `.asar`.
- `.dmg` needs upstream 7-Zip (`7zz`); p7zip can't read APFS, so contents went unscanned.

### Correctness

- Long Linux scans aborted with "memory allocation failed" that wasn't OOM: jemalloc's `retain:true` split a VMA per free until the kernel mapping count hit `vm.max_map_count`, at 19 GB RSS against a 108 GiB limit.
- `cleave diff` on directories hid `.github/` — the `.git` skip was a prefix match, so CI workflows, `.gitignore`, and `.gitattributes` were invisible.
- A 1.5 GB APFS partition inside a `.dmg` was analyzed as VBScript: three generic markers hundreds of MB apart satisfied the script sniff, which is now capped at 4 KB.
- Syscall evidence anchored every unresolved call site at byte 0 — the ELF magic.
- Benign fixtures with an explicitly raised cap still failed against a hard-coded suspicious ceiling.

### Rule authoring

- New count-min-regex-alternation validator: `count_min` over an alternation counts one branch repeatedly.
- Alternation-decomposition warnings scoped to counted traits; comment matchers exempt from the regex-length check.
- Directories fanning past 150 subdirectories are flagged — a taxonomy level that became a flat list.
- `well-known/` subdirectory whitelists for `dual-use/`, `app/`, `lib/`, `tool/`.

### Performance

- Byte-native regex: one engine per pattern instead of an ASCII/Unicode pair whose Unicode NFAs ran 5–10× larger. `\w`, `.`, `\s`, `\b` are now ASCII-only against non-ASCII content, as in YARA.
- Members over 10 MiB are mapped, not read — one sample held ~1.4 GB of member buffers at once.
- Member traits, strings, and facts are freed at fold time on the disk-walk paths, which never released them (57,857 members on one archive).
- Whole-file UTF-8 view built once per file; a 487 MB disk image was spending ~185 CPU-s re-transcoding it.
- Universal, file-type, and archive-family regex sets scan concurrently.
- Regex scratch pool is a flat 512 MiB, not 1/32 of RAM: on a 57k-member archive, 2 GiB cost 12.8 GB peak / 506 s, 512 MiB cost 11.6 GB / 468 s.

### Platforms

- 32-bit ARM sizes the regex scratch pool to [64 MiB, 512 MiB] rather than the 64-bit [512 MiB, 4 GiB].
- Homebrew tap renamed: `brew install atomdrift-project/tap/cleave`.

## 2.5.0 (2026-08-04)

### Detection

- Support for analyzing ISO images.
- Mach-O code signatures are verified, not just read.
- Truncated archives raise `anti-analysis/malformed/archive-incomplete`.
- Clearer Mach-O entitlement labels.

### Correctness

- Rizin skip was process-global: a member opting out muted rizin for whatever binary another thread was parsing.
- Truncated gzip now analyzes the decoded prefix instead of aborting with no report at all.
- PE signer names with escaped commas were truncated: `O=Postman\, Inc.` surfaced as `Postman\`, including in finding ids.
- `cleave update` no longer wedges on a dangling traits symlink.

### Performance

- Cold start drops ~5s of per-invocation setup: regex derivations memoized to disk.
- Archive scans: string atoms gate regexes, duplicate lazy compiles deduped.
- Member strings are freed after matching — multiple GB on member-heavy archives.

### Platforms

- Initial Windows & NetBSD builds.
- illumos cross-builds.

## 2.4.0 (2026-07-25)

### Faster

- Large-archive scans up to ~8× faster (a 63k-member archive: 2,865s → matches the 337s loose-file baseline).

### Detection

- Java exfil now needs explicit exfil vocabulary.
- IP filter recovers real hosts like 3.147.61.167 that were dropped as version-strings.
- Better CRX signed-but-unverified detection.
- New filetype: static libs (`.a`).

### Correctness

- Dependency findings dedup per-artifact, not per-report.

### Output

- `--format=interpret` renders LLM-friendly ASCII windows with offset gutters (cheaper for local models); terminal view unchanged.

## 2.3.0 (2026-07-11)

### Features

- `length_min`/`length_max` bound regex match length; replaces costly `{4000,}` repetitions.
- KV length bounds now match strings by byte length (previously never matched).
- New regex-memory validator flags patterns that exceed budget or silently never compile.
- Benign fixtures can require a minimum score.
- Compact JSON: parent id (`pid`), trait IDs in descriptions.
- Archive entries report entropy, magic bytes, and extension/type mismatch.
- PyInstaller entries tagged by kind.
- Tiny render: benign files show their strongest traits; binary windows get hex-offset rows.
- FreeBSD/arm64 builds again!
- Automated trait publishing on a timer (unsigned for now).

### Fixes

- `near_*` windows could match on `any:` legs alone while an `all:` leg sat far away; windows now require every `all:` leg. Fixes false positives.
- Java exfil triggers narrowed to explicit exfil terms; upload alone no longer fires.
- Mach-O malformed-header check skips files under 4 KB.
- XOR payload noise in text files suppressed unless it looks like runnable source.

### Optimizations

- Regex engine rebuilt on `regex_automata` with byte-budgeted caches; removes 1.5–4 GB RSS spikes on large binaries. Match semantics unchanged.
- Parallel prefilter and path-trait evaluation for large archives.
- Indexed `unless:` suppression; was a linear scan per finding.
- YARA scanner cache 4 to 64; avoids ~31k scanner rebuilds on a 13k-member archive.

## 2.2.1 (2026-07-07)

- Performance improvements: lazy loading indexes & mappers.

## 2.2.0 (2026-07-06)

### Features

- New filetype recognition so rules can target WASM, Android DEX, CAB, and APK.
- Local reference graphs linking files to their package/provenance origins (new `reference_graph` type).
- Richer package registry lookups, with registry records grafted into analysis output.
- New `crit: exception` composite rules for clearer intent signalling for trait authors.
- Facts now carry metric spans (byte ranges) pinpointing where each measurement's evidence lives.
- Tiny output gains component-level line detail and a top-5 files summary.

### Fixes

- Fixed YARA cold-bucket and init deadlocks; stopped clearing the YARA cache unnecessarily.
- Fixed base64/XOR false positives in SVG files; added XOR source-detection test fixtures.
- Loosened IP-address and metrics validation to reduce false positives.
- Description-length requirements now also apply to composite rules.

### Performance

- Non-blocking cache cleanup.

## 2.1.2 (2026-06-22)

- matcher: fix subtle hex variable gap bug.
- matcher: add initial entropy window metrics.
- deps: pin to rusqlite 0.39.0 for Rust 1.94 compat.
- validate: increase max suppress cap.

## 2.1.1 (2026-06-22)

- Precompiled YARA files — load prebuilt YARA rules (new yara-precompile tool).
- Dynamic YARA tier loading — tiers load on demand instead of all upfront.
- YARA tier preheating — warms the right tiers based on incoming file type for lower latency.
- `validate --soft` flag — skips directory caps and other taxonomy-cleanliness rules.
- Loads of dependency updates.

## 2.1.0 (2026-06-20)

- DMG & `go.mod` support.
- Experimental `--fetch` support.
- Moved more parsing onto filefacts.
- Added `iter-files --newer-than`.
- Added `validate --soft`.
- Tightened trait validation checks.
- Tightened testdata validation.
- Improved archive decompression handling.
- Fixed Alpine APK multi-member parsing.
- Reduced compact JSON size.
- Improved batch file symbol handling.
- Improved Java class handling.
- Improved source symbol matching.
- Improved binary metadata anchoring.
- Improved rizin/filefacts cache maintenance.
- Updated manifest generator behavior.
- Added pre-commit hook support.
- Updated dependencies.

## 2.0.0 (2026-06-14)

Since our last release (1.4.0):

- Engine swap — all parsing moved to the filefacts crate; breaking JSON schema v3 + CLI renames.
- Context-centric output — context as sole evidence surface, grep-style hex, Z85 compact.
- Package + platform coverage — npm/crate/NuGet/APK/ASAR/CRX archives; FortiOS/PanOS/JunOS/Ivanti, RouterOS, JCL; Program Identity.
- Signed trait-bundle updates — R2-backed `.tar.zst` with sha256, pin/check/update, daily check.
- Memory & perf — admission gate, bounded regex cache (fixed ~7.7 GB leak), SIMD matching.
- Correctness — Mach-O offsets, archive XOR/payload recursion, generic JSON, fewer false positives.

Since rc5:

- Context-centric output — new context module (+925) and major output rewrite: context is the sole evidence surface, grep-style hex windows with bold evidence, overlap-dedup by confidence×level.
- New appliance platforms — FortiOS, PanOS, JunOS, Netscaler, Ivanti detection; plus RouterOS (`.rsc`) and JCL (z/OS) rule support.
- Program Identity — publisher/package metadata surfaced; signing info promoted to notable.
- Z85 binary encoding for compact output; improved embedded-binary display, per-trait offsets.
- Binary fixes — corrected Mach-O FAT offsets; tighter tiny-binary context windows.
- Rule eval timeouts extended (90s) for heavily loaded systems.
- Stricter trait-reference validation, perf sweep, dependency updates.

## 2.0.0-rc.5 (2026-06-09)

### Features

- Added R2-backed trait bundle updates with sha256 verification, atomic install, pin/check/update support, and signed manifest publishing.
- Updated to filefacts 0.9.5 and stng 1.6.0 for richer package, PE/CLR, Mach-O, PE import, and string-extraction signals.
- Added archive routing for package ecosystems like gem, npm, crate, conda, egg, NuGet, IPA, VSIX, Android/Alpine APK, and Arch/FreeBSD pkg.
- Archive/outer-scoped composites can now pool findings across archive members, useful for browser extensions and split payload packages.
- JVM bytecode imports now include owner-qualified symbols like `java/lang/Runtime.exec`.
- npm script capability checks moved toward YAML traits for more precise per-hook supply-chain features.

### Performance

- Trait update artifacts now use `.tar.zst` bundles instead of git clones/pulls.
- Manifest generation now compat-tests release versions and HEAD, caches validation, and supports pre-publish integrity checks.
- Archive members now share the same encoded-payload processing path as standalone files instead of duplicating logic.

### Bugfixes

- Fixed archive members missing encoded-payload findings and decoded payload recursion.
- Fixed archive members skipping XOR extraction, which weakened detection inside npm/zips/jars.
- Tiny structured manifests under 100 bytes now still evaluate KV/value traits.
- UTF-16 test matching now normalizes text like production analysis.
- Office external-template findings now distinguish remote injection targets from benign local template paths.
- IP matching no longer lifts false IPv4 hits out of OIDs or long version strings.
- Edge extension update URLs are treated as first-party, avoiding Chrome extension false positives.
- Embedded-code evidence offsets now map back to parent-file line proximity correctly.

## 2.0.0-rc.4 (2026-06-07)

### Update notifications (initial implementation, not yet live)

- Once-a-day update check against a static TOML manifest (no telemetry); disable with `--no-update-check` or `CLEAVE_NO_UPDATE_CHECK`.
- New manifest tooling: manifest-gen (Go, soak-gated beta/stable channels) and update-manifest (bash, one-shot builds with cosign signing).

### Memory & performance

- Memory-aware admission gate: large archives serialize while small files fill the pool, using live available-memory readings so concurrent instances share the host.
- Archive members analyzed in bounded byte-windows instead of all-resident; per-member reports folded and dropped immediately.
- Trait regexes moved to a bounded LRU cache — the old design leaked every compiled engine (~7.7 GB RSS on member-heavy archives).
- `word:`/`substr:` matching via SIMD literal searchers, no regex engine; ASCII raw patterns skip the unicode engine entirely.
- Evidence values capped at storage time; exact match counts computed only when a rule needs them.
- Accurate physical-core detection (SMT siblings excluded, Apple Silicon P-cores, illumos, FreeBSD/arm64 sysctl fix) drives pool sizing.
- Instantaneous RSS readings on FreeBSD/illumos so the memory gate can reopen; optional memprofile feature for phase-tagged heap accounting.

### Matching semantics & correctness

- AST query cache made unbounded with serialized compiles — fixes nondeterministic finding loss during parallel archive analysis.
- UTF-16 scripts normalized to UTF-8 before text matching — a UTF-16 VBS now matches like its UTF-8 twin.
- `not: exact:` is now case-sensitive, so excluding PowerShell doesn't excuse pOwErShElL.
- AST walks bounded by CPU time, not wall clock — starved threads no longer silently drop detections.
- Markdown code blocks treated as documentation, not embedded scripts.
- New trait surface: `type: comment`, `type: path` (basename/dirname scopes), import `alias:` filters, multi-arg `args:` matching, `is: valid_ip`, bare section names (`rsrc`, `__cstring`) for PE/Mach-O.
- Cache-hit reports re-stamp `file.basename`/`file.stem` — no more phantom diffs between identical files.

### Analyzers

- Chrome/WebExtension manifests now emit neutral per-permission and per-host capability traits instead of hardcoded risk scores.
- XML parsing rejects pathologically deep documents (stack-overflow DoS guard).
- VBA identifier metrics (length, entropy, distinct triggers); compact JSON schema bumped to v6 with smaller evidence locations.

### Rule validation

- New checks: `scope: archive` with non-archive `for:`, repeated inline `unless:` exclusions, duplicate detection scoped to matching sections.
- Explicit `for:` type limit relaxed to 8; per-condition-type caps removed; hardware/gpu taxonomy section added.

### API & maintenance

- New `scan_files()` library entry point (explicit path list, shared resources, streaming callback).
- Symbol source field removed from output; deadlock detection now an opt-in feature.
- Dependency updates.

## 2.0.0-rc.3 (2026-05-28)

### Features

- Electron ASAR archive support — `.asar` containers are now parsed in-memory and their members routed through normal file-type detection.

### Fixes

- Correct identification of Clojure, `.whl`, and `.xpi` files.
- Better Chrome extension (CRX) handling.
- Fixed a trait near/scope matching conflict.
- Trait location info now propagates through to results.

### Internal

- Removed the obsolete fileid crate (~3,700 lines) in favor of the built-in detector.
- Dropped the legacy ast compatibility type (now fully tree-sitter) and the `./traits` directory convention.
- Dependency updates.

## 2.0.0-rc.2 (2026-05-26)

### Features

- Generic JSON analysis. New `FileType::Json` routes any non-manifest `.json` through the generic analyzer (via filefacts); directory scans no longer skip them. (b2a9bf9)
- Cross-file kv comparisons in archives. `type: value` conditions gain `eq:` / `ne:` keys for path-vs-path comparisons, with optional `<filename>::` prefix to reach a sibling archive entry. Case-insensitive, whitespace-trimmed, scalar-only. (3400b90)
- Markdown + PkgInfo archive members now analyzed so cross-file matchers can reach their identity facts. (3400b90)
- `traits_repo` prefers a workspace-local `./traits` before the platform data dir / auto-clone. (b065f97)

### Behavior changes

- Regex↔substr duplicate detection decodes pure-literal regexes (e.g. `\.aws/credentials` ↔ `.aws/credentials`) and adds a complementary-surface allowlist (basename↔content, encoded↔content). (b2a9bf9)
- `protocol` added to the banned vague-subcategory list. (00d15a3)
- `UnifiedSourceAnalyzer::new` no longer returns `Result` (was infallible). (e66f247)
- `ArgFilter` visibility tightened from `pub` to `pub(crate)`. (e66f247)

### Fixes

- filefacts `ArchiveMember` interface hardened — members now expose nested compression, ownership, offsets sub-structs; VBA sentinel relocated to `filefacts::VBA_NON_LITERAL_SENTINEL`. (f3856b6)
- Removed leftover local-dev `[patch]` override for filefacts. (214cf0a)

### Build & deps

- Default release profile = thin LTO + `codegen-units = 16` (~3× faster link); fat LTO is opt-in via new `release-lto` profile and `make release-lto`; wolfi/melange packaging switched to it. (b4538b6)
- Edition bumped to Rust 2024, version → 2.0.0-rc.2. (c4a4c10)
- Deps: filefacts advanced four times (→ 74b002f, plus 0.6 → 0.7); stng 1.4 → 1.5 and moved to crates.io; bincode 1.x dropped; dirs deduped to a single 6.0 copy. (6ed7327, 6e24c11, 6c3d0b7, 00d15a3, a20678e, f3856b6, c4a4c10)

### Internal

- New library override hooks — `set_skip_traits_override`, `set_skip_yara_override`, `set_builtin_yara_only_override` (env vars still work as fallback). (c4a4c10)
- `main.rs` no longer sets `CLEAVE_VERBOSE` (Rust 2024 makes `set_var` unsafe; value was unused). (c4a4c10)
- 130-file Rust 2024 sweep is otherwise mechanical (let-chains, rustfmt 2024 import order). (c4a4c10)

## 2.0.0-rc.1 (2026-05-25)

### Engine swap to filefacts

The new filefacts crate (codeberg.org/atomdrift/filefacts) owns every parse cleave used to do directly. Cleave no longer depends on goblin, gimli, png, jpeg-decoder, or any of the 21 tree-sitter grammar crates.

### Breaking — JSON schema v3

`AnalysisReport` reshaped:

- Removed: `binary_properties`, `code_metrics`, `source_code_metrics`, `overlay_metrics`, `metrics`.
- Added: `filefacts` — typed views (values, metrics, sections, imports, exports, functions, errors). Read `filefacts.values.pe.machine` directly.
- Added: `filefacts_metrics: BTreeMap<String, f64>` — the only numeric metric surface.
- Renamed: `kv_tree` → `values_tree`.

### Breaking — CLI

- `cleave kv` → `cleave value`.
- New: `facts` (alias `inspect`), `imports`, `exports`, `functions`.
- Trait matcher `type: kv` → `type: value`.
- Section gained `flags[]`.

### Features

- Cached AST traits reuse filefacts's `tree_sitter::Tree`.
- Subfile pipeline — better OOXML and embedded-payload routing.
- Archive analyzers reworked; Dockerfile support; archive kv/metrics.
- NATS and gRPC under communication taxonomy.

### Docs & packaging

- New: `docs/INTEGRATION.md`, `RUST_API.md`, `SERVER_API.md`, `JSON.md`.
- New: `packaging/wolfi/` (apko/melange/lima + scripts).

### Build & performance

- Release: `lto = "fat"`, `codegen-units = 1`.
- Profiling: `lto = "thin"`, cu = 16 (cuts ~10 min per link in profiling iterations).
- Dev `opt-level = 3` for cleave + regex + serde_yaml + aho-corasick — kills 30 s of trait-init overhead per subprocess test.
- Strings: skip XOR + UTF-16 scan on large ASCII inputs.
- `analyze` takes the report by ownership instead of cloning.

## 1.4.0 (2026-05-13)

Pre-CackalackyCon release.

### Features

- PDF analysis now reports richer structure: objects, ObjStm contents, streams, signatures, forms, actions, embedded files, and more.
- LNK analysis now extracts richer shortcut metadata: relative paths, volume/network info, environment targets, shim/Darwin data, and more.
- Improved illumos/Solaris support (jemalloc, memory reporting).

### Bugfixes

- Diff formula rendering handles absent formulas cleanly.
- Diff header/formula alignment tests no longer trip unwrap/expect lints.
- PDF stream parsing now records malformed length/delimiter/endstream cases.

## 1.3.1 (2026-05-09)

### Features

- Diff now shows behavioral formula changes per file and in single-file headers.
- Malecule formulas now track updated well-known categories: app, game, lib, tool, and malware.

### Performance

- Metrics diffs are quieter: numeric and boolean signals stay in metrics, raw strings/arrays move to kv.
- Updated analysis/runtime deps, including stng 1.3.0, yara-x 1.16, and Wasmtime/Cranelift 43.

### Bugfixes

- Diff headers no longer overlap when formula fingerprints are wider than filenames.
- Formulas are consistent across terminal, JSON, JSONL, library API, and diff output.
- JSON, JSONL, terminal, API, and diff formulas now use the same confidence/criticality filter.
- Low-confidence, baseline, and component findings no longer pollute formulas.
- Metrics diffs no longer duplicate kv-style string and array changes.

## 1.3.0 (2026-05-08)

### Features

- `cleave diff` compares files or directories across traits, metrics, kv, symbols, strings, and sections.
- `cleave kv` now covers binaries, Office, RTF, PDF, images, JAR/class, pyc, pickle, RPM, PDF, and source.
- Added CHM parsing, LZX decode, member analysis, metrics, and kv.
- Added Office metrics for VBA, XLM, DDE, external refs, embedded payloads, and template injection.
- Added binary provenance: PE manifests, signing data, DWARF, Go build info, Mach-O codesign, entitlements, and plist data.
- `cleave validate` now tests hostile, benign, and does-nothing fixtures.
- Added PyInstaller extraction and kv.

### Performance

- Archive analysis now avoids nested rayon deadlocks.
- ZIP, JAR, CHM, and PyInstaller analysis avoid unnecessary `/tmp` extraction.
- macOS defaults rayon to performance cores when possible.
- YARA stores only the match ranges useful for evidence.
- PNG and JPEG skip huge pixel decodes but keep structural signal.

### Bugfixes

- Large source files skip risky tree-sitter AST parsing.
- Non-OLE `.msg` files no longer go through Office parsing.
- Directory output chooses tied traits deterministically.
- Archive and UPX wrappers inherit child findings correctly.
- Diff suppresses low-value churn and handles order-independent kv arrays.
- Multi-line evidence now indents instead of trashing terminal output.
- Package-lock and XHTML detection were cleaned up.

## 1.2.1 (2026-05-01)

### Features

- `cleave validate` now prints the resolved traits directory for easier rule-pack auditing.

### Performance

- Linux memory limits now respect cgroup v2 `memory.high` / `memory.max`, improving behavior in containers and systemd services.
- Updated stng to 1.2.1 and refreshed dependency versions.

### Bugfixes

- Prevented crashes on deeply indented Python by skipping risky tree-sitter AST parsing and emitting a dedicated suspicious parser finding.
- Moved invisible-Unicode detection out of hardcoded findings and into metrics, reducing false positives while preserving signal for rules.
- Improved string evidence to show context around the actual matched substring.
- Reduced noisy unknown XOR/encoded-payload findings unless the decoded preview contains actionable indicators like commands, scripts, or URLs.
- Cleaned up encoded payload evidence formatting.

## 1.2.0 (2026-04-28)

### Features

- New `kv` subcommand for key-value extraction.
- Scanner support for XDG `.desktop`, XML, Makefile, plain text.
- In-memory analysis support.
- Symbol offset tracking.
- New PE metrics: `primary_signer`, `self_versioned_forwarder`.
- Embedded file and archive entry metrics.
- MBC/ATT&CK data in reports.

### Performance

- Parallel rizin + goblin analysis.
- Reworked rayon threading to eliminate deadlocks.
- Skip rizin for Go binaries; scale rizin by file size.
- Pre-compiled traits and in-memory archive caching.
- SHA256 reuse and cache pre-warming.
- Faster string extraction on embedded binaries.
- Disable YARA in validate mode; cap rizin memory; kill rizin on exit.

### Bugfixes

- Stop misdetecting Kotlin as Python (with AST validation).
- Fix YARA deadlock in capability mapper.
- Fix rayon deadlock in archive analyzer.
- Fix rizin stdout blocking.
- Fix crashes on malformed sections via boundary checks.
- Recover from goblin parse failures; cap unbounded ELF note reader.
- Filter unroutable `.0`-octet IPs.
- Fix CRX3 extraction.
- Handle oversized archive filenames.
- Prevent YARA panics with timeouts and error recovery.

## 1.1.0 (2026-04-10)

### Features

- New systemd service unit file type (`systemd`).
- v4 compact JSON schema for `--format json/jsonl`: string tuples, 2dp metrics, deduplicated findings, criticality as unsigned ordinals 0–5.
- ~60 new PE fields: header scalars, Authenticode, timestamps, anomaly booleans.
- ~20 new ELF fields: header, linking metadata, symbol counts, build ID/debuglink.
- ~25 new Mach-O fields: CPU type, load commands, dylib info, build version, code signature.
- New ELF finding-level metadata: interpreter, soname, needed libs, rpath/runpath, build-id, debuglink.
- Archive member limit raised 1K → 100K.
- `reload_capability_mapper` made public for external hot-reload.

### Improvements

- Non-program archive members skipped by default (previously all entries were fully analyzed).
- Streaming archive implementation removed; single unified code path.
- Code-classified strings evaluated first, capped at max(100, len/20) attempts.
- Already-matched traits not re-evaluated.
- In-memory AES payload decryption (eliminates per-extraction disk I/O).
- Detection limits restored: 256 strings, 1KB file-type sniffing, 5MB AA.
- CLI no longer creates 0-byte log files; log path moved to `XDG_STATE_HOME`.
- `string_value`/`string_literal` renamed to `text` in trait YAML (old names still accepted).
- YARA classifier and fileid extracted to their own crates.

### Bugfixes

- `FileType::Unknown` was incorrectly matched against ELF/PE/Mach-O rules.
- ELF syms incorrectly pushed to imports regardless of `SHN_UNDEF`.
- Orphaned server task slots never released, eventually causing 503s.
- node-gyp Python symlinks falsely flagged as symlink-escape.
- Same base64 payload at multiple offsets reported multiple times.
- `RawContentRegexIndex` matched decoded string content instead of raw binary data.

## 1.0.0 (2026-04-10)

### Features

- Added a version command showing the binary version, traits revision, rule counts, and YARA rule count.
- Improved archive/container handling with more specific archive file types in rule evaluation.
- Added PE section offsets to analysis output.

### Bugfixes

- Cut false positives across embedded code, payload, package, Office, and archive analysis.
- Improved file-type detection so docs, templates, and other text are less likely to be misclassified as code.
- Fixed composite rule parsing/evaluation issues, including AST predicate handling and stricter validation of malformed shorthand rules.
- Refined severity for rust-based traits, especially around PE parsing issues and benign embedded content.

### Performance

- Skipped expensive string and embedded-code analysis for unknown text files.
- Reduced overhead in archive detection, sorting, and cache handling.

## 0.9.0 (2026-03-24)

### New Features

- Lua script detection: Added content-based heuristic to detect Lua scripts without `.lua` extension.
- Supply-chain taxonomy: New `objectives/supply-chain/` trait category with validated subdirectories: credential-theft, hidden-payload, impersonation, install-hook, metadata-anomaly, recon-exfil, trojanized. Moved out of `lateral-movement/` to properly distinguish package ecosystem attacks from network propagation.

## 0.8.0 (2026-03-24)

### New Features

- Library crate — Cleave can now be used as a Rust library, not just a CLI.
- Pickle analyzer — Detects malicious deserialization in `.pkl`, `.pickle`, and `.joblib` files by scanning for dangerous callables like `os.system`.
- CAB archive support.
- Bitcoin address validation — `--is bitcoin_addr` validates Legacy, P2SH, SegWit, and Taproot addresses with full checksum verification.
- Criticality filters — `--min-crit`, `--max-crit`, `--min-file-crit`, `--max-file-crit`.
- File-in-archive caching — Identical files across multiple archives are analyzed only once.
- Per-channel image entropy — R/G/B entropy for JPEG and PNG significantly improves steganography detection.
- Trait taxonomy expansion — New supply-chain objective and fleshed-out subcategories.

### Bug Fixes

- Precision overhaul — Eliminates false positives on HTML/SVG templates, bare PHP files, NSIS binaries, and `package.json` dotfile refs outside install hooks.
- PE overlay analysis — Signed executables no longer flag for their own Authenticode certificates.
- .NET embedded PEs — Downgraded to Notable; bundling native DLLs is normal behavior.
- Zip bomb threshold — Raised to 100 MB uncompressed to reduce false positives on well-compressed files.
- Stack overflows in recursive analysis paths fixed.

### Performance & Reliability

- Request cancellation — Server timeouts now halt analysis immediately rather than running it to completion.
- `/health` endpoint — Returns 503 when memory is exhausted or the thread pool is full.
- Memory and resource caps — Default limit set to 25% of system RAM; string extraction capped at 100K strings / 50 MB per file; VBA decompressor capped at 10 MB. Override memory limit with `CLEAVE_MAX_RSS_GB`.
- `make install` target added. Updated dependencies: zip 8.4, toml 1.1, cab 0.6 (new).

## 0.3.0 (2026-03-17)

### New Features

- Office document support — Initial OLE/Office doc analysis.
- Steganography detection — New steganography metrics and improved detection.
- Platform-aware filetype group auto-filtering.
- `--format=tiny` output mode — Minimal output format for scripting and pipelines.
- VBScript support — Analyze VBScript files.
- JPEG filetypes.
- Diagnostic HTTP endpoints — Added server endpoints for runtime diagnostics.
- `CLEAVE_LOGS_DIR` env var — Configurable log output directory.
- Platform/filetype inferencing for 3rd-party YARA queries.
- FreeBSD thread monitoring.
- `action.yaml` recognized as github-actions filetype.

### Performance

- jemalloc as default allocator for improved memory performance.
- Dynamic memory thresholds — Automatically adjust memory limits at runtime.
- Improved thread pooling and memory/cache protection.
- Faster YARA — Speed up YARA build and tier processing.
- Startup cache tuning and removal of mode from cache key.
- Efficiency tuning — Read-once I/O path, sampled benchmarks, and multiple rounds of perf tuning.
- AST processing deadline to prevent hangs on pathological inputs.

### Bug Fixes

- Fix aho-corasick overlap matching, producing incorrect results.
- Fix directory scanning with archives.
- Fix PE/zst detection.
- Fix m68k architecture identification.
- Make XOR extraction consistent across analysis paths.
