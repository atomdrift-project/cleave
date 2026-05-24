# Edit allowlist for implementing agents

The proposer hands ideas to a coding-agent (gemini by default) which
edits files inside the worktree. The agent has wide latitude in *how*
to realize an idea, but the following boundaries are enforced.

## May edit

- `src/**/*.rs`
- `Cargo.toml`
- `Cargo.lock` (let cargo regenerate after dep changes)
- Anywhere under a Rust source tree the proposer named explicitly via `hints`.

## Must not edit

- `tests/**` — never weaken test coverage to make a perf change pass.
- `.github/**` — CI changes are out of scope.
- `Makefile` — bench targets are the contract; changing them invalidates the measurement.
- `traits/**` and `*.yaml` trait definitions — these are the product's
  capability surface and have their own validation pipeline.
- `benches/**` if added later — same reasoning as tests.

## Trigger an auto-revert

`cleave-tuna` reverts the experiment without benchmarking if:

- `cargo check` fails.
- `cargo test --lib` fails.
- The agent produced no changes after its run.
- Diff touches any path in the "must not edit" list.

The third one matters: if you can't realize the idea, return early.
Better to leave the slate slot empty than to commit a no-op.
